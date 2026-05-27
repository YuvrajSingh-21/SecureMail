import logging
from ..models import SyncJob, EmailMessage, ConnectedAccount
from .gmail_service import GmailService
from django.utils import timezone
from django.db import transaction, IntegrityError

logger = logging.getLogger(__name__)

class SyncManager:
    """
    Manages background Gmail synchronization jobs.
    """
    def __init__(self, user):
        self.user = user
        try:
            self.account = ConnectedAccount.objects.get(user=user)
            self.gmail = GmailService(self.account)
            # Re-use a single pipeline instance for the entire thread
            from .email_pipeline import EmailPipeline
            try:
                self.pipeline = EmailPipeline()
                logger.info(f"SyncManager initialized with EmailPipeline for {user.username}")
            except Exception as pe:
                logger.error(f"SyncManager failed to initialize EmailPipeline: {str(pe)}")
                self.pipeline = None
        except Exception as e:
            logger.error(f"SyncManager failed to initialize Gmail context for {user.username}: {str(e)}")
            self.account = None
            self.gmail = None
            self.pipeline = None

    def start_sync(self, full_sync=False):
        """Initializes a new sync job."""
        if not self.gmail:
            return None

        # Cancel any existing running jobs for this user
        SyncJob.objects.filter(user=self.user, status='RUNNING').update(status='FAILED', error_message='Overridden by new job')

        job = SyncJob.objects.create(
            user=self.user,
            status='RUNNING',
            total_messages=0,
            synced_messages=0
        )
        
        # To meet the < 3s login requirement while still importing all messages:
        # We run the sync process in a separate thread.
        import threading
        thread = threading.Thread(target=self._run_sync_thread, args=(job, full_sync))
        thread.daemon = True
        thread.start()
            
        return job

    def _run_sync_thread(self, job, full_sync):
        """Wrapper for thread execution to handle errors and database connections."""
        from django.db import connection
        try:
            # We don't limit if full_sync is True
            limit = None if full_sync else 50
            self._execute_sync(job, limit=limit)
        except Exception as e:
            job.status = 'FAILED'
            job.error_message = str(e)
            job.save()
            logger.error(f"Background sync failed: {str(e)}")
        finally:
            connection.close()

    def _execute_sync(self, job, limit=None):
        """Internal execution of the sync process."""
        # 1. Fetch all IDs to know the scope
        summaries = self.gmail.fetch_all_message_ids(max_total=limit)
        job.total_messages = len(summaries)
        job.save()

        # 2. Process in batches of 50
        batch_size = 50
        for i in range(0, len(summaries), batch_size):
            batch = summaries[i:i + batch_size]
            
            # We avoid transaction.atomic() for the whole batch to prevent poisoning.
            # Instead, we process each message individually.
            for summary in batch:
                msg_id = summary['id']
                
                try:
                    # Individual atomic block for each message to isolate failures
                    with transaction.atomic():
                        full_msg = self.gmail.get_message(msg_id)
                        if not full_msg: continue

                        parsed = self.gmail.parse_message_data(full_msg)
                        labels = parsed['labels']
                        
                        # Map folder
                        folder = 'INBOX'
                        if 'SENT' in labels: folder = 'SENT'
                        elif 'DRAFT' in labels: folder = 'DRAFTS'
                        elif 'SPAM' in labels: folder = 'SPAM'
                        elif 'TRASH' in labels: folder = 'TRASH'

                        # Use update_or_create to prevent duplicate key violations and transaction poisoning
                        email, created = EmailMessage.objects.update_or_create(
                            user=self.user,
                            gmail_message_id=parsed['gmail_id'],
                            defaults={
                                'thread_id': parsed['thread_id'],
                                'sender_email': self.gmail._extract_email(parsed['from']),
                                'sender_name': self.gmail._extract_name(parsed['from']),
                                'recipient_email': self.gmail._extract_email(parsed['to']),
                                'subject': parsed['subject'],
                                'body': parsed['plain_body'] or parsed['snippet'], # Legacy fallback
                                'plain_body': parsed['plain_body'],
                                'html_body': parsed['html_body'],
                                'snippet': parsed['snippet'],
                                'timestamp': parsed['date'],
                                'unread': 'UNREAD' in labels,
                                'starred': 'STARRED' in labels,
                                'in_trash': 'TRASH' in labels,
                                'has_attachments': parsed['has_attachments'],
                                'folder': folder
                            }
                        )
                        
                        # Run intelligence analysis if needed
                        if (created or not email.analysis_completed) and self.pipeline:
                            # Manually trigger to control context and suppress redundant signals
                            email.skip_analysis = True
                            self.pipeline.run(email.id)
                        
                except IntegrityError as e:
                    logger.warning(f"Duplicate detected or integrity error for {msg_id}: {str(e)}")
                except Exception as e:
                    logger.error(f"Failed to sync message {msg_id}: {str(e)}")

            job.synced_messages += len(batch)
            job.save()
            
            # Brief sleep to avoid hitting API rate limits
            import time
            time.sleep(0.1)

        job.status = 'COMPLETED'
        job.save()
        
        # Trigger global stats update
        from .email_pipeline import EmailPipeline
        try:
            last_email = EmailMessage.objects.filter(user=self.user).latest('timestamp')
            EmailPipeline()._update_user_profile(last_email)
        except:
            pass
