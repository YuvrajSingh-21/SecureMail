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
        from django.core.cache import cache
        lock_id = f"sync_lock_{self.user.id}"
        
        # Concurrency protection
        if not cache.add(lock_id, "true", timeout=600):
            logger.warning(f"Sync already running for {self.user.username}. Aborting duplicate request.")
            job.status = 'FAILED'
            job.error_message = 'Sync already in progress'
            job.save()
            connection.close()
            return
            
        try:
            if not full_sync and self.account.history_id:
                logger.info(f"History sync started for {self.user.username}")
                self._incremental_sync(job)
            else:
                # Legacy full sync or initial limited sync
                limit = None if full_sync else 50
                self._execute_sync(job, limit=limit)
        except Exception as e:
            job.status = 'FAILED'
            job.error_message = str(e)
            job.save()
            logger.error(f"Background sync failed: {str(e)}")
        finally:
            cache.delete(lock_id)
            connection.close()

    def _execute_sync(self, job, limit=None):
        """Internal execution of the sync process."""
        # 1. Fetch all IDs to know the scope
        summaries = self.gmail.fetch_all_message_ids(max_total=limit)
        job.total_messages = len(summaries)
        job.save()

        # Reconciliation: Full Sync Cleanup
        if not limit:
            gmail_ids = set(s['id'] for s in summaries)
            local_ids = set(EmailMessage.objects.filter(user=self.user, is_remote_deleted=False).values_list('gmail_message_id', flat=True))
            stale_ids = local_ids - gmail_ids
            
            if stale_ids:
                # Mark as remote deleted, clearing bodies so we don't permanently store deleted data
                EmailMessage.objects.filter(user=self.user, gmail_message_id__in=stale_ids).update(
                    is_remote_deleted=True,
                    html_body='',
                    plain_body='',
                    body=''
                )
                logger.info(f"Reconciliation: Marked {len(stale_ids)} stale emails as remotely deleted.")

        # 2. Process in batches of 50
        batch_size = 50
        for i in range(0, len(summaries), batch_size):
            batch = summaries[i:i + batch_size]
            
            # We avoid transaction.atomic() for the whole batch to prevent poisoning.
            # Instead, we process each message individually.
            for summary in batch:
                msg_id = summary['id']
                
                try:
                    # NETWORK CALL: Outside transaction
                    full_msg = self.gmail.get_message(msg_id)
                    if not full_msg: continue
                    
                    if isinstance(full_msg, dict) and full_msg.get('error') == 404:
                        with transaction.atomic():
                            email = EmailMessage.objects.filter(user=self.user, gmail_message_id=msg_id).first()
                            if email:
                                email.is_remote_deleted = True
                                email.html_body = ''
                                email.plain_body = ''
                                email.body = ''
                                email.save(update_fields=['is_remote_deleted', 'html_body', 'plain_body', 'body'])
                                logger.info(f"Sync: 404 on get_message, marked {msg_id} as deleted.")
                        continue

                    parsed = self.gmail.parse_message_data(full_msg)
                    labels = parsed['labels']
                    
                    folder = 'INBOX'
                    if 'SENT' in labels: folder = 'SENT'
                    elif 'DRAFT' in labels: folder = 'DRAFTS'
                    elif 'SPAM' in labels: folder = 'SPAM'
                    elif 'TRASH' in labels: folder = 'TRASH'

                    needs_analysis = False
                    email_id = None
                    
                    # DATABASE WRITE: Inside transaction
                    with transaction.atomic():
                        email, created = EmailMessage.objects.update_or_create(
                            user=self.user,
                            gmail_message_id=parsed['gmail_id'],
                            defaults={
                                'thread_id': parsed['thread_id'],
                                'sender_email': self.gmail._extract_email(parsed['from']),
                                'sender_name': self.gmail._extract_name(parsed['from']),
                                'recipient_email': self.gmail._extract_email(parsed['to']),
                                'subject': parsed['subject'],
                                'body': parsed['plain_body'] or parsed['snippet'],
                                'plain_body': parsed['plain_body'],
                                'html_body': parsed['html_body'],
                                'snippet': parsed['snippet'],
                                'timestamp': parsed['date'],
                                'unread': 'UNREAD' in labels,
                                'starred': 'STARRED' in labels,
                                'in_trash': 'TRASH' in labels,
                                'is_remote_deleted': False,
                                'has_attachments': parsed['has_attachments'],
                                'folder': folder,
                                'spf_pass': parsed.get('spf_pass', True),
                                'dkim_pass': parsed.get('dkim_pass', True),
                                'dmarc_pass': parsed.get('dmarc_pass', True)
                            }
                        )
                        email_id = email.id
                        if created:
                            self._process_attachments(email, parsed)
                            
                        if (created or not email.analysis_completed) and self.pipeline:
                            needs_analysis = True
                        elif email.analysis_completed and hasattr(email, 'analysis') and 'analysis' not in email.analysis.detailed_report and self.pipeline:
                            needs_analysis = True
                            
                    # NETWORK CALL (EmailPipeline): Outside transaction
                    if needs_analysis and self.pipeline:
                        try:
                            email_obj = EmailMessage.objects.get(id=email_id)
                            email_obj.skip_analysis = True
                            self.pipeline.run(email_id)
                        except Exception as pe:
                            logger.error(f"Pipeline failed for {email_id}: {str(pe)}")
                            
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

        # Phase 3A: History API Bootstrap
        # Only initialize history_id if the entire synchronization succeeded (job is COMPLETED)
        try:
            if not self.account.history_id:
                profile = self.gmail.get_profile()
                if profile and 'historyId' in profile:
                    self.account.history_id = str(profile['historyId'])
                    self.account.save(update_fields=['history_id'])
                    logger.info(f"History ID persisted and initialized to {self.account.history_id} for {self.user.username}")
                else:
                    logger.warning(f"History ID unavailable in Gmail profile for {self.user.username}")
            else:
                logger.info(f"History ID skipped for {self.user.username} (already initialized)")
        except Exception as e:
            logger.error(f"Failed to extract historyId for {self.user.username}: {str(e)}")

    def _process_attachments(self, email, parsed):
        if not parsed.get('attachments'):
            return
            
        from django.core.files.base import ContentFile
        from ..models import Attachment
        import hashlib
        import base64
        from ..tasks import analyze_attachment_task
        
        for att in parsed['attachments']:
            att_data = self.gmail.get_attachment(parsed['gmail_id'], att['attachmentId'])
            if att_data and 'data' in att_data:
                try:
                    # Some padding might be missing in urlsafe b64
                    b64_data = att_data['data'].replace('-', '+').replace('_', '/')
                    b64_data += '=' * ((4 - len(b64_data) % 4) % 4)
                    raw_data = base64.b64decode(b64_data)
                    
                    sha256 = hashlib.sha256(raw_data).hexdigest()
                    md5 = hashlib.md5(raw_data).hexdigest()
                    
                    new_att = Attachment(
                        email=email,
                        filename=att['filename'],
                        size=att['size'] if att.get('size') else len(raw_data),
                        content_type=att['mimeType'],
                        sha256=sha256,
                        md5=md5,
                        scan_status='QUEUED'
                    )
                    new_att.file.save(f"{sha256}_{att['filename']}", ContentFile(raw_data), save=True)
                    
                    # Queue ATAE task
                    analyze_attachment_task.delay(new_att.id)
                except Exception as att_err:
                    logger.error(f"Failed to process attachment {att['filename']}: {str(att_err)}")

    def _incremental_sync(self, job):
        """Phase 3B: Incremental Synchronization via History API."""
        from .gmail_service import HistoryExpiredError, HistoryInvalidError
        try:
            # Process history page by page to avoid OOM on massive responses
            for page in self.gmail.fetch_history(self.account.history_id):
                records = page.get('history', [])
                latest_history_id = page.get('historyId')
                
                if not records and latest_history_id:
                    # No changes in this page, just bump the ID
                    if str(latest_history_id) != str(self.account.history_id):
                        self.account.history_id = str(latest_history_id)
                        self.account.save(update_fields=['history_id'])
                    continue

                delta = self.gmail.parse_history_response(records)
                added_ids = list(set(m['id'] for m in delta['messagesAdded']))
                deleted_ids = list(set(m['id'] for m in delta['messagesDeleted']))
                
                # NETWORK CALL: Fetch full messages outside transaction
                full_messages = []
                if added_ids:
                    logger.info(f"Messages added: {len(added_ids)} for {self.user.username}")
                    for full_msg in self.gmail.batch_fetch_messages(added_ids):
                        if isinstance(full_msg, dict) and full_msg.get('error') == 404:
                            continue
                        full_messages.append(full_msg)
                
                # DATABASE WRITE: Atomic update for this single page
                new_email_ids = []
                with transaction.atomic():
                    # 1. Process Messages Added
                    for full_msg in full_messages:
                        parsed = self.gmail.parse_message_data(full_msg)
                        labels = parsed['labels']
                        
                        folder = 'INBOX'
                        if 'SENT' in labels: folder = 'SENT'
                        elif 'DRAFT' in labels: folder = 'DRAFTS'
                        elif 'SPAM' in labels: folder = 'SPAM'
                        elif 'TRASH' in labels: folder = 'TRASH'

                        email, created = EmailMessage.objects.update_or_create(
                            user=self.user,
                            gmail_message_id=parsed['gmail_id'],
                            defaults={
                                'thread_id': parsed['thread_id'],
                                'sender_email': self.gmail._extract_email(parsed['from']),
                                'sender_name': self.gmail._extract_name(parsed['from']),
                                'recipient_email': self.gmail._extract_email(parsed['to']),
                                'subject': parsed['subject'],
                                'body': parsed['plain_body'] or parsed['snippet'],
                                'plain_body': parsed['plain_body'],
                                'html_body': parsed['html_body'],
                                'snippet': parsed['snippet'],
                                'timestamp': parsed['date'],
                                'unread': 'UNREAD' in labels,
                                'starred': 'STARRED' in labels,
                                'in_trash': 'TRASH' in labels,
                                'is_remote_deleted': False,
                                'has_attachments': parsed['has_attachments'],
                                'folder': folder,
                                'spf_pass': parsed.get('spf_pass', True),
                                'dkim_pass': parsed.get('dkim_pass', True),
                                'dmarc_pass': parsed.get('dmarc_pass', True)
                            }
                        )
                        if created:
                            self._process_attachments(email, parsed)
                            
                        if created or not email.analysis_completed:
                            new_email_ids.append(email.id)
                            
                    # 2. Process Messages Deleted
                    if deleted_ids:
                        logger.info(f"Messages deleted: {len(deleted_ids)} for {self.user.username}")
                        EmailMessage.objects.filter(user=self.user, gmail_message_id__in=deleted_ids).update(
                            is_remote_deleted=True, html_body='', plain_body='', body=''
                        )
                    
                    # 3. Process Labels Added
                    if delta['labelsAdded']:
                        for record in delta['labelsAdded']:
                            msg_id = record['message']['id']
                            labels = record.get('labelIds', [])
                            updates = {}
                            if 'UNREAD' in labels: updates['unread'] = True
                            if 'STARRED' in labels: updates['starred'] = True
                            if 'TRASH' in labels: 
                                updates['in_trash'] = True
                                updates['folder'] = 'TRASH'
                            if 'SPAM' in labels: updates['folder'] = 'SPAM'
                            if 'SENT' in labels: updates['folder'] = 'SENT'
                            if 'INBOX' in labels: updates['folder'] = 'INBOX'
                            if updates:
                                EmailMessage.objects.filter(user=self.user, gmail_message_id=msg_id).update(**updates)

                    # 4. Process Labels Removed
                    if delta['labelsRemoved']:
                        for record in delta['labelsRemoved']:
                            msg_id = record['message']['id']
                            labels = record.get('labelIds', [])
                            updates = {}
                            if 'UNREAD' in labels: updates['unread'] = False
                            if 'STARRED' in labels: updates['starred'] = False
                            if 'TRASH' in labels: 
                                updates['in_trash'] = False
                            if updates:
                                EmailMessage.objects.filter(user=self.user, gmail_message_id=msg_id).update(**updates)

                    # 5. Commit History ID Update for this page
                    if latest_history_id and str(latest_history_id) != str(self.account.history_id):
                        self.account.history_id = str(latest_history_id)
                        self.account.save(update_fields=['history_id'])
                        
                # NETWORK CALL: Run EmailPipeline OUTSIDE transaction
                if self.pipeline and new_email_ids:
                    for email_id in new_email_ids:
                        try:
                            email_obj = EmailMessage.objects.get(id=email_id)
                            email_obj.skip_analysis = True
                            self.pipeline.run(email_id)
                        except Exception as e:
                            logger.error(f"Pipeline failed for {email_id}: {str(e)}")

                job.synced_messages += len(added_ids)
                job.save()

            # Job finished
            job.status = 'COMPLETED'
            job.save()
            logger.info(f"History sync completed for {self.user.username}")
            
            # Global stats update
            from .email_pipeline import EmailPipeline
            try:
                last_email = EmailMessage.objects.filter(user=self.user).latest('timestamp')
                EmailPipeline()._update_user_profile(last_email)
            except:
                pass

        except HistoryExpiredError:
            logger.warning(f"History ID expired for {self.user.username}. Triggering legacy full sync recovery.")
            self.account.history_id = None
            self.account.save(update_fields=['history_id'])
            # Full sync creates a new baseline
            self._execute_sync(job, limit=None)
            
        except Exception as e:
            logger.error(f"History sync failed for {self.user.username}: {str(e)}")
            logger.info(f"Legacy fallback triggered for {self.user.username}")
            # Fallback must ALWAYS result in complete recovery per requirements
            self.account.history_id = None
            self.account.save(update_fields=['history_id'])
            self._execute_sync(job, limit=None)
