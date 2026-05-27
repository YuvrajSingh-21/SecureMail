import base64
import logging
import re
import time
import bleach
from bleach.css_sanitizer import CSSSanitizer
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from google.oauth2.credentials import Credentials
from .google_auth import GoogleAuthService
from ..models import EmailMessage, Attachment
from django.utils import timezone
from dateutil import parser as date_parser
import datetime

logger = logging.getLogger(__name__)

class GmailService:
    def __init__(self, connected_account):
        self.connected_account = connected_account
        self.auth_service = GoogleAuthService()
        self.creds = self.auth_service.refresh_user_token(connected_account)
        self.service = build('gmail', 'v1', credentials=self.creds)

    def _call_api(self, func, *args, **kwargs):
        """Helper to call Google API with retries and exponential backoff."""
        max_retries = 5
        for i in range(max_retries):
            try:
                return func(*args, **kwargs).execute()
            except HttpError as e:
                if e.resp.status in [429, 500, 502, 503, 504]:
                    wait = (2 ** i) + (0.1 * i)
                    logger.warning(f"Gmail API error {e.resp.status}. Retrying in {wait}s...")
                    time.sleep(wait)
                    continue
                raise
            except Exception as e:
                if "Unable to find the server" in str(e) or "Timeout" in str(e):
                    wait = (2 ** i) + (0.1 * i)
                    logger.warning(f"Network error: {str(e)}. Retrying in {wait}s...")
                    time.sleep(wait)
                    continue
                raise
        return func(*args, **kwargs).execute()

    def get_profile(self):
        """Get the user's Gmail profile."""
        try:
            return self._call_api(self.service.users().getProfile, userId='me')
        except Exception as e:
            logger.error(f"Failed to get Gmail profile: {str(e)}")
            return None

    def fetch_all_message_ids(self, label_ids=None, max_total=None):
        """
        Fetch all message IDs using Gmail API pagination.
        """
        all_messages = []
        page_token = None
        page_count = 1
        search_labels = label_ids
        
        try:
            while True:
                results = self._call_api(
                    self.service.users().messages().list,
                    userId='me',
                    labelIds=search_labels,
                    maxResults=500,
                    pageToken=page_token
                )
                messages = results.get('messages', [])
                all_messages.extend(messages)
                logger.info(f"Page {page_count}: {len(messages)} messages")
                page_token = results.get('nextPageToken')
                if not page_token or (max_total and len(all_messages) >= max_total):
                    break
                page_count += 1
            logger.info(f"Total Gmail messages found: {len(all_messages)}")
            return all_messages
        except Exception as e:
            logger.error(f"Failed to fetch Gmail message list: {str(e)}")
            return all_messages

    def get_message(self, message_id):
        """Get full details of a single message."""
        try:
            return self._call_api(self.service.users().messages().get, userId='me', id=message_id, format='full')
        except Exception as e:
            logger.error(f"Failed to get Gmail message {message_id}: {str(e)}")
            return None

    def parse_message_data(self, msg_payload):
        """Parse Gmail API response into a flat dictionary."""
        headers = msg_payload['payload'].get('headers', [])
        data = {
            'gmail_id': msg_payload['id'],
            'thread_id': msg_payload['threadId'],
            'snippet': msg_payload.get('snippet', ''),
            'subject': '(No Subject)',
            'from': '',
            'to': '',
            'date': timezone.now(),
            'plain_body': '',
            'html_body': '',
            'has_attachments': False,
            'labels': msg_payload.get('labelIds', [])
        }

        for header in headers:
            name = header['name'].lower()
            if name == 'subject':
                data['subject'] = header['value']
            elif name == 'from':
                data['from'] = header['value']
            elif name == 'to':
                data['to'] = header['value']
            elif name == 'date':
                try:
                    data['date'] = date_parser.parse(header['value'])
                except:
                    pass

        # Extract body
        parts = msg_payload['payload'].get('parts', [])
        if not parts: # Simple message
            body_data = msg_payload['payload'].get('body', {}).get('data', '')
            mime_type = msg_payload['payload'].get('mimeType', 'text/plain')
            if body_data:
                decoded = base64.urlsafe_b64decode(body_data).decode('utf-8', errors='ignore')
                if mime_type == 'text/html':
                    data['html_body'] = decoded
                else:
                    data['plain_body'] = decoded
        else:
            bodies = self._get_body_from_parts(parts)
            data['plain_body'] = bodies.get('plain', '')
            data['html_body'] = bodies.get('html', '')
            data['has_attachments'] = any(p.get('filename') for p in parts)

        # Sanitize HTML
        if data['html_body']:
            data['html_body'] = self.sanitize_html(data['html_body'])

        return data

    def _get_body_from_parts(self, parts):
        bodies = {'plain': '', 'html': ''}
        for part in parts:
            mime_type = part.get('mimeType')
            body_data = part.get('body', {}).get('data', '')
            
            if mime_type == 'text/plain' and body_data:
                bodies['plain'] += base64.urlsafe_b64decode(body_data).decode('utf-8', errors='ignore')
            elif mime_type == 'text/html' and body_data:
                bodies['html'] += base64.urlsafe_b64decode(body_data).decode('utf-8', errors='ignore')
            elif 'parts' in part:
                nested = self._get_body_from_parts(part['parts'])
                bodies['plain'] += nested['plain']
                bodies['html'] += nested['html']
        return bodies

    def sanitize_html(self, html_content):
        """Sanitize HTML content using modern bleach API."""
        allowed_tags = [
            'a', 'abbr', 'acronym', 'b', 'blockquote', 'code', 'em', 'i', 'li', 'ol', 'strong', 'ul',
            'p', 'br', 'div', 'span', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'img', 'table', 'thead', 'tbody', 'tr', 'th', 'td',
            'font', 'center', 'u', 's', 'hr', 'body', 'html', 'head', 'style'
        ]
        allowed_attrs = {
            'a': ['href', 'title', 'target', 'style', 'class'],
            'abbr': ['title'],
            'acronym': ['title'],
            'img': ['src', 'alt', 'width', 'height', 'style', 'class'],
            'table': ['width', 'border', 'cellpadding', 'cellspacing', 'style', 'class', 'align'],
            'td': ['width', 'height', 'style', 'class', 'align', 'valign', 'bgcolor', 'colspan', 'rowspan'],
            'tr': ['style', 'class', 'align', 'valign', 'bgcolor'],
            'div': ['style', 'class', 'align'],
            'span': ['style', 'class'],
            'p': ['style', 'class', 'align'],
            'font': ['color', 'size', 'face', 'style'],
            '*': ['style', 'class', 'id']
        }
        allowed_styles = [
            'color', 'font-weight', 'font-size', 'font-family', 'text-align', 'background-color', 
            'padding', 'margin', 'border', 'width', 'height', 'display', 'line-height', 
            'text-decoration', 'vertical-align', 'max-width', 'min-width'
        ]
        
        # Modern Bleach (5.0+) uses CSSSanitizer for styles
        css_sanitizer = CSSSanitizer(allowed_css_properties=allowed_styles)
        
        return bleach.clean(
            html_content,
            tags=allowed_tags,
            attributes=allowed_attrs,
            css_sanitizer=css_sanitizer,
            strip=True
        )

    def sync_mailbox(self, max_emails=None):
        """
        Sync emails from Gmail to local DB.
        """
        from .sync_manager import SyncManager
        manager = SyncManager(self.connected_account.user)
        job = manager.start_sync(full_sync=(max_emails is None))
        return job.synced_messages if job else 0

    def _extract_email(self, text):
        match = re.search(r'[\w\.-]+@[\w\.-]+', text)
        return match.group(0) if match else text

    def _extract_name(self, text):
        if '<' in text:
            return text.split('<')[0].strip().strip('"')
        return text

    def mark_as_read(self, gmail_id):
        return self._call_api(
            self.service.users().messages().batchModify,
            userId='me',
            body={'ids': [gmail_id], 'removeLabelIds': ['UNREAD']}
        )

    def delete_message(self, gmail_id):
        return self._call_api(self.service.users().messages().trash, userId='me', id=gmail_id)

    def send_message(self, to, subject, body):
        from email.mime.text import MIMEText
        message = MIMEText(body)
        message['to'] = to
        message['from'] = 'me'
        message['subject'] = subject
        raw = base64.urlsafe_b64encode(message.as_bytes()).decode()
        return self._call_api(self.service.users().messages().send, userId='me', body={'raw': raw})
