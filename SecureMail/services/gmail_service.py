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
                if e.resp.status == 404:
                    # Don't retry 404s, raise immediately
                    raise e
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
        except HttpError as e:
            if e.resp.status == 404:
                return {'error': 404, 'id': message_id}
            logger.error(f"Failed to get Gmail message {message_id}: {str(e)}")
            return None
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
            'labels': msg_payload.get('labelIds', []),
            'spf_pass': True,
            'dkim_pass': True,
            'dmarc_pass': True
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
            elif name == 'authentication-results':
                val = header['value'].lower()
                data['spf_pass'] = 'spf=pass' in val
                data['dkim_pass'] = 'dkim=pass' in val
                data['dmarc_pass'] = 'dmarc=pass' in val

        # Extract body
        parts = msg_payload['payload'].get('parts', [])
        if not parts: # Simple message
            body_data = msg_payload['payload'].get('body', {}).get('data', '')
            mime_type = msg_payload['payload'].get('mimeType', 'text/plain')
            
            if mime_type in ['application/ld+json', 'application/json', 'text/calendar']:
                body_data = ''

            if body_data:
                body_data += '=' * ((4 - len(body_data) % 4) % 4)
                decoded = base64.urlsafe_b64decode(body_data).decode('utf-8', errors='ignore')
                if not self._is_structured_data(decoded):
                    if mime_type == 'text/html':
                        data['html_body'] = decoded
                    else:
                        data['plain_body'] = decoded
        else:
            bodies = self._get_body_from_parts(parts)
            data['plain_body'] = bodies.get('plain', '')
            data['html_body'] = bodies.get('html', '')
            data['has_attachments'] = any(p.get('filename') for p in parts)

        # STRICT MIME PARSING PRIORITY: Never concatenate HTML and Plain.
        if data['html_body']:
            data['plain_body'] = '' # Discard fallback text if HTML exists

        # FORCE RAW TEXT REMOVAL
        if data['plain_body']:
            if "<div class=" in data['plain_body'] or "<html" in data['plain_body'].lower():
                data['plain_body'] = ''

        # Render the ORIGINAL MIME HTML exactly as received
        # if data['html_body']:
        #     data['html_body'] = self.sanitize_html(data['html_body'])

        final_html = data['html_body']
        text_body_included = bool(data['plain_body'])
        html_used = bool(data['html_body'])

        print("FINAL HTML LENGTH:", len(final_html))
        print("TEXT BODY INCLUDED:", text_body_included)
        print("HTML BODY INCLUDED:", html_used)

        logger.info(f"FINAL HTML LENGTH: {len(final_html)}")
        logger.info(f"TEXT BODY INCLUDED: {text_body_included}")
        logger.info(f"HTML BODY INCLUDED: {html_used}")

        return data

    def _is_structured_data(self, text):
        """Detects if text is a JSON-LD or schema.org blob."""
        trimmed = text.strip()
        if trimmed.startswith('{') and '"@context"' in trimmed:
            return True
        if 'schema.org' in trimmed and ('"@type"' in trimmed or '"@graph"' in trimmed):
            return True
        return False

    def _get_body_from_parts(self, parts):
        """
        Extracts exactly ONE canonical body part.
        Priority: text/html > text/plain.
        Ignores attachments and application/* metadata.
        """
        logger.info(f"MIME PARTS COUNT: {len(parts)}")
        
        html_parts = []
        plain_parts = []
        
        def collect_parts(p_list):
            for p in p_list:
                m_type = p.get('mimeType', '')
                if p.get('filename') or m_type.startswith('application/'):
                    continue
                if m_type == 'text/html':
                    html_parts.append(p)
                elif m_type == 'text/plain':
                    plain_parts.append(p)
                elif 'parts' in p:
                    collect_parts(p['parts'])
        
        collect_parts(parts)
        
        bodies = {'html': '', 'plain': ''}
        
        if html_parts:
            logger.info("HTML PART USED")
            logger.info("TEXT PART DISCARDED")
            b_data = html_parts[0].get('body', {}).get('data', '')
            if b_data:
                b_data += '=' * ((4 - len(b_data) % 4) % 4)
                decoded = base64.urlsafe_b64decode(b_data).decode('utf-8', errors='ignore')
                if not self._is_structured_data(decoded):
                    bodies['html'] = decoded
        elif plain_parts:
            logger.info("PLAIN TEXT PART USED (Fallback)")
            b_data = plain_parts[0].get('body', {}).get('data', '')
            if b_data:
                b_data += '=' * ((4 - len(b_data) % 4) % 4)
                decoded = base64.urlsafe_b64decode(b_data).decode('utf-8', errors='ignore')
                if not self._is_structured_data(decoded):
                    bodies['plain'] = decoded
                    
        return bodies

    def sanitize_html(self, html_content):
        """
        Sanitize HTML while preserving email structural layout.
        Strips dangerous elements (scripts, iframes) and structured metadata.
        """
        from bs4 import BeautifulSoup, Comment
        
        # 1. BeautifulSoup Pre-Cleanup
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # Remove comments (like <![if ...]> and <!--[if mso]>...)
        for comment in soup.find_all(string=lambda text: isinstance(text, Comment)):
            comment.extract()
            
        # Remove JSON-LD and structured data blocks
        for ld_script in soup.find_all('script', type='application/ld+json'):
            ld_script.decompose()
        
        # Remove all other scripts, objects, embeds, iframes, meta, link, xml
        for tag in soup.find_all(['script', 'object', 'embed', 'iframe', 'applet', 'meta', 'link', 'xml']):
            tag.decompose()
            
        # Remove hidden tracking/spacer divs if they look like metadata
        for div in soup.find_all('div', style=re.compile(r'display:\s*none|font-size:\s*1px', re.I)):
            if div.get_text(strip=True) == '' or len(div.get_text(strip=True)) < 5:
                div.decompose()

        cleaned_html = str(soup)

        # Regex strip raw MSO conditionals and schema JSON that bs4 might miss if malformed
        cleaned_html = re.sub(r'<!\[if[^>]*>', '', cleaned_html, flags=re.I)
        cleaned_html = re.sub(r'<!\[endif\]>', '', cleaned_html, flags=re.I)
        cleaned_html = re.sub(r'<!--\[if[^>]*>.*?<!\[endif\]-->', '', cleaned_html, flags=re.I|re.DOTALL)
        cleaned_html = re.sub(r'\{"@context".*?\}', '', cleaned_html, flags=re.I|re.DOTALL)

        # 2. Bleach Sanitization (Structural Preservation)
        allowed_tags = [
            'a', 'b', 'blockquote', 'code', 'em', 'i', 'li', 'ol', 'strong', 'ul',
            'p', 'br', 'div', 'span', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'img', 
            'table', 'thead', 'tbody', 'tfoot', 'tr', 'th', 'td',
            'font', 'center', 'u', 's', 'hr', 'body', 'html', 'head', 'section', 'header', 'footer', 'style'
        ]
        allowed_attrs = {
            'a': ['href', 'title', 'target', 'style', 'class', 'id'],
            'img': ['src', 'alt', 'width', 'height', 'style', 'class', 'id', 'border', 'hspace', 'vspace'],
            'table': ['width', 'height', 'border', 'cellpadding', 'cellspacing', 'style', 'class', 'id', 'align', 'bgcolor'],
            'td': ['width', 'height', 'style', 'class', 'id', 'align', 'valign', 'bgcolor', 'colspan', 'rowspan'],
            'tr': ['style', 'class', 'id', 'align', 'valign', 'bgcolor'],
            'div': ['style', 'class', 'id', 'align'],
            'span': ['style', 'class', 'id'],
            'p': ['style', 'class', 'id', 'align'],
            'font': ['color', 'size', 'face', 'style', 'class'],
            '*': ['style', 'class', 'id']
        }
        allowed_styles = [
            'color', 'font-weight', 'font-size', 'font-family', 'text-align', 'background-color', 'background',
            'padding', 'padding-left', 'padding-right', 'padding-top', 'padding-bottom',
            'margin', 'margin-left', 'margin-right', 'margin-top', 'margin-bottom',
            'border', 'border-collapse', 'border-spacing',
            'width', 'height', 'display', 'line-height', 'text-decoration', 'vertical-align', 
            'max-width', 'min-width', 'list-style-type', 'overflow'
        ]
        
        css_sanitizer = CSSSanitizer(allowed_css_properties=allowed_styles)
        
        sanitized = bleach.clean(
            cleaned_html,
            tags=allowed_tags,
            attributes=allowed_attrs,
            css_sanitizer=css_sanitizer,
            strip=True
        )
        
        # 3. Structural Wrapper
        return f'<div class="email-body-wrapper" style="max-width: 100%; overflow-x: auto; font-family: sans-serif; background-color: #ffffff;">{sanitized}</div>'

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
