import os
import google_auth_oauthlib.flow
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from django.conf import settings
from django.utils import timezone
import datetime
from ..models import ConnectedAccount

class GoogleAuthService:
    SCOPES = [
        'openid',
        'https://www.googleapis.com/auth/userinfo.email',
        'https://www.googleapis.com/auth/userinfo.profile',
        'https://www.googleapis.com/auth/gmail.readonly',
        'https://www.googleapis.com/auth/gmail.modify',
        'https://www.googleapis.com/auth/gmail.send'
    ]

    def __init__(self, redirect_uri=None):
        self.client_id = os.getenv('GOOGLE_CLIENT_ID')
        self.client_secret = os.getenv('GOOGLE_CLIENT_SECRET')
        # Default to localhost for dev, but allow override
        self.redirect_uri = redirect_uri or "http://localhost:8000/auth/google/callback/"

    def get_auth_url(self):
        flow = google_auth_oauthlib.flow.Flow.from_client_config(
            self._get_client_config(),
            scopes=self.SCOPES
        )
        flow.redirect_uri = self.redirect_uri
        
        authorization_url, state = flow.authorization_url(
            access_type='offline',
            include_granted_scopes='true',
            prompt='consent'
        )
        # Capture code_verifier for PKCE
        return authorization_url, state, flow.code_verifier

    def get_credentials_from_code(self, code, state, code_verifier):
        flow = google_auth_oauthlib.flow.Flow.from_client_config(
            self._get_client_config(),
            scopes=self.SCOPES,
            state=state
        )
        flow.redirect_uri = self.redirect_uri
        flow.fetch_token(code=code, code_verifier=code_verifier)
        return flow.credentials

    def update_or_create_connected_account(self, user, credentials):
        service = build('oauth2', 'v2', credentials=credentials)
        user_info = service.userinfo().get().execute()

        expiry = credentials.expiry if credentials.expiry else (timezone.now() + datetime.timedelta(hours=1))
        
        account, created = ConnectedAccount.objects.update_or_create(
            user=user,
            defaults={
                'email': user_info.get('email'),
                'google_id': user_info.get('id'),
                'access_token': credentials.token,
                'refresh_token': credentials.refresh_token if credentials.refresh_token else None,
                'token_expiry': expiry,
                'profile_picture': user_info.get('picture')
            }
        )
        
        # Also update user profile with connected email if empty
        if not user.profile.connected_gmail:
            user.profile.connected_gmail = user_info.get('email')
            user.profile.save()
            
        return account

    def refresh_user_token(self, connected_account):
        creds = Credentials(
            token=connected_account.access_token,
            refresh_token=connected_account.refresh_token,
            token_uri="https://oauth2.googleapis.com/token",
            client_id=self.client_id,
            client_secret=self.client_secret,
            scopes=self.SCOPES
        )
        
        if creds.expired:
            creds.refresh(Request())
            connected_account.access_token = creds.token
            connected_account.token_expiry = creds.expiry
            connected_account.save()
            
        return creds

    def _get_client_config(self):
        return {
            "web": {
                "client_id": self.client_id,
                "project_id": "securemail-ai",
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
                "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
                "client_secret": self.client_secret,
                "redirect_uris": [self.redirect_uri]
            }
        }
