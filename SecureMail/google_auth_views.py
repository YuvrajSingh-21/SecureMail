import logging
from django.shortcuts import redirect
from django.contrib.auth import login
from django.contrib.auth.models import User
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.http import HttpResponseBadRequest
from .services.google_auth import GoogleAuthService
from .models import ConnectedAccount
from googleapiclient.discovery import build

logger = logging.getLogger(__name__)

def get_redirect_uri(request):
    """Helper to generate absolute redirect URI based on current request."""
    host = request.get_host()
    protocol = 'https' if request.is_secure() else 'http'
    return f"{protocol}://{host}/auth/google/callback/"

from .decorators import rate_limit_view
from .services.audit_service import AuditService

@rate_limit_view(key='ip', rate='10/m')
def google_login(request):
    redirect_uri = get_redirect_uri(request)
    service = GoogleAuthService(redirect_uri=redirect_uri)
    
    # get_auth_url returns state AND code_verifier for PKCE
    auth_url, state, code_verifier = service.get_auth_url()
    
    # Store state and verifier in session
    request.session['oauth_state'] = state
    request.session['oauth_code_verifier'] = code_verifier
    request.session.modified = True
    request.session.save()
    
    logger.info(f"OAuth Login initiated. State: {state}, Verifier exists: {bool(code_verifier)}, Session ID: {request.session.session_key}")
    
    return redirect(auth_url)

@rate_limit_view(key='ip', rate='10/m')
def google_callback(request):
    # Log incoming parameters
    url_state = request.GET.get('state')
    url_code = request.GET.get('code')
    session_state = request.session.get('oauth_state')
    code_verifier = request.session.get('oauth_code_verifier')
    
    logger.info(f"OAuth Callback received. URL State: {url_state}, Session State: {session_state}, Verifier present: {bool(code_verifier)}")

    if not url_code or not url_state:
        logger.error("OAuth Callback failed: Missing code or state in URL")
        return HttpResponseBadRequest("Invalid request: missing code or state in URL")
    
    if not session_state:
        logger.error("OAuth Callback failed: Missing state in session")
        return HttpResponseBadRequest("Invalid request: missing state in session")
        
    if url_state != session_state:
        logger.error(f"OAuth Callback failed: State mismatch. URL: {url_state}, Session: {session_state}")
        return HttpResponseBadRequest("Invalid request: state mismatch")

    if not code_verifier:
        logger.error("OAuth Callback failed: Missing PKCE code_verifier in session")
        return HttpResponseBadRequest("Invalid request: missing code verifier")

    # Ensure service uses EXACT same redirect URI for token exchange
    redirect_uri = get_redirect_uri(request)
    service = GoogleAuthService(redirect_uri=redirect_uri)

    # 1. Exchange OAuth code for tokens and fetch user profile
    try:
        credentials = service.get_credentials_from_code(url_code, session_state, code_verifier)
        oauth_service = build('oauth2', 'v2', credentials=credentials)
        user_info = oauth_service.userinfo().get().execute()
        email = user_info.get('email')
        logger.info(f"OAuth token exchange success for email: {email}")
    except Exception as e:
        logger.error(f"Google OAuth token exchange or profile retrieval failed: {str(e)}", exc_info=True)
        messages.error(request, "Google Authentication failed. Please try signing in again.")
        return redirect('login')

    # 2. Handle Existing Authenticated User connecting their Gmail
    if request.user.is_authenticated:
        try:
            service.update_or_create_connected_account(request.user, credentials)
            messages.success(request, "Gmail account connected successfully!")
        except Exception as e:
            logger.error(f"Failed to link ConnectedAccount for user {request.user.username}: {str(e)}", exc_info=True)
            messages.error(request, "Failed to link Gmail account. Please try again.")
            return redirect('settings')
            
        AuditService.log(request.user, 'connect_gmail', category='system', request=request)
        return redirect('settings')

    # 3. Handle New or Returning User Signing In
    try:
        user, created = User.objects.get_or_create(
            email=email,
            defaults={'username': email.split('@')[0]}
        )
        if created:
            user.set_unusable_password()
            user.save()
            messages.success(request, f"Welcome to SecureMail, {user.username}!")
        
        login(request, user)
    except Exception as e:
        logger.error(f"Failed to authenticate user session for {email}: {str(e)}", exc_info=True)
        messages.error(request, "An error occurred while establishing your session. Please try again.")
        return redirect('login')

    AuditService.log(user, 'login', category='auth', request=request)

    # 4. Save ConnectedAccount credentials
    try:
        account = service.update_or_create_connected_account(user, credentials)
    except Exception as e:
        logger.error(f"Failed to persist Google account credentials for {user.username}: {str(e)}", exc_info=True)
        messages.warning(request, "Logged in, but failed to connect Gmail tokens. Please reconnect in Settings.")

    # 5. Trigger Background Sync
    try:
        from .services.sync_manager import SyncManager
        SyncManager(user).start_sync(full_sync=True)
        logger.info(f"Background full sync initiated for {user.username}")
    except Exception as e:
        logger.warning(f"Failed to initiate background sync for {user.username}: {str(e)}", exc_info=True)

    # 6. Clean up session parameters
    for key in ['oauth_state', 'oauth_code_verifier']:
        if key in request.session:
            del request.session[key]
        
    return redirect('inbox')

@login_required
def google_disconnect(request):
    try:
        account = ConnectedAccount.objects.get(user=request.user)
        token_to_revoke = account.refresh_token or account.access_token
        
        if token_to_revoke:
            import requests
            try:
                response = requests.post(
                    'https://oauth2.googleapis.com/revoke',
                    data={'token': token_to_revoke},
                    headers={'content-type': 'application/x-www-form-urlencoded'},
                    timeout=10
                )
                
                if response.status_code == 200:
                    logger.info(f"Successfully revoked Google token for user {request.user.id}")
                else:
                    error_msg = None
                    try:
                        resp_json = response.json()
                        error_msg = resp_json.get('error')
                    except ValueError:
                        pass
                        
                    if response.status_code == 400 and error_msg == 'invalid_token':
                        logger.info(f"Google token for user {request.user.id} already invalid or expired")
                    else:
                        logger.error(f"Failed to revoke Google token for user {request.user.id}: {response.status_code}")
                        messages.error(request, "A temporary network error occurred while disconnecting your account. Please try again.")
                        return redirect('settings')
            except requests.RequestException as e:
                logger.error(f"Network error while revoking Google token for user {request.user.id}: {str(e)}")
                messages.error(request, "A temporary network error occurred while disconnecting your account. Please try again.")
                return redirect('settings')
                
        account.delete()
        if hasattr(request.user, 'profile'):
            request.user.profile.connected_gmail = None
            request.user.profile.save()
            
        messages.info(request, "Gmail account disconnected.")
        AuditService.log(request.user, 'disconnect_gmail', category='system', request=request)
    except ConnectedAccount.DoesNotExist:
        pass
        
    return redirect('settings')
