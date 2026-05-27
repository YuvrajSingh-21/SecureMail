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

def google_login(request):
    redirect_uri = get_redirect_uri(request)
    service = GoogleAuthService(redirect_uri=redirect_uri)
    
    # get_auth_url now returns state AND code_verifier for PKCE
    auth_url, state, code_verifier = service.get_auth_url()
    
    # Store state and verifier in session
    request.session['oauth_state'] = state
    request.session['oauth_code_verifier'] = code_verifier
    request.session.modified = True
    request.session.save()
    
    logger.info(f"OAuth Login initiated. State: {state}, Verifier exists: {bool(code_verifier)}, Session ID: {request.session.session_key}")
    
    return redirect(auth_url)

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

    try:
        # Use the state and verifier from the Session for token exchange
        credentials = service.get_credentials_from_code(url_code, session_state, code_verifier)
        
        # Get user info from Google
        oauth_service = build('oauth2', 'v2', credentials=credentials)
        user_info = oauth_service.userinfo().get().execute()
        email = user_info.get('email')
        
        logger.info(f"OAuth Success. User Email: {email}")
        
        if request.user.is_authenticated:
            # Case 1: Existing user connecting their Gmail
            service.update_or_create_connected_account(request.user, credentials)
            messages.success(request, "Gmail account connected successfully!")
            return redirect('settings')
        else:
            # Case 2: New/Returning user signing in with Google
            user, created = User.objects.get_or_create(
                email=email,
                defaults={'username': email.split('@')[0]}
            )
            if created:
                user.set_unusable_password()
                user.save()
                messages.success(request, f"Welcome to SecureMail, {user.username}!")
            
            login(request, user)
            
            # Now update/create the ConnectedAccount for this user
            account = service.update_or_create_connected_account(user, credentials)
            
            # Trigger Background Sync (FULL sync in background)
            try:
                from .services.sync_manager import SyncManager
                # Non-blocking full sync
                SyncManager(user).start_sync(full_sync=True)
                logger.info(f"Background full sync initiated for {user.username}")
            except Exception as e:
                logger.warning(f"Failed to initiate background sync: {str(e)}")
            
            # Clean up session
            for key in ['oauth_state', 'oauth_code_verifier']:
                if key in request.session:
                    del request.session[key]
                
            return redirect('inbox')
            
    except Exception as e:
        logger.error(f"Google Authentication failed: {str(e)}", exc_info=True)
        messages.error(request, f"Google Authentication failed: {str(e)}")
        return redirect('login')

@login_required
def google_disconnect(request):
    try:
        account = ConnectedAccount.objects.get(user=request.user)
        account.delete()
        request.user.profile.connected_gmail = None
        request.user.profile.save()
        messages.info(request, "Gmail account disconnected.")
    except ConnectedAccount.DoesNotExist:
        pass
        
    return redirect('settings')
