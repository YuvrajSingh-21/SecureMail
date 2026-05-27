from django.apps import AppConfig

class SecuremailConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'SecureMail'

    def ready(self):
        import SecureMail.signals.handlers
        self._validate_env()

    def _validate_env(self):
        import os
        import logging
        logger = logging.getLogger(__name__)
        
        gemini_key = os.getenv('GEMINI_API_KEY')
        client_id = os.getenv('GOOGLE_CLIENT_ID')
        client_secret = os.getenv('GOOGLE_CLIENT_SECRET')
        
        if gemini_key:
            logger.info("Using Gemini API Key for Analysis")
        else:
            logger.warning("CRITICAL: GEMINI_API_KEY is missing. Intelligent analysis will be limited.")
            
        if client_id and client_secret:
            logger.info("Using Google OAuth Credentials for Gmail Access")
        else:
            if not client_id:
                logger.warning("CRITICAL: GOOGLE_CLIENT_ID is missing. Gmail integration will fail.")
            if not client_secret:
                logger.warning("CRITICAL: GOOGLE_CLIENT_SECRET is missing. Gmail integration will fail.")
