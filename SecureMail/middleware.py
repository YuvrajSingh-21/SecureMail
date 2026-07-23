from django.utils import timezone, translation
import zoneinfo

TIMEZONE_MAP = {
    "UTC (Coordinated Universal Time)": "UTC",
    "UTC-08:00 (Pacific Time)": "America/Los_Angeles",
    "UTC-05:00 (Eastern Time)": "America/New_York",
    "UTC+00:00 (Greenwich Mean Time)": "Europe/London",
    "UTC+01:00 (Central European Time)": "Europe/Paris",
    "UTC+05:30 (India Standard Time)": "Asia/Kolkata",
    "UTC+08:00 (China Standard Time)": "Asia/Shanghai",
    "UTC+09:00 (Japan Standard Time)": "Asia/Tokyo",
    "UTC+10:00 (Australian Eastern Time)": "Australia/Sydney",
}

LANGUAGE_MAP = {
    "English (US)": "en-us",
    "English (UK)": "en-gb",
    "Spanish (ES)": "es",
    "French (FR)": "fr",
    "German (DE)": "de",
    "Hindi (HI)": "hi",
}

class UserPreferencesMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.user.is_authenticated and hasattr(request.user, 'profile'):
            profile = request.user.profile
            
            # Activate Timezone
            tz_str = TIMEZONE_MAP.get(profile.timezone, "UTC")
            try:
                tz = zoneinfo.ZoneInfo(tz_str)
                timezone.activate(tz)
            except Exception:
                timezone.deactivate()
                
            # Activate Language
            lang = LANGUAGE_MAP.get(profile.language, "en-us")
            translation.activate(lang)
            request.LANGUAGE_CODE = translation.get_language()
        else:
            timezone.deactivate()
            translation.deactivate()

        response = self.get_response(request)
        return response
