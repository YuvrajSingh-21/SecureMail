from django.http import HttpResponse
from django_ratelimit.decorators import ratelimit
from functools import wraps
from .utils import get_client_ip

def _ratelimit_ip_key(group, request):
    return get_client_ip(request) or '127.0.0.1'

def rate_limit_view(key='ip', rate='5/m'):
    resolved_key = _ratelimit_ip_key if key == 'ip' else key

    def decorator(view_func):
        @ratelimit(key=resolved_key, rate=rate, block=False)
        @wraps(view_func)
        def _wrapped_view(request, *args, **kwargs):
            if getattr(request, 'limited', False):
                return HttpResponse('Too many requests, please try again later.', status=429)
            return view_func(request, *args, **kwargs)
        return _wrapped_view
    return decorator
