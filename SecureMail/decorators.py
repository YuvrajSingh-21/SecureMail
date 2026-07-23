from django.http import HttpResponse
from django_ratelimit.decorators import ratelimit
from functools import wraps

def rate_limit_view(key='ip', rate='5/m'):
    def decorator(view_func):
        @ratelimit(key=key, rate=rate, block=False)
        @wraps(view_func)
        def _wrapped_view(request, *args, **kwargs):
            if getattr(request, 'limited', False):
                return HttpResponse('Too many requests, please try again later.', status=429)
            return view_func(request, *args, **kwargs)
        return _wrapped_view
    return decorator
