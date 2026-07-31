"""
SecureMail utility functions.

safe_redirect: Validates a redirect candidate against the current
request host before issuing the redirect, preventing open redirect
attacks from untrusted HTTP_REFERER or other user-controlled URLs.
"""
from django.shortcuts import redirect
from django.utils.http import url_has_allowed_host_and_scheme


def safe_redirect(request, candidate, fallback='inbox'):
    """
    Return a safe redirect response.

    Accepts the candidate URL only when ALL of the following hold:
      - candidate is a non-empty string
      - url_has_allowed_host_and_scheme validates it against the current
        request host (blocks external hosts and protocol-relative
        external URLs such as //evil.example/)
      - When the current request is HTTPS, an HTTP target is rejected
        (require_https=True prevents HTTP downgrade)

    Falls back to the named route `fallback` (default: 'inbox') for:
      - missing / empty candidate
      - external hosts
      - protocol-relative external URLs
      - malformed URLs
      - HTTP targets on an HTTPS request

    Parameters
    ----------
    request   : HttpRequest  – the current Django request
    candidate : str | None   – the proposed redirect destination
    fallback  : str          – Django named URL or path used when
                               candidate fails validation

    Validation uses parsed host/scheme semantics via Django's
    url_has_allowed_host_and_scheme; it does NOT rely on substring
    matching, so values such as:

        https://trusted.example.evil.example/

    are rejected because their actual host does not equal the allowed
    host.
    """
    if candidate and url_has_allowed_host_and_scheme(
        url=candidate,
        allowed_hosts={request.get_host()},
        require_https=request.is_secure(),
    ):
        try:
            return redirect(candidate)
        except Exception:
            # url_has_allowed_host_and_scheme passed but Django could not
            # build a valid response (e.g. colon-prefixed pseudo-paths that
            # look relative to the parser but are not valid URL targets).
            pass
    return redirect(fallback)
