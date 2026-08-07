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


import ipaddress


def normalize_ip_address(raw_ip: str | None) -> str | None:
    """
    Parse, sanitize, and validate an incoming IP address string.

    Handles:
    - Standard IPv4 strings: '157.48.193.106' -> '157.48.193.106'
    - IPv4 host:port strings: '157.48.193.106:47818' -> '157.48.193.106'
    - Standard IPv6 strings: '2001:db8::1' -> '2001:db8::1'
    - Bracketed IPv6 host:port: '[2001:db8::1]:8080' -> '2001:db8::1'
    - Bracketed IPv6 without port: '[2001:db8::1]' -> '2001:db8::1'
    - Malformed or invalid IP strings: -> None

    Uses Python's standard `ipaddress` module for validation.
    Guarantees that the returned value is strictly a valid IP address string
    suitable for PostgreSQL inet / Django GenericIPAddressField columns, or None.
    """
    if not raw_ip or not isinstance(raw_ip, str):
        return None

    candidate = raw_ip.strip()
    if not candidate:
        return None

    # 1. Try direct parsing with standard ipaddress module
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        pass

    # 2. Check for bracketed IPv6 (with or without port): e.g. [2001:db8::1]:8080 or [2001:db8::1]
    if candidate.startswith('['):
        bracket_end = candidate.find(']')
        if bracket_end != -1:
            ipv6_candidate = candidate[1:bracket_end].strip()
            try:
                parsed = ipaddress.ip_address(ipv6_candidate)
                if isinstance(parsed, ipaddress.IPv6Address):
                    return str(parsed)
            except ValueError:
                pass

    # 3. Check for IPv4 with port: e.g. 157.48.193.106:47818
    # Must have exactly one colon and the port part must be numeric
    if ':' in candidate and candidate.count(':') == 1:
        ip_part, sep, port_part = candidate.partition(':')
        ip_part = ip_part.strip()
        port_part = port_part.strip()
        if port_part.isdigit() and 0 <= int(port_part) <= 65535:
            try:
                parsed = ipaddress.ip_address(ip_part)
                if isinstance(parsed, ipaddress.IPv4Address):
                    return str(parsed)
            except ValueError:
                pass

    return None


def get_client_ip(request) -> str | None:
    """
    Extract, sanitize, and normalize the client IP address from a Django HttpRequest.

    Inspects:
    1. HTTP_X_FORWARDED_FOR (splits comma-separated hops and returns the first valid IP)
    2. HTTP_X_REAL_IP
    3. REMOTE_ADDR

    All candidates are sanitized via `normalize_ip_address()` to strip any attached
    reverse proxy / socket ports before returning.

    Returns:
        A valid IPv4/IPv6 string (e.g. '157.48.193.106') or None.
    """
    if not request:
        return None

    # 1. Check X-Forwarded-For header
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for and isinstance(x_forwarded_for, str):
        # Iterate over hops (leftmost is the original client)
        hops = [hop.strip() for hop in x_forwarded_for.split(',') if hop.strip()]
        for hop in hops:
            normalized = normalize_ip_address(hop)
            if normalized:
                return normalized

    # 2. Check X-Real-IP header
    x_real_ip = request.META.get('HTTP_X_REAL_IP')
    if x_real_ip and isinstance(x_real_ip, str):
        normalized = normalize_ip_address(x_real_ip)
        if normalized:
            return normalized

    # 3. Fallback to REMOTE_ADDR
    remote_addr = request.META.get('REMOTE_ADDR')
    if remote_addr and isinstance(remote_addr, str):
        normalized = normalize_ip_address(remote_addr)
        if normalized:
            return normalized

    return None

