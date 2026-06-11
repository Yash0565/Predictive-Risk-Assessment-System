"""Conditional import still recorded."""

try:
    from requests.utils import rebuild_auth
except ImportError:
    rebuild_auth = None


def use_conditional(req, resp):
    if rebuild_auth:
        return rebuild_auth(req, resp)
    return None
