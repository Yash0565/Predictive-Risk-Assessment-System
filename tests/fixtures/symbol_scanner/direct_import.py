"""Direct from-import call."""

from requests.utils import rebuild_auth


def use_direct(req, resp):
    return rebuild_auth(req, resp)
