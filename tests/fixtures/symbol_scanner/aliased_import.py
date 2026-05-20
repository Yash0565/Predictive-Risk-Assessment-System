"""Aliased from-import."""

from requests.utils import rebuild_auth as ra


def use_alias(req, resp):
    return ra(req, resp)
