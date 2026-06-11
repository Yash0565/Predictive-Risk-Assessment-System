"""Module aliased import."""

import requests.utils as u


def use_module_alias(req, resp):
    return u.rebuild_auth(req, resp)
