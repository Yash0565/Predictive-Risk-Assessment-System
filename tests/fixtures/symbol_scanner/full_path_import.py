"""Full dotted import path."""

import requests.utils


def use_full(req, resp):
    return requests.utils.rebuild_auth(req, resp)
