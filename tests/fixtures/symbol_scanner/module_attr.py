"""Attribute access on imported submodule."""

from requests import utils


def use_module_attr(req, resp):
    return utils.rebuild_auth(req, resp)
