"""Star import — medium confidence."""

from requests.utils import *


def use_star(req, resp):
    return rebuild_auth(req, resp)
