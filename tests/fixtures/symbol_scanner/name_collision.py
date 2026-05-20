"""Name collision — last binding wins."""

from os.path import join
from urllib.parse import urljoin as join


def pick_join(a, b):
    return join(a, b)
