"""PIL.Image.open attribute chain."""

from PIL import Image


def load(path):
    return Image.open(path)
