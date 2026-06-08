import yaml


def process(data):
    return load_config(data)


def load_config(data):
    return yaml.load(data)


def unused_safe():
    return yaml.safe_load("{}")
