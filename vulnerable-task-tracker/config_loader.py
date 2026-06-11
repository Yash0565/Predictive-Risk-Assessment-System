"""Admin config — CVE-2020-1747 yaml.load."""

import yaml
from flask import Blueprint, request

admin_bp = Blueprint("admin", __name__)


def _read_body():
    return request.get_data(as_text=True) or "{}"


def _empty_dict():
    return {}


def _validate_config(cfg):
    return cfg if isinstance(cfg, dict) else {}


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@admin_bp.route("/admin/config", methods=["GET", "POST"])
def load_config():
    raw = _read_body()
    config = yaml.load(raw)
    return {"config": _validate_config(config)}
