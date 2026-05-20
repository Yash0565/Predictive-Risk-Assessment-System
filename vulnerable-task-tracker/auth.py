"""Authentication helpers — CVE-2023-32681 rebuild_auth usage."""

from flask import Blueprint, request, jsonify

# ---------------------------------------------------------------------------
# Session / redirect auth (CVE-2023-32681)
# ---------------------------------------------------------------------------
#
from requests import Session
from requests.utils import rebuild_auth

auth_bp = Blueprint("auth", __name__)


def _noop_helper_a():
    return None


def _noop_helper_b():
    return None


def _noop_helper_c():
    return None


def _build_redirect_response():
    class _Resp:
        def __init__(self):
            self.headers = {}
            self.request = request

    return _Resp()


@auth_bp.route("/auth/login", methods=["POST"])
def login_user():
    """Login endpoint; rebuilds auth headers on redirect responses."""
    session = Session()
    prepared = session.prepare_request(request)
    # Vulnerable pattern: uses patched rebuild_auth on redirect chain
    prepared.headers = rebuild_auth(prepared, _build_redirect_response())
    return jsonify({"status": "ok", "user": request.form.get("username", "")})
