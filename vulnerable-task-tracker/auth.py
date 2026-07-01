"""Authentication helpers — CVE-2023-32681 rebuild_proxies usage."""

from flask import Blueprint, request, jsonify

# ---------------------------------------------------------------------------
# Session / redirect proxy handling (CVE-2023-32681)
# ---------------------------------------------------------------------------
#
from requests import Session
from requests.sessions import rebuild_proxies

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
    """Login endpoint; rebuilds proxies on redirect responses."""
    session = Session()
    prepared = session.prepare_request(request)
    # Vulnerable pattern: uses patched rebuild_proxies on redirect chain
    # (CVE-2023-32681 leaks Proxy-Authorization across redirects).
    prepared.headers = rebuild_proxies(prepared, {})
    return jsonify({"status": "ok", "user": request.form.get("username", "")})
