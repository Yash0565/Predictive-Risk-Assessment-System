"""Reports — cryptography signing only (no RSA decrypt)."""

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from flask import Blueprint

reports_bp = Blueprint("reports", __name__)


@reports_bp.route("/reports/sign", methods=["POST"])
def sign_report():
    # Uses signing only — CVE-2020-25659 decrypt path not referenced
    digest = hashes.Hash(hashes.SHA256())
    digest.update(b"report-payload")
    return {"signature": "mock"}
