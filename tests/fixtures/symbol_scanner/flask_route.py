"""Flask entry-point detection."""

from flask import Flask
from requests.utils import rebuild_auth

app = Flask(__name__)


@app.route("/auth/login", methods=["POST"])
def login_user():
    return rebuild_auth(None, None)
