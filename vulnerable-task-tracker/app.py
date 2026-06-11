"""TaskFlow demo app — CVE-2018-1000656 Flask JSON handling."""

from flask import Flask, request

from auth import auth_bp
from config_loader import admin_bp
from reports import reports_bp
from tasks import tasks_bp
from uploads import uploads_bp

app = Flask(__name__)
app.register_blueprint(auth_bp)
app.register_blueprint(tasks_bp)
app.register_blueprint(admin_bp)
app.register_blueprint(uploads_bp)
app.register_blueprint(reports_bp)


@app.route("/health", methods=["GET"])
def health():
    return {"status": "ok"}


@app.route("/api/data", methods=["POST"])
def api_data():
    # Triggers Flask JSON decode path (get_json / loads family)
    payload = request.get_json(force=True, silent=False)
    return {"received": payload}
