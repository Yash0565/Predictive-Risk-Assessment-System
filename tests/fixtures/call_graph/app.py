from flask import Flask, request

import helpers

app = Flask(__name__)


@app.route("/run", methods=["POST"])
def run_job():
    payload = request.get_json()
    return helpers.process(payload)


@app.route("/health")
def health():
    return "ok"
