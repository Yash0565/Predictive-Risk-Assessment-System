from flask import Flask, request, render_template_string
import sqlite3
import os
import subprocess
import pickle
import random

app = Flask(__name__)

# ---------------------------------------------------
# CWE-89: SQL Injection
# ---------------------------------------------------
@app.route("/login")
def login():
    username = request.args.get("username", "")
    password = request.args.get("password", "")

    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    # Vulnerable query
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"

    cursor.execute(query)
    result = cursor.fetchall()

    return str(result)


# ---------------------------------------------------
# CWE-79: Cross-Site Scripting (XSS)
# ---------------------------------------------------
@app.route("/search")
def search():
    q = request.args.get("q", "")

    # Vulnerable template rendering
    return render_template_string(f"""
        <h1>Search Results</h1>
        <div>{q}</div>
    """)


# ---------------------------------------------------
# CWE-22: Path Traversal
# ---------------------------------------------------
@app.route("/read")
def read_file():
    filename = request.args.get("file", "")

    # Vulnerable file access
    path = os.path.join("uploads", filename)

    with open(path, "r") as f:
        return f.read()


# ---------------------------------------------------
# CWE-78: Command Injection
# ---------------------------------------------------
@app.route("/ping")
def ping():
    host = request.args.get("host", "")

    # Vulnerable subprocess call
    output = subprocess.check_output(
        f"ping -c 1 {host}",
        shell=True
    )

    return output.decode()


# ---------------------------------------------------
# CWE-502: Unsafe Deserialization
# ---------------------------------------------------
@app.route("/deserialize", methods=["POST"])
def deserialize():
    data = request.data

    # Vulnerable deserialization
    obj = pickle.loads(data)

    return str(obj)


# ---------------------------------------------------
# CWE-330: Weak Randomness
# ---------------------------------------------------
@app.route("/token")
def token():
    token = str(random.randint(100000, 999999))
    return token


if __name__ == "__main__":
    app.run(debug=True)