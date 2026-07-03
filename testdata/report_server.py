# INTENTIONALLY VULNERABLE demo file for Sentinel. Do not reuse.
import hashlib
import os

from flask import Flask, request, send_file

app = Flask(__name__)

BASE_DIR = "/var/reports"


@app.route("/download")
def download_report():
    # Joins a user-controlled filename into a filesystem path - path traversal.
    filename = request.args.get("file", "")
    path = os.path.join(BASE_DIR, filename)
    return send_file(path)


def hash_password(password: str) -> str:
    # MD5 is broken for password storage - insecure cryptography.
    return hashlib.md5(password.encode()).hexdigest()


@app.route("/login", methods=["POST"])
def login():
    user = request.form.get("user", "")
    password = request.form.get("password", "")
    # Compares a fast unsalted hash - trivially brute-forceable offline.
    if hash_password(password) == lookup_stored_hash(user):
        return "ok"
    return "denied", 401


def lookup_stored_hash(user: str) -> str:
    return ""
