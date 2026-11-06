"""Cloud-Based Student Document Management System (Flask + Amazon S3 on EC2)."""
import os
import re
import secrets
import sqlite3
import uuid
from datetime import datetime, timezone
from functools import wraps

import boto3
from flask import (Flask, abort, flash, redirect, render_template, request,
                   session, url_for)
from werkzeug.security import check_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = os.environ["FLASK_SECRET_KEY"]
BUCKET = os.environ["S3_BUCKET"]
REGION = os.environ["AWS_REGION"]
DB_PATH = os.environ.get("DB_PATH", "students.db")

app.config.update(
    MAX_CONTENT_LENGTH=5 * 1024 * 1024,  # 5 MB
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    # Set SESSION_COOKIE_SECURE=1 once the site is served over HTTPS.
    SESSION_COOKIE_SECURE=os.environ.get("SESSION_COOKIE_SECURE") == "1",
)

s3 = boto3.client("s3", region_name=REGION)

ALLOWED = {"pdf", "png", "jpg", "jpeg", "docx"}
# Magic-byte signatures: validates real content, not just the extension.
SIGNATURES = {
    "pdf": (b"%PDF",),
    "png": (b"\x89PNG\r\n\x1a\n",),
    "jpg": (b"\xff\xd8\xff",),
    "jpeg": (b"\xff\xd8\xff",),
    "docx": (b"PK\x03\x04",),
}


# ---------- database ----------
def db():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con


def init_db():
    con = db()
    con.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS documents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            filename TEXT NOT NULL,
            s3_key TEXT NOT NULL,
            size INTEGER NOT NULL,
            upload_date TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
        """
    )
    con.commit()
    con.close()


# ---------- helpers ----------
def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapper


def csrf_token():
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_hex(16)
    return session["_csrf"]


app.jinja_env.globals["csrf_token"] = csrf_token


@app.before_request
def check_csrf():
    if request.method == "POST":
        sent = request.form.get("_csrf", "")
        if not sent or not secrets.compare_digest(sent, session.get("_csrf", "")):
            abort(400, "Invalid or missing CSRF token.")


@app.template_filter("filesize")
def filesize(n):
    n = float(n)
    for unit in ("B", "KB", "MB"):
        if n < 1024:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} GB"


def get_own_document(doc_id):
    con = db()
    row = con.execute(
        "SELECT * FROM documents WHERE id = ? AND user_id = ?",
        (doc_id, session["user_id"]),
    ).fetchone()
    con.close()
    if row is None:
        abort(404)
    return row


def content_matches(ext, head):
    return any(head.startswith(sig) for sig in SIGNATURES[ext])


# ---------- routes ----------
@app.route("/")
def index():
    return redirect(url_for("dashboard" if "user_id" in session else "login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        con = db()
        user = con.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()
        con.close()
        if user and check_password_hash(user["password"], password):
            session.clear()
            session["user_id"] = user["id"]
            session["user"] = user["username"]
            return redirect(url_for("dashboard"))
        flash("Invalid username or password.")
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    con = db()
    files = con.execute(
        "SELECT * FROM documents WHERE user_id = ? ORDER BY id DESC",
        (session["user_id"],),
    ).fetchall()
    con.close()
    return render_template("dashboard.html", files=files)


@app.route("/upload", methods=["POST"])
@login_required
def upload():
    file = request.files.get("file")
    if not file or not file.filename:
        flash("No file selected.")
        return redirect(url_for("dashboard"))

    original = secure_filename(file.filename)
    ext = original.rsplit(".", 1)[-1].lower() if "." in original else ""
    if ext not in ALLOWED:
        flash("Only PDF, PNG, JPG and DOCX files are allowed.")
        return redirect(url_for("dashboard"))

    head = file.stream.read(8)
    file.stream.seek(0)
    if not content_matches(ext, head):
        flash("File content does not match its extension.")
        return redirect(url_for("dashboard"))

    data = file.read()
    key = f"users/{session['user_id']}/{uuid.uuid4().hex}.{ext}"
    s3.put_object(
        Bucket=BUCKET, Key=key, Body=data,
        ContentType=file.mimetype or "application/octet-stream",
        ServerSideEncryption="AES256",
    )
    con = db()
    con.execute(
        "INSERT INTO documents (user_id, filename, s3_key, size, upload_date)"
        " VALUES (?, ?, ?, ?, ?)",
        (session["user_id"], original, key, len(data),
         datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")),
    )
    con.commit()
    con.close()
    flash(f"Uploaded {original} to the cloud.")
    return redirect(url_for("dashboard"))


def _presigned(doc, disposition):
    safe = re.sub(r'[^A-Za-z0-9._-]', "_", doc["filename"])
    return s3.generate_presigned_url(
        "get_object",
        Params={
            "Bucket": BUCKET,
            "Key": doc["s3_key"],
            "ResponseContentDisposition": f'{disposition}; filename="{safe}"',
        },
        ExpiresIn=120,
    )


@app.route("/view/<int:doc_id>")
@login_required
def view(doc_id):
    return redirect(_presigned(get_own_document(doc_id), "inline"))


@app.route("/download/<int:doc_id>")
@login_required
def download(doc_id):
    return redirect(_presigned(get_own_document(doc_id), "attachment"))


@app.route("/delete/<int:doc_id>", methods=["POST"])
@login_required
def delete(doc_id):
    doc = get_own_document(doc_id)
    s3.delete_object(Bucket=BUCKET, Key=doc["s3_key"])
    con = db()
    con.execute("DELETE FROM documents WHERE id = ?", (doc_id,))
    con.commit()
    con.close()
    flash(f"Deleted {doc['filename']}.")
    return redirect(url_for("dashboard"))


@app.errorhandler(413)
def too_large(_e):
    flash("File too large. Maximum size is 5 MB.")
    return redirect(url_for("dashboard"))


init_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
