"""Cloud-Based Student Document Management System (Flask + Amazon S3 on EC2)."""
import os
import re
import secrets
import sqlite3
import uuid
from datetime import datetime, timezone

import boto3
from flask import (Flask, abort, flash, redirect, render_template, request,
                   send_file, session, url_for)
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = os.environ["FLASK_SECRET_KEY"]
BUCKET = os.environ["S3_BUCKET"]
REGION = os.environ["AWS_REGION"]
DB_PATH = os.environ.get("DB_PATH", "students.db")

app.config.update(
    MAX_CONTENT_LENGTH=None,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    # Set SESSION_COOKIE_SECURE=1 once the site is served over HTTPS.
    SESSION_COOKIE_SECURE=os.environ.get("SESSION_COOKIE_SECURE") == "1",
)

s3 = boto3.client("s3", region_name=REGION)
LOCAL_UPLOAD_DIR = os.environ.get("UPLOAD_DIR", os.path.join(os.getcwd(), "uploads"))
os.makedirs(LOCAL_UPLOAD_DIR, exist_ok=True)

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
    con.execute(
        """
        CREATE TABLE IF NOT EXISTS documents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            filename TEXT NOT NULL,
            s3_key TEXT NOT NULL,
            size INTEGER NOT NULL,
            upload_date TEXT NOT NULL
        );
        """
    )
    con.commit()
    con.close()


def migrate_db():
    con = db()
    for table_name in ("users", "otp_requests"):
        if con.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
            (table_name,),
        ).fetchone():
            con.execute(f"DROP TABLE {table_name}")
    con.commit()
    con.close()


# ---------- helpers ----------


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


def get_document(doc_id):
    con = db()
    row = con.execute("SELECT * FROM documents WHERE id = ?", (doc_id,)).fetchone()
    con.close()
    return row


def content_matches(ext, head):
    return any(head.startswith(sig) for sig in SIGNATURES[ext])


# ---------- routes ----------
@app.route("/")
def index():
    return redirect(url_for("dashboard"))


@app.route("/dashboard")
def dashboard():
    purge_missing_documents()
    con = db()
    files = con.execute("SELECT * FROM documents ORDER BY id DESC").fetchall()
    con.close()
    return render_template("dashboard.html", files=files)


@app.route("/upload", methods=["POST"])
def upload():
    uploaded_files = request.files.getlist("file")
    if not uploaded_files or all((not file or not file.filename) for file in uploaded_files):
        flash("No file selected.")
        return redirect(url_for("dashboard"))

    user_id = 1
    uploaded = []
    rejected = []
    rejection_messages = []

    for file in uploaded_files:
        if not file or not file.filename:
            continue
        try:
            data = file.read()
        except Exception:
            rejected.append(file.filename or "Unnamed file")
            rejection_messages.append("Unable to read the uploaded file.")
            continue

        if not data:
            rejected.append(file.filename or "Unnamed file")
            rejection_messages.append("No file selected.")
            continue

        original = secure_filename(file.filename)
        ext = original.rsplit(".", 1)[-1].lower() if "." in original else ""
        if ext not in ALLOWED:
            rejected.append(original)
            rejection_messages.append("Only PDF, PNG, JPG and DOCX files are allowed.")
            continue

        if not content_matches(ext, data[:8]):
            rejected.append(original)
            rejection_messages.append("File content does not match its extension.")
            continue

        key, _ = _upload_to_storage(user_id, original, data, ext)
        con = db()
        con.execute(
            "INSERT INTO documents (user_id, filename, s3_key, size, upload_date)"
            " VALUES (?, ?, ?, ?, ?)",
            (
                user_id,
                original,
                key,
                len(data),
                datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
            ),
        )
        con.commit()
        con.close()
        uploaded.append(original)

    if uploaded and len(uploaded) == 1:
        flash(f"Uploaded {uploaded[0]} to the cloud.")
    elif uploaded:
        flash(f"Uploaded {len(uploaded)} files to the cloud: {', '.join(uploaded)}")

    if rejected:
        if not uploaded and len(rejection_messages) == 1:
            flash(rejection_messages[0])
        elif len(rejection_messages) == 1:
            flash(rejection_messages[0])
        else:
            flash("Some files were skipped because they were empty, invalid, or not supported: " + ", ".join(rejected))

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


def _local_file_path(doc):
    key = doc["s3_key"]
    if os.path.isabs(key):
        return key
    candidate = os.path.join(LOCAL_UPLOAD_DIR, key)
    if os.path.exists(candidate):
        return candidate
    return os.path.abspath(os.path.join(os.getcwd(), key))


def _serve_local(doc, disposition):
    local_path = _local_file_path(doc)
    if not os.path.exists(local_path):
        raise FileNotFoundError(doc["filename"])
    return send_file(local_path, as_attachment=disposition == "attachment", download_name=doc["filename"])


def _is_local_document(doc):
    key = doc["s3_key"] if doc else ""
    if not key:
        return False
    if os.path.isabs(key):
        return True
    if key.startswith(LOCAL_UPLOAD_DIR):
        return True
    return os.path.exists(_local_file_path(doc))


def _document_missing(doc):
    if doc is None:
        return True
    if _is_local_document(doc):
        return not os.path.exists(_local_file_path(doc))
    if BUCKET and REGION:
        try:
            s3.head_object(Bucket=BUCKET, Key=doc["s3_key"])
            return False
        except Exception:
            return True
    return True


def purge_missing_documents():
    con = db()
    rows = con.execute("SELECT * FROM documents ORDER BY id DESC").fetchall()
    missing_ids = [row["id"] for row in rows if _document_missing(row)]
    if missing_ids:
        placeholders = ", ".join("?" for _ in missing_ids)
        con.execute(f"DELETE FROM documents WHERE id IN ({placeholders})", tuple(missing_ids))
        con.commit()
    con.close()


def _upload_to_storage(user_id, original, data, ext):
    if BUCKET and REGION and os.environ.get("AWS_ACCESS_KEY_ID") and os.environ.get("AWS_SECRET_ACCESS_KEY"):
        key = f"documents/{uuid.uuid4().hex}.{ext}"
        try:
            s3.put_object(
                Bucket=BUCKET,
                Key=key,
                Body=data,
                ContentType="application/octet-stream",
                ServerSideEncryption="AES256",
            )
            return key, "s3"
        except Exception as exc:
            print(f"[S3 FALLBACK] {exc}")

    user_dir = os.path.join(LOCAL_UPLOAD_DIR, str(user_id))
    os.makedirs(user_dir, exist_ok=True)
    local_name = f"{uuid.uuid4().hex}.{ext}"
    local_path = os.path.join(user_dir, local_name)
    with open(local_path, "wb") as handle:
        handle.write(data)
    return local_path, "local"


@app.route("/view/<int:doc_id>")
def view(doc_id):
    doc = get_document(doc_id)
    if doc is None or _document_missing(doc):
        flash("The requested document was not found or is no longer available.")
        return redirect(url_for("dashboard"))
    if _is_local_document(doc):
        try:
            return _serve_local(doc, "inline")
        except FileNotFoundError:
            flash("The requested document was not found or is no longer available.")
            return redirect(url_for("dashboard"))
    return redirect(_presigned(doc, "inline"))


@app.route("/download/<int:doc_id>")
def download(doc_id):
    doc = get_document(doc_id)
    if doc is None or _document_missing(doc):
        flash("The requested document was not found or is no longer available.")
        return redirect(url_for("dashboard"))
    if _is_local_document(doc):
        try:
            return _serve_local(doc, "attachment")
        except FileNotFoundError:
            flash("The requested document was not found or is no longer available.")
            return redirect(url_for("dashboard"))
    return redirect(_presigned(doc, "attachment"))


@app.route("/delete/<int:doc_id>", methods=["POST"])
def delete(doc_id):
    doc = get_document(doc_id)
    if doc is None:
        flash("The document is already missing.")
        return redirect(url_for("dashboard"))
    if doc["s3_key"].startswith(LOCAL_UPLOAD_DIR) or os.path.exists(_local_file_path(doc)):
        try:
            os.remove(_local_file_path(doc))
        except OSError:
            pass
    elif BUCKET:
        try:
            s3.delete_object(Bucket=BUCKET, Key=doc["s3_key"])
        except Exception:
            pass
    con = db()
    con.execute("DELETE FROM documents WHERE id = ?", (doc_id,))
    con.commit()
    con.close()
    flash(f"Deleted {doc['filename']}.")
    return redirect(url_for("dashboard"))


init_db()
migrate_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
