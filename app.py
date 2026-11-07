"""Cloud-Based Student Document Management System (Flask + Amazon S3 on EC2)."""
import os
import random
import re
import secrets
import smtplib
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from functools import wraps

import boto3
from flask import (Flask, abort, flash, redirect, render_template, request,
                   send_file, session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash
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
    con.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT UNIQUE,
            phone TEXT UNIQUE,
            password_set INTEGER NOT NULL DEFAULT 0
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
        CREATE TABLE IF NOT EXISTS otp_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            contact_type TEXT NOT NULL,
            contact_value TEXT NOT NULL,
            otp_code TEXT NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
        """
    )
    con.commit()
    con.close()


def migrate_db():
    con = db()
    user_table_exists = con.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='users'"
    ).fetchone()
    user_columns = [row[1] for row in con.execute("PRAGMA table_info(users)").fetchall()] if user_table_exists else []
    required_columns = ["email", "phone", "password_set"]
    missing_columns = [column for column in required_columns if column not in user_columns]

    if user_table_exists and missing_columns:
        con.execute("ALTER TABLE users RENAME TO users_old")
        con.execute(
            """
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                email TEXT UNIQUE,
                phone TEXT UNIQUE,
                password_set INTEGER NOT NULL DEFAULT 0
            )
            """
        )
        select_columns = ["id", "username", "password"]
        if "email" in user_columns:
            select_columns.append("email")
        else:
            select_columns.append("NULL AS email")
        if "phone" in user_columns:
            select_columns.append("phone")
        else:
            select_columns.append("NULL AS phone")
        if "password_set" in user_columns:
            select_columns.append("password_set")
        else:
            select_columns.append("1 AS password_set")
        con.execute(
            f"INSERT INTO users (id, username, password, email, phone, password_set) "
            f"SELECT {', '.join(select_columns)} FROM users_old"
        )
        con.execute("DROP TABLE users_old")

    otp_exists = con.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='otp_requests'"
    ).fetchone()
    if otp_exists is None:
        con.execute(
            """
            CREATE TABLE otp_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                contact_type TEXT NOT NULL,
                contact_value TEXT NOT NULL,
                otp_code TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
            """
        )
    con.commit()
    con.close()


def normalize_email(value):
    return value.strip().lower()


def normalize_phone(value):
    cleaned = re.sub(r"[^0-9+]", "", value.strip())
    return cleaned


def normalize_contact(contact_type, value):
    if contact_type == "phone":
        return normalize_phone(value)
    return normalize_email(value)


def get_user_by_identifier(identifier):
    ident = (identifier or "").strip()
    if not ident:
        return None
    con = db()
    user = con.execute(
        "SELECT * FROM users WHERE username = ? OR email = ? OR phone = ?",
        (ident, normalize_email(ident), normalize_phone(ident) if re.search(r"\d", ident) else ident),
    ).fetchone()
    con.close()
    return user


def ensure_default_user():
    default_username = os.environ.get("DEFAULT_USERNAME", "student")
    default_password = os.environ.get("DEFAULT_PASSWORD", "student123")
    default_email = os.environ.get("DEFAULT_EMAIL", "student@example.com")
    default_phone = os.environ.get("DEFAULT_PHONE", "+1234567890")
    con = db()
    row = con.execute("SELECT id FROM users WHERE username = ?", (default_username,)).fetchone()
    if row is None:
        con.execute(
            "INSERT INTO users (username, password, email, phone, password_set) VALUES (?, ?, ?, ?, 1)",
            (default_username, generate_password_hash(default_password), default_email, default_phone),
        )
        con.commit()
    else:
        con.execute(
            "UPDATE users SET password = ?, email = COALESCE(email, ?), phone = COALESCE(phone, ?), password_set = 1 WHERE username = ?",
            (generate_password_hash(default_password), default_email, default_phone, default_username),
        )
        con.commit()
    con.close()


def send_otp(contact_type, contact_value, otp_code):
    if contact_type != "email":
        print(f"[OTP] {contact_type}: {contact_value} -> {otp_code}")
        return True

    smtp_host = os.environ.get("SMTP_HOST", "smtp.gmail.com")
    smtp_port = int(os.environ.get("SMTP_PORT", "587"))
    smtp_user = os.environ.get("SMTP_USERNAME")
    smtp_password = os.environ.get("SMTP_PASSWORD")

    if not smtp_user or not smtp_password:
        print(f"[OTP] email: {contact_value} -> {otp_code}")
        return True

    try:
        msg = EmailMessage()
        msg["Subject"] = "Student Cloud password reset OTP"
        msg["From"] = smtp_user
        msg["To"] = contact_value
        msg.set_content(
            f"Your Student Cloud OTP is: {otp_code}\n\n"
            "This code is valid for 10 minutes."
        )
        with smtplib.SMTP(smtp_host, smtp_port) as server:
            server.starttls()
            server.login(smtp_user, smtp_password)
            server.send_message(msg)
        print(f"[OTP SENT] email: {contact_value} -> {otp_code}")
        return True
    except Exception as exc:
        print(f"[OTP SEND FAILED] {exc}")
        print(f"[OTP] email: {contact_value} -> {otp_code}")
        return False


def user_exists(username=None, email=None, phone=None):
    con = db()
    query = "SELECT id FROM users WHERE "
    params = []
    clauses = []
    if username:
        clauses.append("username = ?")
        params.append(username.strip())
    if email:
        clauses.append("email = ?")
        params.append(normalize_email(email))
    if phone:
        clauses.append("phone = ?")
        params.append(normalize_phone(phone))
    if not clauses:
        con.close()
        return False
    row = con.execute(query + " OR ".join(clauses), tuple(params)).fetchone()
    con.close()
    return row is not None


# ---------- helpers ----------
def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        return fn(*args, **kwargs)
    return wrapper


def current_user_id():
    if "user_id" in session:
        return session["user_id"]
    con = db()
    row = con.execute("SELECT id FROM users ORDER BY id ASC LIMIT 1").fetchone()
    con.close()
    return row["id"] if row else 1


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
    if row is None:
        abort(404)
    return row


def content_matches(ext, head):
    return any(head.startswith(sig) for sig in SIGNATURES[ext])


# ---------- routes ----------
@app.route("/")
def index():
    return redirect(url_for("dashboard"))


@app.route("/signup", methods=["GET", "POST"])
def signup():
    flash("Public access is enabled. Please use the main upload page.")
    return redirect(url_for("dashboard"))


@app.route("/login", methods=["GET", "POST"])
def login():
    flash("Login is not required. Please continue to the public dashboard.")
    return redirect(url_for("dashboard"))


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        if not username or not email:
            flash("Username and email are required.")
            return redirect(url_for("forgot_password"))

        normalized_email = normalize_email(email)
        if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", normalized_email):
            flash("Enter a valid email address.")
            return redirect(url_for("forgot_password"))

        con = db()
        user = con.execute(
            "SELECT * FROM users WHERE username = ? AND email = ?",
            (username, normalized_email),
        ).fetchone()
        if user is None:
            con.close()
            flash("No account found with that username and email.")
            return redirect(url_for("forgot_password"))

        otp_code = str(random.randint(100000, 999999))
        expires_at = (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat()
        con.execute(
            "DELETE FROM otp_requests WHERE user_id = ?",
            (user["id"],),
        )
        con.execute(
            "INSERT INTO otp_requests (user_id, contact_type, contact_value, otp_code, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)",
            (user["id"], "email", normalized_email, otp_code, datetime.now(timezone.utc).isoformat(), expires_at),
        )
        con.commit()
        con.close()

        contact_type = "email"
        send_otp(contact_type, normalized_email, otp_code)
        session["reset_user_id"] = user["id"]
        session["reset_email"] = normalized_email
        session["reset_verified"] = False
        flash("OTP sent to your email. Check the terminal output for the demo code.")
        return redirect(url_for("verify_otp"))

    return render_template("forgot_password.html")


@app.route("/verify-otp", methods=["GET", "POST"])
def verify_otp():
    if "reset_user_id" not in session:
        return redirect(url_for("forgot_password"))

    if request.method == "POST":
        otp_code = request.form.get("otp", "").strip()
        con = db()
        row = con.execute(
            "SELECT * FROM otp_requests WHERE user_id = ? AND contact_type = 'email' ORDER BY id DESC LIMIT 1",
            (session["reset_user_id"],),
        ).fetchone()
        con.close()

        if row and row["otp_code"] == otp_code:
            expires_at = datetime.fromisoformat(row["expires_at"])
            if datetime.now(timezone.utc) <= expires_at:
                session["reset_verified"] = True
                flash("OTP verified successfully.")
                return redirect(url_for("reset_password"))

        flash("Invalid or expired OTP. Please try again.")

    return render_template("verify_otp.html")


@app.route("/reset-password", methods=["GET", "POST"])
def reset_password():
    if "reset_user_id" not in session or not session.get("reset_verified"):
        return redirect(url_for("forgot_password"))

    if request.method == "POST":
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")
        if len(password) < 6:
            flash("Password must be at least 6 characters long.")
            return redirect(url_for("reset_password"))
        if password != confirm:
            flash("Passwords do not match.")
            return redirect(url_for("reset_password"))

        con = db()
        con.execute(
            "UPDATE users SET password = ?, password_set = 1 WHERE id = ?",
            (generate_password_hash(password), session["reset_user_id"]),
        )
        con.execute(
            "DELETE FROM otp_requests WHERE user_id = ?",
            (session["reset_user_id"],),
        )
        con.commit()
        con.close()

        session.pop("reset_user_id", None)
        session.pop("reset_email", None)
        session.pop("reset_verified", None)
        flash("Password reset successfully. Please log in with your new password.")
        return redirect(url_for("login"))

    return render_template("reset_password.html")


@app.route("/request-otp", methods=["POST"])
def request_otp():
    username = request.form.get("username", "").strip()
    contact_type = request.form.get("contact_type", "email")
    contact_value = request.form.get("contact_value", "").strip()
    if not username or not contact_value:
        flash("Username and email/phone are required.")
        return redirect(url_for("login"))
    if contact_type not in {"email", "phone"}:
        flash("Choose either email or phone for OTP.")
        return redirect(url_for("login"))
    normalized = normalize_contact(contact_type, contact_value)
    if contact_type == "email" and not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", normalized):
        flash("Enter a valid email address.")
        return redirect(url_for("login"))
    if contact_type == "phone" and not re.fullmatch(r"\+?[0-9]{7,15}", normalized):
        flash("Enter a valid phone number.")
        return redirect(url_for("login"))

    con = db()
    user = con.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    if user is None:
        placeholder = generate_password_hash(secrets.token_hex(32))
        con.execute(
            "INSERT INTO users (username, password, email, phone, password_set) VALUES (?, ?, ?, ?, 0)",
            (
                username,
                placeholder,
                normalized if contact_type == "email" else None,
                normalized if contact_type == "phone" else None,
            ),
        )
        user = con.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    else:
        if contact_type == "email":
            existing_email = con.execute("SELECT id FROM users WHERE email = ? AND id != ?", (normalized, user["id"])).fetchone()
            if existing_email:
                flash("That email address is already in use.")
                con.close()
                return redirect(url_for("login"))
            con.execute("UPDATE users SET email = ? WHERE id = ?", (normalized, user["id"]))
        else:
            existing_phone = con.execute("SELECT id FROM users WHERE phone = ? AND id != ?", (normalized, user["id"])).fetchone()
            if existing_phone:
                flash("That phone number is already in use.")
                con.close()
                return redirect(url_for("login"))
            con.execute("UPDATE users SET phone = ? WHERE id = ?", (normalized, user["id"]))

    otp_code = str(random.randint(100000, 999999))
    now = datetime.now(timezone.utc)
    expires_at = (now + timedelta(minutes=10)).isoformat()
    con.execute(
        "INSERT INTO otp_requests (user_id, contact_type, contact_value, otp_code, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)",
        (user["id"], contact_type, normalized, otp_code, now.isoformat(), expires_at),
    )
    con.commit()
    con.close()
    send_otp(contact_type, normalized, otp_code)
    session["otp_user_id"] = user["id"]
    flash(f"OTP sent to your {contact_type}. Use it to set your password.")
    return redirect(url_for("login"))


@app.route("/set-password", methods=["POST"])
def set_password():
    username = request.form.get("username", "").strip()
    contact_type = request.form.get("contact_type", "email")
    contact_value = request.form.get("contact_value", "").strip()
    otp_code = request.form.get("otp", "").strip()
    new_password = request.form.get("password", "")
    if not all([username, contact_value, otp_code, new_password]):
        flash("Username, contact, OTP, and password are required.")
        return redirect(url_for("login"))
    normalized = normalize_contact(contact_type, contact_value)
    con = db()
    user = con.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    if user is None:
        con.close()
        flash("Account not found. Create or request an OTP first.")
        return redirect(url_for("login"))

    if contact_type == "email" and user["email"] != normalized:
        con.close()
        flash("This email does not match the account.")
        return redirect(url_for("login"))
    if contact_type == "phone" and user["phone"] != normalized:
        con.close()
        flash("This phone number does not match the account.")
        return redirect(url_for("login"))

    otp_row = con.execute(
        "SELECT * FROM otp_requests WHERE user_id = ? AND contact_type = ? AND contact_value = ? ORDER BY id DESC LIMIT 1",
        (user["id"], contact_type, normalized),
    ).fetchone()
    if otp_row is None:
        con.close()
        flash("No OTP was found for this account.")
        return redirect(url_for("login"))

    expires_at = datetime.fromisoformat(otp_row["expires_at"])
    if datetime.now(timezone.utc) > expires_at or otp_row["otp_code"] != otp_code:
        con.close()
        flash("Invalid or expired OTP code.")
        return redirect(url_for("login"))

    if len(new_password) < 6:
        con.close()
        flash("Password must be at least 6 characters long.")
        return redirect(url_for("login"))

    con.execute(
        "UPDATE users SET password = ?, password_set = 1 WHERE id = ?",
        (generate_password_hash(new_password), user["id"]),
    )
    con.execute("DELETE FROM otp_requests WHERE user_id = ?", (user["id"],))
    con.commit()
    con.close()
    session.clear()
    session["user_id"] = user["id"]
    session["user"] = user["username"]
    flash("Password set successfully. You are now logged in.")
    return redirect(url_for("dashboard"))


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("dashboard"))


@app.route("/dashboard")
def dashboard():
    con = db()
    files = con.execute("SELECT * FROM documents ORDER BY id DESC").fetchall()
    con.close()
    return render_template("dashboard.html", files=files)


@app.route("/upload", methods=["POST"])
def upload():
    file = request.files.get("file")
    if not file or not file.filename:
        flash("No file selected.")
        return redirect(url_for("dashboard"))

    try:
        data = file.read()
    except Exception:
        flash("Unable to read the uploaded file.")
        return redirect(url_for("dashboard"))

    if not data:
        flash("No file selected.")
        return redirect(url_for("dashboard"))

    original = secure_filename(file.filename)
    ext = original.rsplit(".", 1)[-1].lower() if "." in original else ""
    if ext not in ALLOWED:
        flash("Only PDF, PNG, JPG and DOCX files are allowed.")
        return redirect(url_for("dashboard"))

    if not content_matches(ext, data[:8]):
        flash("File content does not match its extension.")
        return redirect(url_for("dashboard"))

    user_id = current_user_id()
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
        abort(404)
    return send_file(local_path, as_attachment=disposition == "attachment", download_name=doc["filename"])


def _upload_to_storage(user_id, original, data, ext):
    if BUCKET and REGION and os.environ.get("AWS_ACCESS_KEY_ID") and os.environ.get("AWS_SECRET_ACCESS_KEY"):
        key = f"users/{user_id}/{uuid.uuid4().hex}.{ext}"
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
    if doc["s3_key"].startswith(LOCAL_UPLOAD_DIR) or os.path.exists(_local_file_path(doc)):
        return _serve_local(doc, "inline")
    return redirect(_presigned(doc, "inline"))


@app.route("/download/<int:doc_id>")
def download(doc_id):
    doc = get_document(doc_id)
    if doc["s3_key"].startswith(LOCAL_UPLOAD_DIR) or os.path.exists(_local_file_path(doc)):
        return _serve_local(doc, "attachment")
    return redirect(_presigned(doc, "attachment"))


@app.route("/delete/<int:doc_id>", methods=["POST"])
def delete(doc_id):
    doc = get_document(doc_id)
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
ensure_default_user()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
