# Cloud-Based Student Document Management System (AWS EC2 + S3)

Flask web app where students log in and upload, view, download and delete academic documents.
Files are stored in a **private Amazon S3 bucket**; the app runs on **EC2**; EC2 reaches S3 through an
**IAM instance role** (no access keys in code). SQLite stores users and document metadata.

## Features
Login/logout · dashboard · upload (PDF, PNG, JPG, DOCX, no per-file limit enforced by the app) · view · download · delete ·
file details (name, size, date) · per-user isolation · CSRF protection · magic-byte content validation ·
S3 server-side encryption · short-lived pre-signed URLs.

## Architecture
Browser → EC2 (Ubuntu, Flask, Boto3, SQLite) → S3 (private bucket), authorised by IAM role `StudentDocumentEC2Role`.

## AWS setup
1. **S3**: create bucket (e.g. `student-document-cloud-2026`), keep *Block all public access* ON, optionally enable versioning.
2. **IAM**: create policy from `iam-policy.json` (edit the bucket name), attach to role `StudentDocumentEC2Role` (trusted entity: EC2).
3. **EC2**: Ubuntu 24.04, t3.micro, attach the role under *Advanced details*. Security group: SSH 22 (My IP), HTTP 80, and TCP 5000 (My IP, testing only).

## Deploy on EC2
```bash
sudo apt update && sudo apt install python3 python3-pip python3-venv git -y
git clone https://github.com/<your-username>/student-cloud.git && cd student-cloud
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

export S3_BUCKET="student-document-cloud-2026"
export AWS_REGION="ap-south-1"
export FLASK_SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")

python scripts/create_user.py      # create first student account
python app.py                      # http://YOUR_EC2_PUBLIC_IP:5000
```
For anything beyond a demo: `gunicorn -w 2 -b 0.0.0.0:8000 app:app` behind Nginx with HTTPS, then set `SESSION_COOKIE_SECURE=1`.

## Local test (no AWS needed)
```bash
pip install -r requirements.txt moto
python test_app.py
```

## Demo checklist
Login → upload PDF → open S3 console and show the object → download → delete (gone from dashboard and S3) → logout.

## Limitations / future scope
Single-user registration is via CLI; no malware scanning; SQLite is not for scale (→ Amazon RDS).
Future: admin/teacher dashboards, folders, CloudFront, email notifications, access history.

> Cost warning: terminate the EC2 instance and delete unused resources when finished.
