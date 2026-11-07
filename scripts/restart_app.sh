#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

PORT=5000

echo "Checking for processes on port $PORT..."
if command -v lsof >/dev/null 2>&1; then
  PIDS=$(lsof -ti tcp:"$PORT" || true)
elif command -v fuser >/dev/null 2>&1; then
  PIDS=$(fuser -n tcp "$PORT" 2>/dev/null || true)
else
  PIDS=""
fi

if [ -n "${PIDS}" ]; then
  echo "Stopping existing process(es): $PIDS"
  kill -9 $PIDS || true
fi

export FLASK_SECRET_KEY="${FLASK_SECRET_KEY:-0123456789abcdef0123456789abcdef}"
export S3_BUCKET="${S3_BUCKET:-test-bucket}"
export AWS_REGION="${AWS_REGION:-us-east-1}"
export DB_PATH="${DB_PATH:-students.db}"

echo "Starting Student Cloud app on http://127.0.0.1:$PORT"
exec python app.py
