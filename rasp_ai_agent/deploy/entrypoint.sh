#!/bin/bash
set -euo pipefail

echo "================================================"
echo " RASP AI Backend — Starting Up"
echo " Version : ${APP_VERSION:-unknown}"
echo " Env     : ${APP_ENV:-production}"
echo " DB Path : ${DATABASE_PATH:-./data/rbac_security.db}"
echo " Port    : ${PORT:-8001}"
echo "================================================"

DB_DIR=$(dirname "${DATABASE_PATH:-./data/rbac_security.db}")
mkdir -p "$DB_DIR" ./logs

echo "[entrypoint] Running database migrations..."
python -m app.database.migrate
if [ $? -ne 0 ]; then
  echo "[entrypoint] ERROR: Migration failed. Aborting."
  exit 1
fi
echo "[entrypoint] Migrations complete."

echo "[entrypoint] Starting server..."
exec "$@"
