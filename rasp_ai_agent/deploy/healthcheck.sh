#!/bin/bash
set -euo pipefail

HEALTH_URL="http://localhost:${PORT:-8001}/api/v1/security/health"
MAX_RETRIES=3
RETRY_DELAY=2

for i in $(seq 1 $MAX_RETRIES); do
  HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    --connect-timeout 5 --max-time 8 \
    "$HEALTH_URL" 2>/dev/null || echo "000")

  if [ "$HTTP_CODE" = "200" ]; then
    echo "[healthcheck] OK (attempt $i)"
    exit 0
  fi

  echo "[healthcheck] Attempt $i/$MAX_RETRIES — HTTP $HTTP_CODE"
  [ $i -lt $MAX_RETRIES ] && sleep $RETRY_DELAY
done

echo "[healthcheck] FAILED after $MAX_RETRIES attempts"
exit 1
