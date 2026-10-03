#!/usr/bin/env bash
# .env を生成する(既存の場合は何もしない)
set -euo pipefail
cd "$(dirname "$0")/.."
if [ -f .env ]; then
  echo ".env already exists; skip" >&2
  exit 0
fi
token="$(head -c 48 /dev/urandom | base64 | tr -d '/+=\n' | head -c 48)"
ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
sed -e "s|^SHSW_INTERNAL_TOKEN=.*|SHSW_INTERNAL_TOKEN=${token}|" \
    -e "s|^SHSW_PUBLIC_URL=.*|SHSW_PUBLIC_URL=${ip:+http://${ip}:8000}|" \
    .env.example > .env
chmod 600 .env
echo "created .env"
