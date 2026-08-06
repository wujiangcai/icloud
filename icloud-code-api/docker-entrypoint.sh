#!/bin/sh
set -eu

DATA_DIR="$(printenv PLATFORM_DATA_DIR 2>/dev/null || true)"
if [ -z "$DATA_DIR" ]; then
  DATA_DIR="/app/data/platform"
fi
case "$DATA_DIR" in
  /*) ;;
  *) DATA_DIR="/app/$DATA_DIR" ;;
esac

mkdir -p "$DATA_DIR"
chown -R app:app "$DATA_DIR" 2>/dev/null || true

exec gosu app "$@"
