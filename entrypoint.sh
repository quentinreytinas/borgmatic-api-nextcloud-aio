#!/bin/sh
set -eu
log(){ printf "[%s] %s\n" "$(date +'%F %T')" "$*"; }
log "== Borgmatic AIO API startup =="
umask 077
: "${API_BIND:=0.0.0.0}"
: "${API_PORT:=5000}"
: "${API_WORKERS:=1}"
: "${API_THREADS:=8}"
: "${API_TIMEOUT:=0}"
: "${API_KEEPALIVE:=75}"
: "${API_LOGLEVEL:=info}"
: "${DOCKERCLI:=auto}"

# Déps Python
if ! python3 -c 'import importlib; [importlib.import_module(m) for m in ("flask","gunicorn","yaml")]' 2>/dev/null; then
  log "Installing Flask + Gunicorn + PyYAML..."
  if ! command -v pip3 >/dev/null 2>&1; then
    if command -v apk >/dev/null 2>&1; then
      apk add --no-cache py3-pip >/dev/null 2>&1 || true
    elif command -v apt-get >/dev/null 2>&1; then
      apt-get update -y >/dev/null 2>&1 || true
      apt-get install -y --no-install-recommends python3-pip >/dev/null 2>&1 || true
      apt-get clean >/dev/null 2>&1 || true
      rm -rf /var/lib/apt/lists/* || true
    fi
  fi
  python3 -m pip install --no-cache-dir --upgrade pip >/dev/null 2>&1 || true
  python3 -m pip install --no-cache-dir flask gunicorn PyYAML >/dev/null 2>&1 \
    || python3 -m pip install --no-cache-dir --break-system-packages flask gunicorn PyYAML >/dev/null 2>&1
fi

# docker CLI optionnel
if [ "$DOCKERCLI" != "off" ] && ! command -v docker >/dev/null 2>&1; then
  log "docker CLI not found; attempting install ..."
  if command -v apk >/dev/null 2>&1; then
    apk add --no-cache docker-cli >/dev/null 2>&1 || true
  elif command -v apt-get >/dev/null 2>&1; then
    apt-get update -y >/dev/null 2>&1 || true
    (apt-get install -y --no-install-recommends docker.io >/dev/null 2>&1 \
      || apt-get install -y --no-install-recommends moby-cli >/dev/null 2>&1) || true
    apt-get clean >/dev/null 2>&1 || true
    rm -rf /var/lib/apt/lists/* || true
  fi
fi

# gunicorn_config.py
cat >/gunicorn_config.py <<EOF
import os
bind         = f"{os.getenv('API_BIND','${API_BIND}')}:{int(os.getenv('API_PORT','${API_PORT}'))}"
workers      = int(os.getenv('API_WORKERS','${API_WORKERS}'))
threads      = int(os.getenv('API_THREADS','${API_THREADS}'))
worker_class = "gthread"
timeout      = int(os.getenv('API_TIMEOUT','${API_TIMEOUT}'))
keepalive    = int(os.getenv('API_KEEPALIVE','${API_KEEPALIVE}'))
accesslog    = "-"
errorlog     = "-"
loglevel     = "${API_LOGLEVEL}"
forwarded_allow_ips = "*"
EOF

# Sanity
if [ ! -f /app/borgmatic_api.py ]; then
  echo "[FATAL] /app/borgmatic_api.py introuvable"; sleep 2; exit 1
fi

log "Starting gunicorn on ${API_BIND}:${API_PORT} ..."
cd /app
exec python3 -m gunicorn --config /gunicorn_config.py borgmatic_api:app
