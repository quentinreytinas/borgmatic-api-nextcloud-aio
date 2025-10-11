#!/bin/sh
set -eu

log(){ printf "[%s] %s\n" "$(date +'%F %T')" "$*"; }
err(){ log "ERROR: $*" >&2; exit 1; }

log "== Borgmatic AIO API startup =="
umask 077

# Configuration par variables d'environnement
: "${API_BIND:=0.0.0.0}"
: "${API_PORT:=5000}"
: "${API_WORKERS:=2}"
: "${API_THREADS:=4}"
: "${API_TIMEOUT:=300}"
: "${API_KEEPALIVE:=75}"
: "${API_LOGLEVEL:=info}"
: "${BORGMATIC_CONFIG_DIR:=/etc/borgmatic.d}"
: "${BORG_SSH_DIR:=/root/.ssh}"

# Validation des variables critiques
[ -z "${API_TOKEN:-}" ]       && err "API_TOKEN is required"
[ -z "${APP_FROM_HEADER:-}" ] && err "APP_FROM_HEADER is required"
[ -f /app/borgmatic_api.py ]  || err "/app/borgmatic_api.py not found"

# Vérification des dépendances
if ! python3 - 2>/dev/null <<'PYCHK'; then
import flask, gunicorn, yaml
PYCHK
    err "Missing Python dependencies. Build image properly!"
fi

command -v borgmatic >/dev/null 2>&1 || err "borgmatic not found in PATH"
if ! command -v docker >/dev/null 2>&1; then
  log "WARNING: docker CLI not found. Some endpoints may fail."
fi

# Préparation des répertoires
mkdir -p "$BORGMATIC_CONFIG_DIR" "$BORG_SSH_DIR"
chmod 700 "$BORG_SSH_DIR"

# Génération du fichier de configuration Gunicorn (docstrings internes remplacés par commentaires)
python3 - <<'PYGEN'
from pathlib import Path
from textwrap import dedent

CONFIG = dedent("""\
import os
import json
import time
import urllib.request
import logging

bind         = f"{os.getenv('API_BIND')}:{int(os.getenv('API_PORT'))}"
workers      = int(os.getenv('API_WORKERS'))
threads      = int(os.getenv('API_THREADS'))
worker_class = "gthread"
timeout      = int(os.getenv('API_TIMEOUT'))
keepalive    = int(os.getenv('API_KEEPALIVE'))
accesslog    = "-"
errorlog     = "-"
loglevel     = os.getenv('API_LOGLEVEL')
forwarded_allow_ips = "*"

def when_ready(server):
    # Trigger a webhook once the API becomes ready.
    webhook_url = os.getenv('APP_READY_WEBHOOK_URL', '').strip()
    if not webhook_url:
        return
    time.sleep(3)
    try:
        req = urllib.request.Request(
            webhook_url,
            data=json.dumps({
                "status": "ready",
                "timestamp": time.time(),
                "workers": workers,
                "service": "borgmatic-api"
            }).encode(),
            headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            server.log.info(f"[ready] Webhook triggered: {webhook_url} (status: {resp.status})")
    except Exception as e:
        server.log.warning(f"[ready] Webhook failed {webhook_url}: {e}")

def on_exit(server):
    # Log a message when the Gunicorn server shuts down.
    logging.info("Gunicorn shutdown complete")
""")

Path("/gunicorn_config.py").write_text(CONFIG)
PYGEN

# Validation du fichier de config généré
if ! python3 - 2>/dev/null <<'PYCHK'; then
import gunicorn_config  # noqa
PYCHK
    err "Generated gunicorn_config.py is invalid"
fi

# Résumé de la configuration
log "Configuration:"
log "  - Bind: ${API_BIND}:${API_PORT}"
log "  - Workers: ${API_WORKERS} x ${API_THREADS} threads"
log "  - Timeout: ${API_TIMEOUT}s"
log "  - Config dir: ${BORGMATIC_CONFIG_DIR}"
log "  - SSH dir: ${BORG_SSH_DIR}"
log "  - Ready webhook: ${APP_READY_WEBHOOK_URL:-none}"

# Démarrage de Gunicorn
log "Starting Gunicorn..."
cd /app
exec python3 -m gunicorn --config /gunicorn_config.py --preload borgmatic_api:app
