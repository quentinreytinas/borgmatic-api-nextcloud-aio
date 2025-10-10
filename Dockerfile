# Utilise l'image officielle borgmatic comme base
FROM borgmatic/borgmatic:latest

# Métadonnées
LABEL org.opencontainers.image.source="https://github.com/quentinreytinas/borgmatic-api-nextcloud-aio"
LABEL org.opencontainers.image.description="Borgmatic API for Nextcloud AIO with Node-RED integration"
LABEL org.opencontainers.image.licenses="MIT"

# Installer dépendances système
RUN apk add --no-cache \
    python3 \
    py3-pip \
    docker-cli \
    openssh-client \
    fuse3 \
    && rm -rf /var/cache/apk/*

# Installer dépendances Python (versions fixées)
RUN pip3 install --no-cache-dir \
    flask==3.0.0 \
    gunicorn==21.2.0 \
    PyYAML==6.0.1

# Copier l'application
WORKDIR /app
COPY borgmatic_api.py /app/
COPY borgmatic_api_app /app/borgmatic_api_app
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Configuration par défaut
ENV API_WORKERS=2 \
    API_TIMEOUT=300 \
    API_THREADS=4 \
    PYTHONUNBUFFERED=1

# Volumes
VOLUME ["/etc/borgmatic.d", "/root/.ssh", "/var/lib/borg"]

# Healthcheck
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:5000/health', timeout=3)"

EXPOSE 5000
ENTRYPOINT ["/entrypoint.sh"]
