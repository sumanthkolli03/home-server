#!/usr/bin/env bash
# First run on a new Linux host, after cloning and filling in .env, the secrets (each has a
# .example next to it) and the WireGuard configs:
#   bash bootstrap.sh
# Sets file modes (secrets 600, scripts executable) and creates every folder the containers
# mount, so they belong to you rather than to Docker, which would create them as root.
set -euo pipefail
cd "$(dirname "$0")"
[ -f .env ] || { echo "copy .env.example to .env and fill it in first"; exit 1; }

chmod 600 .env
find backend \( -path '*/secrets/*' ! -name '*.example' -o -name 'wg*.conf' -o -name 'users_database.yml' -o -name 'users.toml' \) \
     -type f -exec chmod 600 {} +
find . \( -path ./logs -o -path ./internal-config -o -path ./shared-files \) -prune -o -name '*.sh' -type f -exec chmod +x {} +

mkdir -p logs/authelia logs/docker logs/metrics logs/security \
         logs/caddy/caddy-public logs/caddy/caddy-private logs/caddy/caddy-internal \
         logs/private-apps/jellyfin/app logs/private-apps/jellyfin/ffmpeg \
         logs/private-apps/jf-gate/app logs/private-apps/copyparty/app \
         logs/internal-apps/log-viewer/access logs/internal-apps/log-viewer/app logs/internal-apps/log-collector/app \
         internal-config/authelia internal-config/caddy/caddy-public internal-config/caddy/caddy-private \
         internal-config/private-apps/jellyfin internal-config/private-apps/copyparty \
         shared-files/media backend/public-apps generated/caddy-public

# Until the generator has added a public app, compose still needs the file .env's COMPOSE_FILE names.
[ -f generated/docker-compose.apps.yml ] || printf 'services: {}\n' > generated/docker-compose.apps.yml

docker compose config -q && echo "ready: docker compose up -d   (public apps: see the generator's README)"
