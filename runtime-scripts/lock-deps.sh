#!/usr/bin/env bash
# =============================================================================
#  lock-deps.sh — resolve the newest Python packages and pin them by hash
#
#  For every folder under backend/ with a requirements.in (an app's direct
#  dependencies): resolves the newest compatible versions of everything,
#  transitive dependencies included, and writes requirements.txt next to it with
#  exact versions and SHA-256 hashes. Dockerfiles that install with
#  --require-hashes --only-binary=:all: then get exactly what was locked,
#  verified, with no code run at install time.
#
#    bash runtime-scripts/lock-deps.sh            every app
#    bash runtime-scripts/lock-deps.sh cdn        only folders whose path contains "cdn"
#  Then rebuild the apps: docker compose up -d --build <containers>
#  requirements.txt is tracked: it is the record of what is running.
# =============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
while [ ! -f "$ROOT/docker-compose.yml" ] && [ "$ROOT" != / ]; do ROOT="$(dirname "$ROOT")"; done
[ -f "$ROOT/docker-compose.yml" ] || { echo "can't find the project folder" >&2; exit 1; }
PY_IMAGE="python:3.14-slim-trixie"      # must match the apps' FROM lines

mapfile -t dirs < <(find "$ROOT/backend" -name requirements.in -not -path '*/node_modules/*' -printf '%h\n' | sort | grep -F -- "${1:-}" || true)
[ "${#dirs[@]}" -gt 0 ] || { echo "no requirements.in under backend/${1:+ matching $1}"; exit 0; }
docker pull -q "$PY_IMAGE" >/dev/null

for dir in "${dirs[@]}"; do
    echo "== ${dir#"$ROOT"/}"
    docker run --rm \
        -e HOST_UID="$(id -u)" -e HOST_GID="$(id -g)" \
        -v "$dir:/w" -w /w "$PY_IMAGE" sh -c '
            set -e
            pip install --quiet --disable-pip-version-check --root-user-action=ignore uv
            uv pip compile requirements.in --generate-hashes --quiet -o requirements.txt
            chown "$HOST_UID:$HOST_GID" requirements.txt'
    grep -E '^[A-Za-z0-9_.-]+==' "$dir/requirements.txt" | sed 's/ .*//; s/^/   /'
done
