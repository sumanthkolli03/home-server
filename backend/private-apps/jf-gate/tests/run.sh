#!/usr/bin/env bash
# =============================================================================
#  Build jf-gate and run its test suite inside the real image, locked down like
#  the running container: no network, read-only root, non-root, no capabilities.
#
#    bash backend/private-apps/jf-gate/tests/run.sh          # want: "128/128 checks passed"
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")/.."
docker build -q -t jf-gate:local . >/dev/null
docker run --rm --network none --read-only --tmpfs /tmp:size=16m,mode=1777 \
    --user "${PUID:-1000}:${PGID:-1000}" --cap-drop ALL --security-opt no-new-privileges:true \
    -v "$PWD/tests:/tests:ro" jf-gate:local python -I /tests/test_gate.py
