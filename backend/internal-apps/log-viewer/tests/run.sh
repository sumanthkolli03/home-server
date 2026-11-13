#!/usr/bin/env bash
# The log viewer's checks, inside its own image: no network, read-only, not root.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
docker build -q -t log-viewer:local "$here/.." >/dev/null
docker run --rm --network none --read-only --user 65534:65534 --cap-drop ALL --security-opt no-new-privileges \
  --tmpfs /tmp:size=64m -v "$here:/tests:ro" log-viewer:local python /tests/test_viewer.py
