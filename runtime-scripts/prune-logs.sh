#!/bin/bash
# Log retention, run by hand (or from cron on a host that stays on). Finds the project folder by itself,
# so it works wherever runtime-scripts lives.
#
# Two tiers:
#   FOREVER, never touched here: what people did. logs/authelia/, every app's logs under
#     logs/{public,private,internal}-apps/ (access, app, egress) except Jellyfin's, every access log,
#     logs/security/ALERTS.log, and anything not listed below.
#   PRUNED: how the machine was doing. 90 days: metrics, security snapshots, the viewer's probe
#     results, the collector's events, tunnel logs. 60 days: Jellyfin's text and FFmpeg logs.
#     Caddy deletes its own rolled runtime and handshake logs (roll_keep_for 2160h).
#   The 10 GB cap counts and deletes only the pruned tier.
cd "$(dirname "$0")" || exit 1
until [ -f docker-compose.yml ]; do
  [ "$PWD" = / ] && { echo "can't find the project folder (docker-compose.yml)"; exit 1; }
  cd ..
done

DAYS=90
JF_DAYS=60
CAP=$((10 * 1024 * 1024 * 1024))
ROTATE_AT=20971520

JF=logs/private-apps/jellyfin/app
FF=logs/private-apps/jellyfin/ffmpeg
VIEWER=logs/internal-apps/log-viewer/app
COLLECTOR=logs/internal-apps/log-collector/app
mkdir -p "$FF"

# 1. sweep session logs out of the jellyfin log dir (leaves last 5 min alone)
n=$(find "$JF" -maxdepth 1 -name 'FFmpeg*.log' -mmin +5 | wc -l)
find "$JF" -maxdepth 1 -name 'FFmpeg*.log' -mmin +5 \
     -exec mv {} "$FF/" \; 2>/dev/null
[ "$n" -gt 0 ] && echo "swept $n ffmpeg logs out of $JF"

# 2. collapse previous days into one gzip each
for d in $(find "$FF" -maxdepth 1 -name 'FFmpeg*.log' -mtime +0 \
           -printf '%f\n' | grep -oE '[0-9]{4}-[0-9]{2}-[0-9]{2}' | sort -u); do
  OUT="$FF/ffmpeg-$d.log.gz"
  c=0
  for f in "$FF"/FFmpeg*"$d"*.log; do
    [ -e "$f" ] || continue
    { printf '\n===== %s =====\n' "$(basename "$f")"; cat "$f"; } | gzip -c >> "$OUT"
    rm -f "$f"
    c=$((c+1))
  done
  [ "$c" -gt 0 ] && echo "archived $c logs -> $OUT"
done

# 3. authelia has no rotation: copy-truncate (the copies are kept forever)
A=logs/authelia/authelia.log
if [ -f "$A" ] && [ "$(stat -c%s "$A")" -gt "$ROTATE_AT" ]; then
  cp "$A" "logs/authelia/authelia-$(date +%Y%m%d-%H%M%S).log" && : > "$A"
  echo "rotated authelia.log"
fi

# The pruned tier, every file of it. Extra find tests narrow it further.
pruned() {
  find logs -type f \( -path 'logs/metrics/metrics-*.jsonl' \
                    -o -path 'logs/security/snapshot-*.jsonl' \
                    -o -path "$VIEWER/health-*.jsonl" \
                    -o -path "$COLLECTOR/log-collector-*.jsonl" \
                    -o -path 'logs/docker/*.log' \
                    -o -path "$JF/*" -o -path "$FF/*" \
                    -o \( -path 'logs/caddy/*' -name 'caddy*.log*' \) \) "$@"
}

# 4. age-based cleanup: Jellyfin's after 60 days, the rest after 90 (a monthly file goes 90 days
#    after its last line). Caddy deletes its own rolled files.
pruned -path 'logs/private-apps/jellyfin/*' -mtime +$JF_DAYS -delete
pruned -not -path 'logs/private-apps/jellyfin/*' -not -path 'logs/caddy/*' -mtime +$DAYS -delete

# 5. hard ceiling on the pruned tier: oldest first, but never a file a running container still
#    holds open (Caddy's live caddy.log and caddy-tls.log; today's Jellyfin log is spared by
#    -mtime +1). Deleting an open file loses everything written to it until that container
#    restarts.
total=$(pruned -printf '%s\n' | awk '{s += $1} END {printf "%.0f\n", s}')
while [ "$total" -gt "$CAP" ] && read -r _ size f; do
  rm -f "$f" && echo "capped: removed $f" && total=$((total - size))
done < <(pruned -mtime +1 -not \( -path 'logs/caddy/*' -name '*.log' \) -printf '%T@ %s %p\n' | sort -n)
[ "$total" -gt "$CAP" ] && echo "over the cap, but nothing pruned is old enough to delete"

du -sh logs/* ; echo "---" ; du -sh logs
echo "pruned tier: $((total / 1048576)) MB of $((CAP / 1048576)) MB"