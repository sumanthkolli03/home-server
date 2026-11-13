#!/bin/bash
cd "$(dirname "$0")" || exit 1
until [ -f docker-compose.yml ]; do [ "$PWD" = / ] && exit 1; cd ..; done
case "$1" in
  auth)   tail -f logs/authelia/authelia.log ;;
  files)  tail -f logs/private-apps/copyparty/app/copyparty-*.log ;;
  caddy)  tail -f logs/caddy/caddy-private/access.log ;;
  public) tail -f logs/public-apps/"${2:?usage: logs.sh public APP}"/access/*access.log ;;
  jf)     tail -f "logs/private-apps/jellyfin/app/log_$(date +%Y%m%d).log" ;;
  ffmpeg) f=$(ls -t logs/private-apps/jellyfin/ffmpeg/FFmpeg*.log logs/private-apps/jellyfin/app/FFmpeg*.log 2>/dev/null | head -1)
          [ -n "$f" ] && tail -f "$f" || echo "no uncompressed ffmpeg logs present" ;;
  wg)     tail -f logs/docker/*wg-*.log ;;
  fails)  grep -E 'Unsuccessful [^ ]+ authentication attempt' logs/authelia/authelia.log | tail -30 ;;
  ffarchive) zcat logs/private-apps/jellyfin/ffmpeg/ffmpeg-*.log.gz 2>/dev/null | less ;;
  ffgrep) shift; zgrep -h "$@" logs/private-apps/jellyfin/ffmpeg/*.log.gz 2>/dev/null ;;
  dump)   for c in $(docker ps --format '{{.Names}}'); do
            docker logs --tail 200 "$c" > "logs/docker/snapshot-$c.log" 2>&1
          done; echo "snapshots written to logs/docker/" ;;
  *) echo "usage: logs.sh {auth|files|caddy|public APP|jf|ffmpeg|wg|fails|ffarchive|ffgrep|dump}" ;;
esac