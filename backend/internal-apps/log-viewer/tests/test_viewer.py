"""Checks for the log viewer and the collector. tests/run.sh runs them inside the image: no network,
read-only, not root. Fixtures follow the real formats and use documentation addresses
(192.0.2.x, 198.51.100.x, 203.0.113.x) and example.net names."""
import gzip
import json
import os
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from http.server import ThreadingHTTPServer
from pathlib import Path

os.environ["TZ"] = "Etc/GMT+7"        # UTC-7 all year: the fixtures are written at -07:00
TMP = Path(tempfile.mkdtemp())
LOGS, APP = TMP / "logs", TMP / "app"
os.environ.update(LOGS_DIR=str(LOGS), APP_LOG_DIR=str(APP))
APP.mkdir()
here = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(here if (here / "main.py").exists() else Path("/app")))

import collect  # noqa: E402
import health   # noqa: E402
import helper   # noqa: E402
import main     # noqa: E402

PASSED, FAILED = 0, []


def check(name, ok):
    global PASSED
    if ok:
        PASSED += 1
    else:
        FAILED.append(name)
        print("FAIL", name)


def put(rel, lines, gz=False):
    p = LOGS / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    data = "".join(line + "\n" for line in lines)
    p.write_bytes(gzip.compress(data.encode())) if gz else p.write_text(data)


TZ = helper.TZ
NOW = time.time()
DAY = datetime.now(TZ).replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(hours=12)   # yesterday noon
t = lambda m: (DAY + timedelta(minutes=m)).timestamp()
z = lambda ts: datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
D8, MONTH = DAY.strftime("%Y%m%d"), DAY.strftime("%Y-%m")
RANGE = {"from": DAY.date().isoformat(), "to": DAY.date().isoformat()}
TOKEN = "0123456789abcdef01234567"
(APP / "state.json").write_text(json.dumps({"probe_token": TOKEN}))
EVIL = "<script>alert(1)</script>"


def caddy(m, ip, host, uri, status=200, size=1000):
    return json.dumps({"level": "info", "ts": t(m), "logger": "http.log.access.log0", "msg": "handled request",
                       "request": {"remote_ip": ip, "client_ip": ip, "method": "GET", "host": host, "uri": uri,
                                   "headers": {"User-Agent": ["Mozilla/5.0"]}}, "duration": 0.01, "size": size, "status": status})


def jf(m, level, src, msg):
    return f"[{(DAY + timedelta(minutes=m)).strftime('%Y-%m-%d %H:%M:%S')}.117 -07:00] [{level}] [40] {src}: {msg}"


# ---------------------------------------------------------------- fixtures
put("public-apps/cdn/access/access.log", [
    caddy(0, "198.51.100.20", "cdn.example.net", "/abc123defg.mp4?q=QUERYSTRING"),
    caddy(1, "198.51.100.20", "cdn.example.net", "/abc123defg.mp4", 206, 5000),
    caddy(2, "198.51.100.20", "cdn.example.net", "/zzz.png", 404, 10),
    caddy(20, "198.51.100.20", "cdn.example.net", "/later.png"),
    caddy(3, "203.0.113.7", "cdn.example.net", f"/?lvprobe={TOKEN}"),
    caddy(4, "203.0.113.7", "cdn.example.net", "/?lvprobe=someoneelse")])
put("public-apps/cdn/access/fix-access.log", [caddy(6, "198.51.100.50", "fix.example.net", "/abc123defg.mp4")])
put("public-apps/skull-viewer/access/access.log", [caddy(5, "198.51.100.30", "skulls.example.net", "/"),
    *(caddy(31 + i / 10, "198.51.100.40", "skulls.example.net", u, 404) for i, u in enumerate(("/", "/robots.txt", "/sitemap.xml")))])
secret = json.loads(caddy(10.5, "203.0.113.8", "media.example.net", "/jellyfin/socket?api_key=SECRETKEY123&deviceId=dev1"))
secret["request"]["headers"]["X-Emby-Token"] = ["SECRETTOKEN"]
secret["request"]["headers"]["Authorization"] = ["REDACTED"]
put("internal-apps/big/app/big.jsonl", [json.dumps({"ts": z(t(50)), "event": "huge", "blob": "x" * 70000})])
put("caddy/caddy-public/caddy.log", [
    json.dumps({"level": "info", "ts": t(-60), "logger": "http", "msg": "enabling automatic TLS certificate management",
                "domains": ["cdn.example.net", "fix.example.net", "skulls.example.net", "*.bad"]}),
    json.dumps({"level": "info", "ts": t(6), "logger": "http.log.access", "msg": "handled request",
                "request": {"remote_ip": "192.0.2.66", "host": "192.0.2.1", "uri": "/.env"}, "status": 308}),
    json.dumps({"level": "info", "ts": t(7), "logger": "http.log.access", "msg": "handled request",
                "request": {"remote_ip": "192.0.2.66", "host": "192.0.2.1", "uri": "/wp-login.php"}, "status": 308}),
    json.dumps({"level": "error", "ts": t(8), "logger": "http.handlers.reverse_proxy", "msg": "dial tcp: connection refused"})])
put("caddy/caddy-public/caddy-tls.log", [
    json.dumps({"level": "debug", "ts": t(9), "logger": "tls.handshake", "msg": "choosing certificate", "identifier": "cdn.example.net"}),
    json.dumps({"level": "error", "ts": t(9), "logger": "http.stdlib", "msg": "http: TLS handshake error from 192.0.2.99:55555: no certificate available for '192.0.2.1'"})])
put("caddy/caddy-private/caddy.log", [json.dumps({"level": "info", "ts": t(-60), "msg": "enabling automatic TLS certificate management",
                                                "domains": ["media.example.net", "auth.example.net"]})])
put("caddy/caddy-private/access.log", [caddy(10, "203.0.113.8", "media.example.net", "/jellyfin/Videos/x/stream", 401),
                                     json.dumps(secret), caddy(11, "203.0.113.8", "media.example.net", "/files/")])
put("public-apps/cdn/app/api/audit.jsonl", [
    json.dumps({"ts": z(t(0)), "event": "login_ok", "ip": "198.51.100.20", "ua": "x", "user": "alice", "role": "uploader"}),
    json.dumps({"ts": z(t(1)), "event": "login_fail", "ip": "198.51.100.21", "ua": "x", "user": EVIL, "reason": "bad", "locked": False})])
put("public-apps/cdn/app/api/uploads.jsonl", [json.dumps({"ts": z(t(2)), "event": "upload_ok", "ip": "198.51.100.20", "user": "alice", "id": "abc123defg", "size": 5})])
put("public-apps/cdn/app/worker/jobs.jsonl", [json.dumps({"ts": z(t(3)), "event": "done", "name": "abc123defg.mp4", "action": "copy"})])
put(f"private-apps/jf-gate/app/gate-{MONTH}.jsonl", [
    *(json.dumps({"ts": z(t(i)), "event": "auth", "user": "carol", "admin": False, "ip": "203.0.113.8", "tok": "abcdef0123"}) for i in (0, 1, 2)),
    json.dumps({"ts": z(t(3)), "event": "deny", "reason": "no_token", "ip": "192.0.2.50", "path": "/jellyfin/Items"})])
put("authelia/authelia.log", [
    f'time="{(DAY + timedelta(minutes=12)).isoformat()}" level=error msg="Unsuccessful 1FA authentication attempt by user \'dave\'" method=POST path=/api/firstfactor remote_ip=192.0.2.77',
    f'time="{(DAY + timedelta(minutes=13)).isoformat()}" level=error msg="Unsuccessful 1FA authentication attempt by user \'dave\' and they are banned until 2026-10-28 12:30:00 -0700 MST" remote_ip=192.0.2.77',
    f'time="{(DAY + timedelta(minutes=14)).isoformat()}" level=error msg="Error occurred getting details for user with username input \'nobody\'" remote_ip=192.0.2.78',
    f'time="{(DAY + timedelta(minutes=15)).isoformat()}" level=info msg="Startup complete"',
    f'time="{(DAY + timedelta(minutes=15, seconds=1)).isoformat()}" level=error msg="Error occurred running a startup check" error="the system clock is not synchronized accurately enough with the configured NTP server" provider=ntp',
    f'time="{(DAY + timedelta(minutes=15, seconds=2)).isoformat()}" level=fatal msg="One or more providers had fatal failures performing startup checks, for more details check the error level logs" providers="[ntp]" stack="github.com/authelia/authelia/v4/internal/commands/root.go:93 (*CmdCtx).RootRunE\\nruntime/asm_amd64.s:1771 goexit"'])
hm = lambda m: (DAY + timedelta(minutes=m)).strftime("%H:%M:%S")
put(f"private-apps/copyparty/app/copyparty-{DAY.strftime('%Y-%m%d')}.log", [
    f"{hm(16)}.100 203.0.113.9 51234 K1: GET /files/doc.pdf @bob",
    f"{hm(16)}.200 203.0.113.9 51234 K1: PUT /files/up.bin @bob",
    f"{hm(16)}.300 203.0.113.9 51234 K1: wrote 2048/2048 bytes to '/w/storage/up.bin'",
    f"{hm(17)}.000 203.0.113.9 51235 K2: no more chunks, setting times (1, 2) (4096) on '/w/storage/big.bin'",
    f"{hm(17)}.500 192.0.2.80 51236 K3: http403: no access to /files/cdn",
    f"{hm(17)}.600 192.0.2.80 51236 K3: something routine"])
put(f"private-apps/jellyfin/app/log_{D8}.log", [
    jf(20, "INF", "Jellyfin.Server.Implementations.Users.UserManager", 'Authentication request for "carol" has succeeded.'),
    jf(20, "INF", "Emby.Server.Implementations.Session.SessionManager", 'Current/Max sessions for user "carol": 0/0'),
    jf(21, "INF", "Emby.Server.Implementations.HttpServer.WebSocketManager", 'WS "::ffff:203.0.113.8" request'),
    jf(21, "WRN", "Jellyfin.Networking.Manager.NetworkManager", '"203.0.113.8": Only loopback "::1" returned, using that as bind address.'),
    jf(22, "INF", "Jellyfin.Api.Helpers.MediaInfoHelper", 'User policy for "carol". EnablePlaybackRemuxing: True EnableVideoPlaybackTranscoding: True'),
    jf(23, "INF", "Emby.Server.Implementations.Session.SessionManager", 'Playback stopped reported by app "Jellyfin Web" "10.11.11" playing "Pilot". Stopped at "419401" ms'),
    jf(24, "INF", "Jellyfin.Server.Implementations.Users.UserManager", 'Authentication request for "eve" has been denied (IP: "192.0.2.90").'),
    jf(25, "ERR", "MediaBrowser.Providers.Manager.ProviderManager", 'Error in "TheMovieDb" for "Item 1"'),
    "System.Net.Http.HttpRequestException: timed out",
    "   at Something.Do()",
    jf(26, "ERR", "MediaBrowser.Providers.Manager.ProviderManager", 'Error in "TheMovieDb" for "Item 2"'),
    jf(27, "ERR", "MediaBrowser.Providers.Manager.ProviderManager", 'Error in "TheMovieDb" for "Item 3"'),
    jf(28, "INF", "Emby.Server.Implementations.ScheduledTasks.TaskManager", '"Optimize database" Completed after 0 minute(s) and 2 seconds')])
FF_INFO = json.dumps({"Protocol": 0, "Path": "/data/media/Movies/Example (2025)/Example (2025).mkv", "RunTimeTicks": 82525360000,
                      "MediaStreams": [{"Codec": "hevc", "Type": 1, "Width": 3840, "Height": 2160}, {"Codec": "eac3", "Type": 0, "Channels": 6}]})
FF_CMD = '/usr/lib/jellyfin-ffmpeg/ffmpeg -analyzeduration 200M -i file:"/data/media/x.mkv" -map 0:0 -codec:v:0 libx264 -preset veryfast -codec:a:0 aac -f hls x.m3u8'
ff_name = f"FFmpeg.Transcode-{DAY.strftime('%Y-%m-%d')}_12-30-00_8abaf076_90e3994b.log"
session = [FF_INFO, "", FF_CMD, "", "", "ffmpeg version 7.1.4-Jellyfin", "  Duration: 02:17:32.54, start: 0.000000",
           "frame=  100 fps= 50 time=00:00:04.00 speed=1.99x\rframe=  200 fps= 52 time=00:00:08.00 speed=2.07x",
           "[q] command received. Exiting.", "[libx264 @ 0x5] kb/s:4444.60"]
put(f"private-apps/jellyfin/app/{ff_name}", session)
put(f"private-apps/jellyfin/ffmpeg/ffmpeg-{DAY.strftime('%Y-%m-%d')}.log.gz",
    [f"===== {ff_name.replace('12-30-00', '13-00-00')} =====", *session[:5], "Conversion failed!",
     f"===== {ff_name.replace('12-30-00', '13-30-00')} =====", *session], gz=True)
put("docker/wg-private.log", [f"{(DAY + timedelta(minutes=29)).isoformat()}    Brought to you by linuxserver.io",
                            f"{(DAY + timedelta(minutes=29)).isoformat()} [#] ip link add wg0 type wireguard",
                            f"{(DAY + timedelta(minutes=30)).isoformat()} **** All tunnels are now active ****"])
put("security/ALERTS.log", [f"{z(t(m))} wg-private  KILLSWITCH_HIT: pkts=3 bytes=180" for m in (30, 35, 40)]
    + [f"{z(t(45))} wg-public    IP_FORWARD: 1 (want 0)"])

# Health: relative to now
snap = lambda ago, pkts, hs, extra=(), rs=0: json.dumps({"v": 1, "ts": z(NOW - ago * 60), "tunnels": [
    {"container": "wg-public", "running": True, "ks_rules": 1, "ks_pkts": 0, "ks_bytes": 0, "forward_policy": "DROP",
     "ip_forward": 0, "handshake": int(NOW - 900), "rx": 5000, "tx": 7000},
    {"container": "wg-private", "running": True, "ks_rules": 1, "ks_pkts": pkts, "ks_bytes": pkts * 60, "forward_policy": "DROP",
     "ip_forward": 0, "handshake": hs, "rx": 1, "tx": 2}],
    "containers": [{"name": n, "status": "running", "health": h, "started": z(NOW - 7200), "restarts": rs if n == "jellyfin" else 0,
                    "image": "img", "image_id": "sha256:0123456789ab"}
                   for n, h in (("cdn-api", "unhealthy"), ("jellyfin", None), ("skull-viewer", "healthy"), ("wg-private", None), *extra)]})
put(f"security/snapshot-{time.strftime('%Y-%m', time.gmtime())}.jsonl",
    [snap(20, 0, int(NOW - 60), (("old-thing", None),)), snap(15, 3, int(NOW - 60), rs=4), snap(10, 0, int(NOW - 60), rs=12), snap(5, 0, int(NOW - 60), rs=31)])
put(f"metrics/metrics-{time.strftime('%Y-%m', time.gmtime())}.jsonl", [
    *(json.dumps({"ts": z(NOW - m * 60), "event": "stats", "containers": {"cdn-api": {"cpu": 2.5 + m, "mem": 50_000_000},
                                                                        "jellyfin": {"cpu": 30.0, "mem": 900_000_000}}}) for m in range(12, 0, -1)),
    json.dumps({"ts": z(NOW - 600), "event": "sizes", "disk": {"total": 10 ** 12, "free": 10 ** 10}, "sizes": {
        "backend/public-apps/cdn": 1000, "backend/public-apps/skull-viewer": 29_000_000, "backend/unclaimed/thing": 7,
        "internal-config/private-apps/jellyfin": 5000, "logs/private-apps/jellyfin": 7000, "logs/private-apps/jf-gate": 300,
        "shared-files/media/Movies": 9 * 10 ** 9, "shared-files/cdn/cdn-fix": 4000, "logs/docker/.": 50, "logs/security": 20}})])
probes = []
for i in range(40, 0, -1):
    ts = NOW - i * 300 + 240
    probes.append({"ts": z(ts), "event": "probe", "host": "cdn.example.net", "ip": "198.51.100.1", "code": 404 if i <= 2 else 200, "ms": 180, "ok": True, "cert_days": 60})
    probes.append({"ts": z(ts), "event": "probe", "host": "fix.example.net", "ip": "198.51.100.1", "code": 404, "ms": 170, "ok": True, "cert_days": 5})
    probes.append({"ts": z(ts), "event": "probe", "host": "skulls.example.net", "ip": "198.51.100.1", "ok": i > 1, "code": None if i == 1 else 200,
                   "error": "TimeoutError: timed out" if i == 1 else None, "ms": 150})
put(f"internal-apps/log-viewer/app/health-{time.strftime('%Y-%m', time.gmtime())}.jsonl", [json.dumps(p) for p in probes])

# ---------------------------------------------------------------- converters and queries
day0, day1 = t(-720), t(720)
ctx = {"token": TOKEN}
q = lambda stacks=None, **kw: helper.query(day0, day1, stacks, ctx=ctx, **kw)[0]
pub, priv = q({"public"}), q({"private"})
visits = [r for r in pub if r["app"] == "cdn" and r["event"] == "visit"]
check("cdn requests fold into visits: 3 within 5 min, 1 later, 1 with a foreign probe mark", sorted(r["detail"]["requests"] for r in visits) == [1, 1, 3])
v3 = next(r for r in visits if r["detail"]["requests"] == 3)
check("visit counts statuses, bytes, first/last path", v3["detail"]["status"] == {"200": 1, "206": 1, "404": 1} and v3["detail"]["bytes"] == 6010
      and v3["detail"]["first"] == "/abc123defg.mp4" and v3["detail"]["last"] == "/zzz.png")
check("query strings never reach a record", "QUERYSTRING" not in json.dumps(pub))
check("a public app's access log is that app", any(r["app"] == "skull-viewer" for r in pub))
check("a second site's log is <app>-<site>", any(r["app"] == "cdn-fix" for r in pub))
check("our probe is hidden by default", not any(r["event"] == "probe" for r in pub))
check("probes toggle shows it", any(r["event"] == "probe" for r in q({"public"}, show={"probe"})))
check("scanners hidden by default", not any(r["event"] == "scanner" for r in pub))
scan = [r for r in q({"public"}, show={"scanner"}) if r["event"] == "scanner"]
check("bare-IP requests fold into one scanner visit", any(r["ip"] == "192.0.2.66" and r["detail"].get("requests") == 2 for r in scan))
check("a TLS handshake error is a scanner record with its IP", any(r["ip"] == "192.0.2.99" for r in scan))
check("ordinary handshakes are Details only", not any("choosing" in json.dumps(r) for r in q(show={"scanner"}))
      and any(r["detail"].get("msg") == "choosing certificate" for r in q(details=True)))
check("caddy runtime errors show", any(r["app"] == "caddy-public" and r["event"] == "error" for r in pub))
check("CDN audit login_ok has user and ip", any(r["event"] == "login_ok" and r["user"] == "alice" and r["ip"] == "198.51.100.20" for r in pub))
check("worker jobs show on Public", any(r["app"] == "cdn-worker" and r["event"] == "done" for r in pub))
check("public stays public", all(r["stack"] == "public" for r in pub) and not any(r["app"] in ("jellyfin", "copyparty", "private") for r in pub))
check("media access splits by path", {"jellyfin", "copyparty"} <= {r["app"] for r in priv if r["event"] == "visit"})
check("gate auth folds (3 -> 1, count 3)", [r["detail"].get("count") for r in priv if r["event"] == "auth"] == [3])
check("gate deny shows", any(r["event"] == "deny" and r["ip"] == "192.0.2.50" for r in priv))
check("authelia failure: user + ip", any(r["event"] == "login_fail" and r["user"] == "dave" and r["ip"] == "192.0.2.77" for r in priv))
check("authelia ban", any(r["event"] == "login_banned" and "banned until" in r["detail"]["msg"] for r in priv))
check("authelia unknown user", any(r["event"] == "unknown_user" and r["user"] == "nobody" for r in priv))
check("authelia info lines only on Details", not any(r["app"] == "authelia" and r["event"] == "info" for r in priv))
au = {r["event"]: r for r in priv if r["app"] == "authelia"}
check("authelia failures keep every field", any(r["event"] == "login_fail" and r["detail"] == {"level": "error", "msg": "Unsuccessful 1FA authentication attempt by user 'dave'",
      "method": "POST", "path": "/api/firstfactor"} for r in priv))
check("authelia keeps every field", au["error"]["detail"].get("provider") == "ntp" and "not synchronized" in au["error"]["detail"].get("error", "")
      and au["fatal"]["detail"].get("providers") == "[ntp]" and "\n" in au["fatal"]["detail"].get("stack", ""))
check("summary shows providers, not the stack", "providers=[ntp]" in helper.summary(au["fatal"]) and "stack" not in helper.summary(au["fatal"]))
cp = [r for r in priv if r["app"] == "copyparty"]
check("copyparty visit with its user and local time", any(r["event"] == "visit" and r["user"] == "bob" and r["detail"]["requests"] == 2
                                                          and abs(r["ts"] - t(16) - 0.2) < 0.01 for r in cp))
check("copyparty uploads credited to the connection's user", [(r["user"], r["detail"]["msg"][:5]) for r in sorted(cp, key=lambda r: r["ts"]) if r["event"] == "upload"]
      == [("bob", "wrote"), (None, "no mo")])
check("copyparty refusal", any(r["event"] == "denied" and r["detail"] == {"port": "51236", "tag": "K3", "msg": "http403: no access to /files/cdn"} for r in cp))
check("copyparty routine lines only on Details", not any(r["event"] == "line" for r in cp))
jfr = [r for r in priv if r["app"] == "jellyfin" and r["event"] != "visit"]
ev = {r["event"] for r in jfr}
check("jellyfin named events", {"login_ok", "session", "play_request", "play_stop", "login_fail"} <= ev)
check("jellyfin denied sign-in carries the IP", any(r["event"] == "login_fail" and r["user"] == "eve" and r["ip"] == "192.0.2.90" for r in jfr))
check("jellyfin lines keep level, thread, source and message", any(r["event"] == "play_stop" and r["detail"] == {"level": "INF", "thread": "40",
      "source": "Emby.Server.Implementations.Session.SessionManager", "msg": 'Playback stopped reported by app "Jellyfin Web" "10.11.11" playing "Pilot". Stopped at "419401" ms'} for r in jfr))
errs = [r for r in jfr if r["event"] == "error"]
check("jellyfin errors of one shape fold (3 -> 1)", len(errs) == 1 and errs[0]["detail"].get("count") == 3)
check("exception lines join their record", "HttpRequestException" in errs[0]["detail"].get("exception", ""))
check("'Only loopback' warning is demoted", not any(r["event"] == "warn" for r in jfr))
check("jellyfin info and WS lines only on Details", "info" not in ev and "ws_open" not in ev)
check("ffmpeg hidden by default", "ffmpeg" not in ev)
ff = sorted((r for r in q({"private"}, show={"ffmpeg"}) if r["event"] == "ffmpeg"), key=lambda r: r["ts"])
check("three ffmpeg sessions (one live file, two archived)", len(ff) == 3)
check("ffmpeg session summary", ff and ff[0]["detail"] == {"kind": "transcode", "file": "Example (2025).mkv", "input": "hevc 3840x2160 / eac3",
                                                            "output": "libx264 / aac", "length": "2:17:32", "speed": "2.07x", "ended": "stopped",
                                                            "last": "[libx264 @ 0x5] kb/s:4444.60", "session": ff_name, "command": FF_CMD})
check("ffmpeg failure noticed", any(r["detail"]["ended"] == "failed" for r in ff))
check("ffmpeg start time from the file name (local)", ff and ff[0]["ts"] == t(30))
wgr = [r for r in priv if r["app"] == "wg-private" and not r["event"].isupper()]   # not its ALERTS lines
check("tunnel status lines show, banner and commands don't", [r["event"] for r in wgr] == ["tunnel_up"])
al = [r for r in q(None) if r["event"] == "KILLSWITCH_HIT"]
check("repeated alerts fold (3 -> 1)", len(al) == 1 and al[0]["detail"]["count"] == 3 and al[0]["stack"] == "private")
check("an alert for wg-public is public", any(r["event"] == "IP_FORWARD" and r["stack"] == "public" for r in q(None)))
det = q(None, picks={"app": ["jellyfin"]}, details=True)
check("Details shows jellyfin info lines", any(r["event"] == "info" for r in det))
check("a pick is exact", {r["user"] for r in q(None, picks={"user": ["carol"]}, details=True)} == {"carol"}
      and {r["app"] for r in q({"public"}, picks={"app": ["cdn"]})} == {"cdn"})
check("several picks in one box: any of them", {r["app"] for r in q({"public"}, picks={"app": ["cdn", "cdn-api"]})} == {"cdn", "cdn-api"})
check("picks in two boxes: both", {(r["user"], r["app"]) for r in q({"public"}, picks={"user": ["alice"], "app": ["cdn-api"]})} == {("alice", "cdn-api")})
seen = helper.query(day0, day1, {"public"}, picks={"user": ["alice"]}, ctx=ctx)[2]
check("the lists follow the other picks", set(seen["ip"]) == {"198.51.100.20"} and {"alice", EVIL} <= set(seen["user"]) and "cdn-worker" not in seen["app"])
rob = q({"public"}, text="robots")
check("q finds robots.txt inside a longer visit", [(r["ip"], r["detail"]["first"], r["detail"]["requests"]) for r in rob] == [("198.51.100.40", "/robots.txt", 1)])
check("q finds fatal lines", any(r["app"] == "authelia" and r["event"] == "fatal" for r in q(None, text="FATAL")))
check("q looks through every field", q({"private"}, text="pilot") and all("pilot" in helper.searchable(r) for r in q({"private"}, text="pilot")))
check("q ignores the time", not q(None, text=z(t(0))[:13], details=True))
raw = [r for r in q(None, details=True) if r["app"] == "cdn" and r["event"] == "visit"]
check("Details: one record per request, the whole line", len(raw) == 5 and all({"level", "logger", "msg", "request", "duration", "size", "status"} <= set(r["detail"]) for r in raw)
      and any("QUERYSTRING" in r["detail"]["request"]["uri"] for r in raw))
sec = next(r for r in q(None, details=True) if "socket" in json.dumps(r["detail"]))
check("secrets are masked: query parameter, token header, Authorization", sec["detail"]["request"]["uri"] == "/jellyfin/socket?api_key=REDACTED&deviceId=dev1"
      and sec["detail"]["request"]["headers"]["X-Emby-Token"] == "REDACTED" and "SECRET" not in json.dumps(sec))
check("mask leaves other things alone", helper.mask({"tok": "abcdef0123", "uri": "/x?lvprobe=1&pw=hunter2", "n": 5, "l": ["/y?token=z"]})
      == {"tok": "abcdef0123", "uri": "/x?lvprobe=1&pw=REDACTED", "n": 5, "l": ["/y?token=REDACTED"]})
recs, more, _ = helper.query(day0, day1, {"public"}, ctx=ctx, limit=2)
check("limit and 'more'", len(recs) == 2 and more)
check("newest first", recs[0]["ts"] >= recs[1]["ts"])
check("parse_ts: Z, offset, nanoseconds, epoch, junk", helper.parse_ts("2026-10-28T19:04:05Z") == 1793214245.0
      and helper.parse_ts("2026-10-28T12:04:05-07:00") == 1793214245.0 and abs(helper.parse_ts("2026-10-28T19:04:05.123456789Z") - 1793214245.123456) < 1e-6
      and helper.parse_ts(5) == 5.0 and helper.parse_ts("nope") is None and helper.parse_ts(True) is None)
APPS = {"public": {"game", "cdn"}, "private": {"jellyfin"}, "internal": {"log-viewer"}}
check("stack_of", [helper.stack_of(n, APPS) for n in ("authelia", "jellyfin", "cdn-api", "skull", "game", "wg-game", "wg-public",
                                                       "caddy-private", "log-viewer", "syslog")]
      == ["private", "private", "public", "internal", "public", "public", "public", "private", "internal", "internal"])
check("app folders by stack", {"cdn", "skull-viewer"} <= helper.app_folders()["public"] and "jellyfin" in helper.app_folders()["private"])
check("summary of a visit", helper.summary(v3) == "3 req · 200×1 206×1 404×1 · 6.0 KB · /abc123defg.mp4 → /zzz.png")

# ---------------------------------------------------------------- health
o = health.overview(24, now=NOW)
att = "\n".join(text for _, text in o["attention"])
check("sites come from Caddy's own startup lines", health.sites() == ["auth.example.net", "cdn.example.net", "fix.example.net", "media.example.net", "skulls.example.net"])
check("a site that changes status is flagged", "cdn.example.net answers 404, usually 200" in att)
check("a site with a steady 404 is not", "fix.example.net answers" not in att and "fix.example.net is down" not in att)
check("a site that stops answering is down", "skulls.example.net is down since" in att and "TimeoutError" in att)
check("certificate close to expiry", "fix.example.net: certificate expires in 5 days" in att)
check("kill-switch hit in the history", "wg-private: kill switch dropped 3 packets" in att)
check("kill-switch counter reset", "wg-private: kill-switch counter reset" in att)
check("stale handshake", "wg-public: last handshake 15 min ago" in att)
check("unhealthy container", "cdn-api is unhealthy" in att)
check("vanished container", "old-thing is gone" in att)
check("restart loop", "jellyfin restarted 31 times in this window" in att and "cdn-api restarted" not in att)
check("low disk", "only 10.0 GB free" in att)
check("critical first", o["attention"][0][0] == "critical" and o["attention"][-1][0] != "critical")
st = {app: parts for app, parts, _ in o["storage"]}
check("storage per app", st.get("jellyfin") == {"internal-config": 5000, "logs": 7000, "shared-files": 9 * 10 ** 9}
      and st.get("jf-gate") == {"logs": 300} and st.get("cdn") == {"backend": 1000, "shared-files": 4000} and st.get("syslog") == {"logs": 50}
      and st.get("log-collector") == {"logs": 20} and st.get("skull-viewer") == {"backend": 29_000_000} and st.get("other") == {"backend": 7})
check("cpu series per stack", len(o["series"]["cpu"]["public"]["cdn-api"]) == 12 and "jellyfin" in o["series"]["mem"]["private"])
check("skull-viewer counts as public (from its public-apps folder)", any(c["name"] == "skull-viewer" and c["stack"] == "public" for c in o["containers"]))
check("uptime", next(s for s in o["sites"] if s["host"] == "skulls.example.net")["uptime"] < 100)
r = health.probe("nonexistent.invalid", TOKEN)
check("a failed probe is recorded, not raised", r["ok"] is False and r["error"] and "code" not in r)
check("probe token survives a restart", health.token() == TOKEN)

# ---------------------------------------------------------------- the collector (the security snapshot)
IPT = ("Chain OUTPUT (policy ACCEPT 0 packets, 0 bytes)\n    pkts      bytes target     prot opt in     out     source               destination\n"
       "       {p}        {b} DROP       0    --  *      !wg0    10.0.2.2             0.0.0.0/0\n")
OUT = lambda p=0, b=0, policy="DROP", fwd=0: "@@\n".join([
    IPT.format(p=p, b=b), f"Chain FORWARD (policy {policy})\ntarget     prot opt source               destination\n", f"{fwd}\n",
    "peerkey\t1761678245\n", "peerkey\t123456\t654321\n",
    "5: wg0    inet 10.0.2.2/24 scope global wg0\\       valid_lft forever preferred_lft forever\n"])
running = {"Name": "/wg-private", "State": {"Running": True}}
tun, alerts = collect.tunnel(running, OUT())
check("tunnel entry: same keys, order and values as the script", list(tun.items()) == list({
    "container": "wg-private", "running": True, "ks_rules": 1, "ks_pkts": 0, "ks_bytes": 0, "forward_policy": "DROP",
    "ip_forward": 0, "handshake": 1761678245, "rx": 123456, "tx": 654321}.items()) and alerts == [])
tun, alerts = collect.tunnel(running, OUT(p=3, b=180, policy="ACCEPT", fwd=1))
check("alerts, worded as the script words them", alerts == ["KILLSWITCH_HIT: pkts=3 bytes=180", "FORWARD_POLICY: ACCEPT (want DROP)", "IP_FORWARD: 1 (want 0)"])
tun, alerts = collect.tunnel(running, OUT().replace("10.0.2.2             0.0.0.0/0", "10.9.9.9             0.0.0.0/0"))
check("a DROP rule for another address doesn't count", tun["ks_rules"] == 0 and alerts == ["KILLSWITCH_MISSING: no DROP rule for 10.0.2.2 in OUTPUT"])
tun, alerts = collect.tunnel(running, "")
check("unreadable: -1, unknown, no alert", tun == {"container": "wg-private", "running": True, "ks_rules": -1, "ks_pkts": -1, "ks_bytes": -1,
                                                  "forward_policy": "unknown", "ip_forward": -1, "handshake": -1, "rx": -1, "tx": -1} and alerts == [])
check("not running", collect.tunnel({"Name": "/wg-public", "State": {"Running": False}}, "")[0] == {"container": "wg-public", "running": False})
c = collect.container({"Name": "/cdn-api", "State": {"Status": "running", "StartedAt": "2026-10-28T22:57:39.123456789Z", "Health": {"Status": "healthy"}},
                       "RestartCount": 2, "Config": {"Image": "cdn-api:local"}, "Image": "sha256:0123456789abcdef0123"})
check("container entry: the script's fields, in order", list(c.items()) == [("name", "cdn-api"), ("status", "running"), ("health", "healthy"),
      ("started", "2026-10-28T22:57:39.123456789Z"), ("restarts", 2), ("image", "cdn-api:local"), ("image_id", "sha256:0123456789ab")])
check("no healthcheck -> null", collect.container({"Name": "/x", "State": {"Status": "exited"}})["health"] is None)
tree = TMP / "project"
for rel, size in (("backend/public-apps/cdn/api/main.py", 10), ("backend/private-apps/copyparty/copyparty.conf", 20), ("logs/docker/wg-public.log", 30),
                  ("logs/docker/sub/x", 40), ("shared-files/media/Movies/a.mkv", 50), ("shared-files/top.txt", 60)):
    (tree / rel).parent.mkdir(parents=True, exist_ok=True)
    (tree / rel).write_bytes(b"x" * size)
collect.PROJECT, collect.METRICS = str(tree), str(TMP)
collect.sizes()
got = json.loads((TMP / f"metrics-{time.strftime('%Y-%m', time.gmtime())}.jsonl").read_text().splitlines()[-1])
check("sizes: every byte once, two levels deep", got["event"] == "sizes" and got["sizes"] == {
    "backend/public-apps/cdn": 10, "backend/private-apps/copyparty": 20, "logs/docker/sub": 40, "logs/docker/.": 30,
    "shared-files/media/Movies": 50, "shared-files/.": 60} and got["disk"]["total"] > 0)

# ---------------------------------------------------------------- the pages
main.CTX["token"] = TOKEN
srv = ThreadingHTTPServer(("127.0.0.1", 0), main.Handler)
threading.Thread(target=srv.serve_forever, daemon=True).start()
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def get(path, method="GET"):
    try:
        with opener.open(urllib.request.Request(f"http://127.0.0.1:{srv.server_port}{path}", method=method), timeout=30) as r:
            return r.status, dict(r.headers), r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode()


qs = f"from={RANGE['from']}&to={RANGE['to']}"
code, hdr, body = get("/")
check("Health renders", code == 200 and "cdn.example.net answers 404" in body and "<svg" in body and 'http-equiv="refresh"' in body)
check("CSP and friends on every page", hdr.get("Content-Security-Policy") == main.CSP and hdr.get("X-Content-Type-Options") == "nosniff"
      and hdr.get("Cache-Control") == "no-store")
check("Health 7 days", get("/?range=7d")[0] == 200)
code, _, body = get(f"/public?{qs}")
check("Public renders with dividers and links", code == 200 and 'class="who"' in body and "/details?user=alice" in body)
check("Show is the form's first button, so Enter presses it", body.index('<button class="show">') < body.index('<button name="'))
check("each box lists its values with counts", '<button name="app" value="cdn-api">cdn-api<span>3</span></button>' in body)
code, _, b2 = get(f"/public?{qs}&app=cdn&app=cdn-worker&user=")
check("picks become bubbles and hidden fields; the rest stay in the list", code == 200 and b2.count('class="bubble"') == 2
      and '<input type="hidden" name="app" value="cdn-worker">' in b2 and 'value="cdn-api"' in b2 and 'value="cdn-worker">cdn-worker<' not in b2
      and f"/public?from={RANGE['from']}&amp;to={RANGE['to']}&amp;app=cdn-worker" in b2)
check("log text is escaped", "&lt;script&gt;" in body and EVIL not in body)
code, _, body = get(f"/private?{qs}&ffmpeg=1")
check("Private with the ffmpeg toggle", code == 200 and "libx264 / aac" in body and 'name="ffmpeg" value="1" checked' in body)
check("Private without it", "libx264" not in get(f"/private?{qs}")[2])
code, _, body = get(f"/details?user=alice&{qs}")
check("Details for a user: its rows, and its IPs in the ip list", code == 200 and '<button name="ip" value="198.51.100.20">' in body and "upload_ok" in body)
code, _, body = get(f"/details?app=jellyfin&{qs}")
check("Details shows info lines", code == 200 and "Optimize database" in body)
code, _, body = get(f"/details?app=authelia&{qs}")
check("Details shows every field, the stack whole", "the system clock is not synchronized" in body and "&quot;providers&quot;: &quot;[ntp]&quot;" in body
      and "runtime/asm_amd64.s:1771 goexit" in body)
code, _, body = get(f"/details?app=big&{qs}")
check("a huge line is cut past 64 KB, and says so", code == 200 and "KB more)" in body and len(body) < 90000)
code, _, body = get("/details")
check("Details with nothing picked shows everything", code == 200 and "log lines, newest first" in body)
code, _, body = get(f"/public?{qs}&user=%3Cb%3E&from=junk")
check("odd input is escaped or ignored", code == 200 and 'value="&lt;b&gt;"' in body)
code, hdr, body = get("/", "HEAD")
check("HEAD: headers, no body", code == 200 and body == "" and int(hdr["Content-Length"]) > 0)
code, hdr, _ = get("/", "POST")
check("POST refused", code == 405 and hdr.get("Allow") == "GET, HEAD")
check("unknown path", get("/../etc/passwd")[0] == 404 and get("/nope")[0] == 404)
check("app.js", get("/app.js")[1].get("Content-Type", "").startswith("text/javascript") and "script-src 'self'" in main.CSP)
check("style.css and healthz", get("/style.css")[1].get("Content-Type", "").startswith("text/css") and get("/healthz")[2] == "ok\n")
srv.shutdown()

print(f"{PASSED}/{PASSED + len(FAILED)} checks passed")
sys.exit(1 if FAILED else 0)
