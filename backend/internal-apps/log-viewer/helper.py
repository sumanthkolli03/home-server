"""Log sources, one converter per format, and the queries behind the tabs.

A converter turns each line of one file into one record:
    {"ts": epoch seconds, "app": str, "user": str|None, "ip": str|None,
     "event": str, "detail": {...}, "vis": None|"detail"|"ffmpeg"|"probe"|"scanner"}
`detail` is every other field of the line, as the app wrote it; Details shows it whole.
Public and Private fold the busiest kinds afterwards (the last column of SOURCES).
vis says where a record shows: None everywhere, "detail" only on Details, the other
three only when their toggle is on. Nothing here writes HTML; main.py does.
"""
import gzip
import heapq
import itertools
import json
import os
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

LOGS = Path(os.environ.get("LOGS_DIR", "/mnt/logs"))
try:
    TZ = ZoneInfo(os.environ.get("TZ") or "UTC")
except Exception:
    TZ = timezone.utc
FIELDS = ("user", "ip", "app", "event")    # the filter boxes; q searches these and the detail
VISIT_GAP = 300          # a visit: one IP on one app, requests no more than 5 minutes apart ...
VISIT_MAX = 3600         # ... for at most an hour
LINE_MAX = 1 << 20       # a longer line is read in pieces of this size


# ---------------------------------------------------------------- small pieces

def rec(ts, app, event, user=None, ip=None, vis=None, detail=None, **more):
    """One record. `detail` holds the line's own fields; `more` adds a few (None left out)."""
    return {"ts": ts, "app": app, "user": _s(user), "ip": _ip(ip), "event": event,
            "detail": {**(detail or {}), **{k: v for k, v in more.items() if v is not None}}, "vis": vis}


def _s(x):
    return str(x)[:200] if x not in (None, "") else None


def _ip(x):
    x = _s(x)
    return x[7:] if x and x.startswith("::ffff:") else x


_FRAC = re.compile(r"(\.\d{6})\d+")


def parse_ts(s):
    """ISO 8601 (Z or an offset; naive = UTC) or epoch seconds -> epoch seconds, else None."""
    if isinstance(s, (int, float)) and not isinstance(s, bool):
        return float(s)
    if not isinstance(s, str):
        return None
    try:
        d = datetime.fromisoformat(_FRAC.sub(r"\1", s.strip()))
    except ValueError:
        return None
    return (d if d.tzinfo else d.replace(tzinfo=timezone.utc)).timestamp()


def iso(ts):
    return datetime.fromtimestamp(ts, timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def local(ts, fmt="%b %d %H:%M:%S"):
    return datetime.fromtimestamp(ts, TZ).strftime(fmt)


def human(n):
    n = float(n or 0)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1000 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1000


def read_lines(path):
    """Text lines of a plain or gzipped file. Universal newlines, so ffmpeg's \\r progress
    lines come out one by one. A file that vanishes or a gzip still being written ends early."""
    opener = gzip.open if path.name.endswith(".gz") else open
    try:
        with opener(path, "rt", encoding="utf-8", errors="replace") as f:
            while line := f.readline(LINE_MAX):
                yield line.rstrip("\n")
    except (OSError, EOFError):
        return


def json_lines(path):
    for line in read_lines(path):
        if line.startswith("{"):
            try:
                j = json.loads(line)
            except ValueError:
                continue
            if isinstance(j, dict):
                yield j


def grouped(lines, head):
    """(match, the lines after it) for every line that matches head(): lines that don't (an
    exception's trace, a wrapped message) belong to the line above. Blank lines are dropped."""
    m, more = None, []
    for line in lines:
        if n := head(line):
            if m:
                yield m, more
            m, more = n, []
        elif m and line.strip():
            more.append(line)
    if m:
        yield m, more


_SECRET = re.compile(r"token|key|auth|pass|secret", re.I)
_SECRET_QS = re.compile(r"([?&;](?:[^=&#\s\"']*(?:token|key|auth|pass|secret)[^=&#\s\"']*|pw)=)[^&#\s\"']*", re.I)


def mask(x, name=""):
    """x with secrets replaced: the value of anything named like one (a header, a field), and of
    such a parameter inside a URL. Caddy already writes REDACTED for cookies and Authorization."""
    if name and (_SECRET.search(name) or name.lower() == "pw"):
        return "REDACTED"
    if isinstance(x, dict):
        return {k: mask(v, str(k)) for k, v in x.items()}
    if isinstance(x, list):
        return [mask(v) for v in x]
    return _SECRET_QS.sub(r"\1REDACTED", x) if isinstance(x, str) else x


# ---------------------------------------------------------------- folds (Public and Private only)

def fold(records, key, gap, cap=VISIT_MAX, start=None, add=None):
    """Merges records with the same key(r) (None: leave it alone) that come within `gap` seconds
    of the previous one and `cap` of the first into one: ts becomes the latest, detail.since the
    first. By default detail.count counts them; start() and add() build visits instead."""
    open_ = {}
    for r in records:
        k = key(r)
        if k is None:
            yield r
            continue
        o = open_.get(k)
        if o and r["ts"] - o["ts"] <= gap and r["ts"] - o["_t0"] <= cap:
            o["ts"] = max(o["ts"], r["ts"])
            (add or _count)(o, r)
            continue
        if o:
            yield _close(open_.pop(k))
        o = start(r) if start else dict(r, detail=dict(r["detail"]))
        o["_t0"] = r["ts"]
        open_[k] = o
    for o in open_.values():
        yield _close(o)


def _count(o, r):
    o["detail"]["count"] = o["detail"].get("count", 1) + 1


def _close(o):
    t0 = o.pop("_t0")
    if o["ts"] != t0:
        o["detail"]["since"] = iso(t0)
    return o


def _visit_start(r):
    b = r["brief"]
    d = {"host": b.get("host"), "requests": 1, "status": {str(b["status"]): 1} if "status" in b else None,
         "methods": {b["method"]: 1} if "method" in b else None, "bytes": b.get("bytes"),
         "first": b["path"], "last": b["path"], "ua": b.get("ua") or None}
    return {**{k: v for k, v in r.items() if k != "brief"}, "detail": {k: v for k, v in d.items() if v is not None}}


def _visit_add(o, r):
    d, b = o["detail"], r["brief"]
    d["requests"] += 1
    d["last"] = b["path"]
    if "bytes" in b:
        d["bytes"] = d.get("bytes", 0) + (b["bytes"] or 0)
    for field, k in (("status", "status"), ("methods", "method")):
        if k in b:
            d.setdefault(field, {})[str(b[k])] = d[field].get(str(b[k]), 0) + 1


def visits(recs):
    """Requests (those with a `brief`): one IP on one app, at most 5 minutes apart, become a visit."""
    return fold(recs, lambda r: (r["ip"], r["app"], r["user"], r["event"]) if "brief" in r else None,
                VISIT_GAP, VISIT_MAX, _visit_start, _visit_add)


def repeats(key, gap, cap=VISIT_MAX):
    """The same thing again and again (equal key(r), `gap` seconds apart): one record with a count."""
    return lambda recs: fold(recs, key, gap, cap)


# ---------------------------------------------------------------- converters

_ACCESS = re.compile(r"^(?:(.+?)-)?access(?:-\d{4}-\d\d-\d\dT[\d.-]+?(?:-[a-z]+)?)?\.log(?:\.gz)?$")


def caddy_access(path, app, ctx):
    """Caddy's JSON access logs: one record per request, the whole line in detail. A request
    carrying this viewer's probe token is a probe (hidden unless the toggle is on)."""
    mark = "lvprobe=" + ctx["token"] if ctx.get("token") else None
    for j in json_lines(path):
        r, ts = j.get("request"), j.pop("ts", None)
        if not isinstance(r, dict) or not isinstance(ts, (int, float)):
            continue
        uri = str(r.get("uri", ""))
        p = uri.split("?", 1)[0][:200]            # visits show paths only: query strings can hold tokens
        a = app
        if app == "private":                     # the private site's one log: its paths are its apps
            a = "jellyfin" if p.startswith("/jellyfin") else "copyparty" if p.startswith("/files") else "private"
        probe = bool(mark) and mark in uri
        ua = (r.get("headers") or {}).get("User-Agent") or [""]
        out = rec(float(ts), a, "probe" if probe else "visit", None, r.get("client_ip") or r.get("remote_ip"),
                  "probe" if probe else None, j)
        out["brief"] = {"host": r.get("host"), "path": p, "status": j.get("status"), "bytes": j.get("size") or 0, "ua": str(ua[0])[:200]}
        yield out


_FROM = re.compile(r"from \[?([0-9a-fA-F.:]+?)\]?:\d+")


def caddy_runtime(path, app, ctx):
    """caddy.log and caddy-tls.log, one record per line. Requests no site claimed (bare IPs) and
    failed handshakes are 'scanner' records; warnings, errors and certificate news show; the
    rest (ordinary handshakes too) is Details only."""
    for j in json_lines(path):
        ts = j.pop("ts", None)
        if not isinstance(ts, (int, float)):
            continue
        logger, msg, level = str(j.get("logger", "")), str(j.get("msg", "")), str(j.get("level", "info"))
        r = j.get("request")
        if isinstance(r, dict):
            out = rec(float(ts), app, "scanner", None, r.get("client_ip") or r.get("remote_ip"), "scanner", j)
            out["brief"] = {"host": r.get("host"), "path": str(r.get("uri", "")).split("?", 1)[0][:200], "status": j.get("status")}
            yield out
        elif logger == "http.stdlib" or (logger.startswith("tls.handshake") and "no " in msg):
            m = _FROM.search(msg)
            yield rec(float(ts), app, "scanner", None, j.get("remote_ip") or (m and m[1]), "scanner", j)
        else:
            loud = level not in ("debug", "info") or logger.startswith(("tls.obtain", "tls.renew"))
            yield rec(float(ts), app, level, None, None, None if loud else "detail", j)


def scanners(recs):
    """Bare-IP requests fold into visits, failed handshakes from one IP into one record."""
    return fold(visits(recs), lambda r: (r["ip"], r["app"]) if r["event"] == "scanner" and "requests" not in r["detail"] else None,
                VISIT_GAP)


def standard(path, app, ctx):
    """JSON lines in the logging standard: ts, event, user and/or ip, anything else.
    The CDN's, the gate's, every app's and this viewer's own logs all look like this."""
    for j in json_lines(path):
        ts = parse_ts(j.pop("ts", None))
        if ts is None:
            continue
        ev = str(j.pop("event", "") or "line")[:60]
        yield rec(ts, app, ev, j.pop("user", None), j.pop("ip", None), "probe" if ev == "probe" else None, j)


GATE = {"auth": ("user", "ip", "tok"), "deny": ("ip", "reason")}   # the gate's busiest events
gate = repeats(lambda r: (r["event"], *(str(r.get(k) or r["detail"].get(k)) for k in GATE[r["event"]])) if r["event"] in GATE else None,
               VISIT_GAP)


_LOGFMT = re.compile(r'(\w+)=("(?:[^"\\]|\\.)*"|\S*)')
_AUTH_FAIL = re.compile(r"Unsuccessful (\S+) authentication attempt by user '([^']*)'")
_AUTH_UNKNOWN = re.compile(r"Error occurred getting details for user with username input '([^']*)'")


def authelia(path, app, ctx):
    """Authelia 4.39's text (logfmt) or JSON log, one record per line with every field it wrote.
    Failed sign-ins name the user in the message; successful ones are only logged at debug."""
    for line in read_lines(path):
        if line.startswith("{"):
            try:
                f = json.loads(line)
            except ValueError:
                continue
            if not isinstance(f, dict):
                continue
        else:
            f = {k: _unquote(v) for k, v in _LOGFMT.findall(line)}
        ts = parse_ts(f.pop("time", None))
        if ts is None:
            continue
        ip, msg = f.pop("remote_ip", None), str(f.get("msg", ""))
        if m := _AUTH_FAIL.match(msg):
            yield rec(ts, app, "login_banned" if "banned until" in msg else "login_fail", m[2], ip, None, f)
        elif m := _AUTH_UNKNOWN.match(msg):
            yield rec(ts, app, "unknown_user", m[1], ip, None, f)
        else:
            level = str(f.pop("level", "info"))
            yield rec(ts, app, level, None, ip, None if level in ("warning", "error", "fatal", "panic") else "detail", f)


def _unquote(v):
    if v.startswith('"'):
        try:
            return json.loads(v)
        except ValueError:
            return v.strip('"')
    return v


_CP = re.compile(r"^(\d\d):(\d\d):(\d\d)\.(\d{3}) (\S+)(?: +(\d+))? +([A-Z0-9]+): ?(.*)$")
_CP_REQ = re.compile(r"^([A-Z]+) +(\S+) @(\S+)$")
_CP_WROTE = re.compile(r"wrote (\d+)/(\d+) bytes to '(.*)'")
_CP_UP2K = re.compile(r"^no more chunks, setting times \([^)]*\) \((\d+)\) on '(.*)'$")
_CP_DENY = re.compile(r"^http(40[13]): (.*)$")
_CP_DATE = re.compile(r"copyparty-(\d{4})-(\d\d)(\d\d)")


def copyparty(path, app, ctx):
    """copyparty 1.20: local times, the date in the file name; one record per line, credited to
    the user of its connection. Lines without a time belong to the line above."""
    d = _CP_DATE.search(path.name)
    if not d:
        return
    day, users = datetime(int(d[1]), int(d[2]), int(d[3]), tzinfo=TZ), {}
    for m, more in grouped(read_lines(path), _CP.match):
        ts = day.replace(hour=int(m[1]), minute=int(m[2]), second=int(m[3]), microsecond=int(m[4]) * 1000).timestamp()
        ip, conn, rest = m[5], (m[5], m[6]), m[8]
        detail = {"port": m[6], "tag": m[7], "msg": "\n".join([rest, *more])}
        if q := _CP_REQ.match(rest):
            users[conn] = None if q[3] == "*" else q[3]
            r = rec(ts, app, "visit", users[conn], ip, None, detail)
            r["brief"] = {"method": q[1], "path": q[2].split("?", 1)[0][:200]}
            yield r
        elif _CP_WROTE.search(rest) or _CP_UP2K.match(rest):
            yield rec(ts, app, "upload", users.get(conn), ip, None, detail)
        elif _CP_DENY.match(rest):
            yield rec(ts, app, "denied", users.get(conn), ip, None, detail)
        else:
            yield rec(ts, app, "line", users.get(conn), ip, "detail", detail)


_JF = re.compile(r"^\[(\d{4}-\d\d-\d\d) (\d\d:\d\d:\d\d(?:\.\d+)?) ([+-]\d\d:\d\d)\] \[([A-Z]{3})\] \[(\d+)\] (\S+?): (.*)$")
_JF_EVENTS = [   # Jellyfin 10.11's messages worth naming, and who they name; "detail" = Details only
    ("login_ok", None, r'Authentication request for "(?P<user>.*)" has succeeded\.$'),
    ("login_fail", None, r'Authentication request for "(?P<user>.*)" has been denied \(IP: "(?P<ip>.*)"\)\.$'),
    ("session", None, r'Current/Max sessions for user "(?P<user>.*)": \d+/\d+$'),
    ("play_request", None, r'User policy for "(?P<user>.*)"\. '),
    ("play_start", None, r'Playback start reported by app "'),
    ("play_stop", None, r'Playback stopped reported by app "'),
    ("ws_open", "detail", r'WS "(?P<ip>.*)" request$'),
    ("ws_close", "detail", r'WS "(?P<ip>.*)" closed$'),
]
_JF_EVENTS = [(e, v, re.compile(x)) for e, v, x in _JF_EVENTS]
_JF_LEVEL = {"WRN": "warn", "ERR": "error", "FTL": "fatal", "CRT": "fatal"}
_SHAPE = re.compile(r'"[^"]*"|\d+')


def jellyfin(path, app, ctx):
    """Jellyfin's daily text log, one record per line; exception lines join the line above."""
    for m, more in grouped(read_lines(path), _JF.match):
        detail = {"level": m[4], "thread": m[5], "source": m[6], "msg": m[7]}
        if more:
            detail["exception"] = "\n".join(more)
        yield _jf_record(parse_ts(f"{m[1]}T{m[2]}{m[3]}"), app, detail)


def _jf_record(ts, app, detail):
    msg = detail["msg"]
    for event, vis, rx in _JF_EVENTS:
        if m := rx.match(msg):
            return rec(ts, app, event, m.groupdict().get("user"), m.groupdict().get("ip"), vis, detail)
    ev = _JF_LEVEL.get(detail["level"], "info")
    if ev == "warn" and "Only loopback" in msg:      # NetworkManager says this on every request
        ev = "info"
    return rec(ts, app, ev, None, None, "detail" if ev == "info" else None, detail)


jf_repeats = repeats(lambda r: (r["detail"].get("source"), _SHAPE.sub("#", r["detail"].get("msg", ""))[:120])
                     if r["event"] in ("warn", "error", "fatal") else None, 600)


_FF_NAME = re.compile(r"FFmpeg\.(\w+)-(\d{4})-(\d\d)-(\d\d)_(\d\d)-(\d\d)-(\d\d)_")
_FF_HEAD = re.compile(r"^===== (.+) =====$")
_FF_SPEED = re.compile(r"speed=\s*([\d.]+)x")
_FF_CODEC = re.compile(r"-codec:([va])(?::\d+)? (\S+)")


def ffmpeg(path, app, ctx):
    """One record per FFmpeg session (its file is mostly progress lines), from Jellyfin's live
    session files or prune-logs.sh's daily archives (sessions behind '===== name =====' lines)."""
    s = None if path.name.endswith(".gz") else _ff_new(path.name)
    for line in read_lines(path):
        if m := _FF_HEAD.match(line):
            if s:
                yield _ff_record(s, app)
            s = _ff_new(m[1])
        elif s is not None:
            s["n"] += 1
            if s["n"] == 1 and line.startswith("{"):
                try:
                    s["info"] = json.loads(line)
                except ValueError:
                    pass
            elif not s["cmd"] and line.startswith("/") and "ffmpeg" in line:
                s["cmd"] = line
            elif "speed=" in line and (m := _FF_SPEED.search(line)):
                s["speed"] = m[1] + "x"
            if "Conversion failed" in line or "Error while" in line or "Error opening" in line:
                s["failed"] = True
            elif "command received" in line or "received signal" in line:
                s["stopped"] = True
            if line.strip():
                s["last"] = line.strip()
    if s:
        yield _ff_record(s, app)


def _ff_new(name):
    return {"name": name, "n": 0, "info": {}, "cmd": "", "speed": None, "last": None, "failed": False, "stopped": False}


def _ff_record(s, app):
    m = _FF_NAME.search(s["name"])
    if not m:
        return None
    info = s["info"] if isinstance(s["info"], dict) else {}
    streams = [x for x in info.get("MediaStreams") or [] if isinstance(x, dict)]
    v = next((x for x in streams if x.get("Width")), {})
    a = next((x for x in streams if x.get("Channels")), {})
    out = {}
    for k, codec in _FF_CODEC.findall(s["cmd"]):
        out.setdefault(k, codec)
    ticks = info.get("RunTimeTicks")
    length = f"{int(ticks / 1e7 // 3600)}:{int(ticks / 1e7 % 3600 // 60):02d}:{int(ticks / 1e7 % 60):02d}" if isinstance(ticks, (int, float)) else None
    return rec(datetime(*map(int, m.groups()[1:]), tzinfo=TZ).timestamp(), app, "ffmpeg", vis="ffmpeg",
               kind=m[1].lower(), file=os.path.basename(str(info.get("Path") or "")),
               input=f"{v.get('Codec', '?')} {v.get('Width', '?')}x{v.get('Height', '?')} / {a.get('Codec', '?')}",
               output=f"{out.get('v', '?')} / {out.get('a', '?')}", length=length, speed=s["speed"],
               ended="failed" if s["failed"] else "stopped" if s["stopped"] else "finished", last=s["last"],
               session=s["name"], command=s["cmd"] or None)


def wg(path, app, ctx):
    """syslog-ng's per-container file: '<ISO time> <message>'. Status lines show; the banner
    and wg-quick's commands are Details only."""
    app = path.name.removesuffix(".log")
    for line in read_lines(path):
        t, _, msg = line.partition(" ")
        ts = parse_ts(t)
        if ts is None:
            continue
        msg = msg.strip()
        ev = ("tunnel_up" if "All tunnels are now active" in msg else "tunnel_down" if "All tunnels are down" in msg
              else "status" if msg.startswith("****") else "line")
        yield rec(ts, app, ev, vis="detail" if ev == "line" else None, msg=msg)


_ALERT = re.compile(r"^(\S+) (\S+)\s+([A-Z_]+): ?(.*)$")


def alerts(path, app, ctx):
    """The collector's ALERTS.log: '<ts> <container> <KIND>: <text>'."""
    for line in read_lines(path):
        if (m := _ALERT.match(line)) and (ts := parse_ts(m[1])) is not None:
            yield rec(ts, m[2], m[3], text=m[4])


alert_repeats = repeats(lambda r: (r["app"], r["event"]), 360, cap=10 ** 9)   # one alert repeats every 5 minutes while it holds


def _dir(n):                # the app is the folder n levels above the file
    return lambda p: p.parts[-n]


def _site(p):               # <stack>-apps/<app>/access/[<site>-]access.log: <app>, or <app>-<site>
    m = _ACCESS.match(p.name)
    return p.parts[-3] + (f"-{m[1]}" if m and m[1] else "")


def _service(p):            # <stack>-apps/<app>/app/<service>/x.jsonl: the container <app>-<service>
    return f"{p.parts[-4]}-{p.parts[-2]}"


SOURCES = [   # (files under logs/, stack (None = from the app's name), converter, app, fold on Public and Private)
    ("caddy/caddy-private/*access*.log*", "private", caddy_access, "private", visits),
    ("caddy/caddy-internal/misdirected*.log*", "internal", caddy_access, "caddy-internal", visits),
    ("public-apps/*/access/*.log*", "public", caddy_access, _site, visits),
    ("internal-apps/*/access/*.log*", "internal", caddy_access, _site, visits),
    ("caddy/caddy-public/caddy*.log*", "public", caddy_runtime, "caddy-public", scanners),
    ("caddy/caddy-private/caddy*.log*", "private", caddy_runtime, "caddy-private", scanners),
    ("caddy/caddy-internal/caddy*.log*", "internal", caddy_runtime, "caddy-internal", scanners),
    ("public-apps/*/app/*.jsonl", "public", standard, _dir(3), None),
    ("public-apps/*/app/*/*.jsonl", "public", standard, _service, None),
    ("public-apps/*/egress/*.jsonl", "public", standard, _dir(3), None),
    ("private-apps/jf-gate/app/*.jsonl", "private", standard, "jf-gate", gate),
    ("internal-apps/*/app/*.jsonl", "internal", standard, _dir(3), None),
    ("authelia/authelia*.log*", "private", authelia, "authelia", None),
    ("private-apps/copyparty/app/copyparty-*.log*", "private", copyparty, "copyparty", visits),
    ("private-apps/jellyfin/app/log_*.log*", "private", jellyfin, "jellyfin", jf_repeats),
    ("private-apps/jellyfin/app/FFmpeg*.log", "private", ffmpeg, "jellyfin", None),
    ("private-apps/jellyfin/ffmpeg/*.gz", "private", ffmpeg, "jellyfin", None),
    ("docker/wg-*.log", None, wg, None, None),
    ("security/ALERTS.log", None, alerts, None, alert_repeats),
]


STACKS = ("public", "private", "internal")


def app_folders():
    """{stack: the app names under logs/<stack>-apps/}. Every app has a log folder there."""
    return {s: {p.name for p in (LOGS / f"{s}-apps").glob("*") if p.is_dir()} for s in STACKS}


def stack_of(name, apps=None):
    """public, private or internal: a stack's own tunnel and Caddy (wg-<stack>,
    caddy-<stack>), Authelia for private, and every app in <stack>-apps/, whose containers are
    <app>, <app>-<service> and its egress tunnel wg-<app>. Anything else is internal."""
    name = name or ""
    apps = app_folders() if apps is None else apps
    for s in STACKS:
        if name in (f"wg-{s}", f"caddy-{s}"):
            return s
    if name == "authelia":
        return "private"
    base = name[3:] if name.startswith("wg-") else name
    for s in STACKS:
        if any(base == a or base.startswith(a + "-") for a in apps.get(s, ())):
            return s
    return "internal"


# ---------------------------------------------------------------- queries

def query(start, end, stacks=None, picks=None, text="", show=(), details=False, limit=500, ctx=None):
    """The newest `limit` records with start <= ts < end, whether there are more, and the values
    seen in each filter box. picks = {box: values}: a line must hold one of the values of every
    box picked. text: any part of a line but its time, case-insensitive. Both apply to log lines;
    Public and Private (details=False) fold them afterwards. seen[box] counts the values among
    the lines the text and every other box let through: pick a user and the IPs are that user's."""
    ctx = ctx or {}
    picks = {k: set(v) for k, v in (picks or {}).items() if k in FIELDS and v}
    text = (text or "").strip().lower()
    apps = app_folders()
    seen = {k: Counter() for k in FIELDS}
    newest, tie = [], itertools.count()

    def lines(p, stack, convert, app):
        for r in convert(p, app(p) if callable(app) else app, ctx):
            if r is None or not start <= r["ts"] < end:
                continue
            r["stack"] = stack or stack_of(r["app"], apps)
            v = r["vis"]
            if (stacks and r["stack"] not in stacks) or (v and not ((v == "detail" and details) or v in show)):
                continue
            if text and text not in searchable(r):
                continue
            misses = [k for k in picks if r[k] not in picks[k]]
            for k in FIELDS:
                if r[k] and (not misses or misses == [k]):
                    seen[k][r[k]] += 1
            if not misses:
                yield r

    for pattern, stack, convert, app, folder in SOURCES:
        if stacks and stack and stack not in stacks:
            continue
        for p in sorted(LOGS.glob(pattern)):
            try:
                if p.name.endswith(".tmp") or p.stat().st_mtime < start:
                    continue
            except OSError:
                continue
            recs = lines(p, stack, convert, app)
            for r in (recs if details or not folder else folder(recs)):
                heapq.heappush(newest, (r["ts"], next(tie), r))
                if len(newest) > limit + 1:
                    heapq.heappop(newest)
    out = [r for *_, r in sorted(newest, key=lambda x: x[:2], reverse=True)]
    for r in out:
        r.pop("brief", None)
        r["detail"] = mask(r["detail"])
    return out[:limit], len(out) > limit, seen


def searchable(r):
    """What q looks through: every field of a record but its time, in lower case."""
    return " ".join([str(r[k]) for k in FIELDS if r[k]] + [json.dumps(r["detail"], ensure_ascii=False, default=str)]).lower()


QUIET = {"count", "since", "ua", "level", "thread", "source", "port", "tag", "logger", "exception", "stack", "command"}


def summary(r):
    """One line for Public and Private."""
    d = r["detail"]
    if "requests" in d:
        codes = " ".join(f"{k}×{n}" for k, n in sorted((d.get("status") or d.get("methods") or {}).items()))
        where = d.get("first", "") if d.get("first") == d.get("last") else f"{d.get('first')} → {d.get('last')}"
        size = f" · {human(d['bytes'])}" if "bytes" in d else ""
        return f"{d['requests']} req · {codes}{size} · {where}"
    parts = [f"×{d['count']}"] if d.get("count") else []
    parts += [f"{k}={v if isinstance(v, str) else json.dumps(v, ensure_ascii=False, default=str)}" for k, v in d.items() if k not in QUIET]
    return " · ".join(parts)[:240]
