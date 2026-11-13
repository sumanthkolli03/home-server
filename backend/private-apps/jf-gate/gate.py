#!/usr/bin/env python3
"""
jf-gate — token gate in front of Jellyfin.

Caddy runs `forward_auth jf-gate:8000 { uri /check }` for every /jellyfin request.
The gate receives the client's headers plus X-Forwarded-Method, X-Forwarded-Uri and
X-Real-IP (never the body) and answers:

    200                  allow: Caddy proxies the request to Jellyfin
    401/403/429/503      deny:  Caddy returns this response; Jellyfin never sees the request

Every request falls into one of three groups:

    OPEN    login flow, web client files, branding, server info        -> anyone
            (login and Quick Connect initiation are rate-limited per IP)
    RECENT  images and MKV font attachments, which apps fetch without a token
            -> only from an IP whose /24 presented a valid token in the last RECENT_SECONDS
    TOKEN   everything else, including every stream and the websocket
            -> a token Jellyfin accepts (GET /Users/Me answers 200), cached TOKEN_TTL seconds

Jellyfin still enforces its own auth on everything that passes; the gate only keeps
people without a valid login away from Jellyfin's code.

GATE_MODE=observe computes every decision and logs what it would block, but allows
everything. GATE_MODE=enforce (the default) blocks.

Token extraction mirrors Jellyfin 10.11 (Jellyfin.Server.Implementations/Security/
AuthorizationContext.cs) with legacy authorization enabled, which is Jellyfin's default.
Path handling mirrors Jellyfin's base-URL map and its /emby and /mediabrowser prefix
stripping (LegacyEmbyRouteRewriteMiddleware).

Standard library only. Logs are JSON lines in $LOG_DIR/gate-YYYY-MM.jsonl. Tokens and
query strings are never logged.
"""

import collections
import hashlib
import http.client
import ipaddress
import json
import os
import re
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qsl, quote, unquote_plus, urlsplit


# --------------------------------------------------------------------------- settings
def env_int(name, default):
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        sys.exit(f"jf-gate: {name} must be an integer, not {raw!r}")
    if value < 0:
        sys.exit(f"jf-gate: {name} must not be negative")
    return value


MODE = os.environ.get("GATE_MODE", "enforce").strip().lower()
if MODE not in ("observe", "enforce"):
    sys.exit(f"jf-gate: GATE_MODE must be 'observe' or 'enforce', not {MODE!r}")

JELLYFIN_URL = os.environ.get("JELLYFIN_URL", "http://jellyfin:8096/jellyfin").rstrip("/")
_jf = urlsplit(JELLYFIN_URL)
if _jf.scheme != "http" or not _jf.hostname:
    sys.exit(f"jf-gate: JELLYFIN_URL must be http://host:port/basepath, not {JELLYFIN_URL!r}")
JF_HOST, JF_PORT, JF_BASE = _jf.hostname, _jf.port or 80, _jf.path.rstrip("/")

BASE = os.environ.get("BASE_PATH", "/jellyfin").rstrip("/")   # Jellyfin's Base URL as Caddy sees it
PORT = env_int("PORT", 8000)
LOG_DIR = os.environ.get("LOG_DIR", "/logs")

TOKEN_TTL = env_int("TOKEN_TTL", 60)              # a valid token is re-checked after this
BAD_TTL = env_int("BAD_TTL", 60)                  # an invalid token is re-checked after this
RECENT_SECONDS = env_int("RECENT_SECONDS", 6 * 3600)
RECENT_V4 = env_int("RECENT_PREFIX_V4", 24)
RECENT_V6 = env_int("RECENT_PREFIX_V6", 64)
LOGIN_MAX = env_int("LOGIN_MAX", 10)              # login attempts per IP ...
LOGIN_WINDOW = env_int("LOGIN_WINDOW", 600)       # ... per this many seconds
BAD_MAX = env_int("BAD_TOKEN_MAX", 30)            # fresh invalid tokens per IP ...
BAD_WINDOW = env_int("BAD_TOKEN_WINDOW", 600)     # ... per this many seconds
BLOCK_SECONDS = env_int("BLOCK_SECONDS", 900)     # then new tokens from that IP wait this long
LOG_DENY_MAX = env_int("LOG_DENY_MAX", 60)        # deny log lines per IP per 10 minutes
JF_TIMEOUT = env_int("JF_TIMEOUT", 5)
MAX_ENTRIES = env_int("MAX_ENTRIES", 20000)       # bound on every in-memory table


# --------------------------------------------------------------------------- request groups
# All patterns match the path below the base URL, lowercased (ASP.NET routing ignores case).
ID = r"(?:[0-9a-f]{32}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})"
SEG = r"(?:[a-z0-9._~@+-]|%40)+"

OPEN_GET = re.compile(rf"""(?x) ^ (?:
      /?                                          # /jellyfin -> redirect to the web client
    | /web/?
    | /web/(?!configurationpage){SEG}(?:/{SEG})*  # web client files; plugin config pages need a token
    | /system/info/public
    | /system/ping
    | /branding/configuration
    | /branding/css(?:\.css)?
    | /branding/splashscreen
    | /quickconnect/enabled
    | /quickconnect/connect
) /? $""")

OPEN_POST = re.compile(r"^/system/ping/?$")

LOGIN_POST = re.compile(r"""(?x) ^ (?:
      /users/authenticatebyname
    | /users/authenticatewithquickconnect
    | /quickconnect/initiate
) /? $""")
LOGIN_GET = re.compile(r"^/quickconnect/initiate/?$")      # deprecated GET form

RECENT_GET = re.compile(rf"""(?x) ^ (?:
      /items/{ID}/images/[a-z]+(?:/[a-z0-9._-]+){{0,7}}
    | /users/{ID}/images/[a-z]+(?:/[0-9]+)?
    | /userimage
    | /(?:persons|artists|genres|musicgenres|studios)/[^/]+/images/[a-z]+(?:/[0-9]+)?
    | /videos/{ID}/{ID}/attachments/[0-9]+
) /? $""")

# Anything in a path that could make the gate and Jellyfin disagree about what is requested:
# encoded dots and slashes, backslashes, empty segments, spaces, control or non-ASCII bytes.
UNSAFE = re.compile(r"%(?:2e|2f|5c|00)|\\|//|[^\x21-\x7e]", re.IGNORECASE)
TOKEN_SHAPE = re.compile(r"^[A-Za-z0-9._~+/=-]{1,128}$")


def subpath(path):
    """Path below the base URL, or None when the request is not under it (ASP.NET Map semantics)."""
    if not path.lower().startswith(BASE.lower()):
        return None
    sub = path[len(BASE):]
    if sub and not sub.startswith("/"):
        return None
    return sub


def is_clean(sub):
    if UNSAFE.search(sub):
        return False
    return not any(seg in (".", "..") for seg in sub.split("/"))


def routed(sub):
    """Lowercased path as Jellyfin routes it: /emby and /mediabrowser prefixes are stripped."""
    low = sub.lower()
    for prefix in ("/emby", "/mediabrowser"):
        if low.startswith(prefix):
            return low[len(prefix):]
    return low


def classify(method, sub):
    """-> 'open' | 'login' | 'recent' | 'token'. Anything not recognised needs a token."""
    if not is_clean(sub):
        return "token"
    low = routed(sub)
    if low and not low.startswith("/"):
        return "token"
    if method in ("GET", "HEAD"):
        if OPEN_GET.match(low):
            return "open"
        if LOGIN_GET.match(low):
            return "login"
        if RECENT_GET.match(low):
            return "recent"
    elif method == "POST":
        if OPEN_POST.match(low):
            return "open"
        if LOGIN_POST.match(low):
            return "login"
    return "token"


# --------------------------------------------------------------------------- token extraction
def get_parts(value):
    """Port of AuthorizationContext.GetParts: key="value", key2="value2" (values URL-decoded)."""
    result = {}
    escaped = False
    start = 0
    key = ""
    i = 0
    for i, ch in enumerate(value):
        if ch in ('"', ','):
            escaped = (not escaped) == (ch == '"')
            if ch == ',' and not escaped:
                if start < i:
                    result[key] = unquote_plus(value[start:i].strip('"'))
                    key = ""
                start = i + 1
        elif not escaped and ch == '=':
            key = value[start:i].strip()
            start = i + 1
    else:
        i = len(value)
    if start < i:
        result[key] = unquote_plus(value[start:i].strip('"'))
    return result


def parse_authorization(value):
    """Port of AuthorizationContext.GetAuthorization ('MediaBrowser' or legacy 'Emby' scheme)."""
    space = value.find(" ")
    if space == -1:
        return None
    if value[:space].lower() not in ("mediabrowser", "emby"):
        return None
    return get_parts(value[space + 1:])


def joined(values):
    """ASP.NET StringValues -> string: None when absent, multiple values joined with ','."""
    if not values:
        return None
    return ",".join(values)


def extract_token(headers, query):
    """The token Jellyfin would use for this request, in Jellyfin's order of precedence."""
    auth = headers.get_all("Authorization") or []
    if not joined(auth):
        auth = headers.get_all("X-Emby-Authorization") or []
    token = None
    if auth:
        parts = parse_authorization(auth[0])
        if parts:
            token = parts.get("Token")
    if not token:
        token = joined(headers.get_all("X-Emby-Token"))
    if not token:
        token = joined(headers.get_all("X-MediaBrowser-Token"))
    if not token:
        params = collections.defaultdict(list)
        for k, v in parse_qsl(query, keep_blank_values=True):
            params[k.lower()].append(v)          # ASP.NET query keys are case-insensitive
        token = joined(params.get("apikey")) or joined(params.get("api_key"))
    return token or None


def fingerprint(token):
    return hashlib.sha256(token.encode("utf-8", "replace")).hexdigest()[:10]


# --------------------------------------------------------------------------- small helpers
def client_ip(peer, real_ip):
    """X-Real-IP is trusted only from a private peer (Caddy on an internal network)."""
    try:
        p = ipaddress.ip_address(peer)
    except ValueError:
        return peer
    if real_ip and (p.is_private or p.is_loopback):
        try:
            return str(ipaddress.ip_address(real_ip.strip()))
        except ValueError:
            pass
    return str(p)


def ip_net(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return ip
    bits = RECENT_V4 if a.version == 4 else RECENT_V6
    return str(ipaddress.ip_network(f"{a}/{bits}", strict=False))


class Window:
    """Sliding-window counter per key, with an optional block period once over the limit."""

    def __init__(self, limit, window, block=0):
        self.limit, self.window, self.block = limit, window, block
        self.hits = {}
        self.blocked_until = {}
        self.lock = threading.Lock()

    def hit(self, key, now):
        """Record one event; True when this key is now over the limit."""
        with self.lock:
            q = self.hits.get(key)
            if q is None:
                if len(self.hits) >= MAX_ENTRIES:
                    self._prune(now)
                q = self.hits[key] = collections.deque()
            while q and q[0] <= now - self.window:
                q.popleft()
            q.append(now)
            over = len(q) > self.limit
            if over and self.block:
                self.blocked_until[key] = now + self.block
            return over

    def blocked(self, key, now):
        with self.lock:
            until = self.blocked_until.get(key)
            if until is None:
                return False
            if until <= now:
                del self.blocked_until[key]
                return False
            return True

    def _prune(self, now):
        for k in [k for k, q in self.hits.items() if not q or q[-1] <= now - self.window]:
            del self.hits[k]
        if len(self.hits) >= MAX_ENTRIES:
            self.hits.clear()
        for k in [k for k, t in self.blocked_until.items() if t <= now]:
            del self.blocked_until[k]


class Recent:
    """Networks (/24, /64) that presented a valid token recently."""

    def __init__(self):
        self.seen_at = {}
        self.lock = threading.Lock()

    def mark(self, ip, now):
        net = ip_net(ip)
        with self.lock:
            if net not in self.seen_at and len(self.seen_at) >= MAX_ENTRIES:
                cutoff = now - RECENT_SECONDS
                self.seen_at = {k: t for k, t in self.seen_at.items() if t > cutoff}
                if len(self.seen_at) >= MAX_ENTRIES:
                    self.seen_at.clear()
            self.seen_at[net] = now

    def seen(self, ip, now):
        with self.lock:
            t = self.seen_at.get(ip_net(ip))
        return t is not None and now - t <= RECENT_SECONDS


# --------------------------------------------------------------------------- Jellyfin check
def ask_jellyfin(token):
    """-> ('valid', user) | ('invalid', None) | ('error', None)."""
    conn = http.client.HTTPConnection(JF_HOST, JF_PORT, timeout=JF_TIMEOUT)
    try:
        conn.request("GET", JF_BASE + "/Users/Me", headers={
            # Token only: Jellyfin fills client/device from its own record, so nothing is renamed.
            "Authorization": 'MediaBrowser Token="%s"' % quote(token, safe=""),
            "Accept": "application/json",
            "User-Agent": "jf-gate",
        })
        resp = conn.getresponse()
        status, body = resp.status, resp.read(256 * 1024)
    except (OSError, http.client.HTTPException):
        return "error", None
    finally:
        conn.close()
    if status == 200:
        try:
            data = json.loads(body)
        except ValueError:
            return "error", None
        policy = data.get("Policy") or {}
        return "valid", {
            "name": str(data.get("Name", "?"))[:64],
            "admin": bool(policy.get("IsAdministrator")),
        }
    if status in (400, 401, 403, 404):          # 400 = an API key, which has no user
        return "invalid", None
    return "error", None


class Tokens:
    """Cache of Jellyfin's answers per token. Concurrent checks of one token share one call."""

    def __init__(self, bad_window):
        self.cache = {}
        self.inflight = {}
        self.bad = bad_window
        self.lock = threading.Lock()

    def check(self, token, ip):
        """-> (result, user, fresh). result: valid | invalid | error | throttled."""
        now = time.monotonic()
        with self.lock:
            hit = self.cache.get(token)
            if hit and hit[0] > now:
                return hit[1], hit[2], False
            event = self.inflight.get(token)
            leader = event is None
            if leader:
                if self.bad.blocked(ip, now):
                    return "throttled", None, False
                event = self.inflight[token] = threading.Event()
        if not leader:
            event.wait(JF_TIMEOUT + 2)
            with self.lock:
                hit = self.cache.get(token)
            if hit and hit[0] > time.monotonic():
                return hit[1], hit[2], False
            return "error", None, False
        try:
            result, user = ask_jellyfin(token)
        finally:
            with self.lock:
                self.inflight.pop(token, None)
            event.set()
        with self.lock:
            if result == "valid":
                self.cache[token] = (time.monotonic() + TOKEN_TTL, result, user)
            elif result == "invalid":
                self.cache[token] = (time.monotonic() + BAD_TTL, result, None)
            if len(self.cache) > MAX_ENTRIES:
                now = time.monotonic()
                self.cache = {k: v for k, v in self.cache.items() if v[0] > now}
                if len(self.cache) > MAX_ENTRIES:
                    self.cache.clear()
        if result == "invalid":
            self.bad.hit(ip, time.monotonic())
        return result, user, True


# --------------------------------------------------------------------------- logging
class JsonLog:
    """One JSON object per line, monthly files, opened per write (safe to rotate or delete)."""

    def __init__(self, directory):
        self.dir = directory
        self.lock = threading.Lock()
        self.deny_window = Window(LOG_DENY_MAX, 600)
        self.suppressed = collections.Counter()

    def write(self, event, **fields):
        record = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "event": event}
        record.update(fields)
        line = json.dumps(record, separators=(",", ":"), ensure_ascii=True) + "\n"
        path = os.path.join(self.dir, time.strftime("gate-%Y-%m.jsonl", time.gmtime()))
        with self.lock:
            try:
                with open(path, "a", encoding="utf-8") as fh:
                    fh.write(line)
            except OSError as exc:
                print(f"jf-gate: cannot write {path}: {exc}", file=sys.stderr, flush=True)

    def deny(self, event, ip, **fields):
        """Deny lines are capped per IP so a scanner can't flood the log."""
        if self.deny_window.hit(ip, time.monotonic()):
            with self.lock:
                self.suppressed[ip] += 1
            return
        with self.lock:
            skipped = self.suppressed.pop(ip, 0)
        if skipped:
            fields["suppressed_before"] = skipped
        self.write(event, ip=ip, **fields)


# --------------------------------------------------------------------------- the gate
class Verdict:
    __slots__ = ("code", "reason", "group", "user", "fresh", "tok")

    def __init__(self, code, reason, group, user=None, fresh=False, tok=None):
        self.code, self.reason, self.group = code, reason, group
        self.user, self.fresh, self.tok = user, fresh, tok


class Gate:
    def __init__(self):
        self.logins = Window(LOGIN_MAX, LOGIN_WINDOW)
        self.bad = Window(BAD_MAX, BAD_WINDOW, BLOCK_SECONDS)
        self.tokens = Tokens(self.bad)
        self.recent = Recent()

    def decide(self, method, uri, ip, headers):
        if not method or not uri.startswith("/"):
            return Verdict(400, "missing_forward_headers", "token")
        path, _, query = uri.partition("?")
        sub = subpath(path)
        if sub is None:
            return Verdict(403, "outside_base_url", "token")
        group = classify(method, sub)
        now = time.monotonic()

        if group == "open":
            return Verdict(200, "open", group)
        if group == "login":
            if self.logins.hit(ip, now):
                return Verdict(429, "login_rate", group)
            return Verdict(200, "login", group)

        token = extract_token(headers, query)
        shaped = token is not None and TOKEN_SHAPE.match(token) is not None
        result, user, fresh = (None, None, False)
        if shaped:
            result, user, fresh = self.tokens.check(token, ip)
            if result == "valid":
                self.recent.mark(ip, now)
                return Verdict(200, "token", group, user, fresh, fingerprint(token))

        if group == "recent":
            if self.recent.seen(ip, now):
                return Verdict(200, "recent", group)
            return Verdict(401, "not_recently_signed_in", group)
        if token is None:
            return Verdict(401, "no_token", group)
        if not shaped or result == "invalid":
            return Verdict(401, "invalid_token", group)
        if result == "throttled":
            return Verdict(429, "too_many_bad_tokens", group)
        return Verdict(503, "jellyfin_unreachable", group)


GATE = Gate()
LOG = JsonLog(LOG_DIR)

DENY_BODY = {
    400: b'{"error":"bad request"}',
    401: b'{"error":"authentication required"}',
    403: b'{"error":"forbidden"}',
    429: b'{"error":"too many attempts, try again later"}',
    503: b'{"error":"Jellyfin is unavailable"}',
}


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    timeout = 30                      # idle keep-alive connections from Caddy close after this

    def log_message(self, fmt, *args):   # Caddy logs every request; the gate logs decisions
        pass

    def send_response(self, code, message=None):   # no Server header (it reaches clients on deny)
        self.send_response_only(code, message)
        self.send_header("Date", self.date_time_string())

    def reply(self, code, body=b"", content_type=None, extra=()):
        self.send_response(code)
        if content_type:
            self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for name, value in extra:
            self.send_header(name, value)
        self.end_headers()
        if self.command != "HEAD" and body:
            self.wfile.write(body)

    def do_GET(self):
        # forward_auth's `uri /check` keeps the client's query string (Caddy's rewrite only
        # replaces a query it is given), so this arrives as /check?... — match the path only.
        # The decision itself always uses X-Forwarded-Uri.
        route = self.path.partition("?")[0]
        if route == "/check":
            return self.check()
        if route == "/healthz":
            return self.reply(200, b"ok\n", "text/plain")
        return self.reply(404)

    def do_HEAD(self):
        return self.do_GET()

    def check(self):
        h = self.headers
        ip = client_ip(self.client_address[0], h.get("X-Real-IP"))
        method = (h.get("X-Forwarded-Method") or "").strip().upper()
        uri = h.get("X-Forwarded-Uri") or ""
        try:
            v = GATE.decide(method, uri, ip, h)
        except Exception as exc:          # a bug must fail closed, never open
            print(f"jf-gate: error deciding {method} {uri.partition('?')[0]!r}: {exc!r}",
                  file=sys.stderr, flush=True)
            v = Verdict(503, "gate_error", "token")

        path = uri.partition("?")[0][:300]
        ua = (h.get("User-Agent") or "-")[:120]
        if v.code == 200:
            if v.fresh and v.user:
                LOG.write("auth", user=v.user["name"], admin=v.user["admin"], ip=ip,
                          method=method, path=path, ua=ua, tok=v.tok)
            return self.reply(200)

        event = "would_deny" if MODE == "observe" else "deny"
        LOG.deny(event, ip, reason=v.reason, group=v.group, code=v.code,
                 method=method, path=path, ua=ua)
        if MODE == "observe":
            return self.reply(200)
        extra = (("Retry-After", str(BLOCK_SECONDS if v.reason == "too_many_bad_tokens"
                                     else LOGIN_WINDOW)),) if v.code == 429 else ()
        return self.reply(v.code, DENY_BODY.get(v.code, b'{"error":"denied"}'),
                          "application/json", extra)


def main():
    try:
        os.makedirs(LOG_DIR, exist_ok=True)
    except OSError:
        pass
    LOG.write("startup", mode=MODE, jellyfin=JELLYFIN_URL, base=BASE, token_ttl=TOKEN_TTL,
              recent_seconds=RECENT_SECONDS, recent_prefix_v4=RECENT_V4,
              login_max=LOGIN_MAX, login_window=LOGIN_WINDOW,
              bad_token_max=BAD_MAX, bad_token_window=BAD_WINDOW, block_seconds=BLOCK_SECONDS)
    server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    server.daemon_threads = True
    print(f"jf-gate: {MODE} mode, listening on :{PORT}, checking tokens with {JELLYFIN_URL}",
          flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
