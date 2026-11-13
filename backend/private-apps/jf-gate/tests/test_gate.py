#!/usr/bin/env python3
"""
jf-gate test suite. Standard library only; needs no network beyond loopback.

Starts a fake Jellyfin (just /jellyfin/Users/Me) and two gates (enforce + observe) with
short timers, then plays Caddy: GET /check with X-Forwarded-Method/-Uri and X-Real-IP.

    python -I tests/test_gate.py            # gate.py found next to tests/, or /app/gate.py
    GATE_PY=/path/to/gate.py python -I tests/test_gate.py
"""
import concurrent.futures
import glob
import http.client
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote_plus

HERE = os.path.dirname(os.path.abspath(__file__))
GATE_PY = os.environ.get("GATE_PY") or next(
    p for p in ("/app/gate.py", os.path.join(HERE, "..", "gate.py")) if os.path.exists(p))

ALICE = "a1" * 16          # normal user
BOB = "b2" * 16            # administrator
CAROL = "c3" * 16          # valid now, revoked during the test
APIKEY = "d4" * 16         # an API key: /Users/Me answers 400
ID = "0123456789abcdef0123456789abcdef"

# --------------------------------------------------------------------------- fake Jellyfin
STUB = {"users": {ALICE: ("alice", False), BOB: ("bob", True), CAROL: ("carol", False)},
        "calls": {}, "fail": False, "bad_auth_format": 0}
STUB_LOCK = threading.Lock()


class FakeJellyfin(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def do_GET(self):
        if self.path != "/jellyfin/Users/Me":
            return self.send(404, b"")
        auth = self.headers.get("Authorization", "")
        prefix, suffix = 'MediaBrowser Token="', '"'
        if not (auth.startswith(prefix) and auth.endswith(suffix)):
            with STUB_LOCK:
                STUB["bad_auth_format"] += 1
            return self.send(401, b"")
        token = unquote_plus(auth[len(prefix):-len(suffix)])
        with STUB_LOCK:
            STUB["calls"][token] = STUB["calls"].get(token, 0) + 1
            fail, user = STUB["fail"], STUB["users"].get(token)
        time.sleep(0.05)                       # so concurrent checks overlap
        if fail:
            return self.send(500, b"")
        if token == APIKEY:
            return self.send(400, b"")
        if not user:
            return self.send(401, b"")
        body = json.dumps({"Name": user[0], "Id": ID,
                           "Policy": {"IsAdministrator": user[1]}}).encode()
        self.send(200, body, "application/json")

    def send(self, code, body, ctype=None):
        self.send_response(code)
        if ctype:
            self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def calls(token):
    with STUB_LOCK:
        return STUB["calls"].get(token, 0)


# --------------------------------------------------------------------------- harness
def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def start_gate(mode, jf_port, log_dir):
    port = free_port()
    env = dict(os.environ, GATE_MODE=mode, PORT=str(port), LOG_DIR=log_dir,
               JELLYFIN_URL=f"http://127.0.0.1:{jf_port}/jellyfin",
               TOKEN_TTL="2", BAD_TTL="2", RECENT_SECONDS="3",
               LOGIN_MAX="3", LOGIN_WINDOW="60",
               BAD_TOKEN_MAX="3", BAD_TOKEN_WINDOW="60", BLOCK_SECONDS="3",
               LOG_DENY_MAX="1000", JF_TIMEOUT="3")
    proc = subprocess.Popen([sys.executable, "-I", GATE_PY], env=env,
                            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    for _ in range(100):
        try:
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=1)
            c.request("GET", "/healthz")
            if c.getresponse().status == 200:
                return proc, port
        except OSError:
            time.sleep(0.05)
    proc.kill()
    sys.exit(f"gate did not start: {proc.stderr.read().decode()}")


def ask(port, method, uri, ip="198.51.100.7", headers=None):
    """Play Caddy's forward_auth: returns (status, headers, body)."""
    h = {"X-Forwarded-Method": method, "X-Forwarded-Uri": uri, "X-Real-IP": ip,
         "User-Agent": "test-client/1.0"}
    h.update(headers or {})
    h = {k: v for k, v in h.items() if v is not None}
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    # Caddy's forward_auth keeps the client's query string on the auth request.
    query = (uri or "").partition("?")[2]
    c.request("GET", "/check" + ("?" + query if query else ""), headers=h)
    r = c.getresponse()
    body = r.read()
    c.close()
    return r.status, r, body


RESULTS = []


def check(name, cond, detail=""):
    RESULTS.append((name, bool(cond)))
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"   [{detail}]"))


def expect(port, name, method, uri, want, **kw):
    status, _, body = ask(port, method, uri, **kw)
    check(name, status == want, f"got {status} {body[:80]!r}")


def mb(token, scheme="MediaBrowser"):
    return f'{scheme} Client="Jellyfin Web", Device="Firefox", DeviceId="dGVzdA", Version="10.11.11", Token="{token}"'


# --------------------------------------------------------------------------- unit checks
def unit_checks():
    import importlib.util
    sys.dont_write_bytecode = True         # no __pycache__ next to gate.py
    os.environ.setdefault("LOG_DIR", tempfile.mkdtemp(prefix="gate-unit-"))
    spec = importlib.util.spec_from_file_location("gate_unit", GATE_PY)
    g = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(g)

    print("== unit: X-Real-IP is only believed from Caddy (a private peer)")
    check("private peer: X-Real-IP used", g.client_ip("172.20.0.2", "203.0.113.9") == "203.0.113.9")
    check("public peer: X-Real-IP ignored", g.client_ip("8.8.8.8", "203.0.113.9") == "8.8.8.8")
    check("garbage X-Real-IP: peer used", g.client_ip("172.20.0.2", "not-an-ip") == "172.20.0.2")
    check("recent-sign-in key is the /24", g.ip_net("203.0.113.77") == "203.0.113.0/24")

    print("== unit: Jellyfin's own GetParts test cases (DefaultAuthorizationHandlerTests.cs)")
    cases = [('x="123,123",y="123"', {"x": "123,123", "y": "123"}),
             ('x="123,123",         y="123",z="\'hi\'"', {"x": "123,123", "y": "123", "z": "'hi'"}),
             ('x="ab"', {"x": "ab"}),
             ("param=Hörbücher", {"param": "Hörbücher"}),
             ("param=%22%Hörbücher", {"param": '"%Hörbücher'})]
    for raw, want in cases:
        got = g.get_parts(raw)
        check(f"GetParts {raw!r}", all(got.get(k) == v for k, v in want.items()), got)


# --------------------------------------------------------------------------- tests
def main():
    unit_checks()
    jf = ThreadingHTTPServer(("127.0.0.1", 0), FakeJellyfin)
    jf.daemon_threads = True
    threading.Thread(target=jf.serve_forever, daemon=True).start()
    jf_port = jf.server_address[1]

    log_enf = tempfile.mkdtemp(prefix="gate-enforce-")
    log_obs = tempfile.mkdtemp(prefix="gate-observe-")
    enf, P = start_gate("enforce", jf_port, log_enf)
    obs, O = start_gate("observe", jf_port, log_obs)
    used_tokens = [ALICE, BOB, CAROL, APIKEY]

    try:
        print("== open to anyone (login screen, web client, branding)")
        for uri in ["/jellyfin", "/jellyfin/", "/jellyfin/web", "/jellyfin/web/",
                    "/jellyfin/web/index.html", "/jellyfin/web/main.jellyfin.bundle.js?abc123",
                    "/jellyfin/web/assets/img/icon-transparent.png",
                    "/jellyfin/web/node_modules.%40jellyfin.sdk.bundle.js",
                    "/jellyfin/System/Info/Public", "/jellyfin/system/info/public",
                    "/jellyfin/System/Info/Public/", "/jellyfin/System/Ping",
                    "/jellyfin/Branding/Configuration", "/jellyfin/Branding/Css",
                    "/jellyfin/Branding/Css.css", "/jellyfin/Branding/Splashscreen",
                    "/jellyfin/QuickConnect/Enabled", "/jellyfin/QuickConnect/Connect?Secret=abc",
                    "/jellyfin/emby/System/Info/Public"]:
            expect(P, f"GET {uri} -> 200", "GET", uri, 200)
        expect(P, "HEAD web file -> 200", "HEAD", "/jellyfin/web/index.html", 200)
        expect(P, "POST /System/Ping -> 200", "POST", "/jellyfin/System/Ping", 200)

        print("== everything else needs a token")
        for method, uri in [
                ("GET", "/jellyfin/Users/Public"),
                ("GET", "/jellyfin/web/ConfigurationPage?name=x"),
                ("GET", "/jellyfin/web/ConfigurationPages"),
                ("DELETE", "/jellyfin/System/Info/Public"),
                ("POST", "/jellyfin/Users/ForgotPassword"),
                ("POST", f"/jellyfin/Users/{ID}/Authenticate"),
                ("GET", f"/jellyfin/Videos/{ID}/stream?static=true"),
                ("GET", f"/jellyfin/Videos/{ID}/stream.mkv?static=true"),
                ("GET", f"/jellyfin/videos/{ID}/main.m3u8"),
                ("GET", f"/jellyfin/Audio/{ID}/stream"),
                ("GET", f"/jellyfin/Videos/{ID}/{ID}/Subtitles/0/Stream.vtt"),
                ("GET", f"/jellyfin/Videos/{ID}/hls/x/1.ts"),
                ("GET", "/jellyfin/socket"),
                ("GET", "/jellyfin/api-docs/openapi.json"),
                ("GET", "/jellyfin/health"),
                ("GET", "/jellyfin/Startup/Configuration"),
                ("GET", f"/jellyfin/Plugins/{ID}/1.0/Image"),
                ("GET", "/jellyfin/GetUtcTime"),
                ("GET", f"/jellyfin/Users/{ID}/Items"),
                ("OPTIONS", "/jellyfin/System/Info/Public")]:
            expect(P, f"{method} {uri.split('?')[0]} -> 401", method, uri, 401)

        print("== paths that only look open")
        for uri in [f"/jellyfin/web/../Users/{ID}/Items",
                    "/jellyfin/web/%2e%2e/Users", "/jellyfin/web/%2E%2E/Users",
                    "/jellyfin/web/..%2fUsers", "/jellyfin/web//etc/passwd",
                    "/jellyfin/web\\..\\Users",
                    f"/jellyfin/System/Info/Public/../../Videos/{ID}/stream",
                    f"/jellyfin/Items/{ID}/Images/Primary/../../../Videos/{ID}/stream",
                    "/jellyfin/embyweb/index.html", "/jellyfin/web/a b",
                    "/jellyfin/web/%43onfigurationPage?name=x", "/jellyfin/web/%2540"]:
            expect(P, f"GET {uri} -> 401", "GET", uri, 401)
        expect(P, "outside the base URL (/jellyfinx) -> 403", "GET", "/jellyfinx/System/Info/Public", 403)
        expect(P, "outside the base URL (/) -> 403", "GET", "/", 403)
        expect(P, "no X-Forwarded-Uri -> 400", "GET", None, 400)

        print("== login attempts are rate-limited per IP (LOGIN_MAX=3 in tests)")
        codes = [ask(P, "POST", "/jellyfin/Users/AuthenticateByName", ip="192.0.2.10")[0] for _ in range(4)]
        check("3 logins pass, the 4th gets 429", codes == [200, 200, 200, 429], codes)
        status, r, _ = ask(P, "POST", "/jellyfin/Users/AuthenticateByName", ip="192.0.2.10")
        check("429 carries Retry-After", status == 429 and r.getheader("Retry-After"), r.getheader("Retry-After"))
        expect(P, "another IP can still log in", "POST", "/jellyfin/Users/AuthenticateByName", 200, ip="192.0.2.11")
        codes = [ask(P, "POST", "/jellyfin/QuickConnect/Initiate", ip="192.0.2.12")[0] for _ in range(4)]
        check("Quick Connect initiation counts as a login", codes == [200, 200, 200, 429], codes)

        print("== every way Jellyfin accepts a token")
        carriers = {
            "Authorization: MediaBrowser": {"Authorization": mb(ALICE)},
            "Authorization: Emby (legacy)": {"Authorization": mb(ALICE, "Emby")},
            "X-Emby-Authorization": {"X-Emby-Authorization": mb(ALICE)},
            "X-Emby-Token": {"X-Emby-Token": ALICE},
            "X-MediaBrowser-Token": {"X-MediaBrowser-Token": ALICE},
        }
        for name, hdrs in carriers.items():
            expect(P, f"{name} -> 200", "GET", f"/jellyfin/Users/{ID}/Items", 200, headers=hdrs)
        for q in ("ApiKey", "api_key", "APIKEY", "Api_Key"):
            expect(P, f"?{q}= -> 200", "GET", f"/jellyfin/Videos/{ID}/stream?static=true&{q}={ALICE}", 200)
        enc = "".join("%%%02x" % ord(ch) for ch in ALICE[:4]) + ALICE[4:]
        expect(P, "URL-encoded token inside the header -> 200", "GET", "/jellyfin/Users/Me", 200,
               headers={"Authorization": mb(enc)})
        expect(P, "websocket /socket?api_key= -> 200", "GET", f"/jellyfin/socket?api_key={ALICE}&deviceId=x", 200)
        expect(P, "the login POST's token-less header still falls through to ?ApiKey=", "GET",
               f"/jellyfin/Items?ApiKey={ALICE}", 200,
               headers={"Authorization": 'MediaBrowser Client="Jellyfin Web", Device="Firefox"'})

        print("== same precedence as Jellyfin")
        expect(P, "Bearer header hides X-Emby-Authorization (as in Jellyfin) -> 401", "GET", "/jellyfin/Items", 401,
               headers={"Authorization": "Bearer xyz", "X-Emby-Authorization": mb(ALICE)})
        expect(P, "header token wins over a bad ?ApiKey -> 200", "GET", f"/jellyfin/Items?ApiKey={'e5' * 16}", 200,
               headers={"Authorization": mb(ALICE)})
        expect(P, "bad header token wins over a good ?ApiKey -> 401", "GET", f"/jellyfin/Items?ApiKey={ALICE}", 401,
               headers={"Authorization": mb("f6" * 16)}, ip="198.51.100.20")
        expect(P, "duplicate ?ApiKey= values are joined (as ASP.NET does) -> 401", "GET",
               f"/jellyfin/Items?ApiKey={ALICE}&ApiKey={ALICE}", 401, ip="198.51.100.21")

        print("== tokens Jellyfin rejects")
        expect(P, "unknown token -> 401", "GET", "/jellyfin/Items", 401,
               headers={"X-Emby-Token": "17" * 16}, ip="198.51.100.30")
        expect(P, "API key (no user behind it) -> 401", "GET", "/jellyfin/Items", 401,
               headers={"X-Emby-Token": APIKEY}, ip="198.51.100.31")
        before = sum(STUB["calls"].values())
        expect(P, "garbage token -> 401 without asking Jellyfin", "GET", "/jellyfin/Items", 401,
               headers={"X-Emby-Token": 'x" y'}, ip="198.51.100.32")
        check("...and Jellyfin was not asked", sum(STUB["calls"].values()) == before)
        check("the gate always asks Jellyfin with a clean MediaBrowser header",
              STUB["bad_auth_format"] == 0, STUB["bad_auth_format"])
        expect(P, "admin token passes (decision 1A)", "GET", "/jellyfin/System/Configuration", 200,
               headers={"X-Emby-Token": BOB})

        print("== cache: Jellyfin is asked once per token per TOKEN_TTL")
        n0 = calls(CAROL)
        for _ in range(5):
            ask(P, "GET", "/jellyfin/Items", headers={"X-Emby-Token": CAROL})
        check("5 requests, 1 check", calls(CAROL) == n0 + 1, calls(CAROL) - n0)
        with STUB_LOCK:
            del STUB["users"][CAROL]          # revoked in Jellyfin
        expect(P, "revoked token still passes until the cache entry expires", "GET", "/jellyfin/Items", 200,
               headers={"X-Emby-Token": CAROL})
        time.sleep(2.2)
        expect(P, "...and is refused after TOKEN_TTL", "GET", "/jellyfin/Items", 401,
               headers={"X-Emby-Token": CAROL})
        fresh = "29" * 16
        with STUB_LOCK:
            STUB["users"][fresh] = ("dave", False)
        used_tokens.append(fresh)
        with concurrent.futures.ThreadPoolExecutor(20) as pool:
            codes = list(pool.map(lambda _: ask(P, "GET", "/jellyfin/Items",
                                                headers={"X-Emby-Token": fresh})[0], range(20)))
        check("20 simultaneous requests with a new token -> all 200", codes == [200] * 20, codes)
        check("...with a single check against Jellyfin", calls(fresh) == 1, calls(fresh))

        print("== images and fonts: only for a /24 that signed in recently (RECENT_SECONDS=3)")
        img = f"/jellyfin/Items/{ID}/Images/Primary?fillHeight=300&quality=96&tag=abc"
        att = f"/jellyfin/Videos/{ID}/{ID}/Attachments/3"
        expect(P, "image from a stranger -> 401", "GET", img, 401, ip="203.0.113.50")
        expect(P, "font attachment from a stranger -> 401", "GET", att, 401, ip="203.0.113.50")
        expect(P, "same /24 signs in", "GET", "/jellyfin/Items", 200,
               headers={"X-Emby-Token": ALICE}, ip="203.0.113.60")
        expect(P, "image from that /24 -> 200", "GET", img, 200, ip="203.0.113.50")
        expect(P, "HEAD image from that /24 -> 200", "HEAD", img, 200, ip="203.0.113.51")
        expect(P, "font attachment from that /24 -> 200", "GET", att, 200, ip="203.0.113.50")
        expect(P, "person image (encoded name) -> 200", "GET", "/jellyfin/Persons/John%20Doe/Images/Primary", 200, ip="203.0.113.50")
        expect(P, "encoded dot-dot as a name, even from that /24 -> 401", "GET",
               "/jellyfin/Persons/%2e%2e/Images/Primary", 401, ip="203.0.113.50")
        expect(P, "encoded slash in a name, even from that /24 -> 401", "GET",
               "/jellyfin/Artists/AC%2FDC/Images/Primary", 401, ip="203.0.113.50")
        expect(P, "user avatar -> 200", "GET", f"/jellyfin/Users/{ID}/Images/Primary", 200, ip="203.0.113.50")
        expect(P, "image from another /24 -> 401", "GET", img, 401, ip="192.0.2.50")
        expect(P, "image with its own valid token, from anywhere -> 200", "GET", img + f"&api_key={ALICE}", 200, ip="192.0.2.99")
        expect(P, "a stream is never 'recent' -> 401 without a token", "GET",
               f"/jellyfin/Videos/{ID}/stream?static=true", 401, ip="203.0.113.50")
        time.sleep(3.2)
        expect(P, "image after RECENT_SECONDS -> 401", "GET", img, 401, ip="203.0.113.50")

        print("== an IP sending many bad tokens is slowed down (BAD_TOKEN_MAX=3, BLOCK_SECONDS=3)")
        bad_ip = "198.51.100.66"
        good_cached = "38" * 16
        with STUB_LOCK:
            STUB["users"][good_cached] = ("erin", False)
        used_tokens.append(good_cached)
        expect(P, "a valid token used before the block", "GET", "/jellyfin/Items", 200,
               headers={"X-Emby-Token": good_cached}, ip=bad_ip)
        codes = [ask(P, "GET", "/jellyfin/Items", headers={"X-Emby-Token": f"{i:032x}"}, ip=bad_ip)[0]
                 for i in range(1, 5)]
        check("4 different bad tokens -> 401 each", codes == [401] * 4, codes)
        new_valid = "47" * 16
        with STUB_LOCK:
            STUB["users"][new_valid] = ("frank", False)
        used_tokens.append(new_valid)
        expect(P, "now even a new valid token from that IP waits -> 429", "GET", "/jellyfin/Items", 429,
               headers={"X-Emby-Token": new_valid}, ip=bad_ip)
        expect(P, "an already-checked token still works from that IP", "GET", "/jellyfin/Items", 200,
               headers={"X-Emby-Token": good_cached}, ip=bad_ip)
        expect(P, "other IPs are unaffected", "GET", "/jellyfin/Items", 200,
               headers={"X-Emby-Token": new_valid}, ip="198.51.100.67")
        time.sleep(3.2)
        expect(P, "after BLOCK_SECONDS the new token works", "GET", "/jellyfin/Items", 200,
               headers={"X-Emby-Token": new_valid}, ip=bad_ip)

        print("== Jellyfin down: fail closed for tokens, login screen still loads")
        down = "56" * 16
        with STUB_LOCK:
            STUB["fail"] = True
            STUB["users"][down] = ("gina", False)
        used_tokens.append(down)
        expect(P, "new token while Jellyfin errors -> 503", "GET", "/jellyfin/Items", 503,
               headers={"X-Emby-Token": down}, ip="198.51.100.80")
        expect(P, "open path while Jellyfin errors -> 200", "GET", "/jellyfin/web/index.html", 200)
        with STUB_LOCK:
            STUB["fail"] = False
        expect(P, "...and the token works once Jellyfin is back (errors are not cached)", "GET",
               "/jellyfin/Items", 200, headers={"X-Emby-Token": down}, ip="198.51.100.80")

        print("== responses")
        status, r, body = ask(P, "GET", f"/jellyfin/Videos/{ID}/stream", ip="198.51.100.90")
        check("deny is JSON", status == 401 and r.getheader("Content-Type") == "application/json"
              and json.loads(body)["error"], (status, r.getheader("Content-Type"), body))
        check("deny has no Server header", r.getheader("Server") is None, r.getheader("Server"))
        check("deny is not cacheable", r.getheader("Cache-Control") == "no-store")
        s = socket.create_connection(("127.0.0.1", P), timeout=5)
        req = ("GET /check HTTP/1.1\r\nHost: jf-gate\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n"
               "Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
               f"X-Forwarded-Method: GET\r\nX-Forwarded-Uri: /jellyfin/socket?api_key={ALICE}\r\n"
               "X-Real-IP: 198.51.100.91\r\n\r\n")
        s.sendall(req.encode())
        first = s.recv(4096).split(b"\r\n", 1)[0]
        s.close()
        check("a websocket upgrade check gets a plain 200 (Caddy then upgrades to Jellyfin)",
              first == b"HTTP/1.1 200 OK", first)

        print("== observe mode: decides, logs, blocks nothing")
        expect(O, "stream without token -> 200 in observe", "GET", f"/jellyfin/Videos/{ID}/stream", 200,
               ip="198.51.100.95")
        codes = [ask(O, "POST", "/jellyfin/Users/AuthenticateByName", ip="198.51.100.96")[0] for _ in range(5)]
        check("login rate limit is only logged in observe", codes == [200] * 5, codes)

        print("== logs")
        time.sleep(0.2)
        enf_lines = [json.loads(l) for f in glob.glob(f"{log_enf}/gate-*.jsonl") for l in open(f)]
        obs_lines = [json.loads(l) for f in glob.glob(f"{log_obs}/gate-*.jsonl") for l in open(f)]
        raw = "".join(open(f).read() for f in glob.glob(f"{log_enf}/*") + glob.glob(f"{log_obs}/*"))
        check("startup line in both modes", any(l["event"] == "startup" and l["mode"] == "enforce" for l in enf_lines)
              and any(l["event"] == "startup" and l["mode"] == "observe" for l in obs_lines))
        check("auth line names the user and admin flag",
              any(l["event"] == "auth" and l["user"] == "bob" and l["admin"] is True for l in enf_lines))
        check("deny lines carry a reason",
              any(l["event"] == "deny" and l["reason"] == "no_token" for l in enf_lines))
        check("observe logs would_deny (no_token, login_rate)",
              {"no_token", "login_rate"} <= {l.get("reason") for l in obs_lines if l["event"] == "would_deny"})
        check("no token appears anywhere in the logs", not any(t in raw for t in used_tokens))
        check("no query string appears in logged paths",
              all("?" not in l.get("path", "") for l in enf_lines + obs_lines))
    finally:
        for proc in (enf, obs):
            proc.terminate()
            proc.wait(5)
        jf.shutdown()

    passed = sum(ok for _, ok in RESULTS)
    print(f"\n{passed}/{len(RESULTS)} checks passed")
    sys.exit(0 if passed == len(RESULTS) else 1)


if __name__ == "__main__":
    main()
