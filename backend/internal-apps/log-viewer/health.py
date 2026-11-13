"""Health checks and the numbers behind the Health tab.

The prober runs inside the viewer. Every 5 minutes it fetches https://<name>/?lvprobe=<token>
for each name Caddy itself serves (from Caddy's own startup line, never a name a client sent)
and writes one standard record per site to health-YYYY-MM.jsonl. A site is up for any status
below 500; a site whose status differs from its usual one (the commonest over 7 days) is
flagged too, so a page that starts answering 404 shows up, and so does a certificate that is
close to expiring. Everything else comes from the collector's files and ALERTS.log.
"""
import http.client
import json
import os
import re
import secrets
import ssl
import time
from collections import Counter, defaultdict
from pathlib import Path

import helper
from helper import LOGS, human, iso

OUT = Path(os.environ.get("APP_LOG_DIR", "/logs"))   # this app's own log folder, the only one it writes
EVERY = 300
CERT_DAYS = 14
DISK_MIN = 20e9          # flag the project disk below this much free space
STORAGE_ALIAS = {        # folders named after neither a container nor an app
    "media": "jellyfin", "storage": "copyparty", "backups": "copyparty",
    "docker": "syslog", "security": "log-collector", "metrics": "log-collector"}
_HOST = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$")
SEVERITY = {"critical": 0, "warning": 1, "notice": 2}


# ---------------------------------------------------------------- this app's own records

def write(prefix, record):
    """Appends one standard record to <prefix>-YYYY-MM.jsonl in this app's log folder."""
    line = json.dumps({"ts": iso(time.time())} | record, separators=(",", ":"), ensure_ascii=False)
    with open(OUT / f"{prefix}-{time.strftime('%Y-%m', time.gmtime())}.jsonl", "a", encoding="utf-8") as f:
        f.write(line + "\n")


def event(name, **fields):
    try:
        write("log-viewer", {"event": name} | fields)
    except OSError:
        pass


def token():
    """The random mark that tells this viewer's probes apart from real visits, kept in state.json."""
    p = OUT / "state.json"
    try:
        t = json.loads(p.read_text()).get("probe_token")
        if isinstance(t, str) and re.fullmatch(r"[0-9a-f]{24}", t):
            return t
    except (OSError, ValueError, AttributeError):
        pass
    t = secrets.token_hex(12)
    p.write_text(json.dumps({"probe_token": t}) + "\n")
    return t


# ---------------------------------------------------------------- probing

def sites():
    """The names Caddy serves: its newest 'enabling automatic TLS certificate management' line,
    per Caddy, in caddy.log or the rolled copies."""
    names = set()
    for d in sorted((LOGS / "caddy").glob("caddy-*")):
        for p in [d / "caddy.log", *sorted(d.glob("caddy-[0-9]*.log*"), reverse=True)]:
            found = None
            for j in helper.json_lines(p):
                if j.get("msg") == "enabling automatic TLS certificate management" and isinstance(j.get("domains"), list):
                    found = j["domains"]
            if found is not None:
                names.update(n.lower() for n in found if isinstance(n, str) and _HOST.match(n.lower()))
                break
    return sorted(names)


def probe(host, mark):
    r, t0 = {"event": "probe", "host": host, "ok": False}, time.monotonic()
    c = http.client.HTTPSConnection(host, 443, timeout=10, context=ssl.create_default_context())
    try:
        c.request("GET", "/?lvprobe=" + mark, headers={"User-Agent": "log-viewer/1", "Connection": "close"})
        r["ip"] = c.sock.getpeername()[0]
        if notafter := (c.sock.getpeercert() or {}).get("notAfter"):
            r["cert_days"] = round((ssl.cert_time_to_seconds(notafter) - time.time()) / 86400, 1)
        resp = c.getresponse()
        r["code"], r["ms"], r["ok"] = resp.status, round((time.monotonic() - t0) * 1000), resp.status < 500
        resp.read(65536)
    except (OSError, http.client.HTTPException, ValueError) as e:
        r["error"] = f"{type(e).__name__}: {e}"[:200]
    finally:
        c.close()
    return r


def run_prober(mark):
    while True:
        try:
            for host in sites():
                write("health", probe(host, mark))
        except Exception as e:
            event("error", where="prober", error=f"{type(e).__name__}: {e}"[:300])
        time.sleep(EVERY - time.time() % EVERY + 1)


# ---------------------------------------------------------------- the Health tab

def _jsonl(pattern, since):
    for p in sorted(LOGS.glob(pattern)):
        try:
            if p.stat().st_mtime < since:
                continue
        except OSError:
            continue
        for j in helper.json_lines(p):
            t = helper.parse_ts(j.get("ts"))
            if t is not None and t >= since:
                j["_t"] = t
                yield j


def _when(t):
    return helper.local(t, "%b %d %H:%M")


def ago(s):
    s = max(0, s)
    return f"{s:.0f} s" if s < 120 else f"{s / 60:.0f} min" if s < 7200 else f"{s / 3600:.0f} h" if s < 172800 else f"{s / 86400:.0f} d"


def overview(hours, now=None):
    now = now or time.time()
    t0 = now - hours * 3600
    snaps = list(_jsonl("security/snapshot-*.jsonl", t0))
    stats, sizes = [], None
    for j in _jsonl("metrics/metrics-*.jsonl", min(t0, now - 7200)):
        if j.get("event") == "sizes":
            sizes = j
        elif j.get("event") == "stats" and j["_t"] >= t0:
            stats.append(j)
    probes = list(_jsonl("internal-apps/log-viewer/app/health-*.jsonl", now - 7 * 86400))
    alerts = sorted(helper.alert_repeats(helper.alerts(LOGS / "security" / "ALERTS.log", None, {})), key=lambda r: r["ts"], reverse=True)
    o = {"now": now, "t0": t0, "hours": hours, "attention": [], "alerts": alerts[:15]}
    _sites(o, probes)
    _tunnels(o, snaps)
    _containers(o, snaps, stats, sizes)
    _storage(o, sizes)
    o["attention"].sort(key=lambda a: SEVERITY[a[0]])
    return o


def _sites(o, probes):
    now, t0, flag = o["now"], o["t0"], o["attention"].append
    by = defaultdict(list)
    for p in probes:
        if isinstance(p.get("host"), str):
            by[p["host"]].append(p)
    served = set(sites())
    o["sites"] = []
    for host in sorted(served | {h for h, ps in by.items() if ps[-1]["_t"] >= t0}):
        ps = sorted(by.get(host, []), key=lambda p: p["_t"])
        rng = [p for p in ps if p["_t"] >= t0]
        codes = Counter(p.get("code") for p in ps if p.get("code"))
        usual = codes.most_common(1)[0][0] if codes else None
        last = ps[-1] if ps else None
        o["sites"].append({"host": host, "last": last, "usual": usual,
                           "uptime": 100 * sum(1 for p in rng if p.get("ok")) / len(rng) if rng else None,
                           "series": [(p["_t"], p["ms"]) for p in rng if p.get("ok") and isinstance(p.get("ms"), (int, float))],
                           "cells": _cells(rng, t0, now)})
        if not last:
            continue
        run = [p for p in ps if p["_t"] > max([q["_t"] for q in ps if (q.get("ok"), q.get("code")) != (last.get("ok"), last.get("code"))] or [0])]
        if not last.get("ok"):
            flag(("critical", f"{host} is down since {_when(run[0]['_t'])}: {last.get('error') or last.get('code')}"))
        elif usual and last.get("code") != usual and len(run) >= 2:
            flag(("warning", f"{host} answers {last.get('code')}, usually {usual} (since {_when(run[0]['_t'])})"))
        if isinstance(last.get("cert_days"), (int, float)) and last["cert_days"] < CERT_DAYS:
            flag(("warning", f"{host}: certificate expires in {last['cert_days']:.0f} days"))
        if host in served and now - last["_t"] > 3 * EVERY:
            flag(("warning", f"{host}: no probe since {_when(last['_t'])}"))


def _cells(rng, t0, now, n=48):
    w = (now - t0) / n
    cells = [[t0 + i * w, 0, 0] for i in range(n)]
    for p in rng:
        c = cells[min(n - 1, int((p["_t"] - t0) // w))]
        c[1] += 1 if p.get("ok") else 0
        c[2] += 1
    return cells


def _tunnels(o, snaps):
    now, flag = o["now"], o["attention"].append
    full = [s for s in snaps if isinstance(s.get("tunnels"), list)]
    last = snaps[-1] if snaps else None
    if not last:
        flag(("warning", "no security snapshot yet: is log-collector running?"))
    elif now - last["_t"] > 900:
        flag(("critical", f"no security snapshot since {_when(last['_t'])}: is log-collector running?"))
    elif last.get("docker") == "unreachable":
        flag(("critical", "the collector can't reach Docker"))
    o["snapshot"] = full[-1] if full else {"tunnels": [], "containers": [], "_t": now}
    o["tunnels"] = []
    for t in o["snapshot"]["tunnels"]:
        c, hs = t.get("container"), t.get("handshake")
        t = dict(t, age=now - hs if isinstance(hs, int) and hs > 0 else None)
        o["tunnels"].append(t)
        if not t.get("running"):
            flag(("critical", f"{c} is not running"))
            continue
        if t.get("ks_rules") == 0:
            flag(("critical", f"{c}: kill switch missing"))
        if t.get("forward_policy") not in ("DROP", "unknown"):
            flag(("critical", f"{c}: FORWARD policy is {t.get('forward_policy')}"))
        if t.get("ip_forward") == 1:
            flag(("critical", f"{c}: ip_forward is on"))
        if hs == 0:
            flag(("warning", f"{c}: no handshake yet"))
        elif t["age"] and o["snapshot"]["_t"] - hs > 300:        # stale when the snapshot was taken (WireGuard renews every 2 min)
            flag(("warning", f"{c}: last handshake {ago(t['age'])} ago"))
    history = defaultdict(list)                     # the kill-switch counter: flag any nonzero value and any decrease
    for s in full:
        for t in s["tunnels"]:
            if t.get("running") and isinstance(t.get("ks_pkts"), int):
                history[t.get("container")].append((s["_t"], t["ks_pkts"]))
    for c, h in sorted(history.items()):
        if hits := [(ts, p) for ts, p in h if p > 0]:
            flag(("critical", f"{c}: kill switch dropped {max(p for _, p in hits)} packets (last seen {_when(hits[-1][0])})"))
        if resets := [(h[i][0], h[i - 1][1]) for i in range(1, len(h)) if 0 <= h[i][1] < h[i - 1][1]]:
            flag(("warning", f"{c}: kill-switch counter reset at {_when(resets[-1][0])} (was {resets[-1][1]}); see ALERTS.log"))


def _containers(o, snaps, stats, sizes):
    now, flag = o["now"], o["attention"].append
    current = {c.get("name") for c in o["snapshot"]["containers"]}
    seen = {}
    for s in snaps:
        for c in s.get("containers") or []:
            seen[c.get("name")] = s["_t"]
    for name in sorted(n for n in set(seen) - current if n):
        flag(("warning", f"{name} is gone (last seen {_when(seen[name])})"))
    restarts, last = {}, {}                         # restart-count increases between snapshots in this window
    for s in snaps:
        for c in s.get("containers") or []:
            n, r = c.get("name"), c.get("restarts")
            if isinstance(r, int) and r >= 0:
                if n in last and r > last[n]:
                    restarts[n] = (restarts.get(n, (0,))[0] + r - last[n], s["_t"])
                last[n] = r
    for name, (n, t) in sorted(restarts.items()):
        flag(("warning", f"{name} restarted {n} time{'s' if n > 1 else ''} in this window (last by {_when(t)})"))
    apps = helper.app_folders()                   # every app, by stack; sizes add those with no logs yet
    for k in (sizes or {}).get("sizes", {}):
        parts = k.split("/")
        if len(parts) == 3 and parts[1].endswith("-apps") and parts[1][:-5] in apps:
            apps[parts[1][:-5]].add(parts[2])
    o["apps"] = apps
    latest = stats[-1].get("containers") or {} if stats else {}
    if stats and now - stats[-1]["_t"] > 300:
        flag(("warning", f"no CPU/memory sample since {_when(stats[-1]['_t'])}"))
    o["containers"] = []
    for c in o["snapshot"]["containers"]:
        name, st, h = c.get("name") or "?", c.get("status"), c.get("health")
        if st in ("restarting", "dead") or h == "unhealthy":
            flag(("critical", f"{name} is {h if h == 'unhealthy' else st}"))
        elif st != "running":
            flag(("warning", f"{name} is {st}"))
        o["containers"].append(dict(c, stack=helper.stack_of(name, apps), **(latest.get(name) or {})))
    o["containers"].sort(key=lambda c: (c["stack"], c["name"]))
    o["series"] = {"cpu": defaultdict(dict), "mem": defaultdict(dict)}     # what -> stack -> name -> [(t, v)]
    for s in stats:
        for name, v in (s.get("containers") or {}).items():
            for what in ("cpu", "mem"):
                if isinstance(v, dict) and isinstance(v.get(what), (int, float)):
                    o["series"][what][helper.stack_of(name, apps)].setdefault(name, []).append((s["_t"], v[what]))
    o["known"] = set(seen) | set(latest) | set().union(*apps.values())   # storage owners: containers and apps


def _storage(o, sizes):
    o["storage"], o["disk"] = [], None
    if not sizes or not isinstance(sizes.get("sizes"), dict):
        return
    rows = defaultdict(lambda: defaultdict(int))
    for key, n in sizes["sizes"].items():
        parts = key.split("/")
        owner = next((x if x in o["known"] else STORAGE_ALIAS[x] for x in reversed(parts[1:])
                      if x in o["known"] or x in STORAGE_ALIAS), "other")
        rows[owner][parts[0]] += n if isinstance(n, int) else 0
    o["storage"] = sorted(((app, dict(c), sum(c.values())) for app, c in rows.items()), key=lambda r: -r[2])
    disk = sizes.get("disk") if isinstance(sizes.get("disk"), dict) else {}
    logs = sum(n for k, n in sizes["sizes"].items() if k.startswith("logs/") and isinstance(n, int))
    o["disk"] = dict(disk, logs=logs, at=sizes["_t"])
    if isinstance(disk.get("free"), int) and disk["free"] < DISK_MIN:
        o["attention"].append(("critical", f"only {human(disk['free'])} free on the project disk"))
