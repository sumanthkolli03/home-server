"""The collector: the only container with the Docker socket. It has no network
and reads no log, so nothing a stranger wrote reaches it. It imports nothing from the viewer.

every minute  CPU and memory per running container  -> metrics/metrics-YYYY-MM.jsonl
every 5 min   the security snapshot and its alerts (tunnels, kill switches, containers)
                                               -> security/snapshot-YYYY-MM.jsonl, ALERTS.log
every hour    folder sizes (two levels deep) and free disk space -> metrics/metrics-YYYY-MM.jsonl
Its own events (startup, errors) go to /logs/log-collector-YYYY-MM.jsonl. Months are UTC.
Never runs `wg show ... dump`: its first line is the private key.
"""
import http.client
import json
import os
import re
import socket
import struct
import time

SOCK = os.environ.get("DOCKER_SOCK", "/var/run/docker.sock")
PROJECT = os.environ.get("PROJECT_DIR", "/srv")              # read-only; only ever stat()ed
SECURITY = os.environ.get("SECURITY_DIR", "/out/security")
METRICS = os.environ.get("METRICS_DIR", "/out/metrics")
EVENTS = os.environ.get("EVENTS_DIR", "/logs")
TOPS = ("backend", "internal-config", "logs", "shared-files")
TUNNEL_SH = ("iptables -L OUTPUT -n -v -x; echo @@; iptables -L FORWARD -n; echo @@; cat /proc/sys/net/ipv4/ip_forward;"
             " echo @@; wg show wg0 latest-handshakes; echo @@; wg show wg0 transfer; echo @@; ip -4 -o addr show wg0")
PREVIOUS = {}         # container id -> (cpu total, system total) from the last minute


# ---------------------------------------------------------------- Docker over its socket

class _Conn(http.client.HTTPConnection):
    def __init__(self):
        super().__init__("localhost", timeout=15)

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(SOCK)


def api(method, path, body=None):
    c = _Conn()
    try:
        c.request(method, path, body=None if body is None else json.dumps(body),
                  headers={} if body is None else {"Content-Type": "application/json"})
        r = c.getresponse()
        data = r.read()                  # exec output streams until Docker closes the connection
        if r.status >= 400:
            raise OSError(f"docker {method} {path.split('?')[0]}: {r.status} {data[:200]!r}")
        return data
    finally:
        c.close()


def jget(path):
    return json.loads(api("GET", path))


def run(cid, script):
    """stdout of `sh -c script` in a container; stderr is never attached ('2>/dev/null')."""
    ex = json.loads(api("POST", f"/containers/{cid}/exec", {"AttachStdout": True, "AttachStderr": False, "Cmd": ["sh", "-c", script]}))
    raw, out, i = api("POST", f"/exec/{ex['Id']}/start", {"Detach": False, "Tty": False}), [], 0
    while i + 8 <= len(raw):             # Docker's stream: 1 byte stream id, 3 zero, 4 bytes length
        size = struct.unpack(">I", raw[i + 4:i + 8])[0]
        if raw[i] == 1:
            out.append(raw[i + 8:i + 8 + size])
        i += 8 + size
    return b"".join(out).decode("utf-8", "replace")


# ---------------------------------------------------------------- the security snapshot

def num(s):
    s = (s or "").strip()
    return int(s) if re.fullmatch(r"-?\d+", s) else -1


def first_line(s):
    lines = (s or "").strip().splitlines()
    return lines[0].split() if lines else []


def tunnel(info, output):
    """One tunnels[] entry and its alert texts, from `docker inspect` and TUNNEL_SH's output."""
    name = info["Name"].removeprefix("/")
    if not (info.get("State") or {}).get("Running"):
        return {"container": name, "running": False}, []
    ipt, fwd, ipf, hs, tr, addr = (output.split("@@\n") + [""] * 6)[:6]
    ip = m[1] if (m := re.search(r"inet (\d+\.\d+\.\d+\.\d+)/", addr)) else None
    rules = pkts = nbytes = -1
    if ipt.strip():                      # -A OUTPUT -s <tunnel address> ! -o wg0 -j DROP, with -x counts
        rules = pkts = nbytes = 0
        for line in ipt.splitlines():
            f = line.split()
            if "DROP" in line and "!wg0" in line and (f" {ip} " in line if ip else True) and len(f) > 1:
                rules += 1
                pkts += int(f[0]) if f[0].isdigit() else 0
                nbytes += int(f[1]) if f[1].isdigit() else 0
    head = [w.strip("()") for w in first_line(fwd)]
    policy = head[3] if len(head) > 3 and re.fullmatch(r"[A-Z]+", head[3]) else "unknown"
    ipf, hs = num(ipf), num((first_line(hs) + ["", ""])[1])
    rx, tx = (num(x) for x in (first_line(tr) + ["-1", "-1", "-1"])[1:3]) if tr.strip() else (-1, -1)
    alerts = []
    if rules == 0:
        alerts.append(f"KILLSWITCH_MISSING: no DROP rule for {ip or 'wg0 (no address)'} in OUTPUT")
    if pkts > 0:
        alerts.append(f"KILLSWITCH_HIT: pkts={pkts} bytes={nbytes}")
    if policy not in ("DROP", "unknown"):
        alerts.append(f"FORWARD_POLICY: {policy} (want DROP)")
    if ipf == 1:
        alerts.append("IP_FORWARD: 1 (want 0)")
    return {"container": name, "running": True, "ks_rules": rules, "ks_pkts": pkts, "ks_bytes": nbytes,
            "forward_policy": policy, "ip_forward": ipf, "handshake": hs, "rx": rx, "tx": tx}, alerts


def container(info):
    st = info.get("State") or {}
    return {"name": info.get("Name", "").removeprefix("/"), "status": st.get("Status"),
            "health": (st.get("Health") or {}).get("Status") if st.get("Health") else None,
            "started": st.get("StartedAt"), "restarts": info.get("RestartCount"),
            "image": (info.get("Config") or {}).get("Image"), "image_id": str(info.get("Image", ""))[:19]}


def snapshot():
    ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    try:
        api("GET", "/version")
    except (OSError, http.client.HTTPException):
        return append(SECURITY, f"snapshot-{ts[:7]}.jsonl", {"v": 1, "ts": ts, "docker": "unreachable"})
    infos = []
    for c in jget("/containers/json?all=1"):         # newest first, like `docker ps -aq`
        try:
            infos.append(jget(f"/containers/{c['Id']}/json"))
        except OSError:                              # removed in between
            pass
    tunnels, alerts = [], []
    for info in sorted((i for i in infos if i.get("Name", "").startswith("/wg-")), key=lambda i: i["Name"]):
        try:
            output = run(info["Id"], TUNNEL_SH) if (info.get("State") or {}).get("Running") else ""
        except (OSError, ValueError, KeyError, http.client.HTTPException):
            output = ""                              # couldn't read: -1 everywhere, recorded, not alerted
        t, a = tunnel(info, output)
        tunnels.append(t)
        alerts += [f"{ts} {t['container']:<9} {text}\n" for text in a]
    if alerts:
        with open(os.path.join(SECURITY, "ALERTS.log"), "a", encoding="utf-8") as f:
            f.writelines(alerts)
    append(SECURITY, f"snapshot-{ts[:7]}.jsonl", {"v": 1, "ts": ts, "tunnels": tunnels, "containers": [container(i) for i in infos]})


# ---------------------------------------------------------------- metrics

def stats():
    out, seen = {}, set()
    for c in jget("/containers/json"):
        try:
            s = jget(f"/containers/{c['Id']}/stats?stream=false&one-shot=true")
        except (OSError, ValueError):
            continue
        cpu, mem = s.get("cpu_stats") or {}, s.get("memory_stats") or {}
        total, system = (cpu.get("cpu_usage") or {}).get("total_usage"), cpu.get("system_cpu_usage")
        pct, prev = None, PREVIOUS.get(c["Id"])
        if prev and total is not None and system and system > prev[1] and total >= prev[0]:
            pct = round((total - prev[0]) / (system - prev[1]) * (cpu.get("online_cpus") or 1) * 100, 1)
        if total is not None and system:
            PREVIOUS[c["Id"]] = (total, system)
            seen.add(c["Id"])
        used, extra = mem.get("usage"), mem.get("stats") or {}
        if isinstance(used, int):            # what `docker stats` shows: usage minus the file cache
            used -= extra.get("inactive_file", extra.get("total_inactive_file", 0))
        out[c["Names"][0].removeprefix("/")] = {"cpu": pct, "mem": used, "limit": mem.get("limit")}
    for gone in set(PREVIOUS) - seen:
        del PREVIOUS[gone]
    append(METRICS, f"metrics-{time.strftime('%Y-%m', time.gmtime())}.jsonl", {"ts": now_iso(), "event": "stats", "containers": out})


def du(path):
    total, stack = 0, [path]
    while stack:
        try:
            with os.scandir(stack.pop()) as it:
                for e in it:
                    try:
                        if e.is_dir(follow_symlinks=False):
                            stack.append(e.path)
                        else:
                            total += e.stat(follow_symlinks=False).st_size
                    except OSError:
                        pass
        except OSError:
            pass
    return total


def sizes():
    """Every byte under the four top folders counted once: a folder with subfolders is split into
    them (loose files as '<folder>/.'), otherwise counted whole."""
    out = {}
    for top in TOPS:
        try:
            entries = list(os.scandir(os.path.join(PROJECT, top)))
        except OSError:
            continue
        for a in entries:
            key = f"{top}/{a.name}"
            if not a.is_dir(follow_symlinks=False):
                out[f"{top}/."] = out.get(f"{top}/.", 0) + a.stat(follow_symlinks=False).st_size
                continue
            try:
                inner = list(os.scandir(a.path))
            except OSError:
                continue
            subs = [b for b in inner if b.is_dir(follow_symlinks=False)]
            if not subs:
                out[key] = du(a.path)
                continue
            for b in subs:
                out[f"{key}/{b.name}"] = du(b.path)
            if loose := sum(b.stat(follow_symlinks=False).st_size for b in inner if not b.is_dir(follow_symlinks=False)):
                out[f"{key}/."] = loose
    st = os.statvfs(PROJECT)
    append(METRICS, f"metrics-{time.strftime('%Y-%m', time.gmtime())}.jsonl",
           {"ts": now_iso(), "event": "sizes", "sizes": out, "disk": {"total": st.f_blocks * st.f_frsize, "free": st.f_bavail * st.f_frsize}})


# ---------------------------------------------------------------- the loop

def now_iso():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def append(folder, name, record):
    with open(os.path.join(folder, name), "a", encoding="utf-8") as f:
        f.write(json.dumps(record, separators=(",", ":")) + "\n")


def event(name, **fields):
    try:
        append(EVENTS, f"log-collector-{time.strftime('%Y-%m', time.gmtime())}.jsonl", {"ts": now_iso(), "event": name} | fields)
    except OSError:
        pass


def main():
    event("startup", socket=os.path.exists(SOCK))
    due, failing = {}, {}
    while True:
        now = time.time()
        for job, every in ((stats, 60), (snapshot, 300), (sizes, 3600)):
            if now >= due.get(job, 0):
                due[job] = now - now % every + every          # on the wall-clock minute / 5 minutes / hour
                try:
                    job()
                    failing.pop(job, None)
                except Exception as e:
                    msg = f"{type(e).__name__}: {e}"[:300]
                    if failing.get(job) != msg:               # one line per new error, not one per minute
                        event("error", job=job.__name__, error=msg)
                        failing[job] = msg
        time.sleep(1)


if __name__ == "__main__":
    main()
