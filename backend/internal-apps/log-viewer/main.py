"""The log viewer: one page, four tabs. GET and HEAD only.

/          Health: sites, tunnels, containers, storage (numbers from health.py)
/public    the public stack's records, newest first, a divider wherever the user (or IP) changes
/private   the same for the private stack
/details   every log line of every stack, each with all its fields
Only this file writes HTML, and every value from a log goes through esc(). The only script,
app.js, narrows the filter lists as you type; it never touches log text.
"""
import html
import json
import math
import re
import threading
from collections import defaultdict
from datetime import datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlsplit

import health
import helper
from helper import TZ, human, local

PORT = 8080
CSS = (Path(__file__).parent / "style.css").read_bytes()
JS = (Path(__file__).parent / "app.js").read_bytes()
CSP = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
HEADERS = [("Content-Security-Policy", CSP), ("X-Content-Type-Options", "nosniff"), ("Referrer-Policy", "no-referrer"),
           ("Cross-Origin-Opener-Policy", "same-origin"), ("Cross-Origin-Resource-Policy", "same-origin"),
           ("Cache-Control", "no-store")]
TABS = [("Health", "/"), ("Public", "/public"), ("Private", "/private"), ("Details", "/details")]
TOGGLES = {"public": ("probes", "scanners"), "private": ("ffmpeg", "probes", "scanners"), None: ("ffmpeg", "probes", "scanners")}
VIS = {"ffmpeg": "ffmpeg", "probes": "probe", "scanners": "scanner"}
STORAGE = ("backend", "internal-config", "logs", "shared-files")
ICON = {"critical": "✕", "warning": "!", "notice": "i"}
DATE = re.compile(r"^\d{4}-\d\d-\d\d$")
LIST_MAX = 500           # values per filter list, busiest first; type the exact value for the rest
JSON_MAX = 65536         # a record's detail on Details is cut past this, and says so
CTX = {}


def esc(x):
    return html.escape("" if x is None else str(x), quote=True)


def url(path, q):
    """A link to path with q's parameters (each a list of values, or one value); empty ones are left out."""
    pairs = [(k, v) for k, vs in q.items() for v in (vs if isinstance(vs, list) else [vs]) if v not in (None, "")]
    return esc(path + ("?" + urlencode(pairs) if pairs else ""))


def one(q, k):
    """The last value given for k, or ""."""
    return (q.get(k) or [""])[-1]


def page(tab, body, refresh=False):
    nav = "".join(f'<a href="{href}"{" class=on" if name == tab else ""}>{name}</a>' for name, href in TABS)
    meta = '<meta http-equiv="refresh" content="60">' if refresh else ""
    return ('<!doctype html><html lang="en"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width,initial-scale=1">'
            f'<title>{tab} · logs</title><link rel="stylesheet" href="/style.css"><script src="/app.js" defer></script>{meta}</head>'
            f'<body><nav>{nav}</nav><main>{body}</main></body></html>')


def link(by, value):
    return f'<a href="{url("/details", {by: value})}">{esc(value)}</a>' if value else ""


def span(q, days):
    """from/to are local dates, both included; `before` (epoch) pages to older records."""
    today = datetime.now(TZ).date()
    frm = one(q, "from") if DATE.match(one(q, "from")) else (today - timedelta(days=days - 1)).isoformat()
    to = one(q, "to") if DATE.match(one(q, "to")) else today.isoformat()
    try:
        start = datetime.fromisoformat(frm).replace(tzinfo=TZ).timestamp()
        end = (datetime.fromisoformat(to) + timedelta(days=1)).replace(tzinfo=TZ).timestamp()
    except ValueError:
        return span({}, days)
    try:
        end = min(end, float(one(q, "before")))
    except ValueError:
        pass
    return start, end, frm, to


def picks_of(q):
    """The values picked in each filter box (repeated parameters), in the order given."""
    return {k: list(dict.fromkeys(v.strip()[:200] for v in q.get(k, []) if v.strip())) for k in helper.FIELDS}


def filters(action, q, picks, seen, frm, to, toggles):
    """The filter form. A bubble per picked value (its × drops it); a box per field, whose list
    holds the values seen with the other filters (click one to add it); q, the dates, the toggles.
    Show comes first in the form, so Enter in a box presses it (CSS puts it last)."""
    here = {k: v for k, v in q.items() if k != "before"}
    bubbles = "".join(f'<a class="bubble" href="{url(action, dict(here, **{k: [x for x in picks[k] if x != v]}))}" title="remove">'
                      f'{k}: {esc(v)}<b>×</b></a>' for k in helper.FIELDS for v in picks[k])
    boxes = []
    for k in helper.FIELDS:
        items = "".join(f'<li><button name="{k}" value="{esc(v)}">{esc(v)}<span>{n:,}</span></button></li>'
                        for v, n in seen[k].most_common(LIST_MAX + len(picks[k])) if v not in picks[k])
        boxes.append(f'<div class="pick"><label>{k}<input name="{k}" autocomplete="off" placeholder="any"></label>'
                     f'<ul class="list">{items or "<li class=quiet>nothing else in this range</li>"}</ul></div>')
    kept = "".join(f'<input type="hidden" name="{k}" value="{esc(v)}">' for k in helper.FIELDS for v in picks[k])
    ticks = "".join(f'<label class="tick"><input type="checkbox" name="{t}" value="1"'
                    f'{" checked" if one(q, t) == "1" else ""}>{t}</label>' for t in toggles)
    return (f'<form method="get" action="{action}"><button class="show">Show</button>{kept}'
            f'{f"<div class=bubbles>{bubbles}</div>" if bubbles else ""}{"".join(boxes)}'
            f'<label>q<input name="q" value="{esc(one(q, "q"))}" size="18" placeholder="any text"></label>'
            f'<label>from<input type="date" name="from" value="{esc(frm)}"></label>'
            f'<label>to<input type="date" name="to" value="{esc(to)}"></label>{ticks}</form>')


def older(path, q, recs, more):
    if not more:
        return ""
    return f'<p class="more"><a href="{url(path, dict(q, before=repr(recs[-1]["ts"])))}">Older →</a></p>'


def as_json(d):
    j = json.dumps(d, ensure_ascii=False, default=str)
    return j if len(j) <= JSON_MAX else f"{j[:JSON_MAX]} … ({human(len(j) - JSON_MAX)} more)"


# ---------------------------------------------------------------- Public and Private

def stream_page(q, stack):
    start, end, frm, to = span(q, 7)
    show = {VIS[t] for t in TOGGLES[stack] if one(q, t) == "1"}
    picks = picks_of(q)
    recs, more, seen = helper.query(start, end, {stack}, picks, one(q, "q")[:200], show, ctx=CTX)
    rows, who = [], object()
    for r in recs:
        if (r["user"] or r["ip"]) != who:
            who = r["user"] or r["ip"]
            label = link("user", r["user"]) if r["user"] else link("ip", r["ip"]) if r["ip"] else "system"
            rows.append(f'<tr class="who"><th colspan="6">{label}</th></tr>')
        rows.append(f'<tr><td class="t">{esc(local(r["ts"]))}</td><td>{link("app", r["app"])}</td>'
                    f'<td>{link("user", r["user"])}</td><td>{link("ip", r["ip"])}</td><td>{esc(r["event"])}</td>'
                    f'<td class="s">{esc(helper.summary(r))}</td></tr>')
    title = "Public apps" if stack == "public" else "Private apps"
    table = (f'<table class="log"><thead><tr><th>time</th><th>app</th><th>user</th><th>ip</th><th>event</th>'
             f'<th>summary</th></tr></thead><tbody>{"".join(rows)}</tbody></table>') if rows else '<p class="quiet">Nothing in this range.</p>'
    return page(title.split()[0], f'<h1>{title}</h1>{filters("/" + stack, q, picks, seen, frm, to, TOGGLES[stack])}'
                f'<p class="quiet">{len(recs)}{"+" if more else ""} records, newest first.</p>{table}'
                f'{older("/" + stack, q, recs, more)}')


# ---------------------------------------------------------------- Details

def details_page(q):
    """Every log line of every stack, newest first: the five columns, then every other field."""
    start, end, frm, to = span(q, 30)
    show = {VIS[t] for t in TOGGLES[None] if one(q, t) == "1"}
    picks = picks_of(q)
    recs, more, seen = helper.query(start, end, None, picks, one(q, "q")[:200], show, details=True, ctx=CTX)
    rows = "".join(f'<tr><td class="t">{esc(local(r["ts"]))}</td><td>{link("app", r["app"])}</td><td>{link("user", r["user"])}</td>'
                   f'<td>{link("ip", r["ip"])}</td><td>{esc(r["event"])}</td><td class="s">{esc(as_json(r["detail"]))}</td></tr>' for r in recs)
    table = (f'<table class="log"><thead><tr><th>time</th><th>app</th><th>user</th><th>ip</th><th>event</th><th>detail</th></tr></thead>'
             f'<tbody>{rows}</tbody></table>') if rows else '<p class="quiet">Nothing in this range.</p>'
    return page("Details", f'<h1>Details</h1>{filters("/details", q, picks, seen, frm, to, TOGGLES[None])}'
                f'<p class="quiet">{len(recs)}{"+" if more else ""} log lines, newest first.</p>{table}{older("/details", q, recs, more)}')


# ---------------------------------------------------------------- Health

def nice(v):
    """Rounds an axis top up to 1, 2, 2.5 or 5 times a power of ten."""
    if v <= 0:
        return 1
    e = 10 ** math.floor(math.log10(v))
    return next(m * e for m in (1, 2, 2.5, 5, 10) if m * e >= v)


def line_chart(title, series, t0, t1, fmt):
    """One 2px line per name (colors by name order, never by rank), hairline grid, and hover
    bands that list every series at that time. Gaps (the PC asleep) stay gaps."""
    series = {n: v for n, v in series.items() if v}
    if not series:
        return f'<figure class="chart"><figcaption>{esc(title)}</figcaption><p class="quiet">No data yet.</p></figure>'
    names = sorted(series)
    if len(names) > 8:                    # never a 9th color: the 7 busiest stay, the rest add up to "other"
        busiest = sorted(names, key=lambda n: -max(v for _, v in series[n]))
        other = defaultdict(float)
        for n in busiest[7:]:
            for t, v in series[n]:
                other[t] += v
        series = {n: series[n] for n in busiest[:7]} | {"other": sorted(other.items())}
        names = sorted(busiest[:7]) + ["other"]
    W, H, L, R, T, B, N = 640, 170, 54, 8, 8, 20, 120
    bw = (t1 - t0) / N
    pts = {}
    for n in names:
        p = pts[n] = {}
        for t, v in series[n]:
            if 0 <= (i := int((t - t0) // bw)) < N:
                p[i] = max(v, p.get(i, v))
    top = nice(max([v for p in pts.values() for v in p.values()] or [1]))
    x = lambda i: L + (i + 0.5) * (W - L - R) / N
    y = lambda v: T + (1 - v / top) * (H - T - B)
    s = [f'<svg viewBox="0 0 {W} {H}" role="img" aria-label="{esc(title)}">']
    for k in (0, 0.5, 1):
        s.append(f'<line class="grid" x1="{L}" x2="{W - R}" y1="{y(top * k):.1f}" y2="{y(top * k):.1f}"/>'
                 f'<text class="axis" x="{L - 6}" y="{y(top * k) + 4:.1f}" text-anchor="end">{esc(fmt(top * k))}</text>')
    for i, anchor in ((0, "start"), (N // 2, "middle"), (N - 1, "end")):
        s.append(f'<text class="axis" x="{x(i):.1f}" y="{H - 5}" text-anchor="{anchor}">{esc(local(t0 + (i + 0.5) * bw, "%b %d %H:%M"))}</text>')
    for k, n in enumerate(names):
        run = []
        for i in [*sorted(pts[n]), None]:
            if run and (i is None or i - run[-1] > 3):
                if len(run) == 1:
                    s.append(f'<circle class="s{k}" cx="{x(run[0]):.1f}" cy="{y(pts[n][run[0]]):.1f}" r="2"/>')
                else:
                    s.append(f'<polyline class="s{k}" points="{" ".join(f"{x(j):.1f},{y(pts[n][j]):.1f}" for j in run)}"/>')
                run = []
            if i is not None:
                run.append(i)
    for j in range(0, N, 2):              # hover anywhere: every series at that time
        vals = [(pts[n].get(j, pts[n].get(j + 1)), n) for n in names]
        vals = sorted(((v, n) for v, n in vals if v is not None), reverse=True)
        tip = local(t0 + j * bw, "%b %d %H:%M") + "".join(f"\n{fmt(v)}  {n}" for v, n in vals)
        s.append(f'<rect class="hit" x="{x(j) - (W - L - R) / N / 2:.1f}" y="{T}" width="{2 * (W - L - R) / N:.1f}" '
                 f'height="{H - T - B}"><title>{esc(tip)}</title></rect>')
    s.append("</svg>")
    legend = ""
    if len(names) > 1:
        last = {n: series[n][-1][1] if series[n] else None for n in names}
        legend = '<ul class="legend">' + "".join(
            f'<li><svg class="key" viewBox="0 0 16 4"><line class="s{k}" x1="1" y1="2" x2="15" y2="2"/></svg>'
            f'{esc(n)} <b>{esc(fmt(last[n]) if last[n] is not None else "–")}</b></li>' for k, n in enumerate(names)) + "</ul>"
    title += f" · {names[0]}" if len(names) == 1 else ""        # one line: the caption names it, no legend
    return f'<figure class="chart"><figcaption>{esc(title)}</figcaption>{"".join(s)}{legend}</figure>'


def cells(cs):
    out = [f'<svg class="cells" viewBox="0 0 {len(cs) * 6} 14">']
    for i, (a, ok, n) in enumerate(cs):
        cls = "none" if n == 0 else "good" if ok == n else "bad"
        out.append(f'<rect x="{i * 6}" width="4" height="14" rx="1" class="{cls}"><title>{esc(local(a, "%b %d %H:%M"))} · {ok}/{n} ok</title></rect>')
    return "".join(out) + "</svg>"


def segbar(parts, total, i):
    W, x, out = 160, 0.0, [f'<svg class="seg" viewBox="0 0 160 8"><clipPath id="sb{i}"><rect width="160" height="8" rx="4"/></clipPath><g clip-path="url(#sb{i})">']
    for k, cat in enumerate(STORAGE):
        if (n := parts.get(cat, 0)) > 0 and total > 0:
            w = W * n / total
            out.append(f'<rect class="p{k}" x="{x:.1f}" width="{max(w - 2, 1):.1f}" height="8"><title>{cat}: {esc(human(n))}</title></rect>')
            x += w
    return "".join(out) + "</g></svg>"


def table(head, rows):
    return ('<table><thead><tr>' + "".join(f"<th>{h}</th>" for h in head) + '</tr></thead><tbody>'
            + "".join("<tr>" + "".join(f"<td>{c}</td>" for c in r) + "</tr>" for r in rows) + "</tbody></table>")


def health_page(q):
    week = one(q, "range") == "7d"
    o = health.overview(168 if week else 24)
    t0, now = o["t0"], o["now"]
    ms = lambda v: f"{v:.0f} ms"
    pct = lambda v: f"{v:.1f}%" if v < 10 else f"{v:.0f}%"
    out = ['<h1>Health</h1><p class="range">'
           + (f'<a href="/">24 hours</a> · <b>7 days</b>' if week else '<b>24 hours</b> · <a href="/?range=7d">7 days</a>')
           + f' · updated {esc(local(now, "%H:%M:%S"))}, reloads every minute</p>']
    if o["attention"]:
        out.append('<ul class="attention">' + "".join(f'<li class="{sev}"><span class="mark">{ICON[sev]}</span>{esc(text)}</li>'
                                                      for sev, text in o["attention"]) + "</ul>")
    else:
        out.append('<p class="attention clear"><span class="mark">✓</span>All clear</p>')

    out.append("<h2>Sites</h2>")
    rows = []
    for st in o["sites"]:
        last = st["last"] or {}
        state = ("–" if not last else f'<span class="mark good">✓</span>{esc(last.get("code"))}' if last.get("ok")
                 else f'<span class="mark critical">✕</span>{esc(last.get("code") or "down")}')
        rows.append([esc(st["host"]), state, esc(ms(last["ms"])) if last.get("ms") else "–",
                     esc(pct(st["uptime"])) if st["uptime"] is not None else "–",
                     esc(f'{last["cert_days"]:.0f} d') if isinstance(last.get("cert_days"), (int, float)) else "–", cells(st["cells"])])
    out.append(table(("site", "now", "response", "uptime", "certificate", "over the range"), rows) if rows
               else '<p class="quiet">No sites found yet: they come from Caddy\'s startup line in logs/caddy/*/caddy.log.</p>')
    out.append(line_chart("Response time", {s["host"]: s["series"] for s in o["sites"]}, t0, now, ms))

    out.append("<h2>Tunnels</h2>")
    out.append(table(("tunnel", "running", "last handshake", "received", "sent", "kill switch", "FORWARD", "ip_forward"),
                     [[esc(t.get("container")), "yes" if t.get("running") else '<span class="mark critical">✕</span>no',
                       esc(health.ago(t["age"])) if t.get("age") else "–", esc(human(t["rx"])) if t.get("rx", -1) >= 0 else "–",
                       esc(human(t["tx"])) if t.get("tx", -1) >= 0 else "–",
                       esc(f'{t.get("ks_rules")} rule, {t.get("ks_pkts")} dropped') if t.get("running") else "–",
                       esc(t.get("forward_policy", "–")), esc(t.get("ip_forward", "–"))] for t in o["tunnels"]])
               if o["tunnels"] else '<p class="quiet">No tunnel in the latest snapshot.</p>')

    for stack in ("public", "private", "internal"):
        cs = [c for c in o["containers"] if c["stack"] == stack]
        out.append(f'<h2>{stack.capitalize()} containers</h2><div class="pair">'
                   + line_chart("CPU (100% = one core)", o["series"]["cpu"][stack], t0, now, pct)
                   + line_chart("Memory", o["series"]["mem"][stack], t0, now, human) + "</div>")
        out.append(table(("container", "status", "health", "CPU", "memory", "up", "restarts", "image"),
                         [[esc(c["name"]), esc(c.get("status")), esc(c.get("health") or "–"),
                           esc(pct(c["cpu"])) if isinstance(c.get("cpu"), (int, float)) else "–",
                           esc(human(c["mem"])) if isinstance(c.get("mem"), (int, float)) else "–",
                           esc(health.ago(now - started)) if c.get("status") == "running" and (started := helper.parse_ts(c.get("started"))) else "–",
                           esc(c.get("restarts")), esc(c.get("image"))] for c in cs]) if cs else '<p class="quiet">None in the latest snapshot.</p>')

    out.append("<h2>Storage</h2>")
    if o["disk"]:
        d = o["disk"]
        out.append(f'<p>Disk: {esc(human(d.get("free")))} free of {esc(human(d.get("total")))} · logs/ {esc(human(d["logs"]))}'
                   f' · measured {esc(local(d["at"], "%H:%M"))}</p>')
        out.append('<ul class="legend">' + "".join(f'<li><svg class="key" viewBox="0 0 10 10"><rect class="p{k}" width="10" height="10" rx="2"/></svg>{c}</li>'
                                                   for k, c in enumerate(STORAGE)) + "</ul>")
        out.append(table(("app", *STORAGE, "total", ""),
                         [[esc(app), *[esc(human(parts[c])) if parts.get(c) else "–" for c in STORAGE], f"<b>{esc(human(total))}</b>", segbar(parts, total, i)]
                          for i, (app, parts, total) in enumerate(o["storage"])]))
    else:
        out.append('<p class="quiet">No sizes yet: the collector measures them hourly.</p>')

    out.append("<h2>Latest alerts</h2>")
    out.append(table(("time", "container", "alert", "detail", "times"),
                     [[esc(local(r["ts"])), esc(r["app"]), esc(r["event"]), esc(r["detail"].get("text")), esc(r["detail"].get("count", 1))]
                      for r in o["alerts"]]) if o["alerts"] else '<p class="quiet">ALERTS.log is empty.</p>')
    return page("Health", "".join(out), refresh=True)


# ---------------------------------------------------------------- the server

PAGES = {"/": health_page, "/public": lambda q: stream_page(q, "public"),
         "/private": lambda q: stream_page(q, "private"), "/details": details_page}


class Handler(BaseHTTPRequestHandler):
    server_version, sys_version, timeout = "log-viewer", "", 30

    def do_GET(self):
        self.respond(True)

    def do_HEAD(self):
        self.respond(False)

    def refuse(self):
        self.reply(405, "text/plain; charset=utf-8", b"GET and HEAD only\n", extra=[("Allow", "GET, HEAD")])

    do_POST = do_PUT = do_DELETE = do_PATCH = do_OPTIONS = do_TRACE = do_CONNECT = refuse

    def respond(self, body):
        u = urlsplit(self.path)
        if u.path == "/healthz":
            return self.reply(200, "text/plain; charset=utf-8", b"ok\n", body)
        if u.path == "/style.css":
            return self.reply(200, "text/css; charset=utf-8", CSS, body)
        if u.path == "/app.js":
            return self.reply(200, "text/javascript; charset=utf-8", JS, body)
        render = PAGES.get(u.path)
        if not render:
            return self.reply(404, "text/plain; charset=utf-8", b"not found\n", body)
        try:
            data = render(parse_qs(u.query, max_num_fields=200)).encode()
        except Exception as e:
            health.event("error", path=u.path, error=f"{type(e).__name__}: {e}"[:300])
            return self.reply(500, "text/plain; charset=utf-8", b"error: see logs/internal-apps/log-viewer/app/\n", body)
        self.reply(200, "text/html; charset=utf-8", data, body)

    def reply(self, code, ctype, data, body=True, extra=()):
        self.send_response(code)
        for k, v in [*HEADERS, *extra, ("Content-Type", ctype), ("Content-Length", str(len(data)))]:
            self.send_header(k, v)
        self.end_headers()
        if body:
            self.wfile.write(data)

    def log_message(self, *args):       # caddy-internal is the access log
        pass


def main():
    CTX["token"] = health.token()
    health.event("startup", sites=len(health.sites()))
    threading.Thread(target=health.run_prober, args=(CTX["token"],), daemon=True).start()
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
