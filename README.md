# Home server behind two VPS edges

A self-hosted server that runs at home with **no open ports**. A media library and file sharing
for family sit on one domain; public web apps sit on another. Each domain points at its own small
VPS, and each VPS does nothing but forward ports 80 and 443 down a WireGuard tunnel to a Docker
stack at home. TLS ends at home, every visitor's real IP reaches the logs, and the home IP is
never exposed.

This repo is the server: the tunnels, the reverse proxies, the private apps, the monitoring and
the scripts. Public apps are separate projects, added by the
[app generator](https://github.com/sumanthkolli03/app-generator). It isn't a one-command
install: it needs two VPSes, two domains and WireGuard keys. It's here to show how the server is
built. Includes two basic private apps as examples (jellyfin and copyparty via authelia)

## Architecture

```
Internet ── private VPS (WireGuard + DNAT 80/443, no NAT) ══ wg-private ── caddy-private ─┬─ jf-gate ── jellyfin
         │                                                                                ├─ authelia
         │                                                                                └─ copyparty (after Authelia)
         └─ public VPS  (WireGuard + DNAT 80/443, no NAT) ══ wg-public  ── caddy-public ──── public apps (generated)

caddy-internal (127.0.0.1 only) ── log-viewer       log-collector (no network; the Docker socket)
syslog (the tunnels' logs)
```

**Note that this repo is intentionally devoid of any identifying info and any URLs (although I imagine this would be easy to find). Contact me for access, or if you are a friend, contact me for adding your own webapp!**  

## Running it

1. Two VPSes, each with WireGuard: forward 80 and 443 to the tunnel with DNAT only (no
   MASQUERADE), and clamp the TCP MSS.
2. `cp .env.example .env` and fill it in. Copy each `.example` next to a secret and fill that in
   too, including both `wg0.conf` files.
3. `bash bootstrap.sh`, then `docker compose up -d`.
4. Add public apps with the generator.

Settings that live in the apps rather than in this repo:
- **Jellyfin:** Base URL `/jellyfin`; Known proxies `10.252.2.2` (Caddy's pinned address on
  `jellyfin_net`)
- **Authelia:** TOTP enrollments live only in its database (`internal-config/authelia`)
