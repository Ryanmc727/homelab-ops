# homelab-ops

A self-contained FastAPI + static-HTML operations dashboard for a Docker-based homelab. Provides a single-page SOC-style view of:

- **Suricata IDS** — alert timeline, grouped signatures, P1/P2/P3 counts, 24-hour chart
- **Docker services** — container status, uptime, restart detection
- **Network map** — ARP-scan device presence, Pi-hole DNS activity per device, Suricata flow data, top talkers, unknown device detection
- **Pi-hole DNS** — queries today, block rate, top blocked domains
- **SSH events** — login success/failure, brute-force detection from auth.log
- **System stats** — CPU, RAM, disk, uptime via Netdata or psutil
- **Port map** — live listening ports with bind-type classification (public / LAN / localhost / Tailscale / Docker)
- **Cert countdown** — days until wildcard SSL cert expires
- **AI assistant** — Claude-powered chat with live homelab context injected into the system prompt

---

## Stack

- **Backend**: FastAPI (Python 3.12)
- **Frontend**: single static `index.html` — no build step, no framework
- **Reads**: Suricata `eve.json`, `auth.log`, Docker socket, Pi-hole FTL SQLite DB
- **Notifications/AI**: Anthropic Claude API (optional)

---

## Quick start

```bash
git clone https://github.com/Ryanmc727/homelab-ops.git
cd homelab-ops
cp .env.example .env          # fill in your values
```

Add to your `docker-compose.yml`:

```yaml
homelab-ops:
  build: ./homelab-ops
  container_name: homelab-ops
  ports:
    - "127.0.0.1:3009:8000"
  environment:
    - PIHOLE_URL=http://pihole:80
    - PIHOLE_PASSWORD=${PIHOLE_PASSWORD}
    - EVE_LOG=/var/log/suricata/eve.json
    - AUTH_LOG=/var/log/host/auth.log
    - ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY}
  volumes:
    - /var/log/suricata:/var/log/suricata:ro
    - /var/log/auth.log:/var/log/host/auth.log:ro
    - /var/run/docker.sock:/var/run/docker.sock:ro
  networks:
    - monitoring
  restart: unless-stopped
```

Then expose via your reverse proxy (e.g. Nginx Proxy Manager) at `ops.yourdomain.com`.

---

## Configuration

### Device list

Edit `KNOWN_DEVICES` in `main.py` to match your LAN. Each entry has an IP, a friendly name, and a tag:

| Tag | Meaning |
|---|---|
| `NET` | Network gear (router, AP, switch) |
| `SRV` | Servers |
| `PER` | Personal devices |
| `WORK` | Work devices |
| `IOT` | Smart home / IoT |
| `LAB` | Lab / testing |

Unknown IPs (seen in ARP or Pi-hole but not in the list) surface automatically in the Network Map panel.

### Service links

The quick-launch link bar in the header is hardcoded to `*.yourdomain.com`. Update those URLs in `static/index.html` to match your domain.

### AI assistant

Set `ANTHROPIC_API_KEY` in your environment. The assistant receives live alert counts and container state as context. Model defaults to `claude-haiku-4-5-20251001`; override with `AI_MODEL`.

### Cert expiry

Update `CERT_EXPIRY` in `main.py` (or add it as an env var) to track your wildcard cert renewal deadline.

---

## API endpoints

| Endpoint | Description |
|---|---|
| `GET /api/alerts` | Suricata alerts — last 24h, grouped by signature |
| `GET /api/services` | Docker container status |
| `GET /api/network` | ARP scan + Pi-hole + Suricata activity per device |
| `GET /api/network/{ip}` | Pi-hole query log for a single device |
| `GET /api/devices` | Device list with active/inactive status |
| `GET /api/dns` | Pi-hole summary stats |
| `GET /api/system` | CPU, RAM, disk, uptime, load average |
| `GET /api/ports` | Live listening ports with bind-type classification |
| `GET /api/ssh` | SSH login events from auth.log |
| `GET /api/certs` | SSL cert expiry countdown |
| `GET /api/events` | Aggregated event feed (P1 alerts, unknown devices, container restarts) |
| `POST /api/ai` | Claude AI chat with live homelab context |
| `GET /health` | Liveness probe |

---

## Notes

- The container needs read access to `/var/run/docker.sock` to query other containers.
- ARP scanning is done by execing into a host-networked container (Suricata, ntopng, or homepage) and reading `/proc/net/arp`. No additional tools needed.
- Pi-hole queries use the FTL SQLite database directly via `pihole-FTL sqlite3` — no API key required for read-only stats.
- Network activity (LAN subnet) is filtered from Suricata `eve.json` — configure the subnet prefix in `main.py` if yours differs from `192.168.`.
