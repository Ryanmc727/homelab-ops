from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import httpx
import docker
import psutil
import os
import json
import logging
import re as _re
from datetime import datetime, timezone, timedelta
from collections import defaultdict

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="Homelab OPS")

ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")

EVE_LOG         = os.getenv("EVE_LOG", "/var/log/suricata/eve.json")
PIHOLE_URL      = os.getenv("PIHOLE_URL", "http://pihole:80")
PIHOLE_KEY_FILE = os.getenv("PIHOLE_KEY_FILE", "/run/secrets/pihole_api_key")
PIHOLE_PASSWORD = os.getenv("PIHOLE_PASSWORD", "")

# *.yourdomain.com wildcard cert (NPM id=4) — update when renewed
CERT_EXPIRY = datetime(2026, 8, 1, tzinfo=timezone.utc)

# Populate with your LAN devices — used for ARP-scan enrichment and unknown device detection.
# Tags: NET=network gear, SRV=server, PER=personal, WORK=work, IOT=smart home, LAB=lab
KNOWN_DEVICES = [
    {"ip": "192.168.1.1",   "name": "router",       "tag": "NET"},
    {"ip": "192.168.1.2",   "name": "access-point", "tag": "NET"},
    {"ip": "192.168.1.10",  "name": "homelab",      "tag": "SRV"},
    {"ip": "192.168.1.11",  "name": "kali",         "tag": "LAB"},
    {"ip": "192.168.1.20",  "name": "phone-1",      "tag": "PER"},
    {"ip": "192.168.1.21",  "name": "phone-2",      "tag": "PER"},
    {"ip": "192.168.1.30",  "name": "laptop-1",     "tag": "PER"},
    {"ip": "192.168.1.40",  "name": "smart-speaker","tag": "IOT"},
    {"ip": "192.168.1.50",  "name": "smart-tv",     "tag": "IOT"},
    # Add your own devices here
]

KNOWN_IPS = {d["ip"] for d in KNOWN_DEVICES}


# ── HELPERS ──────────────────────────────────────────────────────────────

def _pihole_key() -> str:
    try:
        with open(PIHOLE_KEY_FILE) as f:
            return f.read().strip()
    except Exception:
        return ""


def _get_arp_table() -> dict:
    """Returns {ip: mac} for ARP-complete entries via a host-networked container."""
    try:
        dc = docker.DockerClient(base_url="unix:///var/run/docker.sock")
        for cname in ("suricata", "ntopng", "homepage"):
            try:
                res = dc.containers.get(cname).exec_run(["cat", "/proc/net/arp"], demux=True)
                stdout = (res.output[0] or b"").decode("utf-8", errors="replace")
                arp: dict = {}
                for line in stdout.splitlines()[1:]:
                    p = line.split()
                    if len(p) >= 4 and p[2] == "0x2" and p[3] != "00:00:00:00:00:00":
                        arp[p[0]] = p[3].lower()
                return arp
            except Exception:
                continue
    except Exception:
        pass
    return {}


def _pihole_exec(query: str) -> str:
    try:
        dc = docker.DockerClient(base_url="unix:///var/run/docker.sock")
        pihole = dc.containers.get("pihole")
        res = pihole.exec_run(
            ["pihole-FTL", "sqlite3", "/etc/pihole/pihole-FTL.db", query],
            demux=True,
        )
        return (res.output[0] or b"").decode("utf-8", errors="replace")
    except Exception:
        return ""


def _read_alerts(limit: int = 25, hours: int = 24):
    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
    all_alerts: list = []
    err = None

    try:
        with open(EVE_LOG, "rb") as f:
            f.seek(0, 2)
            size = f.tell()
            chunk = min(size, 2 * 1024 * 1024)
            f.seek(max(0, size - chunk))
            raw = f.read().decode("utf-8", errors="replace")

        lines = raw.splitlines()
        if size > chunk and lines:
            lines = lines[1:]

        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue
            if ev.get("event_type") != "alert":
                continue
            ts_str = ev.get("timestamp", "")
            try:
                ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                if ts < cutoff:
                    continue
            except Exception:
                pass
            a = ev.get("alert", {})
            all_alerts.append({
                "signature": a.get("signature", "Unknown"),
                "category":  a.get("category", "Unknown"),
                "severity":  a.get("severity", 3),
                "src_ip":    ev.get("src_ip", ""),
                "dest_ip":   ev.get("dest_ip", ""),
                "dest_port": ev.get("dest_port"),
                "proto":     ev.get("proto", ""),
                "timestamp": ts_str,
            })
    except FileNotFoundError:
        err = f"eve.json not found at {EVE_LOG}"
    except Exception as e:
        err = str(e)

    all_alerts.sort(key=lambda x: x["timestamp"], reverse=True)

    counts = {
        "p1": sum(1 for a in all_alerts if a["severity"] == 1),
        "p2": sum(1 for a in all_alerts if a["severity"] == 2),
        "p3": sum(1 for a in all_alerts if a["severity"] == 3),
        "total": len(all_alerts),
    }

    now = datetime.now(timezone.utc)
    chart = {"p1": [0] * 24, "p2": [0] * 24, "p3": [0] * 24}
    for a in all_alerts:
        try:
            ts = datetime.fromisoformat(a["timestamp"].replace("Z", "+00:00"))
            h_ago = int((now - ts).total_seconds() // 3600)
            if 0 <= h_ago < 24:
                bucket = 23 - h_ago
                if a["severity"] == 1:
                    chart["p1"][bucket] += 1
                elif a["severity"] == 2:
                    chart["p2"][bucket] += 1
                else:
                    chart["p3"][bucket] += 1
        except Exception:
            pass

    gmap: dict = defaultdict(lambda: {
        "count": 0, "src_ips": set(), "dest_ips": set(),
        "last_seen": "", "severity": 3, "category": "",
        "last_port": None, "last_proto": "",
    })
    for a in all_alerts:
        sig = a["signature"]
        g = gmap[sig]
        g["count"] += 1
        g["severity"] = min(g["severity"], a["severity"])
        g["category"] = a["category"]
        if a["src_ip"]:
            g["src_ips"].add(a["src_ip"])
        if a["dest_ip"]:
            g["dest_ips"].add(a["dest_ip"])
        if a["timestamp"] > g["last_seen"]:
            g["last_seen"] = a["timestamp"]
            g["last_port"] = a["dest_port"]
            g["last_proto"] = a["proto"]

    groups = [
        {
            "signature": sig, "severity": g["severity"], "category": g["category"],
            "count": g["count"], "src_ips": sorted(g["src_ips"])[:4],
            "dest_ips": sorted(g["dest_ips"])[:2], "last_seen": g["last_seen"],
            "last_port": g["last_port"], "last_proto": g["last_proto"],
        }
        for sig, g in gmap.items()
    ]
    groups.sort(key=lambda x: (x["severity"], -x["count"]))

    return all_alerts[:limit], counts, chart, groups[:40], err


# ── API ENDPOINTS ─────────────────────────────────────────────────────────

@app.get("/api/alerts")
def get_alerts():
    events, counts, chart, groups, error = _read_alerts()
    return {"events": events, "counts": counts, "chart": chart,
            "groups": groups, "error": error,
            "ts": datetime.now(timezone.utc).isoformat()}


@app.get("/api/services")
def get_services():
    try:
        dc = docker.DockerClient(base_url="unix:///var/run/docker.sock")
        containers = dc.containers.list(all=True)
        result = []
        for c in containers:
            try:
                tags = c.image.tags
                image = tags[0].split("/")[-1] if tags else c.image.short_id
            except Exception:
                image = c.attrs.get("Config", {}).get("Image", "unknown").split("/")[-1]
            result.append({
                "name":    c.name,
                "status":  c.status,
                "image":   image,
                "started": c.attrs.get("State", {}).get("StartedAt", ""),
            })
        result.sort(key=lambda x: (x["status"] != "running", x["name"]))
        return {"containers": result, "error": None,
                "ts": datetime.now(timezone.utc).isoformat()}
    except Exception as e:
        return {"containers": [], "error": str(e),
                "ts": datetime.now(timezone.utc).isoformat()}


async def _pihole_v5(client: httpx.AsyncClient):
    key = _pihole_key()
    try:
        r = await client.get(f"{PIHOLE_URL}/admin/api.php",
                             params={"summaryRaw": "", "topItems": "5", "auth": key})
        if r.status_code == 200:
            data = r.json()
            if isinstance(data, dict) and "dns_queries_today" in data:
                return data
    except Exception:
        pass
    return None


async def _pihole_v6(client: httpx.AsyncClient):
    if not PIHOLE_PASSWORD:
        return None
    try:
        ar = await client.post(f"{PIHOLE_URL}/api/auth",
                               json={"password": PIHOLE_PASSWORD})
        if ar.status_code != 200:
            return None
        sid = ar.json().get("session", {}).get("sid", "")
        if not sid:
            return None
        hdrs = {"X-FTL-SID": sid}
        sr = await client.get(f"{PIHOLE_URL}/api/stats/summary", headers=hdrs)
        if sr.status_code != 200:
            return None
        v6 = sr.json()
        q = v6.get("queries", {})
        top = {}
        tr = await client.get(f"{PIHOLE_URL}/api/stats/top_domains",
                              params={"blocked": "true", "count": "5"},
                              headers=hdrs)
        if tr.status_code == 200:
            for entry in tr.json().get("domains", []):
                top[entry.get("domain", "")] = entry.get("count", 0)
        return {
            "dns_queries_today":    q.get("total", 0),
            "ads_blocked_today":    q.get("blocked", 0),
            "ads_percentage_today": q.get("percent_blocked", 0),
            "unique_clients":       v6.get("clients", {}).get("active", 0),
            "top_ads": top,
        }
    except Exception:
        pass
    return None


PORT_LABELS = {
    22:    ("SSH",              "system"),
    53:    ("DNS — Pi-hole",    "docker"),
    80:    ("HTTP — NPM",       "docker"),
    81:    ("NPM Admin",        "docker"),
    443:   ("HTTPS — NPM",      "docker"),
    3002:  ("Uptime Kuma",      "docker"),
    3003:  ("Grafana",          "docker"),
    3004:  ("ntfy",             "docker"),
    3005:  ("ntopng",           "docker"),
    3009:  ("Homelab OPS",      "docker"),
    3010:  ("Maybe Finance",    "docker"),
    3100:  ("Loki",             "docker"),
    5053:  ("DNSCrypt-Proxy",   "system"),
    5636:  ("EveBox",           "docker"),
    6379:  ("Redis",            "system"),
    8080:  ("Authentik HTTP",   "docker"),
    8088:  ("Pi-hole Web",      "docker"),
    8585:  ("Grafana-ntfy",     "docker"),
    9000:  ("Portainer HTTP",   "docker"),
    9443:  ("Portainer HTTPS",  "docker"),
    9444:  ("Authentik HTTPS",  "docker"),
    19999: ("Netdata",          "docker"),
    41641: ("Tailscale",        "system"),
}

def _bind_type(addr: str) -> str:
    if addr in ("0.0.0.0", "::"):
        return "public"
    if addr.startswith("127.") or addr == "::1":
        return "localhost"
    if addr.startswith("192.168."):
        return "lan"
    if addr.startswith("100."):
        return "tailscale"
    if addr.startswith("172."):
        return "docker"
    return "other"

@app.get("/api/ports")
def get_ports():
    ports = []
    try:
        dc = docker.DockerClient(base_url="unix:///var/run/docker.sock")
        for cname in ("suricata", "ntopng"):
            try:
                res = dc.containers.get(cname).exec_run(
                    ["ss", "-tlunp"], demux=True
                )
                raw = (res.output[0] or b"").decode("utf-8", errors="replace")
                break
            except Exception:
                continue
        else:
            return {"ports": [], "error": "Could not exec into host-networked container"}

        for line in raw.splitlines()[1:]:
            parts = line.split()
            if len(parts) < 5:
                continue
            proto    = parts[0]
            local    = parts[4]
            if local.startswith("["):
                addr = local[1:local.index("]")]
                port_str = local.split("]:")[-1]
            elif ":" in local:
                addr, port_str = local.rsplit(":", 1)
            else:
                continue
            try:
                port = int(port_str)
            except ValueError:
                continue

            bind = _bind_type(addr)
            label, svc_type = PORT_LABELS.get(port, ("Unknown", "unknown"))
            ports.append({
                "port":     port,
                "proto":    proto,
                "addr":     addr,
                "bind":     bind,
                "label":    label,
                "svc_type": svc_type,
            })

        order = {"public": 0, "lan": 1, "tailscale": 2, "localhost": 3, "docker": 4, "other": 5}
        ports.sort(key=lambda p: (order.get(p["bind"], 9), p["port"]))
    except Exception as e:
        return {"ports": [], "error": str(e)}

    return {"ports": ports, "error": None, "ts": datetime.now(timezone.utc).isoformat()}


@app.get("/api/dns")
async def get_dns():
    async with httpx.AsyncClient(timeout=5.0) as client:
        data = await _pihole_v5(client)
        if data is None:
            data = await _pihole_v6(client)
        if data is None:
            return {"data": {}, "error": "Pi-hole API unavailable",
                    "ts": datetime.now(timezone.utc).isoformat()}
    return {"data": data, "error": None, "ts": datetime.now(timezone.utc).isoformat()}


NETDATA_URL = os.getenv("NETDATA_URL", "http://netdata:19999")


def _netdata_cpu() -> float:
    """Fetch current total CPU % from Netdata."""
    try:
        import urllib.request
        url = f"{NETDATA_URL}/api/v1/data?chart=system.cpu&points=1&after=-1&format=json"
        with urllib.request.urlopen(url, timeout=2) as r:
            d = json.loads(r.read())
        row = d["data"][0][1:]  # drop timestamp
        return round(sum(row), 1)
    except Exception:
        return round(psutil.cpu_percent(interval=0.2), 1)


@app.get("/api/system")
def get_system():
    try:
        cpu  = _netdata_cpu()
        ram  = psutil.virtual_memory()
        disk = psutil.disk_usage("/")
        boot = datetime.fromtimestamp(psutil.boot_time(), timezone.utc)
        up   = datetime.now(timezone.utc) - boot
        d    = int(up.total_seconds() // 86400)
        h    = int((up.total_seconds() % 86400) // 3600)
        m    = int((up.total_seconds() % 3600) // 60)
        l1, l5, l15 = psutil.getloadavg()
        net  = psutil.net_io_counters()
        return {
            "cpu_pct": round(cpu, 1), "cpu_count": psutil.cpu_count(),
            "load1": round(l1, 2), "load5": round(l5, 2), "load15": round(l15, 2),
            "ram_pct": round(ram.percent, 1),
            "ram_used_gb": round(ram.used / (1024**3), 1),
            "ram_total_gb": round(ram.total / (1024**3), 1),
            "disk_pct": round(disk.percent, 1),
            "disk_used_gb": round(disk.used / (1024**3), 1),
            "disk_total_gb": round(disk.total / (1024**3), 1),
            "uptime_str": f"{d}d {h}h {m}m",
            "bytes_sent": net.bytes_sent, "bytes_recv": net.bytes_recv,
            "error": None,
        }
    except Exception as e:
        return {"error": str(e)}


@app.get("/api/certs")
def get_certs():
    days = (CERT_EXPIRY - datetime.now(timezone.utc)).days
    return {
        "certs": [{"domain": "*.yourdomain.com", "expiry": CERT_EXPIRY.date().isoformat(),
                   "days_remaining": days, "critical": days < 14, "warning": days < 30}],
        "ts": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/api/network")
def get_network():
    arp = _get_arp_table()  # {ip: mac} complete entries only

    # Pi-hole DNS stats per client (last hour)
    dns_stats: dict = {}
    raw_ph = _pihole_exec(
        "SELECT client,"
        "COUNT(*) as t,"
        "SUM(CASE WHEN status IN(1,4,5,6,7,8,9,10,11) THEN 1 ELSE 0 END) as blk,"
        "SUM(CASE WHEN status=7 THEN 1 ELSE 0 END) as nx,"
        "MAX(timestamp) as ls,"
        "SUM(CASE WHEN timestamp>strftime('%s','now')-600 THEN 1 ELSE 0 END) as r10,"
        "SUM(CASE WHEN timestamp>strftime('%s','now')-3600 THEN 1 ELSE 0 END) as r1h "
        "FROM queries WHERE timestamp>strftime('%s','now')-3600 GROUP BY client;"
    )
    for line in raw_ph.strip().splitlines():
        p = line.split("|")
        if len(p) >= 7:
            dns_stats[p[0]] = {
                "total": int(p[1] or 0), "blocked": int(p[2] or 0),
                "nxdomain": int(p[3] or 0), "last_seen": int(float(p[4] or 0)),
                "r10m": int(p[5] or 0), "r1h": int(p[6] or 0),
            }

    # Suricata flow aggregation (last hour)
    eve_activity: dict = {}
    talkers: dict = {}
    try:
        now_utc = datetime.now(timezone.utc)
        c1h = now_utc - timedelta(hours=1)
        c10m = now_utc - timedelta(minutes=10)
        with open(EVE_LOG, "rb") as f:
            f.seek(0, 2)
            size = f.tell()
            f.seek(max(0, size - 2 * 1024 * 1024))
            raw = f.read().decode("utf-8", errors="replace")
        for line in raw.splitlines():
            try:
                ev = json.loads(line)
                et = ev.get("event_type", "")
                src = ev.get("src_ip", "")
                if not src.startswith("192.168."):
                    continue
                ts = datetime.fromisoformat(ev.get("timestamp", "").replace("Z", "+00:00"))
                if ts < c1h:
                    continue
                ep = int(ts.timestamp())
                e = eve_activity.setdefault(src, {"f10m": 0, "f1h": 0, "last_seen": 0})
                e["f1h"] += 1
                if ep > e["last_seen"]:
                    e["last_seen"] = ep
                if ts >= c10m:
                    e["f10m"] += 1
                if et == "flow":
                    flow = ev.get("flow", {})
                    b = (flow.get("bytes_toserver") or 0) + (flow.get("bytes_toclient") or 0)
                    talkers[src] = talkers.get(src, 0) + b
            except Exception:
                pass
    except Exception:
        pass

    # Build device list — ARP is ground truth for online/offline
    devices = []
    for d in KNOWN_DEVICES:
        ip = d["ip"]
        dns = dns_stats.get(ip, {})
        eve = eve_activity.get(ip, {})
        arp_online = ip in arp
        r10 = dns.get("r10m", 0) + eve.get("f10m", 0)
        r1h = dns.get("r1h", 0) + eve.get("f1h", 0)
        last = max(dns.get("last_seen", 0), eve.get("last_seen", 0))

        if arp_online and r10 > 0:
            status = "active"
        elif arp_online:
            status = "present"   # in ARP but no recent traffic (sleeping/idle)
        elif r1h > 0:
            status = "active"    # saw traffic even if not in ARP (ARP may have aged out)
        else:
            status = "offline"

        devices.append({
            "name": d["name"], "ip": ip, "tag": d["tag"],
            "status": status, "arp_online": arp_online,
            "queries_1h": dns.get("total", 0), "blocked_1h": dns.get("blocked", 0),
            "nxdomain_1h": dns.get("nxdomain", 0), "flows_1h": eve.get("f1h", 0),
            "last_seen": last,
        })

    # Unknown IPs (in ARP or traffic but not in KNOWN_DEVICES)
    all_seen = set(arp.keys()) | set(dns_stats.keys()) | set(eve_activity.keys())
    unknown = []
    for ip in sorted(all_seen):
        if not ip.startswith("192.168.") or ip in KNOWN_IPS or ip == "127.0.0.1":
            continue
        dns = dns_stats.get(ip, {})
        eve = eve_activity.get(ip, {})
        unknown.append({
            "ip": ip, "mac": arp.get(ip, ""),
            "queries_1h": dns.get("total", 0), "flows_1h": eve.get("f1h", 0),
            "blocked_1h": dns.get("blocked", 0),
            "last_seen": max(dns.get("last_seen", 0), eve.get("last_seen", 0)),
        })
    unknown.sort(key=lambda x: -x["last_seen"])

    # Top talkers
    ip_name = {d["ip"]: d["name"] for d in KNOWN_DEVICES}
    top_talkers = sorted(
        [{"ip": ip, "name": ip_name.get(ip, ip), "bytes": b}
         for ip, b in talkers.items() if ip.startswith("192.168.")],
        key=lambda x: -x["bytes"]
    )[:8]

    return {
        "devices": devices, "unknown": unknown, "top_talkers": top_talkers,
        "arp_count": len(arp), "error": None,
        "ts": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/api/network/{ip}")
def get_device_log(ip: str):
    if not _re.match(r"^[\d.]+$", ip):
        return {"ip": ip, "queries": [], "error": "invalid ip"}
    rows = []
    raw = _pihole_exec(
        f"SELECT datetime(timestamp,'unixepoch','localtime'),domain,status "
        f"FROM queries WHERE client='{ip}' AND timestamp>strftime('%s','now')-3600 "
        f"ORDER BY timestamp DESC LIMIT 40;"
    )
    for line in raw.strip().splitlines():
        p = line.split("|")
        if len(p) >= 3:
            sc = int(p[2] or 0)
            rows.append({
                "ts": p[0], "domain": p[1], "status": sc,
                "type": ("blocked"  if sc in (1, 4, 5, 6, 8, 9, 10, 11)
                         else "nxdomain" if sc == 7
                         else "allowed"),
            })
    return {"ip": ip, "queries": rows, "error": None}


@app.get("/api/devices")
def get_devices():
    arp = _get_arp_table()
    try:
        dc = docker.DockerClient(base_url="unix:///var/run/docker.sock")
        pihole = dc.containers.get("pihole")
        cutoff = int((datetime.now(timezone.utc) - timedelta(minutes=10)).timestamp())
        res = pihole.exec_run(
            ["pihole-FTL", "sqlite3", "/etc/pihole/pihole-FTL.db",
             f"SELECT DISTINCT client FROM queries WHERE timestamp > {cutoff};"],
            demux=True,
        )
        dns_active = set((res.output[0] or b"").decode("utf-8", errors="replace").strip().splitlines())
        dns_active.add("YOUR_SERVER_IP")  # homelab always active
        devs = [{**d, "active": d["ip"] in arp or d["ip"] in dns_active} for d in KNOWN_DEVICES]
        return {"devices": devs, "active_count": sum(1 for d in devs if d["active"]),
                "ts": datetime.now(timezone.utc).isoformat(), "error": None}
    except Exception as e:
        return {"devices": [{**d, "active": d["ip"] in arp} for d in KNOWN_DEVICES],
                "active_count": len(arp), "ts": datetime.now(timezone.utc).isoformat(),
                "error": str(e)}


@app.get("/api/events")
def get_events():
    events = []
    now = datetime.now(timezone.utc)

    # Recent P1 alerts
    _, counts, _, groups, _ = _read_alerts(limit=5, hours=1)
    for g in groups:
        if g["severity"] == 1:
            events.append({"type": "alert_p1", "severity": "critical",
                           "msg": f"P1: {g['signature'][:60]}", "count": g["count"],
                           "ts": g["last_seen"]})
        elif g["severity"] == 2 and g["count"] >= 5:
            events.append({"type": "alert_p2", "severity": "warn",
                           "msg": f"P2 surge ({g['count']}×): {g['signature'][:55]}",
                           "count": g["count"], "ts": g["last_seen"]})

    # Unknown devices
    arp = _get_arp_table()
    for ip, mac in arp.items():
        if ip not in KNOWN_IPS and ip.startswith("192.168."):
            events.append({"type": "unknown_device", "severity": "warn",
                           "msg": f"Unknown device on LAN: {ip} ({mac})",
                           "count": 1, "ts": ""})

    # Recently restarted containers (< 30 min uptime = likely crashed)
    try:
        dc = docker.DockerClient(base_url="unix:///var/run/docker.sock")
        for c in dc.containers.list():
            started_str = c.attrs.get("State", {}).get("StartedAt", "")
            if not started_str:
                continue
            try:
                started = datetime.fromisoformat(started_str.replace("Z", "+00:00"))
                age_min = (now - started).total_seconds() / 60
                if age_min < 30:
                    name = c.name
                    events.append({"type": "container_restart", "severity": "info",
                                   "msg": f"Container restarted {int(age_min)}m ago: {name}",
                                   "count": 1, "ts": started_str})
            except Exception:
                pass
    except Exception:
        pass

    # Sort: critical first, then warn, then info; newest within each tier
    sev_order = {"critical": 0, "warn": 1, "info": 2}
    events.sort(key=lambda x: (sev_order.get(x["severity"], 9), -(len(x["ts"]))))
    return {"events": events[:12], "ts": now.isoformat()}


class AIRequest(BaseModel):
    message: str
    include_context: bool = True


@app.post("/api/ai")
async def ai_chat(req: AIRequest):
    if not ANTHROPIC_API_KEY:
        return {"response": None, "error": "ANTHROPIC_API_KEY not configured — add it to docker-compose.yml environment"}

    system_prompt = "You are a concise assistant for the homelab security operations center."

    if req.include_context:
        _, counts, _, groups, _ = _read_alerts(limit=5, hours=1)
        try:
            dc = docker.DockerClient(base_url="unix:///var/run/docker.sock")
            containers = dc.containers.list(all=True)
            running = [c.name for c in containers if c.status == "running"]
            stopped  = [c.name for c in containers if c.status != "running"]
        except Exception:
            running, stopped = [], []

        top_alerts = [f"  - [{g['severity']}] {g['signature']} ×{g['count']}" for g in groups[:5]]

        system_prompt = f"""You are a concise AI assistant embedded in the Homelab OPS Center — a personal homelab SOC dashboard. You are talking to the homelab operator.

== ABOUT THE OPERATOR ==
Homelab operator. Strong in Docker, Linux administration, networking, and self-hosting. Learning formal security operations, IDS tuning, and forensics through hands-on lab work. Prefers direct, concise answers.

== HOMELAB ==
Server: homelab (YOUR_SERVER_IP), Ubuntu 24, bare metal
Domain: yourdomain.com | Tailscale: YOUR_TAILSCALE_IP (YOUR_TAILSCALE_IPv6)
All services: Docker via /opt/homelab/docker-compose.yml | Container format: <service>
Reverse proxy: nginx-proxy-manager on host network — sole external entry point, wildcard SSL *.yourdomain.com (NPM cert id=4, expires 2026-08-01)

Key services:
- Suricata IDS — af-packet on eno1, eve.json → EveBox + Grafana + this dashboard
- Pi-hole DNS — YOUR_SERVER_IP:53, 282,108 domains blocked (StevenBlack + Phishing Army + Spam404 + KADhosts)
- Grafana/Loki/Promtail — centralized logging, 2 dashboards (Suricata IDS suricata-dashboard, Server Security security-dashboard)
- Grafana-ntfy bridge — custom webhook bridge (bridge.py) → ntfy push notifications (topic: homelab-alerts)
- ntfy — push notifications (topic: homelab-alerts), NOTE: currently HTTP internally (cleartext Basic Auth — open security issue)
- EveBox — Suricata alert browser at evebox.yourdomain.com
- Uptime Kuma — 11 monitors, maxretries=30 (~30min threshold before ntfy fires)
- Portainer — Docker management (stacks lost during migration, need re-import)
- ntopng — network traffic analysis, host network mode
- Homepage, Netdata, NPM — all on *.yourdomain.com

Suricata suppressions (threshold.conf — NO inline comments allowed):
  suppress 2200121 (LLDP/MSRP router noise), 2016149/2016150 (Tailscale STUN), 2022973 (Kali DHCP hostname), 2025627 (Kali apt), 2024897/2060251 (ntopng connectivity checks)
Reload suppression: docker exec suricata suricatasc -c reload-rules

LAN: flat LAN — 30+ devices including kali-lab, router, personal-pc, IoT devices

== OPEN SECURITY TODOS (priority order) ==
1. ntfy running on HTTP internally — Basic Auth cleartext visible to Suricata — needs TLS
2. DNS leak — systemd-resolved falls back to 8.8.4.4 — fix with cloudflared DoH, edit resolved.conf
3. Network segmentation — no VLANs, all devices on flat YOUR_LAN_SUBNET — IoT + lab should be isolated
4. Honeypot — not deployed — OpenCanary or cowrie recommended on unused IP like YOUR_HONEYPOT_IP
5. Portainer stacks lost during migration — needs re-import via Portainer UI
6. Automated IR playbooks — not yet written (/opt/homelab/playbooks/)

== CBROPS STUDY PROGRESS ==
Completed topics (with lab + exam questions done):
- CIA triad, confidentiality deep dive (5 attack classes), network traffic analysis (BPF, Wireshark, tcpdump), PICERL incident response lifecycle, IDS vs IPS

Exam patterns locked in:
- No modification = not integrity | Long dwell + no disruption = confidentiality | Evidence before containment | Lessons Learned → Preparation (cycle) | IDS detects / IPS prevents | Alert fatigue = false positives → false negatives slip through | Fail-closed = secure / fail-open = available | Sensor placement determines visibility

Pending topics: Integrity pillar deep dive, Host-based analysis, Cryptography/TLS/PKI, CVSS scoring, Access control models (DAC/MAC/RBAC), Wireless attacks, Memory forensics, Malware persistence

== CURRENT LIVE STATE (last 1h) ==
- P1 Critical: {counts.get("p1", 0)} | P2 Medium: {counts.get("p2", 0)} | P3 Low: {counts.get("p3", 0)}
- Running containers: {", ".join(running[:14]) or "unknown"}
- Stopped: {", ".join(stopped[:6]) or "none"}
{("- Top alerts:\\n" + chr(10).join(top_alerts)) if top_alerts else "- No active alerts"}

== INSTRUCTIONS ==
Answer concisely and practically. Use markdown. When the operator pastes terminal output or an alert signature, analyze it like a SOC analyst."""

    try:
        import anthropic as _anthropic
        client = _anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
        msg = client.messages.create(
            model=os.getenv("AI_MODEL", "claude-haiku-4-5-20251001"),
            max_tokens=1024,
            system=system_prompt,
            messages=[{"role": "user", "content": req.message}],
        )
        return {"response": msg.content[0].text, "error": None}
    except Exception as e:
        return {"response": None, "error": str(e)}


@app.get("/api/ssh")
def get_ssh():
    AUTH_LOG = os.getenv("AUTH_LOG", "/var/log/host/auth.log")
    cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
    events: list = []
    err = None

    import re as _re2
    _pats = [
        (_re2.compile(r'Accepted (password|publickey) for (\S+) from ([\d.]+) port (\d+)'), "success"),
        (_re2.compile(r'Failed (password|publickey) for (?:invalid user )?(\S+) from ([\d.]+) port (\d+)'), "failure"),
        (_re2.compile(r'Invalid user (\S+) from ([\d.]+) port (\d+)'), "invalid"),
        (_re2.compile(r'Disconnected from user (\S+) ([\d.]+) port (\d+)'), "disconnect"),
        (_re2.compile(r'Connection closed by ([\d.]+) port \d+ \[preauth\]'), "preauth"),
    ]
    _ts_pat = _re2.compile(r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})')

    try:
        with open(AUTH_LOG, errors="replace") as f:
            for line in f:
                m_ts = _ts_pat.match(line)
                if not m_ts:
                    continue
                ts_str = m_ts.group(1)
                try:
                    ts = datetime.fromisoformat(ts_str).replace(tzinfo=timezone.utc)
                    if ts < cutoff:
                        continue
                except Exception:
                    continue
                for pat, etype in _pats:
                    m = pat.search(line)
                    if not m:
                        continue
                    if etype == "success":
                        events.append({"type": etype, "ts": ts_str,
                            "user": m.group(2), "ip": m.group(3), "method": m.group(1),
                            "msg": f"Login OK: {m.group(2)} from {m.group(3)} via {m.group(1)}"})
                    elif etype == "failure":
                        events.append({"type": etype, "ts": ts_str,
                            "user": m.group(2), "ip": m.group(3), "method": m.group(1),
                            "msg": f"Failed login: {m.group(2)} from {m.group(3)} via {m.group(1)}"})
                    elif etype == "invalid":
                        events.append({"type": etype, "ts": ts_str,
                            "user": m.group(1), "ip": m.group(2), "method": "password",
                            "msg": f"Invalid user \"{m.group(1)}\" from {m.group(2)}"})
                    elif etype == "disconnect":
                        events.append({"type": etype, "ts": ts_str,
                            "user": m.group(1), "ip": m.group(2), "method": "",
                            "msg": f"Disconnected: {m.group(1)} from {m.group(2)}"})
                    elif etype == "preauth":
                        events.append({"type": etype, "ts": ts_str,
                            "user": "", "ip": m.group(1), "method": "",
                            "msg": f"Preauth disconnect from {m.group(1)}"})
                    break
    except FileNotFoundError:
        err = f"auth.log not found at {AUTH_LOG} — add /var/log volume to ops container"
    except Exception as e:
        err = str(e)

    events.sort(key=lambda x: x["ts"], reverse=True)

    c1h = datetime.now(timezone.utc) - timedelta(hours=1)
    failures_1h = [e for e in events if e["type"] in ("failure", "invalid")
                   and e["ts"] >= c1h.strftime("%Y-%m-%dT%H:%M:%S")]
    from collections import Counter as _Ctr
    fail_counts = _Ctr(e["ip"] for e in failures_1h)
    brute_force = [{"ip": ip, "count": cnt} for ip, cnt in fail_counts.most_common(5) if cnt >= 3]

    return {
        "events": events[:60],
        "stats": {
            "success_24h": sum(1 for e in events if e["type"] == "success"),
            "failure_24h": sum(1 for e in events if e["type"] in ("failure", "invalid")),
            "preauth_24h": sum(1 for e in events if e["type"] == "preauth"),
            "brute_force": brute_force,
        },
        "error": err,
        "ts": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/health")
def health():
    return {"status": "ok", "ts": datetime.now(timezone.utc).isoformat()}


app.mount("/", StaticFiles(directory="static", html=True), name="static")
