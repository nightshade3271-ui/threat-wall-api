# ThreatWall API 🛡️

**Inbound Attack IP Intelligence & WAF Auto-Blocker Engine**

ThreatWall API is an operational cybersecurity API built for sysadmins, DevOps engineers, and backend developers. It assesses incoming IPv4/IPv6 addresses, flags botnets, Tor exit nodes, and vulnerability scanners, and automatically synthesizes copy-paste firewall rules across 8 major platforms.

---

## 🚀 Live Demo & Documentation
* **Interactive Web Playground:** `https://threat-wall-api.vercel.app`
* **RapidAPI Hub Ready:** `rapidapi-openapi.json` included in repository for 1-click import.

---

## ⚡ Endpoints

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/v1/ip/assess?ip=...` | Single IP threat scoring, Tor detection, and recommended action (`BLOCK`, `CHALLENGE`, `ALLOW`). |
| `POST` | `/v1/ip/bulk-assess` | Batch assess up to 100 IPs simultaneously from server access logs. |
| `GET` | `/v1/firewall/rules?ip=...` | Synthesize copy-paste rules for iptables, nftables, Nginx, Cloudflare, AWS WAF, etc. |
| `GET` | `/v1/threats/top-attackers` | Dynamic attacker droplist for automated cron jobs (JSON, plain IP list, Nginx config). |
| `POST` | `/v1/analyze/request` | Detect SQLi, Path Traversal, Sensitive File Probing (`/.env`), and RCE exploit signatures. |
| `GET` | `/v1/asn/lookup?asn=...` | Query Autonomous System (ASN) threat profile and abuse history. |
| `GET` | `/health` | Service health status. |

---

## 💻 Automated 30-Minute Cron Job (Linux iptables)

Keep your servers protected on autopilot:
```bash
*/30 * * * * curl -s "https://threat-wall-api.vercel.app/v1/threats/top-attackers?format=plain_ip_list" | while read ip; do iptables -C INPUT -s $ip -j DROP 2>/dev/null || iptables -A INPUT -s $ip -j DROP; done
```

---

## 🧪 Testing

Run the included zero-dependency test suite:
```bash
npm test
```

License: MIT
