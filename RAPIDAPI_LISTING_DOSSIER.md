# ThreatWall API — RapidAPI Listing Dossier

## 1. Marketplace Identity
* **API Name:** ThreatWall API — Inbound Attack IP Intelligence & WAF Auto-Blocker
* **Category:** Cybersecurity / Network / Developer Tools
* **Base URL:** `https://threat-wall-api.vercel.app`
* **Short Description (Tagline):**
  > Real-time inbound attack IP threat scoring, Tor exit node detection, botnet discovery, and copy-paste multi-platform firewall generators (iptables, Nginx, Cloudflare, AWS WAF).

---

## 2. Long Description & Marketing Copy

### Stop Attackers, Botnets, and Brute-Forcers Before They Touch Your Database
Most IP intelligence APIs only return generic geographic coordinates. That doesn't protect your servers from an ongoing credential-stuffing attack or an automated vulnerability scanner.

**ThreatWall API** is an operational cybersecurity engine designed for sysadmins, DevOps engineers, and backend developers. It instantly evaluates any incoming IP address, returns an authoritative Threat Score (0–100), classifies the threat vector, and synthesizes copy-paste ready firewall drop rules across 8 major platforms.

---

### Key Capabilities

1. **Sub-10ms IP Threat Assessment (`/v1/ip/assess`)**
   * Real-time risk evaluation (CRITICAL, HIGH, MEDIUM, CLEAN).
   * Detects Tor exit nodes, bulletproof malware hosts, IoT botnets (Mirai/Mozi), residential proxies, and unauthorized vulnerability scrapers.
   * **Search-Engine Whitelist Protection:** Automatically whitelists verified Googlebot, Bingbot, and CDN edge ranges so your SEO and legitimate traffic are never accidentally blocked.

2. **Automated Multi-Platform Firewall Rule Generator (`/v1/firewall/rules`)**
   * Generate instant drop rules without writing complex bash or regex:
     * **Linux `iptables` / `nftables`**
     * **Nginx reverse proxy** (`deny <ip>;`)
     * **Cloudflare WAF Expression Builder & IP Access Rules**
     * **AWS WAF v2 IPSet JSON (Terraform & CLI ready)**
     * **Caddy, Traefik, Apache, & Windows Defender Firewall**

3. **Continuous Cron Attacker Feed (`/v1/threats/top-attackers`)**
   * Set up an automated 30-minute cron job on your Linux boxes to pull live attacker droplists.
   * Supports `format=plain_ip_list` (direct piping to `curl | xargs iptables`) and `format=nginx_conf`.

4. **Malicious Request & Exploit Signature Analyzer (`/v1/analyze/request`)**
   * Test incoming URIs, query strings, and headers against known exploit patterns:
     * SQL Injection (SQLi)
     * Directory / Path Traversal (`../../etc/passwd`)
     * Sensitive Cloud File Probing (`/.env`, `/.git/config`, `wp-config.php`)
     * Remote Code Execution (RCE) / Log4j JNDI payloads
     * Malicious Scanner User-Agents (`sqlmap`, `nikto`, `masscan`)

5. **Batch Log Processing (`/v1/ip/bulk-assess`)**
   * Pass up to 100 IPs simultaneously to filter server access logs in real time.

---

## 3. Pricing Tiers (RapidAPI Model)

| Tier | Price / Month | Quota | Overage | Best For |
| :--- | :--- | :--- | :--- | :--- |
| **Basic** | **$0** (Free) | 100 req / mo | Hard limit | Sandbox testing & developer validation |
| **Pro** | **$29 / mo** | 50,000 req / mo | $0.001 / req | Single VPS, small SaaS, and hourly cron firewall sync |
| **Ultra** | **$79 / mo** | 250,000 req / mo | $0.0005 / req | Growing multi-server clusters & per-request auth gateways |
| **Mega** | **$199 / mo** | 1,000,000 req / mo | $0.0002 / req | High-frequency API screening & enterprise log pipelines |

---

## 4. Quick Code Examples

### cURL (Check IP & Get Nginx Drop Rule):
```bash
curl -X GET "https://threat-wall-api.vercel.app/v1/ip/assess?ip=185.220.101.5" \
  -H "X-RapidAPI-Key: YOUR_API_KEY"
```

### 30-Minute Automated Linux iptables Cron Job:
```bash
*/30 * * * * curl -s "https://threat-wall-api.vercel.app/v1/threats/top-attackers?format=plain_ip_list" | while read ip; do iptables -C INPUT -s $ip -j DROP 2>/dev/null || iptables -A INPUT -s $ip -j DROP; done
```

### Python (Scan Incoming HTTP Request):
```python
import requests

url = "https://threat-wall-api.vercel.app/v1/analyze/request"
payload = {
    "uri": "/api/users?id=1 UNION SELECT password FROM admin--",
    "user_agent": "sqlmap/1.6"
}
headers = {"X-RapidAPI-Key": "YOUR_API_KEY"}

response = requests.post(url, json=payload, headers=headers)
print(response.json())
```

---

## 5. Search & SEO Tags
`cybersecurity`, `waf`, `firewall`, `botnet`, `iptables`, `nginx-block`, `cloudflare-waf`, `threat-intelligence`, `tor-detection`, `ddos-protection`, `cve`, `sql-injection`
