// threat-wall-api/lib/threatFeeds.js
// Dynamic Attacker Blacklist Feeds for Cron & Automated Firewall Synchronization

const TOP_ATTACKERS_DATA = [
  { ip: '185.220.101.5', category: 'tor_exits', threat: 'Tor Exit Node Proxy Relay', asn: 'AS208294', country: 'DE', ports: [80, 443], abuse_score: 95 },
  { ip: '185.220.101.7', category: 'tor_exits', threat: 'Tor Exit Node Proxy Relay', asn: 'AS208294', country: 'DE', ports: [80, 443], abuse_score: 95 },
  { ip: '185.220.102.8', category: 'tor_exits', threat: 'Tor Exit Relay Host', asn: 'AS208294', country: 'DE', ports: [80, 443], abuse_score: 94 },
  { ip: '198.98.56.12', category: 'tor_exits', threat: 'Tor Onion Exit Cluster', asn: 'AS53667', country: 'US', ports: [443, 8080], abuse_score: 93 },
  { ip: '171.25.193.20', category: 'tor_exits', threat: 'Tor Exit Anonymizer', asn: 'AS60729', country: 'SE', ports: [80, 443], abuse_score: 95 },
  
  { ip: '194.26.29.112', category: 'botnet_c2', threat: 'Mirai Variant / C2 Relay', asn: 'AS57523', country: 'RU', ports: [23, 2323, 5555], abuse_score: 99 },
  { ip: '91.240.118.84', category: 'botnet_c2', threat: 'Mozi IoT Botnet Node', asn: 'AS49505', country: 'RU', ports: [81, 8080], abuse_score: 98 },
  { ip: '45.154.255.45', category: 'botnet_c2', threat: 'Cobalt Strike Teamserver Probe', asn: 'AS208643', country: 'VG', ports: [50050, 443], abuse_score: 97 },
  { ip: '185.156.73.19', category: 'botnet_c2', threat: 'AsyncRAT C2 Infrastructure', asn: 'AS44477', country: 'NL', ports: [6667, 7777], abuse_score: 96 },

  { ip: '198.235.24.18', category: 'web_scanners', threat: 'Censys Vulnerability Scanner', asn: 'AS398705', country: 'US', ports: [80, 443, 8443], abuse_score: 75 },
  { ip: '162.142.125.44', category: 'web_scanners', threat: 'Censys Rapid Reconnaissance Node', asn: 'AS398705', country: 'US', ports: [80, 443], abuse_score: 75 },
  { ip: '71.6.232.10', category: 'web_scanners', threat: 'Shodan Port Crawler', asn: 'AS46562', country: 'US', ports: [21, 22, 80, 443], abuse_score: 70 },
  { ip: '71.6.165.200', category: 'web_scanners', threat: 'Shodan Reconnaissance Scanner', asn: 'AS46562', country: 'US', ports: [80, 8080], abuse_score: 70 },
  { ip: '167.94.138.35', category: 'web_scanners', threat: 'Shadowserver Foundation Scanner', asn: 'AS395747', country: 'US', ports: [80, 443], abuse_score: 65 },

  { ip: '193.142.146.88', category: 'brute_force', threat: 'Automated SSH Credential Brute-Forcer', asn: 'AS59729', country: 'HK', ports: [22, 2222], abuse_score: 96 },
  { ip: '45.146.164.110', category: 'brute_force', threat: 'WordPress xmlrpc / wp-login Brute-Forcer', asn: 'AS9009', country: 'RO', ports: [80, 443], abuse_score: 91 },
  { ip: '185.191.171.42', category: 'brute_force', threat: 'High-Volume Aggressive Form Spammer', asn: 'AS202448', country: 'US', ports: [80, 443], abuse_score: 84 },
  { ip: '45.129.56.200', category: 'brute_force', threat: 'RDP Port 3389 Brute-Force Bot', asn: 'AS200019', country: 'SC', ports: [3389], abuse_score: 94 },
  { ip: '194.38.20.55', category: 'brute_force', threat: 'FTP & SMTP Auth Sprayer', asn: 'AS202425', country: 'PA', ports: [21, 25, 587], abuse_score: 89 }
];

/**
 * Returns filtered threat feed formatted according to user requirements
 */
function getThreatFeed(options = {}) {
  const category = (options.category || 'all').toLowerCase();
  const limit = Math.min(Math.max(parseInt(options.limit, 10) || 50, 1), 500);
  const format = (options.format || 'json').toLowerCase();

  let list = TOP_ATTACKERS_DATA;
  if (category !== 'all') {
    list = list.filter(item => item.category === category);
  }

  // Slice to limit
  const results = list.slice(0, limit);
  const ips = results.map(r => r.ip);

  // Return text formats for direct cron piping
  if (format === 'plain_ip_list' || format === 'text') {
    return {
      contentType: 'text/plain',
      body: ips.join('\n')
    };
  }

  if (format === 'nginx' || format === 'nginx_conf') {
    const conf = [
      `# ThreatWall Auto-Generated Nginx Deny List`,
      `# Category: ${category} | Updated: ${new Date().toISOString()}`,
      `# Include this file in your nginx server {} block: include /etc/nginx/threatwall.conf;`,
      ...ips.map(ip => `deny ${ip};`),
      ``
    ].join('\n');
    return {
      contentType: 'text/plain',
      body: conf
    };
  }

  if (format === 'iptables' || format === 'iptables_sh') {
    const sh = [
      `#!/bin/bash`,
      `# ThreatWall Auto-Generated Iptables Droplist`,
      `# Category: ${category} | Generated: ${new Date().toISOString()}`,
      `set -e`,
      ...ips.map(ip => `iptables -A INPUT -s ${ip} -m comment --comment "ThreatWall_${category}" -j DROP`),
      `echo "ThreatWall: Successfully dropped ${ips.length} malicious IPs."`
    ].join('\n');
    return {
      contentType: 'text/plain',
      body: sh
    };
  }

  // Default JSON response
  return {
    contentType: 'application/json',
    body: {
      success: true,
      category,
      count: results.length,
      timestamp: new Date().toISOString(),
      cron_sync_recommendation: 'Run every 30-60 minutes to maintain firewall drop list',
      threats: results
    }
  };
}

module.exports = {
  TOP_ATTACKERS_DATA,
  getThreatFeed
};
