// threat-wall-api/api/index.js
const fs = require('fs');
const path = require('path');
const url = require('url');

function setCorsHeaders(res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-RapidAPI-Key, X-RapidAPI-Host');
}

module.exports = function (req, res) {
  setCorsHeaders(res);
  if (req.method === 'OPTIONS') {
    res.statusCode = 204;
    res.end();
    return;
  }

  const parsedUrl = url.parse(req.url, true);
  const pathname = parsedUrl.pathname.replace(/\/$/, '') || '/';

  if (pathname === '/health') {
    res.statusCode = 200;
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify({
      status: 'healthy',
      service: 'threat-wall-api',
      version: '1.0.0',
      uptime_seconds: process.uptime(),
      timestamp: new Date().toISOString()
    }));
    return;
  }

  // Check if browser is asking for HTML
  const acceptsHtml = req.headers.accept && req.headers.accept.includes('text/html');
  const htmlPath = path.join(__dirname, '..', 'public', 'index.html');

  if (acceptsHtml && fs.existsSync(htmlPath)) {
    try {
      const htmlContent = fs.readFileSync(htmlPath, 'utf8');
      res.statusCode = 200;
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      res.end(htmlContent);
      return;
    } catch (e) {
      // Fall through to JSON
    }
  }

  res.statusCode = 200;
  res.setHeader('Content-Type', 'application/json');
  res.end(JSON.stringify({
    service: 'ThreatWall API',
    description: 'High-Performance Inbound Attack IP Intelligence & WAF Auto-Blocker Engine',
    version: '1.0.0',
    documentation: 'https://rapidapi.com',
    endpoints: {
      assess_ip: 'GET /v1/ip/assess?ip=185.220.101.5',
      bulk_assess: 'POST /v1/ip/bulk-assess (Body: {"ips": ["1.1.1.1", ...]})',
      generate_firewall_rules: 'GET /v1/firewall/rules?ip=185.220.101.5&format=all',
      top_attackers_feed: 'GET /v1/threats/top-attackers?category=all&format=json',
      analyze_request: 'POST /v1/analyze/request (Body: {"uri": "/.env", "user_agent": "sqlmap"})',
      asn_lookup: 'GET /v1/asn/lookup?asn=AS9009',
      health_check: 'GET /health'
    },
    supported_firewall_platforms: [
      'Linux iptables',
      'Linux nftables',
      'Nginx reverse proxy deny',
      'Cloudflare WAF Expression & Access Rules',
      'AWS WAF v2 IPSet JSON',
      'Caddy Web Server',
      'Traefik Middleware',
      'Apache HTTP Server',
      'Windows Defender Firewall'
    ]
  }, null, 2));
};
