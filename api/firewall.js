// threat-wall-api/api/firewall.js
const url = require('url');
const { generateFirewallRules } = require('../lib/firewallGenerator');

function setCorsHeaders(res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
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

  if (req.method === 'POST') {
    let body = '';
    req.on('data', chunk => { body += chunk; });
    req.on('end', () => {
      try {
        const payload = body ? JSON.parse(body) : {};
        const ips = payload.ips || (payload.ip ? [payload.ip] : []);
        const options = {
          comment: payload.comment || 'ThreatWall Automated Block',
          action: payload.action || 'DROP'
        };
        const rules = generateFirewallRules(ips, options);
        res.statusCode = rules.success ? 200 : 400;
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify(rules, null, 2));
      } catch (err) {
        res.statusCode = 400;
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ error: 'Invalid JSON request payload.', message: err.message }));
      }
    });
    return;
  }

  // GET method
  const ipParam = parsedUrl.query.ip;
  if (!ipParam) {
    res.statusCode = 400;
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify({
      error: 'Missing required query parameter "ip". Provide one IP or comma-separated list. Example: /v1/firewall/rules?ip=185.220.101.5',
      code: 'MISSING_IP_PARAM'
    }));
    return;
  }

  const ips = ipParam.split(',').map(s => s.trim()).filter(Boolean);
  const options = {
    comment: parsedUrl.query.comment || 'ThreatWall Auto Drop',
    action: parsedUrl.query.action || 'DROP'
  };

  const result = generateFirewallRules(ips, options);
  if (!result.success) {
    res.statusCode = 400;
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify(result));
    return;
  }

  // If user requested a single format (e.g. format=nginx or format=iptables)
  const format = (parsedUrl.query.format || '').toLowerCase();
  if (format === 'nginx') {
    res.statusCode = 200;
    res.setHeader('Content-Type', 'text/plain');
    res.end(result.rules.nginx);
    return;
  }
  if (format === 'iptables') {
    res.statusCode = 200;
    res.setHeader('Content-Type', 'text/plain');
    res.end(result.rules.iptables);
    return;
  }

  res.statusCode = 200;
  res.setHeader('Content-Type', 'application/json');
  res.end(JSON.stringify(result, null, 2));
};
