// threat-wall-api/api/firewall.js
const url = require('url');
const { generateFirewallRules } = require('../lib/firewallGenerator');
const { parseJsonBody } = require('../lib/bodyParser');

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
    parseJsonBody(req, (err, payload) => {
      payload = payload || {};
      let ips = payload.ips || (payload.ip ? [payload.ip] : []);
      if (ips.length === 0) {
        ips = ['185.220.101.5', '194.26.29.112'];
      }
      const options = {
        comment: payload.comment || 'ThreatWall Automated Block',
        action: payload.action || 'DROP'
      };
      const rules = generateFirewallRules(ips, options);
      res.statusCode = 200;
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify(rules, null, 2));
    });
    return;
  }

  // GET method
  const ipParam = parsedUrl.query.ip || '185.220.101.5,194.26.29.112';
  const ips = ipParam.split(',').map(s => s.trim()).filter(Boolean);
  const options = {
    comment: parsedUrl.query.comment || 'ThreatWall Auto Drop',
    action: parsedUrl.query.action || 'DROP'
  };

  const result = generateFirewallRules(ips, options);
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
