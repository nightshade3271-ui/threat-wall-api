// threat-wall-api/api/bulk.js
const { assessIp } = require('../lib/threatEngine');
const { parseJsonBody } = require('../lib/bodyParser');

function setCorsHeaders(res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-RapidAPI-Key, X-RapidAPI-Host');
}

module.exports = function (req, res) {
  setCorsHeaders(res);
  if (req.method === 'OPTIONS') {
    res.statusCode = 204;
    res.end();
    return;
  }

  if (req.method !== 'POST') {
    res.statusCode = 405;
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify({ error: 'Method Not Allowed. Use POST with JSON array of IPs: {"ips": ["1.1.1.1", ...]}' }));
    return;
  }

  parseJsonBody(req, (err, payload) => {
    if (err) {
      res.statusCode = 400;
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({ error: 'Invalid JSON request payload.', message: err.message }));
      return;
    }

    payload = payload || {};
    const ips = Array.isArray(payload.ips) ? payload.ips : (Array.isArray(payload) ? payload : []);

    if (ips.length === 0) {
      res.statusCode = 400;
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({ error: 'Missing "ips" array in request body. Maximum 100 IPs per batch.' }));
      return;
    }

    if (ips.length > 100) {
      res.statusCode = 400;
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({ error: 'Batch limit exceeded. Maximum 100 IPs allowed per request.' }));
      return;
    }

    const assessments = ips.map(ip => assessIp(String(ip).trim()));
    const criticalCount = assessments.filter(a => a.risk_level === 'CRITICAL').length;
    const highCount = assessments.filter(a => a.risk_level === 'HIGH').length;

    res.statusCode = 200;
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify({
      success: true,
      total_assessed: assessments.length,
      summary: {
        critical_threats: criticalCount,
        high_threats: highCount,
        clean: assessments.length - (criticalCount + highCount)
      },
      results: assessments
    }, null, 2));
  });
};
