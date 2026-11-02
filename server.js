// threat-wall-api/server.js
// Standalone HTTP Server and Local Testing Harness for ThreatWall API

const http = require('http');
const url = require('url');
const fs = require('fs');
const path = require('path');

const assessHandler = require('./api/assess');
const bulkHandler = require('./api/bulk');
const firewallHandler = require('./api/firewall');
const threatsHandler = require('./api/threats');
const analyzeHandler = require('./api/analyze');
const asnHandler = require('./api/asn');
const indexHandler = require('./api/index');

const PORT = process.env.PORT || 3012;

const server = http.createServer((req, res) => {
  const parsedUrl = url.parse(req.url, true);
  let pathname = parsedUrl.pathname.replace(/\/$/, '') || '/';

  // Handle static assets if requested
  if (pathname === '/' || pathname === '/index.html') {
    const htmlPath = path.join(__dirname, 'public', 'index.html');
    if (fs.existsSync(htmlPath)) {
      res.statusCode = 200;
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      fs.createReadStream(htmlPath).pipe(res);
      return;
    }
  }

  // Routing
  if (pathname === '' || pathname === '/' || pathname === '/health') {
    return indexHandler(req, res);
  }
  if (pathname === '/v1/ip/assess') {
    return assessHandler(req, res);
  }
  if (pathname === '/v1/ip/bulk-assess') {
    return bulkHandler(req, res);
  }
  if (pathname === '/v1/firewall/rules') {
    return firewallHandler(req, res);
  }
  if (pathname === '/v1/threats/top-attackers') {
    return threatsHandler(req, res);
  }
  if (pathname === '/v1/analyze/request') {
    return analyzeHandler(req, res);
  }
  if (pathname === '/v1/asn/lookup') {
    return asnHandler(req, res);
  }

  // 404 handler
  res.statusCode = 404;
  res.setHeader('Content-Type', 'application/json');
  res.end(JSON.stringify({
    error: 'Endpoint not found',
    requested_path: pathname,
    available_endpoints: [
      '/v1/ip/assess',
      '/v1/ip/bulk-assess',
      '/v1/firewall/rules',
      '/v1/threats/top-attackers',
      '/v1/analyze/request',
      '/v1/asn/lookup',
      '/health'
    ]
  }));
});

if (require.main === module) {
  server.listen(PORT, () => {
    console.log(`🛡️ ThreatWall API is live on http://localhost:${PORT}`);
  });
}

module.exports = server;
