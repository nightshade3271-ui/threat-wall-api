// threat-wall-api/api/analyze.js
const url = require('url');
const { analyzeRequest } = require('../lib/exploitDetector');
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

  if (req.method === 'POST') {
    parseJsonBody(req, (err, payload) => {
      payload = payload || {};
      // If playground sent empty body, provide sample exploit request to analyze
      if (!payload.uri && !payload.query && !payload.user_agent && !payload.raw_log) {
        payload.uri = '/.env';
        payload.user_agent = 'sqlmap/1.6';
      }
      const result = analyzeRequest(payload);
      res.statusCode = 200;
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify(result, null, 2));
    });
    return;
  }

  // GET method - accepts query parameters or provides sample defaults
  const parsedUrl = url.parse(req.url, true);
  const q = parsedUrl.query;
  const requestData = {
    uri: q.uri || q.url || q.path || '/.env',
    query: q.query || '',
    user_agent: q.user_agent || q.userAgent || req.headers['user-agent'] || 'sqlmap/1.6',
    http_method: q.http_method || q.method || 'GET',
    raw_log: q.raw_log || q.log || ''
  };

  const result = analyzeRequest(requestData);
  res.statusCode = 200;
  res.setHeader('Content-Type', 'application/json');
  res.end(JSON.stringify(result, null, 2));
};
