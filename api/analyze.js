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
      if (err) {
        res.statusCode = 400;
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ error: 'Invalid JSON request payload.', message: err.message }));
        return;
      }
      const result = analyzeRequest(payload || {});
      res.statusCode = 200;
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify(result, null, 2));
    });
    return;
  }

  // GET method - accepts query parameters
  const parsedUrl = url.parse(req.url, true);
  const q = parsedUrl.query;
  const requestData = {
    uri: q.uri || q.url || q.path || '',
    query: q.query || '',
    user_agent: q.user_agent || q.userAgent || req.headers['user-agent'] || '',
    raw_log: q.raw_log || q.log || ''
  };

  if (!requestData.uri && !requestData.query && !requestData.user_agent && !requestData.raw_log) {
    res.statusCode = 400;
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify({
      error: 'Missing request parameters to analyze. Provide "uri", "query", or "user_agent". Example: /v1/analyze/request?uri=/.env&user_agent=sqlmap',
      code: 'MISSING_ANALYZE_PARAMS'
    }));
    return;
  }

  const result = analyzeRequest(requestData);
  res.statusCode = 200;
  res.setHeader('Content-Type', 'application/json');
  res.end(JSON.stringify(result, null, 2));
};
