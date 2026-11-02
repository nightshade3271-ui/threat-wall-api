// threat-wall-api/api/threats.js
const url = require('url');
const { getThreatFeed } = require('../lib/threatFeeds');

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
  const options = {
    category: parsedUrl.query.category || 'all',
    limit: parsedUrl.query.limit || 50,
    format: parsedUrl.query.format || 'json'
  };

  const feed = getThreatFeed(options);

  res.statusCode = 200;
  res.setHeader('Content-Type', feed.contentType);
  if (feed.contentType === 'application/json') {
    res.end(JSON.stringify(feed.body, null, 2));
  } else {
    res.end(feed.body);
  }
};
