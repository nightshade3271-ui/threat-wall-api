// threat-wall-api/lib/bodyParser.js
// Universal body parser for Vercel Serverless (req.body pre-parsed) and raw Node http streams

function parseJsonBody(req, callback) {
  // If Vercel already parsed the body
  if (req.body !== undefined && req.body !== null) {
    if (typeof req.body === 'object') {
      return callback(null, req.body);
    }
    if (typeof req.body === 'string') {
      if (req.body.trim() === '') return callback(null, {});
      try {
        return callback(null, JSON.parse(req.body));
      } catch (err) {
        return callback(err, null);
      }
    }
  }

  // Fallback to reading stream if req.body is not populated (e.g. local node server)
  let body = '';
  req.on('data', chunk => {
    body += chunk;
  });
  req.on('end', () => {
    if (!body || body.trim() === '') {
      return callback(null, {});
    }
    try {
      const parsed = JSON.parse(body);
      callback(null, parsed);
    } catch (err) {
      callback(err, null);
    }
  });
  req.on('error', err => {
    callback(err, null);
  });
}

module.exports = {
  parseJsonBody
};
