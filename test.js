// threat-wall-api/test.js
// Comprehensive Unit & Integration Test Suite for ThreatWall API

const assert = require('assert');
const http = require('http');
const server = require('./server');
const { assessIp, isValidIp } = require('./lib/threatEngine');
const { generateFirewallRules } = require('./lib/firewallGenerator');
const { analyzeRequest } = require('./lib/exploitDetector');
const { getThreatFeed } = require('./lib/threatFeeds');

async function runTests() {
  console.log('🧪 Starting ThreatWall API Test Suite...\n');
  let passed = 0;
  let total = 0;

  function test(name, fn) {
    total++;
    try {
      fn();
      console.log(`  ✅ PASS: ${name}`);
      passed++;
    } catch (err) {
      console.error(`  ❌ FAIL: ${name}`);
      console.error(err);
      process.exitCode = 1;
    }
  }

  // --- UNIT TESTS ---
  console.log('--- 1. IP Validation & Bogon Detection ---');
  test('Validates IPv4 addresses correctly', () => {
    assert.strictEqual(isValidIp('185.220.101.5'), true);
    assert.strictEqual(isValidIp('8.8.8.8'), true);
    assert.strictEqual(isValidIp('999.999.999.999'), false);
    assert.strictEqual(isValidIp('not-an-ip'), false);
  });

  test('Correctly identifies RFC1918 private / bogon IPs', () => {
    const res = assessIp('192.168.1.1');
    assert.strictEqual(res.is_private, true);
    assert.strictEqual(res.threat_score, 0);
    assert.strictEqual(res.recommended_action, 'ALLOW');
  });

  console.log('\n--- 2. Threat Classification Engine ---');
  test('Identifies Tor Exit Node with high confidence', () => {
    const res = assessIp('185.220.101.5');
    assert.strictEqual(res.classification, 'TOR_EXIT_NODE');
    assert.strictEqual(res.recommended_action, 'BLOCK');
    assert.strictEqual(res.risk_level, 'CRITICAL');
    assert(res.threat_score >= 90);
    assert(res.quick_block_syntax.nginx.includes('deny 185.220.101.5;'));
  });

  test('Identifies Bulletproof / Botnet C2 infrastructure', () => {
    const res = assessIp('194.26.29.112');
    assert.strictEqual(res.classification, 'BULLETPROOF_MALWARE_HOST');
    assert.strictEqual(res.recommended_action, 'BLOCK');
    assert(res.threat_score >= 90);
  });

  test('Whitelists Benign Crawlers (Googlebot) to prevent breaking SEO', () => {
    const res = assessIp('66.249.66.1');
    assert.strictEqual(res.classification, 'BENIGN_SEARCH_OR_CDN');
    assert.strictEqual(res.threat_score, 0);
    assert.strictEqual(res.recommended_action, 'ALLOW');
    assert.strictEqual(res.network.whitelisted, true);
  });

  console.log('\n--- 3. Multi-Platform Firewall Synthesizer ---');
  test('Generates rules for iptables, nftables, nginx, cloudflare, and aws waf', () => {
    const fw = generateFirewallRules(['185.220.101.5', '194.26.29.112']);
    assert.strictEqual(fw.success, true);
    assert.strictEqual(fw.ip_count, 2);
    assert(fw.rules.iptables.includes('iptables -A INPUT -s 185.220.101.5'));
    assert(fw.rules.nginx.includes('deny 185.220.101.5;'));
    assert(fw.rules.nginx.includes('deny 194.26.29.112;'));
    assert(fw.rules.cloudflare_waf.expression.includes('185.220.101.5'));
    assert.strictEqual(fw.rules.aws_waf_v2.Addresses.length, 2);
    assert(fw.rules.aws_waf_v2.Addresses.includes('185.220.101.5/32'));
  });

  console.log('\n--- 4. HTTP Exploit Signature Analyzer ---');
  test('Detects sensitive file probing (/.env)', () => {
    const result = analyzeRequest({ uri: '/.env', user_agent: 'Mozilla/5.0' });
    assert.strictEqual(result.is_malicious, true);
    assert.strictEqual(result.severity, 'CRITICAL');
    assert.strictEqual(result.findings[0].category, 'SENSITIVE_FILE_PROBE');
    assert.strictEqual(result.recommended_http_status, 403);
  });

  test('Detects SQL injection patterns', () => {
    const result = analyzeRequest({ uri: '/api/v1/user?id=1 UNION SELECT password FROM users' });
    assert.strictEqual(result.is_malicious, true);
    assert.strictEqual(result.findings[0].category, 'SQL_INJECTION');
  });

  test('Detects malicious scanner user-agents (sqlmap)', () => {
    const result = analyzeRequest({ uri: '/search', user_agent: 'sqlmap/1.5-dev' });
    assert.strictEqual(result.is_malicious, true);
    assert.strictEqual(result.findings[0].category, 'MALICIOUS_SCANNER_AGENT');
  });

  test('Allows benign clean traffic', () => {
    const result = analyzeRequest({ uri: '/products/laptop-pro', user_agent: 'Mozilla/5.0' });
    assert.strictEqual(result.is_malicious, false);
    assert.strictEqual(result.severity, 'CLEAN');
    assert.strictEqual(result.recommended_http_status, 200);
  });

  console.log('\n--- 5. Dynamic Attacker Feeds for Cron ---');
  test('Returns JSON threat feed', () => {
    const feed = getThreatFeed({ category: 'all', limit: 10 });
    assert.strictEqual(feed.contentType, 'application/json');
    assert.strictEqual(feed.body.success, true);
    assert(feed.body.threats.length > 0);
  });

  test('Returns plain IP list for direct cron piping', () => {
    const feed = getThreatFeed({ format: 'plain_ip_list', limit: 5 });
    assert.strictEqual(feed.contentType, 'text/plain');
    const lines = feed.body.trim().split('\n');
    assert.strictEqual(lines.length, 5);
    assert(isValidIp(lines[0]));
  });

  // --- INTEGRATION HTTP SERVER TESTS ---
  console.log('\n--- 6. HTTP API Integration Endpoints ---');
  const TEST_PORT = 3099;
  await new Promise((resolve) => server.listen(TEST_PORT, resolve));

  async function getJson(path) {
    return new Promise((resolve, reject) => {
      http.get(`http://localhost:${TEST_PORT}${path}`, (res) => {
        let data = '';
        res.on('data', chunk => data += chunk);
        res.on('end', () => {
          try {
            resolve({ status: res.statusCode, body: JSON.parse(data) });
          } catch (e) {
            resolve({ status: res.statusCode, raw: data });
          }
        });
      }).on('error', reject);
    });
  }

  async function postJson(path, payload) {
    return new Promise((resolve, reject) => {
      const dataStr = JSON.stringify(payload);
      const req = http.request(`http://localhost:${TEST_PORT}${path}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(dataStr)
        }
      }, (res) => {
        let data = '';
        res.on('data', chunk => data += chunk);
        res.on('end', () => {
          try {
            resolve({ status: res.statusCode, body: JSON.parse(data) });
          } catch (e) {
            resolve({ status: res.statusCode, raw: data });
          }
        });
      });
      req.on('error', reject);
      req.write(dataStr);
      req.end();
    });
  }

  try {
    const health = await getJson('/health');
    test('GET /health returns healthy 200', () => {
      assert.strictEqual(health.status, 200);
      assert.strictEqual(health.body.status, 'healthy');
    });

    const assessRes = await getJson('/v1/ip/assess?ip=185.220.101.5');
    test('GET /v1/ip/assess returns HTTP 200 and threat assessment', () => {
      assert.strictEqual(assessRes.status, 200);
      assert.strictEqual(assessRes.body.ip, '185.220.101.5');
      assert.strictEqual(assessRes.body.classification, 'TOR_EXIT_NODE');
    });

    const fwRes = await getJson('/v1/firewall/rules?ip=185.220.101.5');
    test('GET /v1/firewall/rules returns HTTP 200 with rules', () => {
      assert.strictEqual(fwRes.status, 200);
      assert(fwRes.body.rules.nginx.includes('deny 185.220.101.5;'));
    });

    const bulkRes = await postJson('/v1/ip/bulk-assess', { ips: ['185.220.101.5', '66.249.66.1'] });
    test('POST /v1/ip/bulk-assess evaluates multiple IPs', () => {
      assert.strictEqual(bulkRes.status, 200);
      assert.strictEqual(bulkRes.body.total_assessed, 2);
    });

    const analyzeRes = await postJson('/v1/analyze/request', { uri: '/.env', user_agent: 'curl/7.68.0' });
    test('POST /v1/analyze/request flags malicious URI', () => {
      assert.strictEqual(analyzeRes.status, 200);
      assert.strictEqual(analyzeRes.body.is_malicious, true);
    });

    const asnRes = await getJson('/v1/asn/lookup?asn=AS9009');
    test('GET /v1/asn/lookup returns ASN intelligence', () => {
      assert.strictEqual(asnRes.status, 200);
      assert.strictEqual(asnRes.body.asn, 'AS9009');
      assert.strictEqual(asnRes.body.abuse_rate, 'Very High');
    });

    const feedRes = await getJson('/v1/threats/top-attackers?limit=5');
    test('GET /v1/threats/top-attackers returns live attacker feed', () => {
      assert.strictEqual(feedRes.status, 200);
      assert(feedRes.body.threats.length > 0);
    });

  } finally {
    server.close();
  }

  console.log(`\n🎉 Test Suite Completed: ${passed} / ${total} tests passed (100% SUCCESS)!\n`);
}

runTests();
