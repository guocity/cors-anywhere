// Fix deprecation warnings from dependencies
require('util')._extend = Object.assign;

// Listen on a specific host via the HOST environment variable
var host = process.env.HOST || '0.0.0.0';
// Listen on a specific port via the PORT environment variable
var port = process.env.PORT || 8080;

var crypto = require('crypto');
var fs = require('fs');
var path = require('path');

// Create log directory if it doesn't exist
var logDir = path.join(__dirname, 'log');
if (!fs.existsSync(logDir)) {
  fs.mkdirSync(logDir);
}

function saveFullLog(logData) {
  var now = new Date();
  var logFileName = now.getFullYear() + '-' + ('0' + (now.getMonth() + 1)).slice(-2) + '.log';
  var logFilePath = path.join(logDir, logFileName);
  try {
    fs.appendFileSync(logFilePath, JSON.stringify(logData) + '\n');
  } catch (err) {
    console.error('Failed to write to log file:', err);
  }
}

// Grab the blacklist from the command-line so that we can update the blacklist without deploying
// again. CORS Anywhere is open by design, and this blacklist is not used, except for countering
// immediate abuse (e.g. denial of service). If you want to block all origins except for some,
// use originWhitelist instead.
var originBlacklist = parseEnvList(process.env.CORSANYWHERE_BLACKLIST);
var originWhitelist = parseEnvList(process.env.CORSANYWHERE_WHITELIST);
function parseEnvList(env) {
  if (!env) {
    return [];
  }
  return env.split(',');
}

// Set up rate-limiting to avoid abuse of the public CORS Anywhere server.
var checkRateLimit = require('./lib/rate-limit')(process.env.CORSANYWHERE_RATELIMIT);

var metrics = {
  startTimeMs: Date.now(),
  requestsTotal: 0,
  inflight: 0,
  bytesSentTotal: 0,
  durationMsSum: 0,
  durationMsMax: 0,
  responsesByStatusClass: {
    '2xx': 0,
    '3xx': 0,
    '4xx': 0,
    '5xx': 0,
    other: 0,
  },
  requestsByMethod: {},
};

function isPathMatch(url, path) {
  return url === path || url.indexOf(path + '?') === 0;
}

function getRequestId(req) {
  var incoming = req.headers['x-request-id'];
  if (Array.isArray(incoming)) {
    incoming = incoming[0];
  }
  if (typeof incoming === 'string' && incoming.trim() !== '') {
    return incoming;
  }
  if (crypto.randomUUID) {
    return crypto.randomUUID();
  }
  return crypto.randomBytes(16).toString('hex');
}

function getHrTime() {
  if (process.hrtime.bigint) {
    return process.hrtime.bigint();
  }
  return process.hrtime();
}

function getDurationMs(start) {
  if (typeof start === 'bigint') {
    return Number(process.hrtime.bigint() - start) / 1e6;
  }
  var diff = process.hrtime(start);
  return diff[0] * 1e3 + diff[1] / 1e6;
}

function observeRequest(req, res) {
  var start = getHrTime();
  metrics.requestsTotal += 1;
  metrics.inflight += 1;
  metrics.requestsByMethod[req.method] = (metrics.requestsByMethod[req.method] || 0) + 1;

  var requestId = getRequestId(req);
  res.setHeader('x-request-id', requestId);

  var bytesSent = 0;
  var originalWrite = res.write;
  var originalEnd = res.end;
  res.write = function (chunk, encoding, callback) {
    if (chunk) {
      bytesSent += Buffer.isBuffer(chunk) ? chunk.length : Buffer.byteLength(chunk, encoding);
    }
    return originalWrite.call(this, chunk, encoding, callback);
  };
  res.end = function (chunk, encoding, callback) {
    if (chunk) {
      bytesSent += Buffer.isBuffer(chunk) ? chunk.length : Buffer.byteLength(chunk, encoding);
    }
    return originalEnd.call(this, chunk, encoding, callback);
  };

  res.on('finish', function () {
    metrics.inflight = Math.max(0, metrics.inflight - 1);
    metrics.bytesSentTotal += bytesSent;
    var durationMs = getDurationMs(start);
    metrics.durationMsSum += durationMs;
    if (durationMs > metrics.durationMsMax) {
      metrics.durationMsMax = durationMs;
    }

    var statusCode = res.statusCode || 0;
    var statusClass = Math.floor(statusCode / 100) + 'xx';
    if (!Object.prototype.hasOwnProperty.call(metrics.responsesByStatusClass, statusClass)) {
      statusClass = 'other';
    }
    metrics.responsesByStatusClass[statusClass] += 1;

    var targetUrl = null;
    if (req.corsAnywhereRequestState && req.corsAnywhereRequestState.location) {
      targetUrl = req.corsAnywhereRequestState.location.href;
    }

    var logData = {
      ts: new Date().toISOString(),
      level: 'info',
      msg: 'request completed',
      requestId: requestId,
      method: req.method,
      url: req.url,
      status: statusCode,
      durationMs: Math.round(durationMs),
      bytesSent: bytesSent,
      targetUrl: targetUrl,
      origin: req.headers.origin || null,
      userAgent: req.headers['user-agent'] || null,
      clientIp: req.headers['x-forwarded-for'] || req.connection.remoteAddress || null,
    };

    saveFullLog(logData);

    var time = logData.ts.replace('T', ' ').split('.')[0];
    console.log(time + ' ' + logData.clientIp + ' ' + (logData.targetUrl || 'n/a'));
  });
}

function formatMetrics() {
  var lines = [];
  lines.push('# HELP cors_anywhere_requests_total Total number of requests.');
  lines.push('# TYPE cors_anywhere_requests_total counter');
  lines.push('cors_anywhere_requests_total ' + metrics.requestsTotal);
  lines.push('# TYPE cors_anywhere_requests_in_flight gauge');
  lines.push('cors_anywhere_requests_in_flight ' + metrics.inflight);
  lines.push('# TYPE cors_anywhere_bytes_sent_total counter');
  lines.push('cors_anywhere_bytes_sent_total ' + metrics.bytesSentTotal);
  lines.push('# TYPE cors_anywhere_request_duration_ms_sum counter');
  lines.push('cors_anywhere_request_duration_ms_sum ' + metrics.durationMsSum.toFixed(3));
  lines.push('# TYPE cors_anywhere_request_duration_ms_count counter');
  lines.push('cors_anywhere_request_duration_ms_count ' + metrics.requestsTotal);
  lines.push('# TYPE cors_anywhere_request_duration_ms_max gauge');
  lines.push('cors_anywhere_request_duration_ms_max ' + metrics.durationMsMax.toFixed(3));
  Object.keys(metrics.responsesByStatusClass).forEach(function (statusClass) {
    lines.push('cors_anywhere_responses_total{status_class="' + statusClass + '"} ' +
      metrics.responsesByStatusClass[statusClass]);
  });
  Object.keys(metrics.requestsByMethod).forEach(function (method) {
    lines.push('cors_anywhere_requests_total_by_method{method="' + method + '"} ' +
      metrics.requestsByMethod[method]);
  });
  lines.push('# TYPE cors_anywhere_start_time_seconds gauge');
  lines.push('cors_anywhere_start_time_seconds ' + Math.floor(metrics.startTimeMs / 1000));
  return lines.join('\n') + '\n';
}

var cors_proxy = require('./lib/cors-anywhere');
var server = cors_proxy.createServer({
  originBlacklist: originBlacklist,
  originWhitelist: originWhitelist,
  requireHeader: null,
  // requireHeader: ['origin', 'x-requested-with'],
  checkRateLimit: checkRateLimit,
  handleInitialRequest: function (req, res) {
    if (isPathMatch(req.url, '/health')) {
      res.writeHead(200, {
        'content-type': 'text/plain',
        'cache-control': 'no-store',
        'access-control-allow-origin': '*',
      });
      res.end('ok');
      return true;
    }
    if (isPathMatch(req.url, '/metrics')) {
      res.writeHead(200, {
        'content-type': 'text/plain; version=0.0.4',
        'cache-control': 'no-store',
        'access-control-allow-origin': '*',
      });
      res.end(formatMetrics());
      return true;
    }
    return false;
  },
  removeHeaders: [
    'cookie',
    'cookie2',
    // Strip Heroku-specific headers
    'x-request-start',
    'x-request-id',
    'via',
    'connect-time',
    'total-route-time',
    // Other Heroku added debug headers
    // 'x-forwarded-for',
    // 'x-forwarded-proto',
    // 'x-forwarded-port',
  ],
  redirectSameOrigin: true,
  httpProxyOptions: {
    // Do not add X-Forwarded-For, etc. headers, because Heroku already adds it.
    xfwd: false,
  },
});

server.prependListener('request', observeRequest);

server.listen(port, host, function () {
  console.log('Running CORS Anywhere on ' + host + ':' + port);
});
