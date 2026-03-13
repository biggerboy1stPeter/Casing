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
const { Pool } = require('pg');
const Queue = require('bull');
const Joi = require('joi');
const promClient = require('prom-client');
const winston = require('winston');
const { createLogger, format, transports } = require('winston');
const { v4: uuidv4 } = require('uuid');
const sanitizeHtml = require('sanitize-html');
const xss = require('xss-clean');
const hpp = require('hpp');
const cors = require('cors');
const useragent = require('express-useragent');
const responseTime = require('response-time');
const slowDown = require("express-slow-down");
const Redis = require('ioredis');
const createRedisStore = require('connect-redis').default;
const cookieParser = require('cookie-parser');

// Bull Board imports
const { createBullBoard } = require('@bull-board/api');
const { BullAdapter } = require('@bull-board/api/bullAdapter');
const { ExpressAdapter } = require('@bull-board/express');

// Load environment variables
dotenv.config();

// ─── Configuration Validation ─────────────────────────────────────────────────
const configSchema = Joi.object({
  TARGET_URL: Joi.string().uri().required(),
  NODE_ENV: Joi.string().valid('development', 'production', 'test').default('production'),
  PORT: Joi.number().port().default(10000),
  REDIS_URL: Joi.string().uri().optional().allow('', null),
  REDIS_HOST: Joi.string().optional(),
  REDIS_PORT: Joi.number().port().default(6379),
  REDIS_PASSWORD: Joi.string().optional(),
  SESSION_SECRET: Joi.string().min(32).required(),
  METRICS_API_KEY: Joi.string().min(16).required(),
  ADMIN_USERNAME: Joi.string().min(3).required(),
  ADMIN_PASSWORD_HASH: Joi.string().required(),
  IPINFO_TOKEN: Joi.string().optional(),
  LINK_TTL: Joi.string().pattern(/^(\d+)([smhd])?$/i).default('30m'),
  MAX_LINKS: Joi.number().integer().min(100).max(10000000).default(1000000),
  BOT_URLS: Joi.string().optional(),
  CORS_ORIGIN: Joi.string().optional(),
  DATABASE_URL: Joi.string().uri().optional().allow('', null),
  SMTP_HOST: Joi.string().optional(),
  SMTP_PORT: Joi.number().port().optional(),
  SMTP_USER: Joi.string().optional(),
  SMTP_PASS: Joi.string().optional(),
  ALERT_EMAIL: Joi.string().email().optional(),
  DISABLE_DESKTOP_CHALLENGE: Joi.boolean().default(false),
  HTTPS_ENABLED: Joi.boolean().default(false),
  DEBUG: Joi.boolean().default(false),
  BULL_BOARD_ENABLED: Joi.boolean().default(true),
  BULL_BOARD_PATH: Joi.string().default('/admin/queues')
});

const { error: configError, value: validatedConfig } = configSchema.validate(process.env, {
  allowUnknown: true,
  stripUnknown: true
});

if (configError) {
  console.error('❌ Configuration validation error:', configError.message);
  process.exit(1);
}

// ─── Logger Setup ────────────────────────────────────────────────────────────
const logger = createLogger({
  level: validatedConfig.DEBUG ? 'debug' : 'info',
  format: format.combine(
    format.timestamp(),
    format.errors({ stack: true }),
    format.splat(),
    format.json()
  ),
  defaultMeta: { service: 'redirector-pro' },
  transports: [
    new transports.File({ filename: 'error.log', level: 'error' }),
    new transports.File({ filename: 'combined.log' }),
    new transports.Console({
      format: format.combine(
        format.colorize(),
        format.simple()
      )
    })
  ]
});

// ─── Prometheus Metrics ──────────────────────────────────────────────────────
const collectDefaultMetrics = promClient.collectDefaultMetrics;
collectDefaultMetrics({ timeout: 5000 });

const httpRequestDurationMicroseconds = new promClient.Histogram({
  name: 'http_request_duration_ms',
  help: 'Duration of HTTP requests in ms',
  labelNames: ['method', 'route', 'code'],
  buckets: [0.1, 5, 15, 50, 100, 200, 300, 400, 500, 1000, 2000, 5000]
});

const activeConnections = new promClient.Gauge({
  name: 'active_connections',
  help: 'Number of active connections'
});

const totalRequests = new promClient.Counter({
  name: 'total_requests',
  help: 'Total number of requests'
});

const botBlocks = new promClient.Counter({
  name: 'bot_blocks_total',
  help: 'Total number of bot blocks'
});

const linkGenerations = new promClient.Counter({
  name: 'link_generations_total',
  help: 'Total number of link generations'
});

// ─── App Initialization ──────────────────────────────────────────────────────
const app = express();
const server = http.createServer(app);

// ─── Redis Connection ────────────────────────────────────────────────────────
let redisClient;
let sessionStore;

if (validatedConfig.REDIS_URL && validatedConfig.REDIS_URL.startsWith('redis://')) {
  try {
    redisClient = new Redis(validatedConfig.REDIS_URL, {
      retryStrategy: (times) => {
        const delay = Math.min(times * 50, 2000);
        return delay;
      },
      maxRetriesPerRequest: 3
    });

    redisClient.on('error', (err) => {
      logger.error('Redis error:', err);
    });

    redisClient.on('connect', () => {
      logger.info('✅ Connected to Redis');
    });

    const RedisStore = createRedisStore(session);
    sessionStore = new RedisStore({ 
      client: redisClient,
      prefix: 'redirector:',
      ttl: 86400
    });

  } catch (err) {
    logger.warn('Redis connection failed, using MemoryStore:', err.message);
    sessionStore = new session.MemoryStore();
  }
} else {
  logger.warn('Using MemoryStore - not suitable for production!');
  sessionStore = new session.MemoryStore();
}

// ─── Bull Queues ─────────────────────────────────────────────────────────────
let redirectQueue;
let emailQueue;
let analyticsQueue;
let serverAdapter;
let bullBoard;

if (redisClient) {
  redirectQueue = new Queue('redirect processing', { 
    redis: redisClient,
    defaultJobOptions: {
      attempts: 3,
      backoff: {
        type: 'exponential',
        delay: 2000
      },
      removeOnComplete: 100,
      removeOnFail: 200
    }
  });
  
  emailQueue = new Queue('email sending', { 
    redis: redisClient,
    defaultJobOptions: {
      attempts: 5,
      backoff: 2000,
      removeOnComplete: 50
    }
  });
  
  analyticsQueue = new Queue('analytics processing', { 
    redis: redisClient,
    defaultJobOptions: {
      attempts: 2,
      removeOnComplete: 1000,
      removeOnFail: 500
    }
  });

  redirectQueue.process(async (job) => {
    const { linkId, ip, userAgent, deviceInfo } = job.data;
    await logToDatabase({
      type: 'redirect',
      linkId,
      ip,
      userAgent,
      deviceInfo,
      timestamp: new Date()
    });
    return { success: true };
  });

  emailQueue.process(async (job) => {
    const { to, subject, html } = job.data;
    if (validatedConfig.SMTP_HOST) {
      logger.info(`Email would be sent to ${to} with subject: ${subject}`);
      return { sent: true };
    }
    return { sent: false, reason: 'SMTP not configured' };
  });

  analyticsQueue.process(async (job) => {
    const { type, data } = job.data;
    await updateAnalytics(type, data);
    return { processed: true };
  });

  if (validatedConfig.BULL_BOARD_ENABLED) {
    serverAdapter = new ExpressAdapter();
    serverAdapter.setBasePath(validatedConfig.BULL_BOARD_PATH);
    
    bullBoard = createBullBoard({
      queues: [
        new BullAdapter(redirectQueue),
        new BullAdapter(emailQueue),
        new BullAdapter(analyticsQueue)
      ],
      serverAdapter: serverAdapter,
      options: {
        uiConfig: {
          boardTitle: 'Redirector Pro Queues',
          boardLogo: {
            path: 'https://cdn.jsdelivr.net/npm/heroicons@1.0.6/outline/clock.svg',
            width: 30,
            height: 30
          }
        }
      }
    });
    
    logger.info(`✅ Bull Board enabled at ${validatedConfig.BULL_BOARD_PATH}`);
  }
}

// ─── Database Connection ─────────────────────────────────────────────────────
let dbPool;
if (validatedConfig.DATABASE_URL && validatedConfig.DATABASE_URL.startsWith('postgresql://')) {
  try {
    dbPool = new Pool({
      connectionString: validatedConfig.DATABASE_URL,
      ssl: validatedConfig.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
      max: 20,
      idleTimeoutMillis: 30000,
      connectionTimeoutMillis: 2000
    });

    dbPool.on('error', (err) => {
      if (validatedConfig.DEBUG) {
        logger.error('Unexpected database error:', err);
      }
    });

    dbPool.query(`
      CREATE TABLE IF NOT EXISTS links (
        id VARCHAR(32) PRIMARY KEY,
        target_url TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        expires_at TIMESTAMP NOT NULL,
        creator_ip INET,
        password_hash TEXT,
        max_clicks INTEGER,
        current_clicks INTEGER DEFAULT 0
      );

      CREATE TABLE IF NOT EXISTS clicks (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        link_id VARCHAR(32) REFERENCES links(id) ON DELETE CASCADE,
        ip INET,
        user_agent TEXT,
        device_type VARCHAR(20),
        country VARCHAR(2),
        city TEXT,
        referer TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS logs (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        data JSONB NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      CREATE INDEX IF NOT EXISTS idx_links_expires ON links(expires_at);
      CREATE INDEX IF NOT EXISTS idx_clicks_link_id ON clicks(link_id);
      CREATE INDEX IF NOT EXISTS idx_clicks_created ON clicks(created_at);
    `).catch(err => {
      if (validatedConfig.DEBUG) {
        logger.error('Database initialization error:', err);
      }
    });
    
    logger.info('✅ Database connected');
  } catch (err) {
    logger.warn('Database connection failed, continuing without database:', err.message);
    dbPool = null;
  }
} else {
  logger.info('📁 Running without database (file-based logging only)');
}

async function logToDatabase(entry) {
  if (!dbPool) return;
  
  try {
    const query = 'INSERT INTO logs (data) VALUES ($1)';
    await dbPool.query(query, [JSON.stringify(entry)]);
  } catch (err) {
    if (validatedConfig.DEBUG) {
      logger.debug('Database log failed (non-critical):', err.message);
    }
  }
}

async function updateAnalytics(type, data) {
  if (type === 'request') {
    totalRequests.inc();
  } else if (type === 'bot') {
    botBlocks.inc();
  } else if (type === 'generate') {
    linkGenerations.inc();
  }

  if (dbPool) {
    try {
      const query = 'INSERT INTO analytics (type, data) VALUES ($1, $2)';
      await dbPool.query(query, [type, JSON.stringify(data)]);
    } catch (err) {
      if (validatedConfig.DEBUG) {
        logger.debug('Analytics update failed:', err.message);
      }
    }
  }
}

// ─── Socket.IO Setup ─────────────────────────────────────────────────────────
const io = new Server(server, {
  cors: {
    origin: validatedConfig.CORS_ORIGIN ? validatedConfig.CORS_ORIGIN.split(',') : "*",
    methods: ["GET", "POST"],
    credentials: true
  },
  pingTimeout: 60000,
  pingInterval: 25000,
  transports: ['websocket', 'polling']
});

// ─── Session Setup ───────────────────────────────────────────────────────────
app.set('trust proxy', 1);
app.use(compression({ level: 6, threshold: 0 }));
app.use(morgan('combined', { stream: { write: message => logger.info(message.trim()) } }));
app.use(express.static('public', { maxAge: '1d' }));
app.use(useragent.express());
app.use(xss());
app.use(hpp());
app.use(cors({
  origin: validatedConfig.CORS_ORIGIN ? validatedConfig.CORS_ORIGIN.split(',') : "*",
  credentials: true
}));
app.use(cookieParser(validatedConfig.SESSION_SECRET));

app.use(session({
  store: sessionStore,
  secret: validatedConfig.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  name: 'redirector.sid',
  cookie: { 
    secure: validatedConfig.NODE_ENV === 'production' && validatedConfig.HTTPS_ENABLED === 'true', 
    maxAge: 24 * 60 * 60 * 1000,
    httpOnly: true,
    sameSite: 'lax',
    path: '/',
    domain: validatedConfig.NODE_ENV === 'production' ? process.env.DOMAIN : undefined
  },
  rolling: true
}));

// ─── CSRF Protection (Session-based) ─────────────────────────────────────
app.use((req, res, next) => {
  if (!req.session.csrfToken) {
    req.session.csrfToken = crypto.randomBytes(32).toString('hex');
  }
  res.locals.csrfToken = req.session.csrfToken;
  res.setHeader('X-CSRF-Token', req.session.csrfToken);
  next();
});

const csrfProtection = (req, res, next) => {
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
    return next();
  }
  
  const token = req.body._csrf || 
                req.query._csrf || 
                req.headers['csrf-token'] || 
                req.headers['xsrf-token'] ||
                req.headers['x-csrf-token'] ||
                req.headers['x-xsrf-token'];
  
  if (!token || token !== req.session.csrfToken) {
    logger.warn('CSRF validation failed:', { 
      id: req.id, 
      ip: req.ip, 
      path: req.path,
      method: req.method
    });
    
    if (req.path.startsWith('/api/') || req.xhr) {
      return res.status(403).json({ 
        error: 'Invalid CSRF token',
        id: req.id 
      });
    }
    
    return res.redirect(req.get('referer') || '/admin/login?error=invalid_csrf');
  }
  
  next();
};

// ─── Bull Board Middleware ──────────────────────────────────────────
if (serverAdapter && validatedConfig.BULL_BOARD_ENABLED) {
  app.use(validatedConfig.BULL_BOARD_PATH, (req, res, next) => {
    if (!req.session.authenticated) {
      return res.status(401).send('Unauthorized');
    }
    next();
  });
  
  app.use(validatedConfig.BULL_BOARD_PATH, serverAdapter.getRouter());
}

// ─── Config ──────────────────────────────────────────────────────────────────
const TARGET_URL = validatedConfig.TARGET_URL;
const BOT_URLS = validatedConfig.BOT_URLS ? 
  validatedConfig.BOT_URLS.split(',').map(url => url.trim()) : [
    'https://www.microsoft.com',
    'https://www.apple.com',
    'https://www.google.com',
    'https://en.wikipedia.org/wiki/Main_Page',
    'https://www.bbc.com'
  ];

const LOG_FILE = 'clicks.log';
const REQUEST_LOG_FILE = 'requests.log';
const PORT = validatedConfig.PORT;

const ADMIN_USERNAME = validatedConfig.ADMIN_USERNAME;
const ADMIN_PASSWORD_HASH = validatedConfig.ADMIN_PASSWORD_HASH;

function parseTTL(ttlValue) {
  const defaultTTL = 1800;
  
  if (!ttlValue) return defaultTTL;
  
  const match = String(ttlValue).match(/^(\d+)([smhd])?$/i);
  if (!match) return defaultTTL;
  
  const num = parseInt(match[1]);
  const unit = (match[2] || 'm').toLowerCase();
  
  switch(unit) {
    case 's': return Math.max(60, num);
    case 'm': return Math.max(1, num) * 60;
    case 'h': return Math.max(1, num) * 3600;
    case 'd': return Math.max(1, num) * 86400;
    default: return Math.max(60, num * 60);
  }
}

const LINK_TTL_SEC = parseTTL(validatedConfig.LINK_TTL);
const METRICS_API_KEY = validatedConfig.METRICS_API_KEY;
const IPINFO_TOKEN = validatedConfig.IPINFO_TOKEN;
const NODE_ENV = validatedConfig.NODE_ENV;
const MAX_LINKS = validatedConfig.MAX_LINKS;

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

// Cache instances
const geoCache = new NodeCache({ stdTTL: 86400, checkperiod: 3600, useClones: false, maxKeys: 100000 });
const linkCache = new NodeCache({ stdTTL: LINK_TTL_SEC, checkperiod: Math.min(300, Math.floor(LINK_TTL_SEC / 10)), useClones: false, maxKeys: MAX_LINKS });
const linkRequestCache = new NodeCache({ stdTTL: 60, checkperiod: 10, useClones: false, maxKeys: 10000 });
const failCache = new NodeCache({ stdTTL: 3600, checkperiod: 600, useClones: false, maxKeys: 10000 });
const deviceCache = new NodeCache({ stdTTL: 300, checkperiod: 60, useClones: false, maxKeys: 50000 });
const qrCache = new NodeCache({ stdTTL: 3600, checkperiod: 600, useClones: false, maxKeys: 1000 });

// Stats Tracking
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

// Socket.IO Authentication
io.use((socket, next) => {
  const token = socket.handshake.auth.token;
  if (token === METRICS_API_KEY) {
    next();
  } else {
    next(new Error('Authentication error'));
  }
}).on('connection', (socket) => {
  logger.info('Admin client connected:', socket.id);
  activeConnections.inc();
  
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
    logger.info('Admin client disconnected:', socket.id);
    activeConnections.dec();
  });

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

// Update realtime stats
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
  
  io.emit('stats', stats);
}, 1000);

setInterval(() => {
  stats.realtime.lastMinute = stats.realtime.lastMinute.slice(-60);
}, 60000);

// Device Detection
function getDeviceInfo(req) {
  const ua = req.headers['user-agent'] || '';
  
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

  const uaLower = ua.toLowerCase();
  const botPatterns = [
    'headless', 'phantom', 'slurp', 'zgrab', 'scanner', 'bot', 'crawler', 
    'spider', 'burp', 'sqlmap', 'curl', 'wget', 'python', 'perl', 'ruby', 
    'go-http-client', 'java', 'okhttp', 'scrapy', 'httpclient', 'axios',
    'node-fetch', 'php', 'libwww', 'wget', 'fetch', 'ahrefs', 'semrush',
    'puppeteer', 'selenium', 'playwright', 'cypress'
  ];
  
  if (botPatterns.some(pattern => uaLower.includes(pattern))) {
    deviceInfo.type = 'bot';
    deviceInfo.isBot = true;
    deviceInfo.score = 100;
    deviceCache.set(cacheKey, deviceInfo);
    stats.byDevice.bot = (stats.byDevice.bot || 0) + 1;
    return deviceInfo;
  }

  if (result.device.type === 'mobile' || /Mobi|Android|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(ua)) {
    if (result.device.type === 'tablet' || /Tablet|iPad|PlayBook|Silk|Kindle|(Android(?!.*Mobile))/i.test(ua)) {
      deviceInfo.type = 'tablet';
      deviceInfo.isTablet = true;
    } else {
      deviceInfo.type = 'mobile';
      deviceInfo.isMobile = true;
    }
  }

  if (deviceInfo.isMobile) {
    if (deviceInfo.brand !== 'unknown') deviceInfo.score -= 10;
    if (deviceInfo.model !== 'unknown') deviceInfo.score -= 10;
    if (deviceInfo.os !== 'unknown') deviceInfo.score -= 5;
    if (deviceInfo.browser !== 'unknown') deviceInfo.score -= 5;
    
    if (deviceInfo.browser.includes('Safari') || 
        deviceInfo.browser.includes('Chrome') || 
        deviceInfo.browser.includes('Firefox')) {
      deviceInfo.score -= 15;
    }
    
    if (deviceInfo.os.includes('iOS') || 
        deviceInfo.os.includes('Android')) {
      deviceInfo.score -= 15;
    }
    
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

// Custom Error Class
class AppError extends Error {
  constructor(message, statusCode, isOperational = true) {
    super(message);
    this.statusCode = statusCode;
    this.isOperational = isOperational;
    Error.captureStackTrace(this, this.constructor);
  }
}

// Middleware
app.use((req, res, next) => {
  req.id = uuidv4();
  req.startTime = Date.now();
  req.deviceInfo = getDeviceInfo(req);
  res.locals.nonce = crypto.randomBytes(16).toString('hex');
  res.locals.startTime = Date.now();
  res.locals.deviceInfo = req.deviceInfo;
  res.setHeader('X-Request-ID', req.id);
  res.setHeader('X-Device-Type', req.deviceInfo.type);
  res.setHeader('X-Powered-By', 'Redirector-Pro');
  
  totalRequests.inc();
  stats.totalRequests++;
  
  if (analyticsQueue) {
    analyticsQueue.add({ type: 'request', data: { id: req.id, device: req.deviceInfo.type } });
  }
  
  next();
});

app.use(responseTime((req, res, time) => {
  if (req.route?.path) {
    httpRequestDurationMicroseconds
      .labels(req.method, req.route.path, res.statusCode)
      .observe(time);
  }
}));

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
      upgradeInsecureRequests: NODE_ENV === 'production' ? [] : null
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

// Rate Limiting
const speedLimiter = slowDown({
  windowMs: 15 * 60 * 1000,
  delayAfter: 50,
  delayMs: (hits) => hits * 100
});

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

app.use(speedLimiter);

// Logging Helper
async function logRequest(type, req, res, extra = {}) {
  try {
    const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip || '0.0.0.0';
    const duration = res?.locals?.startTime ? Date.now() - res.locals.startTime : 0;
    
    const logEntry = {
      t: Date.now(),
      id: req.id,
      type,
      ip: ip.substring(0, 15),
      device: req.deviceInfo?.type || 'unknown',
      path: req.path,
      method: req.method,
      duration: duration,
      ...extra
    };
    
    try {
      io.emit('log', logEntry);
    } catch (socketErr) {}

    fs.appendFile(REQUEST_LOG_FILE, JSON.stringify(logEntry) + '\n').catch(() => {});
    logToDatabase(logEntry);
    
    if (validatedConfig.DEBUG) {
      logger.debug(`[${type}] ${ip} ${req.method} ${req.path} (${duration}ms)`);
    }
  } catch (err) {
    logger.error('Logging error:', err);
  }
}

// Bot Detection
function isLikelyBot(req) {
  const deviceInfo = req.deviceInfo;
  
  if (deviceInfo.isBot) {
    stats.botBlocks++;
    botBlocks.inc();
    if (analyticsQueue) {
      analyticsQueue.add({ type: 'bot', data: { reason: 'explicit_bot' } });
    }
    return true;
  }

  const h = req.headers;
  let score = deviceInfo.score;
  const reasons = [];

  if (deviceInfo.isMobile) {
    if (deviceInfo.brand !== 'unknown') score -= 20;
    if (deviceInfo.os.includes('iOS') || deviceInfo.os.includes('Android')) score -= 30;
    if (deviceInfo.browser.includes('Safari') || deviceInfo.browser.includes('Chrome') || deviceInfo.browser.includes('Firefox')) score -= 20;
    if (!h['sec-ch-ua-mobile']) score += 5;
    if (!h['accept-language']) score += 10;
    if (!h['accept']) score += 5;
    
    if (validatedConfig.DEBUG) {
      logger.debug(`[MOBILE-DEVICE] ${deviceInfo.brand} ${deviceInfo.model} | Score: ${score}`);
    }
    
    return score >= 20;
  }

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
    botBlocks.inc();
    reasons.forEach(r => stats.byBotReason[r] = (stats.byBotReason[r] || 0) + 1);
    if (analyticsQueue) {
      analyticsQueue.add({ type: 'bot', data: { score, reasons } });
    }
  }
  
  if (validatedConfig.DEBUG) {
    logger.debug(`[BOT-SCORE] ${score} | ${reasons.join(',') || 'clean'} | Threshold:${botThreshold} | IsBot:${isBot} | Device:${deviceInfo.type}`);
  }

  return isBot;
}

// Geolocation
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

// Encoders
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

// Health Endpoints
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
    },
    database: dbPool ? 'connected' : 'disabled',
    redis: redisClient?.status === 'ready' ? 'connected' : 'disabled',
    queues: {
      redirect: redirectQueue ? 'ready' : 'disabled',
      email: emailQueue ? 'ready' : 'disabled',
      analytics: analyticsQueue ? 'ready' : 'disabled'
    }
  };
  res.status(200).json(healthData);
});

// Metrics Endpoint
app.get('/metrics', async (req, res) => {
  const apiKey = req.headers['x-api-key'] || req.query.key;
  if (apiKey !== METRICS_API_KEY) {
    throw new AppError('Forbidden', 403);
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
    },
    prometheus: await promClient.register.metrics()
  };
  
  res.set('Content-Type', promClient.register.contentType);
  res.send(await promClient.register.metrics());
});

// Generate Link
app.post('/api/generate', csrfProtection, [
  body('url').isURL().withMessage('Valid URL required'),
  body('password').optional().isString().isLength({ min: 6 }),
  body('maxClicks').optional().isInt({ min: 1, max: 10000 }),
  body('expiresIn').optional().isString()
], async (req, res, next) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw new AppError(errors.array()[0].msg, 400);
    }

    const target = req.body.url || TARGET_URL;
    const password = req.body.password;
    const maxClicks = req.body.maxClicks;
    const expiresIn = req.body.expiresIn ? parseTTL(req.body.expiresIn) : LINK_TTL_SEC;
    
    const { encoded } = multiLayerEncode(target + '#' + Date.now());
    
    const id = crypto.randomBytes(8).toString('hex');
    
    const linkData = {
      e: encoded,
      target,
      created: Date.now(),
      expiresAt: Date.now() + (expiresIn * 1000),
      passwordHash: password ? await bcrypt.hash(password, 10) : null,
      maxClicks,
      currentClicks: 0
    };
    
    linkCache.set(id, linkData, expiresIn);
    
    if (dbPool) {
      await dbPool.query(
        'INSERT INTO links (id, target_url, created_at, expires_at, creator_ip, password_hash, max_clicks) VALUES ($1, $2, $3, $4, $5, $6, $7)',
        [id, target, new Date(), new Date(Date.now() + (expiresIn * 1000)), req.ip, linkData.passwordHash, maxClicks]
      );
    }
    
    stats.generatedLinks++;
    linkGenerations.inc();
    
    const response = {
      url: `${req.protocol}://${req.get('host')}/v/${id}`,
      expires: expiresIn,
      expires_human: formatDuration(expiresIn),
      id: id,
      created: Date.now(),
      passwordProtected: !!password,
      maxClicks: maxClicks || null
    };
    
    io.emit('link-generated', response);
    logRequest('generate', req, res, { id });
    
    if (analyticsQueue) {
      analyticsQueue.add({ type: 'generate', data: { id, passwordProtected: !!password } });
    }
    
    res.json(response);
  } catch (err) {
    next(err);
  }
});

app.get('/g', (req, res, next) => {
  req.body = { url: req.query.t };
  app._router.handle(req, res, next);
});

// Get Link Stats
app.get('/api/stats/:id', async (req, res, next) => {
  try {
    const linkId = req.params.id;
    
    if (!/^[a-f0-9]{16}$/i.test(linkId)) {
      throw new AppError('Invalid link ID', 400);
    }
    
    const linkData = linkCache.get(linkId);
    
    let stats = {
      exists: !!linkData,
      created: linkData?.created,
      expiresAt: linkData?.expiresAt,
      clicks: 0,
      uniqueVisitors: 0,
      countries: {},
      devices: {}
    };
    
    if (dbPool && linkData) {
      const result = await dbPool.query(
        `SELECT 
          COUNT(*) as total_clicks,
          COUNT(DISTINCT ip) as unique_visitors,
          jsonb_object_agg(country, country_count) as countries,
          jsonb_object_agg(device_type, device_count) as devices
        FROM clicks 
        WHERE link_id = $1`,
        [linkId]
      );
      
      if (result.rows[0]) {
        stats = { ...stats, ...result.rows[0] };
      }
    }
    
    res.json(stats);
  } catch (err) {
    next(err);
  }
});

// Success Tracking
app.post('/track/success', (req, res) => {
  stats.successfulRedirects++;
  logRequest('success', req, res);
  if (analyticsQueue) {
    analyticsQueue.add({ type: 'success', data: { id: req.id } });
  }
  res.json({ ok: true });
});

// Password Protected Link
app.post('/v/:id/verify', express.json(), async (req, res, next) => {
  try {
    const linkId = req.params.id;
    const { password } = req.body;
    
    const linkData = linkCache.get(linkId);
    if (!linkData) {
      throw new AppError('Link not found', 404);
    }
    
    if (linkData.passwordHash) {
      const valid = await bcrypt.compare(password, linkData.passwordHash);
      if (!valid) {
        throw new AppError('Invalid password', 401);
      }
    }
    
    res.json({ success: true, target: linkData.target });
  } catch (err) {
    next(err);
  }
});

// Verification Gate
app.get('/v/:id', strictLimiter, async (req, res, next) => {
  try {
    const linkId = req.params.id;
    const deviceInfo = req.deviceInfo;
    const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip || '0.0.0.0';
    const showQr = req.query.qr === 'true';
    
    if (!/^[a-f0-9]{16}$/i.test(linkId)) {
      return res.redirect(BOT_URLS[Math.floor(Math.random() * BOT_URLS.length)]);
    }
    
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
      
      if (dbPool) {
        await dbPool.query(
          'UPDATE links SET current_clicks = current_clicks + 1 WHERE id = $1',
          [linkId]
        );
      }
      
      return res.redirect(`/expired?target=${encodeURIComponent(BOT_URLS[0])}`);
    }

    if (data.maxClicks && data.currentClicks >= data.maxClicks) {
      linkCache.del(linkId);
      return res.redirect(`/expired?target=${encodeURIComponent(BOT_URLS[0])}`);
    }

    data.currentClicks = (data.currentClicks || 0) + 1;
    linkCache.set(linkId, data);

    logRequest('redirect', req, res, { target: data.target.substring(0, 50) });

    if (dbPool && redirectQueue) {
      redirectQueue.add({
        linkId,
        ip,
        userAgent: req.headers['user-agent'],
        deviceInfo,
        country: stats.byCountry[ip] || 'XX'
      });
    }

    if (data.passwordHash) {
      return res.send(`
        <!DOCTYPE html>
        <html>
        <head>
          <title>Password Protected - Redirector Pro</title>
          <meta name="viewport" content="width=device-width, initial-scale=1">
          <style>
            *{margin:0;padding:0;box-sizing:border-box}
            body{font-family:sans-serif;background:linear-gradient(135deg,#667eea 0,#764ba2 100%);min-height:100vh;display:flex;align-items:center;justify-content:center}
            .card{background:white;padding:2rem;border-radius:16px;width:100%;max-width:400px;box-shadow:0 20px 60px rgba(0,0,0,0.3)}
            h2{color:#333;margin-bottom:1rem;text-align:center}
            input{width:100%;padding:0.75rem;margin:1rem 0;border:2px solid #e0e0e0;border-radius:8px}
            button{width:100%;padding:1rem;background:linear-gradient(135deg,#667eea 0,#764ba2 100%);color:white;border:none;border-radius:8px;cursor:pointer}
            .error{color:#c00;margin-top:0.5rem;display:none}
          </style>
        </head>
        <body>
          <div class="card">
            <h2>🔒 Password Protected</h2>
            <input type="password" id="password" placeholder="Enter password">
            <button onclick="verify()">Access Link</button>
            <div class="error" id="error">Invalid password</div>
          </div>
          <script nonce="${res.locals.nonce}">
            async function verify() {
              const password = document.getElementById('password').value;
              const res = await fetch('/v/${linkId}/verify', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({password})
              });
              if (res.ok) {
                const data = await res.json();
                window.location.href = data.target;
              } else {
                document.getElementById('error').style.display = 'block';
              }
            }
          </script>
        </body>
        </html>
      `);
    }

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
          <script nonce="${res.locals.nonce}">
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

    if (deviceInfo.isMobile) {
      stats.successfulRedirects++;
      return res.send(`<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="refresh" content="0;url=${data.target}"></head>
<body></body>
</html>`);
    }

    if (validatedConfig.DISABLE_DESKTOP_CHALLENGE) {
      stats.successfulRedirects++;
      return res.send(`<meta http-equiv="refresh" content="0;url=${data.target}">`);
    }

    const hpSuffix = crypto.randomBytes(2).toString('hex');
    const nonce = res.locals.nonce;

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
  } catch (err) {
    next(err);
  }
});

// Expired Link Page
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

// QR Code Endpoints
app.get('/qr', async (req, res, next) => {
  try {
    const url = req.query.url || req.query.u || TARGET_URL;
    const size = parseInt(req.query.size) || 300;
    
    try {
      new URL(url);
    } catch {
      throw new AppError('Invalid URL', 400);
    }
    
    const cacheKey = crypto.createHash('md5').update(`${url}:${size}`).digest('hex');
    let qrData = qrCache.get(cacheKey);
    
    if (!qrData) {
      qrData = await QRCode.toDataURL(url, { 
        width: size,
        margin: 2,
        color: { dark: '#000000', light: '#ffffff' },
        errorCorrectionLevel: 'M'
      });
      qrCache.set(cacheKey, qrData);
    }
    
    res.json({ qr: qrData, url });
  } catch (err) {
    next(err);
  }
});

app.get('/qr/download', async (req, res, next) => {
  try {
    const url = req.query.url || TARGET_URL;
    const size = parseInt(req.query.size) || 300;
    
    try {
      new URL(url);
    } catch {
      throw new AppError('Invalid URL', 400);
    }
    
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
    next(err);
  }
});

// Admin Routes
app.get('/admin/login', (req, res) => {
  if (req.session.authenticated) {
    return res.redirect('/admin');
  }
  
  const nonce = res.locals.nonce;
  const csrfToken = res.locals.csrfToken || '';
  
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>Admin Login - Redirector Pro</title>
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <style nonce="${nonce}">
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
          <input type="hidden" name="_csrf" value="${csrfToken}">
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
        <div class="footer">Redirector Pro v3.0 Enterprise</div>
      </div>
      <script nonce="${nonce}">
        document.getElementById('loginForm').addEventListener('submit', async (e) => {
          e.preventDefault();
          const csrfToken = document.querySelector('input[name="_csrf"]').value;
          const res = await fetch('/admin/login', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'X-CSRF-Token': csrfToken
            },
            body: JSON.stringify({
              username: document.getElementById('username').value,
              password: document.getElementById('password').value,
              _csrf: csrfToken
            }),
            credentials: 'include'
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

app.post('/admin/login', csrfProtection, express.json(), async (req, res, next) => {
  try {
    const { username, password } = req.body;
    
    const ip = req.ip || req.headers['x-forwarded-for']?.split(',')[0] || 'unknown';
    const attempts = linkRequestCache.get(`login:${ip}`) || 0;
    
    if (attempts >= 5) {
      throw new AppError('Too many login attempts. Try again later.', 429);
    }
    
    linkRequestCache.set(`login:${ip}`, attempts + 1, 300);

    if (username === ADMIN_USERNAME && await bcrypt.compare(password, ADMIN_PASSWORD_HASH)) {
      req.session.authenticated = true;
      req.session.user = username;
      req.session.loginTime = Date.now();
      req.session.csrfToken = crypto.randomBytes(32).toString('hex');
      linkRequestCache.del(`login:${ip}`);
      res.json({ success: true });
    } else {
      throw new AppError('Invalid credentials', 401);
    }
  } catch (err) {
    next(err);
  }
});

// FIXED: Interactive Admin Dashboard
app.get('/admin', (req, res, next) => {
  if (!req.session.authenticated) {
    return res.redirect('/admin/login');
  }
  
  const nonce = res.locals.nonce;
  const csrfToken = res.locals.csrfToken || '';
  
  res.send(`<!DOCTYPE html>
<html>
<head>
  <title>Redirector Pro Admin</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <script src="https://cdn.socket.io/4.5.4/socket.io.min.js"></script>
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <style nonce="${nonce}">
    * {
      margin: 0;
      padding: 0;
      box-sizing: border-box;
    }
    
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: #f5f5f5;
    }
    
    .navbar {
      background: linear-gradient(135deg, #667eea 0, #764ba2 100%);
      color: white;
      padding: 1rem 2rem;
      display: flex;
      justify-content: space-between;
      align-items: center;
      box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }
    
    .navbar h1 {
      font-size: 1.5rem;
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }
    
    .navbar button {
      background: rgba(255,255,255,0.2);
      border: 1px solid rgba(255,255,255,0.3);
      color: white;
      padding: 0.5rem 1.5rem;
      border-radius: 8px;
      cursor: pointer;
      font-size: 1rem;
      transition: all 0.2s;
    }
    
    .navbar button:hover {
      background: rgba(255,255,255,0.3);
      transform: translateY(-1px);
    }
    
    .container {
      padding: 2rem;
      max-width: 1400px;
      margin: 0 auto;
    }
    
    .stats-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
      gap: 1.5rem;
      margin-bottom: 2rem;
    }
    
    .stat-card {
      background: white;
      padding: 1.5rem;
      border-radius: 12px;
      box-shadow: 0 4px 6px rgba(0,0,0,0.1);
      transition: transform 0.2s;
    }
    
    .stat-card:hover {
      transform: translateY(-2px);
      box-shadow: 0 6px 12px rgba(0,0,0,0.15);
    }
    
    .stat-card h3 {
      color: #666;
      font-size: 0.9rem;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      margin-bottom: 0.5rem;
    }
    
    .stat-card .value {
      font-size: 2.5rem;
      font-weight: bold;
      color: #333;
      line-height: 1.2;
    }
    
    .stat-card .sub-value {
      font-size: 0.9rem;
      color: #999;
      margin-top: 0.25rem;
    }
    
    .section {
      background: white;
      padding: 2rem;
      border-radius: 12px;
      margin-bottom: 2rem;
      box-shadow: 0 4px 6px rgba(0,0,0,0.1);
    }
    
    .section h2 {
      margin-bottom: 1.5rem;
      color: #333;
      font-size: 1.3rem;
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }
    
    .grid-2 {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 2rem;
    }
    
    .form-group {
      margin-bottom: 1rem;
    }
    
    label {
      display: block;
      margin-bottom: 0.5rem;
      color: #555;
      font-weight: 500;
    }
    
    input, select, textarea {
      width: 100%;
      padding: 0.75rem;
      border: 2px solid #e0e0e0;
      border-radius: 8px;
      font-size: 1rem;
      transition: border-color 0.2s;
    }
    
    input:focus, select:focus, textarea:focus {
      outline: none;
      border-color: #667eea;
    }
    
    button {
      background: linear-gradient(135deg, #667eea 0, #764ba2 100%);
      color: white;
      border: none;
      padding: 0.75rem 1.5rem;
      border-radius: 8px;
      font-size: 1rem;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.2s;
      margin-right: 0.5rem;
    }
    
    button:hover {
      transform: translateY(-2px);
      box-shadow: 0 4px 12px rgba(102,126,234,0.4);
    }
    
    button.secondary {
      background: #f0f0f0;
      color: #333;
    }
    
    button.secondary:hover {
      background: #e0e0e0;
      box-shadow: 0 4px 12px rgba(0,0,0,0.1);
    }
    
    button.danger {
      background: linear-gradient(135deg, #f56565 0, #c53030 100%);
    }
    
    .logs-container {
      background: #1e1e1e;
      color: #0f0;
      padding: 1rem;
      border-radius: 8px;
      font-family: 'Monaco', 'Menlo', 'Courier New', monospace;
      height: 400px;
      overflow-y: auto;
      font-size: 0.9rem;
    }
    
    .log-entry {
      border-bottom: 1px solid #333;
      padding: 0.5rem 0;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }
    
    .log-entry:hover {
      background: #2a2a2a;
    }
    
    .tabs {
      display: flex;
      gap: 0.5rem;
      margin-bottom: 2rem;
      flex-wrap: wrap;
    }
    
    .tab {
      padding: 0.75rem 1.5rem;
      background: white;
      border-radius: 8px;
      cursor: pointer;
      font-weight: 500;
      transition: all 0.2s;
      box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }
    
    .tab:hover {
      transform: translateY(-2px);
      box-shadow: 0 4px 8px rgba(0,0,0,0.15);
    }
    
    .tab.active {
      background: linear-gradient(135deg, #667eea 0, #764ba2 100%);
      color: white;
    }
    
    .tab-content {
      display: none;
    }
    
    .tab-content.active {
      display: block;
    }
    
    .chart-container {
      height: 300px;
      margin: 1rem 0;
      position: relative;
    }
    
    .alert {
      position: fixed;
      top: 20px;
      right: 20px;
      padding: 1rem 2rem;
      border-radius: 8px;
      color: white;
      z-index: 1000;
      display: none;
      animation: slideIn 0.3s ease;
      box-shadow: 0 4px 12px rgba(0,0,0,0.3);
    }
    
    @keyframes slideIn {
      from {
        transform: translateX(100%);
        opacity: 0;
      }
      to {
        transform: translateX(0);
        opacity: 1;
      }
    }
    
    .alert.success {
      background: linear-gradient(135deg, #48bb78 0, #2f855a 100%);
    }
    
    .alert.error {
      background: linear-gradient(135deg, #f56565 0, #c53030 100%);
    }
    
    .alert.info {
      background: linear-gradient(135deg, #4299e1 0, #3182ce 100%);
    }
    
    .result-box {
      margin-top: 1.5rem;
      padding: 1.5rem;
      background: #f8f9fa;
      border-radius: 8px;
      border: 1px solid #e0e0e0;
    }
    
    .url-display {
      display: flex;
      gap: 0.5rem;
      margin: 1rem 0;
    }
    
    .url-display input {
      flex: 1;
      background: white;
    }
    
    .stats-list {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 1rem;
    }
    
    .stat-item {
      background: #f8f9fa;
      padding: 1rem;
      border-radius: 8px;
      text-align: center;
    }
    
    .stat-item .label {
      color: #666;
      font-size: 0.9rem;
      margin-bottom: 0.5rem;
    }
    
    .stat-item .number {
      font-size: 2rem;
      font-weight: bold;
      color: #667eea;
    }
    
    #qrResult {
      text-align: center;
      margin-top: 1rem;
    }
    
    #qrResult img {
      max-width: 200px;
      border: 1px solid #e0e0e0;
      border-radius: 8px;
      padding: 0.5rem;
      background: white;
    }
    
    .system-status {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
      gap: 1rem;
    }
    
    .status-card {
      background: #f8f9fa;
      padding: 1rem;
      border-radius: 8px;
      border-left: 4px solid #667eea;
    }
    
    .status-card .title {
      font-weight: 600;
      margin-bottom: 0.5rem;
    }
    
    .status-card .status {
      display: inline-block;
      padding: 0.25rem 0.75rem;
      border-radius: 20px;
      font-size: 0.9rem;
      font-weight: 500;
    }
    
    .status-card .status.connected {
      background: #c6f6d5;
      color: #22543d;
    }
    
    .status-card .status.disconnected {
      background: #fed7d7;
      color: #742a2a;
    }
    
    @media (max-width: 768px) {
      .grid-2 {
        grid-template-columns: 1fr;
      }
      
      .container {
        padding: 1rem;
      }
      
      .stats-grid {
        grid-template-columns: 1fr;
      }
    }
  </style>
</head>
<body>
  <div class="alert" id="alert"></div>
  
  <div class="navbar">
    <h1>
      <span>🔗</span>
      Redirector Pro Enterprise
    </h1>
    <div>
      <span id="uptime" style="margin-right: 1rem;"></span>
      <button onclick="logout()">Logout</button>
    </div>
  </div>
  
  <div class="container">
    <div class="tabs">
      <div class="tab active" onclick="showTab('dashboard')">📊 Dashboard</div>
      <div class="tab" onclick="showTab('generate')">🔗 Generate Link</div>
      <div class="tab" onclick="showTab('analytics')">📈 Analytics</div>
      <div class="tab" onclick="showTab('logs')">📋 Live Logs</div>
      <div class="tab" onclick="showTab('settings')">⚙️ Settings</div>
      ${redisClient ? '<div class="tab" onclick="window.location.href=\'' + validatedConfig.BULL_BOARD_PATH + '\'">⏱️ Queues</div>' : ''}
    </div>

    <!-- Dashboard Tab -->
    <div id="dashboard" class="tab-content active">
      <div class="stats-grid">
        <div class="stat-card">
          <h3>Total Requests</h3>
          <div class="value" id="totalRequests">0</div>
          <div class="sub-value">all time</div>
        </div>
        <div class="stat-card">
          <h3>Active Links</h3>
          <div class="value" id="activeLinks">0</div>
          <div class="sub-value">current</div>
        </div>
        <div class="stat-card">
          <h3>Bot Blocks</h3>
          <div class="value" id="botBlocks">0</div>
          <div class="sub-value">threats blocked</div>
        </div>
        <div class="stat-card">
          <h3>Success Rate</h3>
          <div class="value" id="successRate">0%</div>
          <div class="sub-value">last 24h</div>
        </div>
      </div>

      <div class="grid-2">
        <div class="section">
          <h2>📈 Requests Over Time</h2>
          <div class="chart-container">
            <canvas id="requestsChart"></canvas>
          </div>
        </div>
        <div class="section">
          <h2>📱 Device Distribution</h2>
          <div class="chart-container">
            <canvas id="deviceChart"></canvas>
          </div>
        </div>
      </div>

      <div class="section">
        <h2>🌍 Top Countries</h2>
        <div class="stats-list" id="countryStats">
          <div class="stat-item">
            <div class="label">Loading...</div>
          </div>
        </div>
      </div>
    </div>

    <!-- Generate Link Tab -->
    <div id="generate" class="tab-content">
      <div class="section">
        <h2>🔗 Generate New Link</h2>
        <input type="hidden" name="_csrf" value="${csrfToken}">
        
        <div class="form-group">
          <label>Target URL</label>
          <input type="url" id="targetUrl" placeholder="https://example.com" value="${TARGET_URL}">
        </div>
        
        <div class="form-group">
          <label>Password Protection (optional)</label>
          <input type="password" id="linkPassword" placeholder="Enter password to protect link">
        </div>
        
        <div class="grid-2">
          <div class="form-group">
            <label>Max Clicks (optional)</label>
            <input type="number" id="maxClicks" placeholder="Unlimited" min="1">
          </div>
          <div class="form-group">
            <label>Expires In</label>
            <select id="expiresIn">
              <option value="5m">5 minutes</option>
              <option value="30m" selected>30 minutes</option>
              <option value="1h">1 hour</option>
              <option value="6h">6 hours</option>
              <option value="24h">24 hours</option>
              <option value="7d">7 days</option>
            </select>
          </div>
        </div>
        
        <button onclick="generateLink()">Generate Link</button>
        
        <div id="result" class="result-box" style="display:none">
          <h3>✅ Link Generated Successfully!</h3>
          <div class="url-display">
            <input type="text" id="generatedUrl" readonly>
            <button class="secondary" onclick="copyToClipboard()">Copy</button>
            <button class="secondary" onclick="showQR()">QR Code</button>
          </div>
          <div id="qrResult"></div>
        </div>
      </div>
    </div>

    <!-- Analytics Tab -->
    <div id="analytics" class="tab-content">
      <div class="section">
        <h2>📊 Link Analytics</h2>
        <div class="form-group">
          <label>Enter Link ID</label>
          <input type="text" id="analyticsLinkId" placeholder="e.g., a1b2c3d4e5f6g7h8">
        </div>
        <button onclick="getLinkStats()">Get Statistics</button>
        
        <div id="linkStats" class="result-box" style="display:none">
          <h3>Link Statistics</h3>
          <div class="stats-list" id="statsContent"></div>
        </div>
      </div>
    </div>

    <!-- Live Logs Tab -->
    <div id="logs" class="tab-content">
      <div class="section">
        <h2>📋 Live Activity Logs</h2>
        <div class="logs-container" id="logs"></div>
      </div>
    </div>

    <!-- Settings Tab -->
    <div id="settings" class="tab-content">
      <div class="grid-2">
        <div class="section">
          <h2>🗑️ Cache Management</h2>
          <button onclick="clearCache()" class="danger">Clear All Caches</button>
          <button onclick="exportLogs()" style="margin-top: 1rem;">Export Logs</button>
        </div>
        
        <div class="section">
          <h2>📊 System Status</h2>
          <div class="system-status" id="systemStatus">
            <div class="status-card">
              <div class="title">Socket Connection</div>
              <div class="status connected" id="socketStatus">Connected</div>
            </div>
            <div class="status-card">
              <div class="title">Database</div>
              <div class="status ${dbPool ? 'connected' : 'disconnected'}" id="dbStatus">
                ${dbPool ? 'Connected' : 'Disconnected'}
              </div>
            </div>
            <div class="status-card">
              <div class="title">Redis</div>
              <div class="status ${redisClient ? 'connected' : 'disconnected'}" id="redisStatus">
                ${redisClient ? 'Connected' : 'Disconnected'}
              </div>
            </div>
          </div>
        </div>
      </div>
      
      <div class="section">
        <h2>ℹ️ About</h2>
        <p><strong>Version:</strong> 3.0.0 Enterprise</p>
        <p><strong>Node.js:</strong> ${process.version}</p>
        <p><strong>Platform:</strong> ${process.platform}</p>
        <p><strong>Memory Usage:</strong> ${Math.round(process.memoryUsage().rss / 1024 / 1024)} MB</p>
      </div>
    </div>
  </div>

  <script nonce="${nonce}">
    const socket = io({
      auth: { token: '${METRICS_API_KEY}' },
      transports: ['websocket', 'polling'],
      reconnection: true,
      reconnectionAttempts: 10,
      reconnectionDelay: 1000
    });
    
    let requestsChart, deviceChart;
    
    socket.on('connect', () => {
      console.log('✅ Socket connected');
      showAlert('Real-time monitoring connected', 'success');
      document.getElementById('socketStatus').textContent = 'Connected';
      document.getElementById('socketStatus').className = 'status connected';
    });
    
    socket.on('disconnect', () => {
      console.log('❌ Socket disconnected');
      showAlert('Real-time monitoring disconnected', 'error');
      document.getElementById('socketStatus').textContent = 'Disconnected';
      document.getElementById('socketStatus').className = 'status disconnected';
    });
    
    socket.on('stats', (data) => {
      updateStats(data);
      updateCharts(data);
      updateCountryStats(data.byCountry);
    });
    
    socket.on('log', (log) => {
      addLogEntry(log);
    });
    
    socket.on('link-generated', (link) => {
      showAlert('New link generated: ' + link.id, 'info');
    });
    
    socket.on('notification', (notification) => {
      showAlert(notification.message, notification.type);
    });
    
    function updateStats(data) {
      document.getElementById('totalRequests').textContent = data.totalRequests?.toLocaleString() || '0';
      document.getElementById('activeLinks').textContent = data.realtime?.activeLinks?.toLocaleString() || '0';
      document.getElementById('botBlocks').textContent = data.botBlocks?.toLocaleString() || '0';
      
      const successRate = data.totalRequests ? 
        ((data.successfulRedirects / data.totalRequests) * 100).toFixed(1) : 0;
      document.getElementById('successRate').textContent = successRate + '%';
    }
    
    function updateCharts(data) {
      const ctx1 = document.getElementById('requestsChart').getContext('2d');
      const ctx2 = document.getElementById('deviceChart').getContext('2d');
      
      if (requestsChart) requestsChart.destroy();
      if (deviceChart) deviceChart.destroy();
      
      const lastMinute = data.realtime?.lastMinute || [];
      const timestamps = lastMinute.map(d => {
        const date = new Date(d.time);
        return date.getHours() + ':' + date.getMinutes().toString().padStart(2, '0') + ':' + date.getSeconds().toString().padStart(2, '0');
      });
      const requests = lastMinute.map(d => d.requests || 0);
      const blocks = lastMinute.map(d => d.blocks || 0);
      const successes = lastMinute.map(d => d.successes || 0);
      
      requestsChart = new Chart(ctx1, {
        type: 'line',
        data: {
          labels: timestamps,
          datasets: [
            {
              label: 'Requests',
              data: requests,
              borderColor: '#667eea',
              backgroundColor: 'rgba(102,126,234,0.1)',
              tension: 0.4,
              fill: true
            },
            {
              label: 'Successful',
              data: successes,
              borderColor: '#48bb78',
              backgroundColor: 'rgba(72,187,120,0.1)',
              tension: 0.4,
              fill: true
            },
            {
              label: 'Blocks',
              data: blocks,
              borderColor: '#f56565',
              backgroundColor: 'rgba(245,101,101,0.1)',
              tension: 0.4,
              fill: true
            }
          ]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          interaction: { mode: 'index', intersect: false },
          plugins: { legend: { position: 'top' } },
          scales: {
            y: { beginAtZero: true, grid: { color: 'rgba(0,0,0,0.05)' } },
            x: { grid: { display: false } }
          }
        }
      });
      
      deviceChart = new Chart(ctx2, {
        type: 'doughnut',
        data: {
          labels: ['Mobile', 'Desktop', 'Tablet', 'Bot'],
          datasets: [{
            data: [
              data.byDevice?.mobile || 0,
              data.byDevice?.desktop || 0,
              data.byDevice?.tablet || 0,
              data.byDevice?.bot || 0
            ],
            backgroundColor: ['#48bb78', '#4299e1', '#ed8936', '#f56565'],
            borderWidth: 0
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: { legend: { position: 'bottom' } },
          cutout: '60%'
        }
      });
    }
    
    function updateCountryStats(countries) {
      const container = document.getElementById('countryStats');
      if (!countries || Object.keys(countries).length === 0) {
        container.innerHTML = '<div class="stat-item"><div class="label">No data yet</div></div>';
        return;
      }
      
      const sorted = Object.entries(countries)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 8);
      
      container.innerHTML = sorted.map(([country, count]) => \`
        <div class="stat-item">
          <div class="label">\${country}</div>
          <div class="number">\${count.toLocaleString()}</div>
        </div>
      \`).join('');
    }
    
    function addLogEntry(log) {
      const logs = document.getElementById('logs');
      const entry = document.createElement('div');
      entry.className = 'log-entry';
      
      const time = new Date(log.t).toLocaleTimeString();
      const device = log.device || 'unknown';
      let emoji = '🌐';
      if (device === 'mobile') emoji = '📱';
      else if (device === 'tablet') emoji = '📟';
      else if (device === 'bot') emoji = '🤖';
      
      entry.innerHTML = \`[\${time}] \${emoji} \${log.ip} \${log.method} \${log.path} [\${device}] \${log.duration}ms\`;
      
      logs.insertBefore(entry, logs.firstChild);
      if (logs.children.length > 200) logs.removeChild(logs.lastChild);
    }
    
    async function generateLink() {
      const csrf = document.querySelector('input[name="_csrf"]').value;
      const url = document.getElementById('targetUrl').value;
      const password = document.getElementById('linkPassword').value;
      const maxClicks = document.getElementById('maxClicks').value;
      const expiresIn = document.getElementById('expiresIn').value;
      
      if (!url) {
        showAlert('Please enter a URL', 'error');
        return;
      }
      
      try {
        const res = await fetch('/api/generate', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-CSRF-Token': csrf
          },
          body: JSON.stringify({ 
            url, 
            password: password || undefined,
            maxClicks: maxClicks ? parseInt(maxClicks) : undefined,
            expiresIn
          }),
          credentials: 'include'
        });
        
        if (res.ok) {
          const data = await res.json();
          document.getElementById('generatedUrl').value = data.url;
          document.getElementById('result').style.display = 'block';
          document.getElementById('qrResult').innerHTML = '';
          showAlert('Link generated successfully!', 'success');
        } else {
          const error = await res.json();
          showAlert(error.error || 'Failed to generate link', 'error');
        }
      } catch (err) {
        showAlert('Network error: ' + err.message, 'error');
      }
    }
    
    async function showQR() {
      const url = document.getElementById('generatedUrl').value;
      if (!url) return;
      
      try {
        const res = await fetch('/qr?url=' + encodeURIComponent(url));
        if (res.ok) {
          const data = await res.json();
          document.getElementById('qrResult').innerHTML = \`
            <h4>QR Code:</h4>
            <img src="\${data.qr}" alt="QR Code">
            <p><small>Scan to open link</small></p>
          \`;
        }
      } catch (err) {
        showAlert('Failed to generate QR code', 'error');
      }
    }
    
    async function getLinkStats() {
      const linkId = document.getElementById('analyticsLinkId').value;
      if (!linkId) {
        showAlert('Please enter a link ID', 'error');
        return;
      }
      
      try {
        const res = await fetch('/api/stats/' + linkId);
        if (res.ok) {
          const stats = await res.json();
          document.getElementById('linkStats').style.display = 'block';
          
          let html = '';
          if (stats.exists) {
            html = \`
              <div class="stat-item">
                <div class="label">Total Clicks</div>
                <div class="number">\${stats.clicks || 0}</div>
              </div>
              <div class="stat-item">
                <div class="label">Unique Visitors</div>
                <div class="number">\${stats.uniqueVisitors || 0}</div>
              </div>
              <div class="stat-item">
                <div class="label">Created</div>
                <div class="number" style="font-size:1rem">\${stats.created ? new Date(stats.created).toLocaleString() : 'N/A'}</div>
              </div>
              <div class="stat-item">
                <div class="label">Expires</div>
                <div class="number" style="font-size:1rem">\${stats.expiresAt ? new Date(stats.expiresAt).toLocaleString() : 'N/A'}</div>
              </div>
            \`;
          } else {
            html = '<div class="stat-item"><div class="label">Link not found or expired</div></div>';
          }
          
          document.getElementById('statsContent').innerHTML = html;
        }
      } catch (err) {
        showAlert('Failed to get statistics', 'error');
      }
    }
    
    async function clearCache() {
      if (!confirm('Are you sure you want to clear all caches? This may temporarily affect performance.')) {
        return;
      }
      
      const csrf = document.querySelector('input[name="_csrf"]').value;
      
      try {
        const res = await fetch('/admin/clear-cache', {
          method: 'POST',
          headers: { 
            'Content-Type': 'application/json',
            'X-CSRF-Token': csrf
          },
          body: JSON.stringify({ _csrf: csrf }),
          credentials: 'include'
        });
        
        if (res.ok) {
          showAlert('Cache cleared successfully', 'success');
        } else {
          showAlert('Failed to clear cache', 'error');
        }
      } catch (err) {
        showAlert('Network error', 'error');
      }
    }
    
    function exportLogs() {
      window.location.href = '/admin/export-logs';
    }
    
    function copyToClipboard() {
      const url = document.getElementById('generatedUrl');
      url.select();
      document.execCommand('copy');
      showAlert('Copied to clipboard!', 'success');
    }
    
    function showAlert(message, type) {
      const alert = document.getElementById('alert');
      alert.className = 'alert ' + type;
      alert.textContent = message;
      alert.style.display = 'block';
      
      setTimeout(() => {
        alert.style.display = 'none';
      }, 3000);
    }
    
    function showTab(tab) {
      document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
      document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
      
      document.querySelector(\`.tab[onclick="showTab('\${tab}')\`).classList.add('active');
      document.getElementById(tab).classList.add('active');
    }
    
    function logout() {
      fetch('/admin/logout', {
        method: 'POST',
        credentials: 'include'
      }).then(() => {
        window.location.href = '/admin/login';
      });
    }
    
    setInterval(() => {
      const uptime = Math.floor(process.uptime());
      const hours = Math.floor(uptime / 3600);
      const minutes = Math.floor((uptime % 3600) / 60);
      const seconds = uptime % 60;
      document.getElementById('uptime').textContent = \`Uptime: \${hours}h \${minutes}m \${seconds}s\`;
    }, 1000);
    
    socket.emit('command', { action: 'getStats' });
  </script>
</body>
</html>`);
});

app.post('/admin/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      logger.error('Logout error:', err);
    }
    res.clearCookie('redirector.sid');
    res.json({ success: true });
  });
});

app.post('/admin/clear-cache', csrfProtection, (req, res) => {
  if (!req.session.authenticated) {
    throw new AppError('Unauthorized', 401);
  }
  
  linkCache.flushAll();
  geoCache.flushAll();
  deviceCache.flushAll();
  qrCache.flushAll();
  
  logger.info('Cache cleared by admin');
  res.json({ success: true });
});

app.get('/admin/export-logs', async (req, res, next) => {
  if (!req.session.authenticated) {
    throw new AppError('Unauthorized', 401);
  }
  
  try {
    const logs = await fs.readFile(REQUEST_LOG_FILE, 'utf8');
    res.setHeader('Content-Type', 'text/plain');
    res.setHeader('Content-Disposition', `attachment; filename="logs-${Date.now()}.txt"`);
    res.send(logs);
  } catch (err) {
    next(err);
  }
});

// 404 Handler
app.use((req, res) => {
  logRequest('404', req, res);
  res.redirect(BOT_URLS[Math.floor(Math.random() * BOT_URLS.length)]);
});

// Global Error Handler
app.use((err, req, res, next) => {
  logger.error('Error:', {
    message: err.message,
    stack: err.stack,
    id: req.id,
    path: req.path,
    method: req.method,
    ip: req.ip
  });
  
  logRequest('error', req, res, { error: err.message });
  
  if (err instanceof AppError && err.isOperational) {
    return res.status(err.statusCode).json({ 
      error: err.message,
      id: req.id 
    });
  }
  
  if (!res.headersSent) {
    if (req.accepts('html')) {
      res.redirect(BOT_URLS[Math.floor(Math.random() * BOT_URLS.length)]);
    } else {
      res.status(500).json({ 
        error: 'Internal server error',
        id: req.id 
      });
    }
  }
});

// Graceful Shutdown
async function gracefulShutdown(signal) {
  logger.info(`Received ${signal}, shutting down gracefully...`);
  
  const shutdownTimeout = setTimeout(() => {
    logger.error('Forcing exit after timeout');
    process.exit(1);
  }, 30000);
  
  try {
    if (redirectQueue) await redirectQueue.close();
    if (emailQueue) await emailQueue.close();
    if (analyticsQueue) await analyticsQueue.close();
    if (dbPool) await dbPool.end();
    if (redisClient) await redisClient.quit();
    await new Promise((resolve) => server.close(resolve));
    
    clearTimeout(shutdownTimeout);
    logger.info('Graceful shutdown completed');
    process.exit(0);
  } catch (err) {
    logger.error('Error during shutdown:', err);
    process.exit(1);
  }
}

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

process.on('uncaughtException', (err) => {
  logger.error('Uncaught Exception:', err);
  gracefulShutdown('UNCAUGHT_EXCEPTION');
});

process.on('unhandledRejection', (reason, promise) => {
  logger.error('Unhandled Rejection at:', promise, 'reason:', reason);
});

// Start Server
server.listen(PORT, '0.0.0.0', () => {
  console.log('\n' + '='.repeat(70));
  console.log(`  🚀 Redirector Pro v3.0 - Enterprise Edition`);
  console.log('='.repeat(70));
  console.log(`  📡 Port: ${PORT}`);
  console.log(`  🔑 Metrics Key: ${METRICS_API_KEY.substring(0, 8)}...`);
  console.log(`  ⏱️  Link TTL: ${formatDuration(LINK_TTL_SEC)}`);
  console.log(`  📊 Max Links: ${MAX_LINKS.toLocaleString()}`);
  console.log(`  📱 Mobile threshold: 20`);
  console.log(`  💻 Desktop threshold: 65`);
  console.log(`  🗄️  Session Store: ${sessionStore.constructor.name}`);
  console.log(`  📍 Admin UI: http://localhost:${PORT}/admin`);
  console.log(`  🔐 Default admin: ${ADMIN_USERNAME} / [protected]`);
  console.log(`  📊 Real-time monitoring: Active`);
  console.log(`  💾 Database: ${dbPool ? 'Connected' : 'Disabled'}`);
  console.log(`  🔄 Redis: ${redisClient?.status === 'ready' ? 'Connected' : 'Disabled'}`);
  console.log(`  📨 Queues: ${redirectQueue ? 'Enabled' : 'Disabled'}`);
  if (serverAdapter && validatedConfig.BULL_BOARD_ENABLED) {
    console.log(`  📊 Bull Board: http://localhost:${PORT}${validatedConfig.BULL_BOARD_PATH}`);
  }
  console.log('='.repeat(70) + '\n');
  
  logger.info('Server started', {
    port: PORT,
    nodeEnv: NODE_ENV,
    version: '3.0.0'
  });
  
  fs.appendFile(REQUEST_LOG_FILE, JSON.stringify({
    t: Date.now(),
    type: 'startup',
    version: '3.0.0-enterprise',
    port: PORT,
    nodeEnv: NODE_ENV
  }) + '\n').catch(() => {});
});

server.keepAliveTimeout = 30000;
server.headersTimeout = 31000;
