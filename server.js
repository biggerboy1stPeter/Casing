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
  BULL_BOARD_PATH: Joi.string().default('/admin/queues'),
  CSRF_SECRET: Joi.string().min(32).optional()
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
    const { linkId, ip, userAgent, deviceInfo, country } = job.data;
    await logToDatabase({
      type: 'redirect',
      linkId,
      ip,
      userAgent,
      deviceInfo,
      country,
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

    // Create tables with proper schema and error handling
    const createTables = async () => {
      try {
        logger.info('📦 Creating database tables...');
        
        // Step 1: Create all tables without indexes
        await dbPool.query(`
          CREATE TABLE IF NOT EXISTS links (
            id VARCHAR(32) PRIMARY KEY,
            target_url TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP NOT NULL,
            creator_ip INET,
            password_hash TEXT,
            max_clicks INTEGER,
            current_clicks INTEGER DEFAULT 0,
            last_accessed TIMESTAMP,
            status VARCHAR(20) DEFAULT 'active',
            metadata JSONB DEFAULT '{}'
          );
        `);
        
        await dbPool.query(`
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
        `);

        await dbPool.query(`
          CREATE TABLE IF NOT EXISTS logs (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            data JSONB NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
          );
        `);

        await dbPool.query(`
          CREATE TABLE IF NOT EXISTS analytics (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            type VARCHAR(50) NOT NULL,
            data JSONB NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
          );
        `);

        await dbPool.query(`
          CREATE TABLE IF NOT EXISTS settings (
            key VARCHAR(100) PRIMARY KEY,
            value JSONB NOT NULL,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_by VARCHAR(100)
          );
        `);

        await dbPool.query(`
          CREATE TABLE IF NOT EXISTS blocked_ips (
            ip INET PRIMARY KEY,
            reason TEXT,
            expires_at TIMESTAMP NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
          );
        `);

        logger.info('✅ Tables created successfully');

        // Step 2: Create indexes separately
        const indexes = [
          { name: 'idx_links_expires', query: 'CREATE INDEX IF NOT EXISTS idx_links_expires ON links(expires_at);' },
          { name: 'idx_links_status', query: 'CREATE INDEX IF NOT EXISTS idx_links_status ON links(status);' },
          { name: 'idx_clicks_link_id', query: 'CREATE INDEX IF NOT EXISTS idx_clicks_link_id ON clicks(link_id);' },
          { name: 'idx_clicks_created', query: 'CREATE INDEX IF NOT EXISTS idx_clicks_created ON clicks(created_at);' },
          { name: 'idx_analytics_type', query: 'CREATE INDEX IF NOT EXISTS idx_analytics_type ON analytics(type);' },
          { name: 'idx_analytics_created', query: 'CREATE INDEX IF NOT EXISTS idx_analytics_created ON analytics(created_at);' },
          { name: 'idx_blocked_ips_expires', query: 'CREATE INDEX IF NOT EXISTS idx_blocked_ips_expires ON blocked_ips(expires_at);' }
        ];

        for (const index of indexes) {
          try {
            await dbPool.query(index.query);
            logger.info(`✅ Created index ${index.name}`);
          } catch (err) {
            logger.warn(`Could not create ${index.name}: ${err.message}`);
          }
        }

        logger.info('✅ Database initialization completed');
      } catch (err) {
        logger.error('Database initialization error:', err);
      }
    };

    // Run table creation in the background
    createTables();
    
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

// ─── Security Middleware - Block URL Parameters with Credentials ───────────
app.use((req, res, next) => {
  // Block any requests with username or password in query parameters
  if (req.query.username || req.query.password) {
    logger.error('🚫 Blocked request with credentials in URL', {
      ip: req.ip,
      path: req.path,
      query: Object.keys(req.query)
    });
    
    // If it's a login page request, redirect to clean URL
    if (req.path === '/admin/login') {
      return res.redirect('/admin/login');
    }
    
    // Otherwise return error
    return res.status(400).json({ 
      error: 'Invalid request format - credentials should not be in URL',
      code: 'CREDENTIALS_IN_URL'
    });
  }
  next();
});

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

// Login attempt tracking
const loginAttempts = new Map();

// Clean up old login attempts every hour
setInterval(() => {
  const now = Date.now();
  for (const [ip, data] of loginAttempts.entries()) {
    if (now - data.lastAttempt > 3600000) { // 1 hour
      loginAttempts.delete(ip);
    }
  }
}, 3600000);

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
  },
  caches: {
    geo: 0,
    linkReq: 0,
    device: 0,
    qr: 0
  }
};

// Socket.IO Authentication and handlers
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
  
  // Update cache stats
  stats.caches = {
    geo: geoCache.keys().length,
    linkReq: linkCache.keys().length,
    device: deviceCache.keys().length,
    qr: qrCache.keys().length
  };
  
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
          stats.caches = {
            geo: 0,
            linkReq: 0,
            device: 0,
            qr: 0
          };
          socket.emit('notification', { type: 'success', message: 'Cache cleared successfully' });
          break;
        case 'clearGeoCache':
          geoCache.flushAll();
          stats.caches.geo = 0;
          socket.emit('notification', { type: 'success', message: 'Geo cache cleared' });
          break;
        case 'clearQRCache':
          qrCache.flushAll();
          stats.caches.qr = 0;
          socket.emit('notification', { type: 'success', message: 'QR cache cleared' });
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
        case 'getLinks':
          const links = await getAllLinks();
          socket.emit('links', links);
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
  
  stats.caches = {
    geo: geoCache.keys().length,
    linkReq: linkCache.keys().length,
    device: deviceCache.keys().length,
    qr: qrCache.keys().length
  };
  
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
      scriptSrc: [
        "'self'", 
        (req, res) => `'nonce-${res.locals.nonce}'`, 
        'https://cdn.socket.io', 
        'https://cdn.jsdelivr.net', 
        'https://cdnjs.cloudflare.com',
        'https://fonts.googleapis.com',
        'https://fonts.gstatic.com'
      ],
      styleSrc: [
        "'self'", 
        "'unsafe-inline'", 
        'https://cdn.jsdelivr.net', 
        'https://cdnjs.cloudflare.com',
        'https://fonts.googleapis.com',
        'https://fonts.gstatic.com'
      ],
      fontSrc: [
        "'self'", 
        'https://cdnjs.cloudflare.com', 
        'https://fonts.gstatic.com',
        'data:'
      ],
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
  body('expiresIn').optional().isString(),
  body('notes').optional().isString().trim().escape()
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
    const notes = req.body.notes ? sanitizeHtml(req.body.notes, { allowedTags: [], allowedAttributes: {} }) : '';
    
    const { encoded } = multiLayerEncode(target + '#' + Date.now());
    
    const id = crypto.randomBytes(16).toString('hex');
    
    const linkData = {
      e: encoded,
      target,
      created: Date.now(),
      expiresAt: Date.now() + (expiresIn * 1000),
      passwordHash: password ? await bcrypt.hash(password, 10) : null,
      maxClicks,
      currentClicks: 0,
      notes,
      metadata: {
        userAgent: req.headers['user-agent'],
        creator: req.session.user || 'anonymous'
      }
    };
    
    linkCache.set(id, linkData, expiresIn);
    
    if (dbPool) {
      await dbPool.query(
        'INSERT INTO links (id, target_url, created_at, expires_at, creator_ip, password_hash, max_clicks, current_clicks, metadata) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)',
        [id, target, new Date(), new Date(Date.now() + (expiresIn * 1000)), req.ip, linkData.passwordHash, maxClicks, 0, JSON.stringify(linkData.metadata)]
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
      maxClicks: maxClicks || null,
      notes: notes || null
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

// Get All Links
async function getAllLinks() {
  if (!dbPool) {
    // Return from cache if no database
    const keys = linkCache.keys();
    const links = [];
    for (const key of keys) {
      const data = linkCache.get(key);
      if (data) {
        links.push({
          id: key,
          target_url: data.target,
          created_at: new Date(data.created),
          expires_at: new Date(data.expiresAt),
          current_clicks: data.currentClicks || 0,
          max_clicks: data.maxClicks || null,
          password_protected: !!data.passwordHash,
          notes: data.notes || '',
          status: data.expiresAt > Date.now() ? 'active' : 'expired'
        });
      }
    }
    return links;
  }

  try {
    const result = await dbPool.query(
      `SELECT id, target_url, created_at, expires_at, current_clicks, max_clicks, 
              (password_hash IS NOT NULL) as password_protected, metadata->>'notes' as notes,
              CASE 
                WHEN expires_at < NOW() THEN 'expired'
                WHEN current_clicks >= max_clicks AND max_clicks IS NOT NULL THEN 'completed'
                ELSE 'active'
              END as status
       FROM links 
       ORDER BY created_at DESC 
       LIMIT 1000`
    );
    return result.rows;
  } catch (err) {
    logger.error('Error fetching links:', err);
    return [];
  }
}

// Get Link Stats
app.get('/api/stats/:id', async (req, res, next) => {
  try {
    const linkId = req.params.id;
    
    if (!/^[a-f0-9]{32}$/i.test(linkId)) {
      throw new AppError('Invalid link ID', 400);
    }
    
    const linkData = linkCache.get(linkId);
    
    let stats = {
      exists: !!linkData,
      created: linkData?.created,
      expiresAt: linkData?.expiresAt,
      target_url: linkData?.target,
      clicks: linkData?.currentClicks || 0,
      maxClicks: linkData?.maxClicks || null,
      passwordProtected: !!linkData?.passwordHash,
      notes: linkData?.notes || '',
      uniqueVisitors: 0,
      countries: {},
      devices: {},
      recentClicks: []
    };
    
    if (dbPool && linkData) {
      const result = await dbPool.query(
        `SELECT 
          COUNT(*) as total_clicks,
          COUNT(DISTINCT ip) as unique_visitors,
          COALESCE(jsonb_object_agg(country, country_count) FILTER (WHERE country IS NOT NULL), '{}') as countries,
          COALESCE(jsonb_object_agg(device_type, device_count) FILTER (WHERE device_type IS NOT NULL), '{}') as devices
        FROM (
          SELECT 
            country,
            device_type,
            COUNT(*) as country_count,
            COUNT(*) as device_count
          FROM clicks 
          WHERE link_id = $1
          GROUP BY country, device_type
        ) sub`,
        [linkId]
      );
      
      const recentResult = await dbPool.query(
        `SELECT ip, country, device_type, created_at 
         FROM clicks 
         WHERE link_id = $1 
         ORDER BY created_at DESC 
         LIMIT 10`,
        [linkId]
      );
      
      if (result.rows[0]) {
        stats = { 
          ...stats, 
          ...result.rows[0],
          recentClicks: recentResult.rows
        };
      }
    }
    
    res.json(stats);
  } catch (err) {
    next(err);
  }
});

// Delete Link
app.delete('/api/links/:id', csrfProtection, async (req, res, next) => {
  try {
    const linkId = req.params.id;
    
    if (!req.session.authenticated) {
      throw new AppError('Unauthorized', 401);
    }
    
    linkCache.del(linkId);
    
    if (dbPool) {
      await dbPool.query('DELETE FROM links WHERE id = $1', [linkId]);
    }
    
    io.emit('link-deleted', { id: linkId });
    res.json({ success: true });
  } catch (err) {
    next(err);
  }
});

// Update Link
app.put('/api/links/:id', csrfProtection, async (req, res, next) => {
  try {
    const linkId = req.params.id;
    const { maxClicks, notes, status } = req.body;
    
    if (!req.session.authenticated) {
      throw new AppError('Unauthorized', 401);
    }
    
    const linkData = linkCache.get(linkId);
    if (!linkData) {
      throw new AppError('Link not found', 404);
    }
    
    if (maxClicks !== undefined) {
      linkData.maxClicks = maxClicks;
    }
    
    if (notes !== undefined) {
      linkData.notes = sanitizeHtml(notes, { allowedTags: [], allowedAttributes: {} });
    }
    
    if (status === 'expired') {
      linkData.expiresAt = Date.now() - 1;
    }
    
    linkCache.set(linkId, linkData, Math.max(1, Math.floor((linkData.expiresAt - Date.now()) / 1000)));
    
    if (dbPool) {
      await dbPool.query(
        'UPDATE links SET max_clicks = $1, metadata = metadata || $2 WHERE id = $3',
        [maxClicks, JSON.stringify({ notes: linkData.notes }), linkId]
      );
    }
    
    io.emit('link-updated', { id: linkId, ...linkData });
    res.json({ success: true });
  } catch (err) {
    next(err);
  }
});

// Get Settings
app.get('/api/settings', async (req, res, next) => {
  try {
    if (!req.session.authenticated) {
      throw new AppError('Unauthorized', 401);
    }
    
    const settings = {
      linkTTL: LINK_TTL_SEC,
      linkTTLFormatted: formatDuration(LINK_TTL_SEC),
      maxLinks: MAX_LINKS,
      targetUrl: TARGET_URL,
      botUrls: BOT_URLS,
      ipinfoToken: IPINFO_TOKEN ? 'configured' : 'not set',
      databaseEnabled: !!dbPool,
      redisEnabled: !!redisClient,
      queuesEnabled: !!redirectQueue,
      desktopChallenge: !validatedConfig.DISABLE_DESKTOP_CHALLENGE,
      botThresholds: {
        mobile: 20,
        desktop: 65
      }
    };
    
    if (dbPool) {
      const dbSettings = await dbPool.query('SELECT key, value FROM settings');
      dbSettings.rows.forEach(row => {
        settings[row.key] = row.value;
      });
    }
    
    res.json(settings);
  } catch (err) {
    next(err);
  }
});

// Update Settings
app.post('/api/settings', csrfProtection, async (req, res, next) => {
  try {
    if (!req.session.authenticated) {
      throw new AppError('Unauthorized', 401);
    }
    
    const { key, value } = req.body;
    
    if (dbPool) {
      await dbPool.query(
        'INSERT INTO settings (key, value, updated_by) VALUES ($1, $2, $3) ON CONFLICT (key) DO UPDATE SET value = $2, updated_at = CURRENT_TIMESTAMP, updated_by = $3',
        [key, JSON.stringify(value), req.session.user]
      );
    }
    
    // Apply settings changes (some may require restart)
    if (key === 'botThresholds') {
      // Update bot thresholds dynamically
      logger.info('Bot thresholds updated:', value);
    }
    
    io.emit('settings-updated', { key, value });
    res.json({ success: true });
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
    
    // Update last accessed
    linkData.lastAccessed = Date.now();
    linkCache.set(linkId, linkData);
    
    if (dbPool) {
      await dbPool.query('UPDATE links SET last_accessed = CURRENT_TIMESTAMP WHERE id = $1', [linkId]);
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
    const embed = req.query.embed === 'true';
    
    if (!/^[a-f0-9]{32}$/i.test(linkId)) {
      return res.redirect(BOT_URLS[Math.floor(Math.random() * BOT_URLS.length)]);
    }
    
    const linkKey = `${linkId}:${ip}`;
    const requestCount = linkRequestCache.get(linkKey) || 0;
    
    if (requestCount >= 5) {
      logRequest('rate-limit', req, res, { linkId, count: requestCount });
      return res.redirect(BOT_URLS[Math.floor(Math.random() * BOT_URLS.length)]);
    }
    
    linkRequestCache.set(linkKey, requestCount + 1);

    const country = await getCountryCode(req);

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

    if (data.expiresAt < Date.now()) {
      linkCache.del(linkId);
      stats.expiredLinks++;
      return res.redirect(`/expired?target=${encodeURIComponent(BOT_URLS[0])}`);
    }

    if (data.maxClicks && data.currentClicks >= data.maxClicks) {
      linkCache.del(linkId);
      return res.redirect(`/expired?target=${encodeURIComponent(BOT_URLS[0])}`);
    }

    data.currentClicks = (data.currentClicks || 0) + 1;
    data.lastAccessed = Date.now();
    linkCache.set(linkId, data);

    logRequest('redirect', req, res, { target: data.target.substring(0, 50) });

    if (dbPool && redirectQueue) {
      redirectQueue.add({
        linkId,
        ip,
        userAgent: req.headers['user-agent'],
        deviceInfo,
        country
      });
    }

    if (embed) {
      return res.send(`
        <!DOCTYPE html>
        <html>
        <head>
          <title>Embedded Content - Redirector Pro</title>
          <style>
            body{margin:0;padding:0;overflow:hidden}
            iframe{width:100vw;height:100vh;border:none}
          </style>
        </head>
        <body>
          <iframe src="${data.target}" sandbox="allow-scripts allow-same-origin allow-forms allow-popups"></iframe>
        </body>
        </html>
      `);
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
    const format = req.query.format || 'json';
    
    try {
      new URL(url);
    } catch {
      throw new AppError('Invalid URL', 400);
    }
    
    const cacheKey = crypto.createHash('md5').update(`${url}:${size}:${format}`).digest('hex');
    let qrData = qrCache.get(cacheKey);
    
    if (!qrData) {
      if (format === 'png') {
        qrData = await QRCode.toBuffer(url, { 
          width: size,
          margin: 2,
          type: 'png',
          errorCorrectionLevel: 'M'
        });
      } else {
        qrData = await QRCode.toDataURL(url, { 
          width: size,
          margin: 2,
          color: { dark: '#000000', light: '#ffffff' },
          errorCorrectionLevel: 'M'
        });
      }
      qrCache.set(cacheKey, qrData);
    }
    
    if (format === 'png') {
      res.setHeader('Content-Type', 'image/png');
      res.setHeader('Content-Disposition', `inline; filename="qrcode-${Date.now()}.png"`);
      res.setHeader('Cache-Control', 'public, max-age=3600');
      res.send(qrData);
    } else {
      res.json({ qr: qrData, url, size });
    }
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

// Admin Routes - Serve HTML
app.get('/admin/login', (req, res) => {
  // Block any requests with query parameters
  if (Object.keys(req.query).length > 0) {
    logger.warn('🚫 Blocked login attempt with query params', { 
      ip: req.ip, 
      query: req.query 
    });
    return res.redirect('/admin/login');
  }
  
  if (req.session.authenticated) {
    return res.redirect('/admin');
  }
  
  // Regenerate session ID to prevent fixation
  req.session.regenerate(async (err) => {
    if (err) {
      logger.error('Session regeneration error:', err);
    }
    
    // Generate new CSRF token
    const csrfToken = crypto.randomBytes(32).toString('hex');
    req.session.csrfToken = csrfToken;
    
    // Generate nonce for CSP
    const nonce = crypto.randomBytes(16).toString('hex');
    
    try {
      // Read the login.html file
      const loginHtmlPath = path.join(__dirname, 'public', 'login.html');
      let html = await fs.readFile(loginHtmlPath, 'utf8');
      
      // Inject the CSRF token and nonce
      html = html
        .replace(
          '<input type="hidden" id="csrfToken" value="">',
          `<input type="hidden" id="csrfToken" value="${csrfToken}">`
        )
        .replace(
          '{{NONCE}}',
          nonce
        );
      
      // Set CSP with nonce for this response
      res.setHeader(
        'Content-Security-Policy',
        `default-src 'self'; script-src 'self' 'nonce-${nonce}' https://cdn.socket.io https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; font-src 'self' https://cdnjs.cloudflare.com data:; img-src 'self' data: https:; connect-src 'self' ws: wss:;`
      );
      
      res.send(html);
    } catch (err) {
      logger.error('Failed to read login.html:', err);
      res.status(500).send('Login page not found');
    }
  });
});

app.post('/admin/login', csrfProtection, express.json(), async (req, res, next) => {
  try {
    const { username, password, remember } = req.body;
    
    const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip || 'unknown';
    
    // Check if IP is blocked (with error handling)
    if (dbPool) {
      try {
        const blocked = await dbPool.query(
          'SELECT * FROM blocked_ips WHERE ip = $1 AND expires_at > NOW()',
          [ip]
        );
        if (blocked.rows.length > 0) {
          logger.error(`Blocked IP attempted login: ${ip}`);
          throw new AppError('Access denied', 403);
        }
      } catch (dbErr) {
        // If table doesn't exist, log but continue
        if (dbErr.code === '42P01') {
          logger.warn('blocked_ips table not found, skipping IP block check');
        } else {
          logger.error('Database error checking blocked IP:', dbErr);
        }
      }
    }
    
    // Check for credentials in URL (should never happen in POST)
    if (req.url.includes('?') || Object.keys(req.query).length > 0) {
      logger.error('Login POST with query parameters', { ip, url: req.url });
      throw new AppError('Invalid request format', 400);
    }
    
    // Track login attempts
    const attemptData = loginAttempts.get(ip) || { count: 0, lastAttempt: Date.now() };
    attemptData.count++;
    attemptData.lastAttempt = Date.now();
    loginAttempts.set(ip, attemptData);
    
    // Progressive rate limiting
    if (attemptData.count > 10) {
      logger.error(`Excessive login attempts from ${ip}: ${attemptData.count}`);
      
      // Block IP in database
      if (dbPool) {
        try {
          await dbPool.query(
            'INSERT INTO blocked_ips (ip, reason, expires_at) VALUES ($1, $2, NOW() + INTERVAL \'1 hour\') ON CONFLICT (ip) DO UPDATE SET expires_at = NOW() + INTERVAL \'1 hour\'',
            [ip, 'Excessive login attempts']
          );
        } catch (dbErr) {
          logger.error('Failed to block IP in database:', dbErr);
        }
      }
      
      throw new AppError('Too many login attempts. IP blocked for 1 hour.', 429);
    }
    
    if (attemptData.count > 5) {
      // Add delay for suspicious attempts
      await new Promise(resolve => setTimeout(resolve, 2000));
    }
    
    // Validate input
    if (!username || !password) {
      throw new AppError('Username and password required', 400);
    }
    
    // Check credentials
    if (username === ADMIN_USERNAME && await bcrypt.compare(password, ADMIN_PASSWORD_HASH)) {
      // Successful login - reset attempts
      loginAttempts.delete(ip);
      
      req.session.regenerate((err) => {
        if (err) {
          logger.error('Session regeneration error:', err);
          return next(err);
        }
        
        req.session.authenticated = true;
        req.session.user = username;
        req.session.loginTime = Date.now();
        req.session.csrfToken = crypto.randomBytes(32).toString('hex');
        
        // Set session length based on remember me
        if (remember) {
          req.session.cookie.maxAge = 30 * 24 * 60 * 60 * 1000; // 30 days
        } else {
          req.session.cookie.maxAge = 24 * 60 * 60 * 1000; // 24 hours
        }
        
        logger.info('Successful admin login', { ip, username });
        res.json({ success: true });
      });
    } else {
      logger.warn('Failed login attempt', { ip, username, attemptCount: attemptData.count });
      throw new AppError('Invalid credentials', 401);
    }
  } catch (err) {
    next(err);
  }
});

// Main Admin Dashboard
app.get('/admin', async (req, res, next) => {
  if (!req.session.authenticated) {
    return res.redirect('/admin/login');
  }
  
  try {
    // Read the dashboard HTML file
    const dashboardPath = path.join(__dirname, 'public', 'index.html');
    let html = await fs.readFile(dashboardPath, 'utf8');
    
    // Replace template variables
    const replacements = {
      '{{METRICS_API_KEY}}': METRICS_API_KEY,
      '{{TARGET_URL}}': TARGET_URL,
      '{{csrfToken}}': req.session.csrfToken,
      '{{dbPoolStatus}}': dbPool ? 'connected' : 'disconnected',
      '{{redisStatus}}': redisClient?.status === 'ready' ? 'connected' : 'disconnected',
      '{{redirectQueueStatus}}': redirectQueue ? 'connected' : 'disconnected',
      '{{bullBoardPath}}': validatedConfig.BULL_BOARD_PATH
    };
    
    for (const [key, value] of Object.entries(replacements)) {
      html = html.replace(new RegExp(key.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'g'), value);
    }
    
    // Generate nonce for CSP
    const nonce = crypto.randomBytes(16).toString('hex');
    res.locals.nonce = nonce;
    
    // Set CSP header
    res.setHeader(
      'Content-Security-Policy',
      `default-src 'self'; script-src 'self' 'nonce-${nonce}' https://cdn.socket.io https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://fonts.googleapis.com https://fonts.gstatic.com; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://fonts.googleapis.com https://fonts.gstatic.com; font-src 'self' https://cdnjs.cloudflare.com https://fonts.gstatic.com data:; img-src 'self' data: https:; connect-src 'self' ws: wss:;`
    );
    
    // Inject nonce into script tag
    html = html.replace(
      '<script nonce="{{NONCE}}">',
      `<script nonce="${nonce}">`
    );
    
    res.send(html);
  } catch (err) {
    logger.error('Failed to read dashboard:', err);
    res.status(500).send('Dashboard not found');
  }
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

// Export link data
app.get('/api/export/:id', async (req, res, next) => {
  try {
    const linkId = req.params.id;
    const format = req.query.format || 'json';
    
    if (!req.session.authenticated) {
      throw new AppError('Unauthorized', 401);
    }
    
    if (!dbPool) {
      throw new AppError('Database not available', 503);
    }
    
    const result = await dbPool.query(
      `SELECT * FROM clicks WHERE link_id = $1 ORDER BY created_at DESC`,
      [linkId]
    );
    
    if (format === 'csv') {
      const headers = ['id', 'link_id', 'ip', 'country', 'device_type', 'created_at'];
      const csv = [
        headers.join(','),
        ...result.rows.map(row => 
          headers.map(h => row[h] || '').join(',')
        )
      ].join('\n');
      
      res.setHeader('Content-Type', 'text/csv');
      res.setHeader('Content-Disposition', `attachment; filename="clicks-${linkId}.csv"`);
      res.send(csv);
    } else {
      res.setHeader('Content-Type', 'application/json');
      res.setHeader('Content-Disposition', `attachment; filename="clicks-${linkId}.json"`);
      res.json(result.rows);
    }
  } catch (err) {
    next(err);
  }
});

// Security monitoring endpoint
app.get('/admin/security/monitor', (req, res) => {
  if (!req.session.authenticated) {
    throw new AppError('Unauthorized', 401);
  }
  
  const now = Date.now();
  const activeAttacks = [];
  
  for (const [ip, data] of loginAttempts.entries()) {
    if (now - data.lastAttempt < 3600000) {
      activeAttacks.push({
        ip,
        attempts: data.count,
        lastAttempt: new Date(data.lastAttempt).toISOString()
      });
    }
  }
  
  res.json({
    blockedIPs: [], // Would need to query database for this
    activeAttacks: activeAttacks.sort((a, b) => b.attempts - a.attempts),
    totalAttempts: Array.from(loginAttempts.values()).reduce((sum, d) => sum + d.count, 0)
  });
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

// Create public directory if it doesn't exist
async function ensurePublicDirectory() {
  try {
    await fs.mkdir('public', { recursive: true });
  } catch (err) {
    // Directory already exists
  }
}

// Start Server
ensurePublicDirectory().then(() => {
  server.listen(PORT, '0.0.0.0', () => {
    console.log('\n' + '='.repeat(80));
    console.log(`  🚀 Redirector Pro v3.0 - Enterprise Edition`);
    console.log('='.repeat(80));
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
    console.log('='.repeat(80) + '\n');
    
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
});

server.keepAliveTimeout = 30000;
server.headersTimeout = 31000;