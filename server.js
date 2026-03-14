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
  
  // Link mode configuration
  LINK_LENGTH_MODE: Joi.string().valid('short', 'long', 'auto').default('short'),
  ALLOW_LINK_MODE_SWITCH: Joi.boolean().default(true),
  LONG_LINK_SEGMENTS: Joi.number().integer().min(3).max(20).default(6),
  LONG_LINK_PARAMS: Joi.number().integer().min(5).max(30).default(13),
  LINK_ENCODING_LAYERS: Joi.number().integer().min(2).max(12).default(4),
  
  // Enhanced encoding options
  ENABLE_COMPRESSION: Joi.boolean().default(true),
  ENABLE_ENCRYPTION: Joi.boolean().default(false),
  ENCRYPTION_KEY: Joi.string().when('ENABLE_ENCRYPTION', { is: true, then: Joi.required() }),
  MAX_ENCODING_ITERATIONS: Joi.number().integer().min(1).max(5).default(3),
  ENCODING_COMPLEXITY_THRESHOLD: Joi.number().integer().min(10).max(100).default(50),
  
  // Rate limiting
  RATE_LIMIT_WINDOW: Joi.number().default(60000),
  RATE_LIMIT_MAX_REQUESTS: Joi.number().default(100),
  ENCODING_RATE_LIMIT: Joi.number().default(10)
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
    new transports.File({ filename: 'logs/error.log', level: 'error', maxsize: 10485760, maxFiles: 10 }),
    new transports.File({ filename: 'logs/combined.log', maxsize: 10485760, maxFiles: 20 }),
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

const linkModeCounter = new promClient.Counter({
  name: 'link_mode_total',
  help: 'Total number of links by mode',
  labelNames: ['mode']
});

const encodingComplexityGauge = new promClient.Gauge({
  name: 'encoding_complexity',
  help: 'Encoding complexity metrics',
  labelNames: ['type']
});

const encodingDurationHistogram = new promClient.Histogram({
  name: 'encoding_duration_seconds',
  help: 'Time spent encoding links',
  labelNames: ['mode', 'layers', 'iterations'],
  buckets: [0.1, 0.5, 1, 2, 5, 10]
});

// ─── App Initialization ──────────────────────────────────────────────────────
const app = express();
const server = http.createServer(app);

// Create logs directory if it doesn't exist
(async () => {
  try {
    await fs.mkdir('logs', { recursive: true });
    await fs.mkdir('public', { recursive: true });
  } catch (err) {
    // Directories already exist
  }
})();

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
let encodingQueue;
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

  encodingQueue = new Queue('encoding processing', {
    redis: redisClient,
    defaultJobOptions: {
      attempts: 2,
      timeout: 30000,
      removeOnComplete: true
    }
  });

  redirectQueue.process(async (job) => {
    const { linkId, ip, userAgent, deviceInfo, country, linkMode, encodingLayers } = job.data;
    await logToDatabase({
      type: 'redirect',
      linkId,
      ip,
      userAgent,
      deviceInfo,
      country,
      linkMode,
      encodingLayers,
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

  encodingQueue.process(async (job) => {
    const { targetUrl, req, options } = job.data;
    const startTime = Date.now();
    try {
      const result = await generateLongLink(targetUrl, req, options);
      encodingDurationHistogram
        .labels('long', options.maxLayers || LINK_ENCODING_LAYERS, options.iterations || MAX_ENCODING_ITERATIONS)
        .observe((Date.now() - startTime) / 1000);
      return result;
    } catch (err) {
      logger.error('Encoding queue processing error:', err);
      throw err;
    }
  });

  if (validatedConfig.BULL_BOARD_ENABLED) {
    serverAdapter = new ExpressAdapter();
    serverAdapter.setBasePath(validatedConfig.BULL_BOARD_PATH);
    
    bullBoard = createBullBoard({
      queues: [
        new BullAdapter(redirectQueue),
        new BullAdapter(emailQueue),
        new BullAdapter(analyticsQueue),
        new BullAdapter(encodingQueue)
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
      connectionTimeoutMillis: 5000
    });

    dbPool.on('error', (err) => {
      logger.error('Unexpected database error:', err);
    });

    // Create tables with proper schema and error handling
    const createTables = async () => {
      try {
        logger.info('📦 Creating database tables...');
        
        await dbPool.query(`
          CREATE TABLE IF NOT EXISTS links (
            id VARCHAR(64) PRIMARY KEY,
            target_url TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP NOT NULL,
            creator_ip INET,
            password_hash TEXT,
            max_clicks INTEGER,
            current_clicks INTEGER DEFAULT 0,
            last_accessed TIMESTAMP,
            status VARCHAR(20) DEFAULT 'active',
            link_mode VARCHAR(10) DEFAULT 'short',
            link_metadata JSONB DEFAULT '{}',
            encoding_metadata JSONB DEFAULT '{}',
            metadata JSONB DEFAULT '{}',
            encoding_complexity INTEGER DEFAULT 0
          );
        `);
        
        await dbPool.query(`
          CREATE TABLE IF NOT EXISTS clicks (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            link_id VARCHAR(64) REFERENCES links(id) ON DELETE CASCADE,
            ip INET,
            user_agent TEXT,
            device_type VARCHAR(20),
            country VARCHAR(2),
            city TEXT,
            referer TEXT,
            link_mode VARCHAR(10),
            encoding_layers INTEGER,
            decoding_time_ms INTEGER,
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

        // Create indexes
        const indexes = [
          { name: 'idx_links_expires', query: 'CREATE INDEX IF NOT EXISTS idx_links_expires ON links(expires_at);' },
          { name: 'idx_links_status', query: 'CREATE INDEX IF NOT EXISTS idx_links_status ON links(status);' },
          { name: 'idx_links_mode', query: 'CREATE INDEX IF NOT EXISTS idx_links_mode ON links(link_mode);' },
          { name: 'idx_clicks_link_id', query: 'CREATE INDEX IF NOT EXISTS idx_clicks_link_id ON clicks(link_id);' },
          { name: 'idx_clicks_ip', query: 'CREATE INDEX IF NOT EXISTS idx_clicks_ip ON clicks(ip);' },
          { name: 'idx_clicks_created', query: 'CREATE INDEX IF NOT EXISTS idx_clicks_created ON clicks(created_at);' },
          { name: 'idx_clicks_mode', query: 'CREATE INDEX IF NOT EXISTS idx_clicks_mode ON clicks(link_mode);' },
          { name: 'idx_clicks_encoding', query: 'CREATE INDEX IF NOT EXISTS idx_clicks_encoding ON clicks(encoding_layers);' },
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
    if (data.mode) {
      linkModeCounter.labels(data.mode).inc();
    }
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
  transports: ['websocket', 'polling'],
  maxHttpBufferSize: 1e6
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
  credentials: true,
  maxAge: 86400
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
  if (req.query.username || req.query.password || req.query.pass || req.query.pwd) {
    logger.error('🚫 Blocked request with credentials in URL', {
      ip: req.ip,
      path: req.path,
      query: Object.keys(req.query)
    });
    
    if (req.path === '/admin/login') {
      return res.redirect('/admin/login');
    }
    
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

const LOG_FILE = 'logs/clicks.log';
const REQUEST_LOG_FILE = 'logs/requests.log';
const PORT = validatedConfig.PORT;

const ADMIN_USERNAME = validatedConfig.ADMIN_USERNAME;
const ADMIN_PASSWORD_HASH = validatedConfig.ADMIN_PASSWORD_HASH;

// Link mode configuration
const LINK_LENGTH_MODE = validatedConfig.LINK_LENGTH_MODE;
const ALLOW_LINK_MODE_SWITCH = validatedConfig.ALLOW_LINK_MODE_SWITCH;
const LONG_LINK_SEGMENTS = validatedConfig.LONG_LINK_SEGMENTS;
const LONG_LINK_PARAMS = validatedConfig.LONG_LINK_PARAMS;
const LINK_ENCODING_LAYERS = validatedConfig.LINK_ENCODING_LAYERS;

// Enhanced encoding options
const ENABLE_COMPRESSION = validatedConfig.ENABLE_COMPRESSION;
const ENABLE_ENCRYPTION = validatedConfig.ENABLE_ENCRYPTION;
const ENCRYPTION_KEY = validatedConfig.ENCRYPTION_KEY;
const MAX_ENCODING_ITERATIONS = validatedConfig.MAX_ENCODING_ITERATIONS;
const ENCODING_COMPLEXITY_THRESHOLD = validatedConfig.ENCODING_COMPLEXITY_THRESHOLD;

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
const encodingCache = new NodeCache({ stdTTL: 3600, checkperiod: 600, maxKeys: 5000 });

// Login attempt tracking
const loginAttempts = new Map();

// Clean up old login attempts every hour
setInterval(() => {
  const now = Date.now();
  for (const [ip, data] of loginAttempts.entries()) {
    if (now - data.lastAttempt > 3600000) {
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
  linkModes: {
    short: 0,
    long: 0,
    auto: 0
  },
  linkLengths: {
    avg: 0,
    min: Infinity,
    max: 0,
    total: 0
  },
  encodingStats: {
    avgLayers: 0,
    avgLength: 0,
    totalEncoded: 0,
    avgComplexity: 0,
    totalComplexity: 0,
    avgDecodeTime: 0,
    totalDecodeTime: 0
  },
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
    qr: 0,
    encoding: 0
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
  
  stats.caches = {
    geo: geoCache.keys().length,
    linkReq: linkCache.keys().length,
    device: deviceCache.keys().length,
    qr: qrCache.keys().length,
    encoding: encodingCache.keys().length
  };
  
  socket.emit('stats', stats);
  socket.emit('config', {
    linkTTL: LINK_TTL_SEC,
    linkTTLFormatted: formatDuration(LINK_TTL_SEC),
    targetUrl: TARGET_URL,
    botUrls: BOT_URLS,
    maxLinks: MAX_LINKS,
    linkLengthMode: LINK_LENGTH_MODE,
    allowLinkModeSwitch: ALLOW_LINK_MODE_SWITCH,
    longLinkSegments: LONG_LINK_SEGMENTS,
    longLinkParams: LONG_LINK_PARAMS,
    linkEncodingLayers: LINK_ENCODING_LAYERS,
    enableCompression: ENABLE_COMPRESSION,
    enableEncryption: ENABLE_ENCRYPTION,
    maxEncodingIterations: MAX_ENCODING_ITERATIONS,
    encodingComplexityThreshold: ENCODING_COMPLEXITY_THRESHOLD,
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
          encodingCache.flushAll();
          stats.caches = { geo: 0, linkReq: 0, device: 0, qr: 0, encoding: 0 };
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
        case 'clearEncodingCache':
          encodingCache.flushAll();
          stats.caches.encoding = 0;
          socket.emit('notification', { type: 'success', message: 'Encoding cache cleared' });
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
            nodeEnv: NODE_ENV,
            linkLengthMode: LINK_LENGTH_MODE,
            allowLinkModeSwitch: ALLOW_LINK_MODE_SWITCH,
            longLinkSegments: LONG_LINK_SEGMENTS,
            longLinkParams: LONG_LINK_PARAMS,
            linkEncodingLayers: LINK_ENCODING_LAYERS,
            enableCompression: ENABLE_COMPRESSION,
            enableEncryption: ENABLE_ENCRYPTION
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
    qr: qrCache.keys().length,
    encoding: encodingCache.keys().length
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
    'puppeteer', 'selenium', 'playwright', 'cypress', 'headless', 'pupeteer',
    'chrome-lighthouse', 'lighthouse', 'pagespeed', 'webpage', 'gtmetrix'
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
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  
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
      imgSrc: [
        "'self'",
        'data:',
        'https:'
      ],
      connectSrc: [
        "'self'",
        'ws:',
        'wss:',
        'https://cdn.socket.io',
        'https://cdn.jsdelivr.net'
      ],
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
  xssFilter: true,
  hidePoweredBy: true
}));

app.use(express.json({ limit: '100kb' }));
app.use(express.urlencoded({ extended: true, limit: '100kb' }));

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

const encodingLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: validatedConfig.ENCODING_RATE_LIMIT,
  keyGenerator: (req) => req.session?.user || req.ip || 'unknown',
  handler: (req, res) => {
    res.status(429).json({ error: 'Too many encoding requests. Please slow down.' });
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

// ─── ENHANCED ENCODING/DECODING SYSTEM FOR LONG LINKS ────────────────────────

// Extended encoder library with more algorithms
const encoderLibrary = [
  // Base64 variants
  { 
    name: 'base64_standard', 
    enc: s => Buffer.from(s).toString('base64'), 
    dec: s => Buffer.from(s, 'base64').toString(),
    complexity: 1
  },
  { 
    name: 'base64_url', 
    enc: s => Buffer.from(s).toString('base64url'), 
    dec: s => Buffer.from(s, 'base64url').toString(),
    complexity: 1
  },
  { 
    name: 'base64_reverse', 
    enc: s => Buffer.from(s.split('').reverse().join('')).toString('base64'), 
    dec: s => Buffer.from(s, 'base64').toString().split('').reverse().join(''),
    complexity: 2
  },
  { 
    name: 'base64_mime', 
    enc: s => Buffer.from(s).toString('base64').replace(/.{76}/g, '$&\n'), 
    dec: s => Buffer.from(s.replace(/\n/g, ''), 'base64').toString(),
    complexity: 2
  },
  
  // Hexadecimal variants
  { 
    name: 'hex_lower', 
    enc: s => Buffer.from(s).toString('hex'), 
    dec: s => Buffer.from(s, 'hex').toString(),
    complexity: 1
  },
  { 
    name: 'hex_upper', 
    enc: s => Buffer.from(s).toString('hex').toUpperCase(), 
    dec: s => Buffer.from(s.toLowerCase(), 'hex').toString(),
    complexity: 1
  },
  { 
    name: 'hex_reverse', 
    enc: s => Buffer.from(s).toString('hex').split('').reverse().join(''), 
    dec: s => Buffer.from(s.split('').reverse().join(''), 'hex').toString(),
    complexity: 2
  },
  
  // ROT ciphers
  { 
    name: 'rot13', 
    enc: s => s.replace(/[a-zA-Z]/g, c => 
      String.fromCharCode((c <= 'Z' ? 90 : 122) >= (c = c.charCodeAt(0) + 13) ? c : c - 26)
    ), 
    dec: s => s.replace(/[a-zA-Z]/g, c => 
      String.fromCharCode((c <= 'Z' ? 90 : 122) >= (c = c.charCodeAt(0) - 13) ? c : c + 26)
    ),
    complexity: 2
  },
  { 
    name: 'rot5', 
    enc: s => s.replace(/[0-9]/g, c => ((parseInt(c) + 5) % 10).toString()), 
    dec: s => s.replace(/[0-9]/g, c => ((parseInt(c) - 5 + 10) % 10).toString()),
    complexity: 1
  },
  { 
    name: 'rot13_rot5_combo', 
    enc: s => {
      const rot13 = s.replace(/[a-zA-Z]/g, c => 
        String.fromCharCode((c <= 'Z' ? 90 : 122) >= (c = c.charCodeAt(0) + 13) ? c : c - 26)
      );
      return rot13.replace(/[0-9]/g, c => ((parseInt(c) + 5) % 10).toString());
    }, 
    dec: s => {
      const rot5 = s.replace(/[0-9]/g, c => ((parseInt(c) - 5 + 10) % 10).toString());
      return rot5.replace(/[a-zA-Z]/g, c => 
        String.fromCharCode((c <= 'Z' ? 90 : 122) >= (c = c.charCodeAt(0) - 13) ? c : c + 26)
      );
    },
    complexity: 3
  },
  
  // URL encoding
  { 
    name: 'url_encode', 
    enc: encodeURIComponent, 
    dec: decodeURIComponent,
    complexity: 1
  },
  { 
    name: 'double_url_encode', 
    enc: s => encodeURIComponent(encodeURIComponent(s)), 
    dec: s => decodeURIComponent(decodeURIComponent(s)),
    complexity: 2
  },
  { 
    name: 'triple_url_encode', 
    enc: s => encodeURIComponent(encodeURIComponent(encodeURIComponent(s))), 
    dec: s => decodeURIComponent(decodeURIComponent(decodeURIComponent(s))),
    complexity: 3
  },
  
  // ASCII transformations
  { 
    name: 'ascii_shift_1', 
    enc: s => s.split('').map(c => String.fromCharCode(c.charCodeAt(0) + 1)).join(''), 
    dec: s => s.split('').map(c => String.fromCharCode(c.charCodeAt(0) - 1)).join(''),
    complexity: 1
  },
  { 
    name: 'ascii_shift_3', 
    enc: s => s.split('').map(c => String.fromCharCode(c.charCodeAt(0) + 3)).join(''), 
    dec: s => s.split('').map(c => String.fromCharCode(c.charCodeAt(0) - 3)).join(''),
    complexity: 1
  },
  { 
    name: 'ascii_shift_5', 
    enc: s => s.split('').map(c => String.fromCharCode(c.charCodeAt(0) + 5)).join(''), 
    dec: s => s.split('').map(c => String.fromCharCode(c.charCodeAt(0) - 5)).join(''),
    complexity: 1
  },
  { 
    name: 'ascii_xor', 
    enc: s => s.split('').map(c => String.fromCharCode(c.charCodeAt(0) ^ 0x2A)).join(''), 
    dec: s => s.split('').map(c => String.fromCharCode(c.charCodeAt(0) ^ 0x2A)).join(''),
    complexity: 2
  },
  
  // Binary representations
  { 
    name: 'binary_8bit', 
    enc: s => s.split('').map(c => c.charCodeAt(0).toString(2).padStart(8, '0')).join(''), 
    dec: s => s.match(/.{1,8}/g).map(b => String.fromCharCode(parseInt(b, 2))).join(''),
    complexity: 4
  },
  { 
    name: 'binary_16bit', 
    enc: s => s.split('').map(c => c.charCodeAt(0).toString(2).padStart(16, '0')).join(''), 
    dec: s => s.match(/.{1,16}/g).map(b => String.fromCharCode(parseInt(b, 2))).join(''),
    complexity: 4
  },
  
  // Octal
  { 
    name: 'octal', 
    enc: s => s.split('').map(c => c.charCodeAt(0).toString(8)).join(' '), 
    dec: s => s.split(' ').map(o => String.fromCharCode(parseInt(o, 8))).join(''),
    complexity: 3
  },
  
  // Reverse
  { 
    name: 'reverse', 
    enc: s => s.split('').reverse().join(''), 
    dec: s => s.split('').reverse().join(''),
    complexity: 1
  },
  
  // Caesar cipher with different shifts
  { 
    name: 'caesar_3', 
    enc: s => s.replace(/[a-zA-Z]/g, c => {
      const code = c.charCodeAt(0);
      if (code >= 65 && code <= 90) return String.fromCharCode(((code - 65 + 3) % 26) + 65);
      if (code >= 97 && code <= 122) return String.fromCharCode(((code - 97 + 3) % 26) + 97);
      return c;
    }), 
    dec: s => s.replace(/[a-zA-Z]/g, c => {
      const code = c.charCodeAt(0);
      if (code >= 65 && code <= 90) return String.fromCharCode(((code - 65 - 3 + 26) % 26) + 65);
      if (code >= 97 && code <= 122) return String.fromCharCode(((code - 97 - 3 + 26) % 26) + 97);
      return c;
    }),
    complexity: 2
  },
  
  // Atbash cipher
  { 
    name: 'atbash', 
    enc: s => s.replace(/[a-zA-Z]/g, c => {
      const code = c.charCodeAt(0);
      if (code >= 65 && code <= 90) return String.fromCharCode(90 - (code - 65));
      if (code >= 97 && code <= 122) return String.fromCharCode(122 - (code - 97));
      return c;
    }), 
    dec: s => s.replace(/[a-zA-Z]/g, c => {
      const code = c.charCodeAt(0);
      if (code >= 65 && code <= 90) return String.fromCharCode(90 - (code - 65));
      if (code >= 97 && code <= 122) return String.fromCharCode(122 - (code - 97));
      return c;
    }),
    complexity: 2
  }
];

// Original encoders for short links
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

/**
 * Enhanced compression function
 */
function compressData(data) {
  if (!ENABLE_COMPRESSION) return data;
  try {
    return Buffer.from(data).toString('base64');
  } catch (err) {
    logger.warn('Compression failed:', err);
    return data;
  }
}

/**
 * Enhanced decompression function
 */
function decompressData(data) {
  if (!ENABLE_COMPRESSION) return data;
  try {
    return Buffer.from(data, 'base64').toString();
  } catch (err) {
    logger.warn('Decompression failed:', err);
    return data;
  }
}

/**
 * Encryption function with proper key derivation
 */
function encryptData(data) {
  if (!ENABLE_ENCRYPTION || !ENCRYPTION_KEY) return data;
  try {
    const iv = crypto.randomBytes(16);
    const key = crypto.pbkdf2Sync(ENCRYPTION_KEY, 'redirector-salt', 100000, 32, 'sha256');
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    let encrypted = cipher.update(data, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return iv.toString('hex') + ':' + encrypted;
  } catch (err) {
    logger.warn('Encryption failed:', err);
    return data;
  }
}

/**
 * Decryption function with proper key derivation
 */
function decryptData(data) {
  if (!ENABLE_ENCRYPTION || !ENCRYPTION_KEY) return data;
  try {
    if (!data.includes(':')) return data;
    const [ivHex, encrypted] = data.split(':');
    const iv = Buffer.from(ivHex, 'hex');
    const key = crypto.pbkdf2Sync(ENCRYPTION_KEY, 'redirector-salt', 100000, 32, 'sha256');
    const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  } catch (err) {
    logger.warn('Decryption failed:', err);
    return data;
  }
}

/**
 * Advanced multi-layer encoding function for long links
 */
function advancedMultiLayerEncode(str, options = {}) {
  const {
    minLayers = 4,
    maxLayers = LINK_ENCODING_LAYERS,
    minNoiseBytes = 8,
    maxNoiseBytes = 24,
    iterations = MAX_ENCODING_ITERATIONS
  } = options;
  
  let result = str;
  const encodingLayers = [];
  const encodingMetadata = {
    layers: [],
    noise: [],
    iterations: iterations,
    complexity: 0,
    timestamp: Date.now(),
    version: '3.0'
  };
  
  // Apply multiple encoding iterations
  for (let iteration = 0; iteration < iterations; iteration++) {
    // Generate random noise for this iteration
    const noiseBytes = minNoiseBytes + Math.floor(Math.random() * (maxNoiseBytes - minNoiseBytes + 1));
    const noise = crypto.randomBytes(noiseBytes).toString('base64url');
    
    // Add noise to both ends
    result = noise + result + noise;
    encodingMetadata.noise.push(noise);
    
    // Shuffle encoders and select random subset
    const shuffled = [...encoderLibrary].sort(() => Math.random() - 0.5);
    const layerCount = minLayers + Math.floor(Math.random() * (maxLayers - minLayers + 1));
    const selectedLayers = shuffled.slice(0, layerCount);
    
    // Apply each encoder
    for (const layer of selectedLayers) {
      result = layer.enc(result);
      encodingLayers.push(layer.name);
      encodingMetadata.layers.push(layer.name);
      encodingMetadata.complexity += layer.complexity || 1;
    }
    
    // Add separator between iterations
    if (iteration < iterations - 1) {
      const separator = crypto.randomBytes(4).toString('hex');
      const reversed = Buffer.from(result).reverse().toString('utf8').substring(0, 10);
      result = result + separator + reversed;
    }
  }
  
  // Apply compression if enabled
  if (ENABLE_COMPRESSION) {
    result = compressData(result);
    encodingMetadata.compressed = true;
  }
  
  // Apply encryption if enabled
  if (ENABLE_ENCRYPTION) {
    result = encryptData(result);
    encodingMetadata.encrypted = true;
  }
  
  // Final URL encoding
  result = encodeURIComponent(result);
  result = encodeURIComponent(result);
  result = encodeURIComponent(result);
  
  // Update metrics
  encodingComplexityGauge.labels('complexity').set(encodingMetadata.complexity);
  
  return {
    encoded: result,
    layers: encodingLayers.reverse(),
    metadata: encodingMetadata,
    totalLength: result.length,
    complexity: encodingMetadata.complexity
  };
}

/**
 * Advanced multi-layer decoding function
 */
function advancedMultiLayerDecode(encoded, metadata) {
  let result = encoded;
  const startTime = Date.now();
  
  try {
    // Triple URL decode
    result = decodeURIComponent(result);
    result = decodeURIComponent(result);
    result = decodeURIComponent(result);
    
    // Decrypt if enabled
    if (metadata.encrypted) {
      result = decryptData(result);
    }
    
    // Decompress if enabled
    if (metadata.compressed) {
      result = decompressData(result);
    }
    
    // Apply decoders in reverse order
    const layers = [...metadata.layers].reverse();
    for (const layerName of layers) {
      const layer = encoderLibrary.find(e => e.name === layerName);
      if (!layer) throw new Error(`Unknown layer: ${layerName}`);
      result = layer.dec(result);
    }
    
    // Remove noise from all iterations
    if (metadata.noise && Array.isArray(metadata.noise)) {
      for (const noise of metadata.noise) {
        if (result.startsWith(noise) && result.endsWith(noise)) {
          result = result.slice(noise.length, -noise.length);
        }
      }
    }
    
    const decodeTime = Date.now() - startTime;
    stats.encodingStats.avgDecodeTime = (stats.encodingStats.avgDecodeTime * stats.encodingStats.totalDecodeTime + decodeTime) / (stats.encodingStats.totalDecodeTime + 1);
    stats.encodingStats.totalDecodeTime++;
    
    return result;
  } catch (err) {
    logger.error('Advanced decode error:', err);
    throw new AppError('Decoding failed', 400, true);
  }
}

/**
 * Generate long tracking link with enhanced encoding
 */
async function generateLongLink(targetUrl, req, options = {}) {
  const startTime = Date.now();
  
  const {
    segments = LONG_LINK_SEGMENTS,
    params = LONG_LINK_PARAMS,
    minLayers = 4,
    maxLayers = LINK_ENCODING_LAYERS,
    includeFingerprint = true,
    iterations = MAX_ENCODING_ITERATIONS
  } = options;
  
  // Add random fragment and timestamp
  const timestamp = Date.now();
  const randomId = crypto.randomBytes(12).toString('hex');
  const sessionMarker = crypto.randomBytes(4).toString('hex');
  const noisyTarget = `${targetUrl}#${randomId}-${timestamp}-${sessionMarker}`;

  // Check cache for identical encoding
  const cacheKey = crypto.createHash('sha256').update(noisyTarget + segments + params + minLayers + maxLayers + iterations).digest('hex');
  const cached = encodingCache.get(cacheKey);
  if (cached) {
    logger.debug('Using cached encoding result');
    return cached;
  }

  // Apply advanced encoding
  const { encoded, layers, metadata, complexity } = advancedMultiLayerEncode(noisyTarget, {
    minLayers,
    maxLayers,
    iterations
  });
  
  // Store encoding metadata
  const encodingMetadata = {
    layers,
    metadata,
    complexity,
    timestamp,
    randomId
  };
  
  const metadataEnc = Buffer.from(JSON.stringify(encodingMetadata)).toString('base64url');

  // Generate random path segments with varied patterns
  const pathSegments = [];
  const segmentPatterns = [
    () => crypto.randomBytes(12).toString('hex'),
    () => Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 10).toUpperCase(),
    () => {
      const words = ['verify', 'session', 'auth', 'secure', 'gate', 'access', 'token', 'portal', 'gateway', 'endpoint'];
      return words[Math.floor(Math.random() * words.length)] + crypto.randomBytes(6).toString('hex');
    },
    () => 'id_' + crypto.randomBytes(8).toString('base64url'),
    () => 'ref_' + Date.now().toString(36) + Math.random().toString(36).substring(2, 7)
  ];
  
  for (let i = 0; i < segments; i++) {
    const pattern = segmentPatterns[i % segmentPatterns.length];
    pathSegments.push(pattern());
  }

  // Create path with multiple random segments
  const path = `/r/${pathSegments.join('/')}/${crypto.randomBytes(24).toString('hex')}`;

  // Generate extensive fake parameters
  const paramList = [];
  const paramKeys = [
    'sid', 'tok', 'ref', 'utm_source', 'utm_medium', 'utm_campaign', 'clid', 'ver', 'ts', 'hmac', 
    'nonce', '_t', 'cid', 'fid', 'l', 'sig', 'key', 'state', 'code', 'session', 'token', 'auth', 
    'access', 'refresh', 'expires', 'redirect', 'return', 'callback', 'next', 'continue', 'goto',
    'dest', 'target', 'url', 'link', 'goto_url', 'redirect_uri', 'response_type', 'client_id',
    'scope', 'grant_type', 'username', 'email', 'phone', 'country', 'lang', 'locale'
  ];
  
  const fingerprint = includeFingerprint ? 
    crypto.createHash('sha256').update(req.headers['user-agent'] || '' + Date.now()).digest('hex').substring(0, 16) : 
    '';
  
  for (let i = 0; i < params; i++) {
    const keyIndex = i % paramKeys.length;
    const key = paramKeys[keyIndex] + (i > 15 ? `_${Math.floor(i/2)}` : '');
    
    let value;
    if (key.startsWith('l') && !key.includes('_')) {
      value = metadataEnc; // The real encoding data
    } else if (key === 'fp' && fingerprint) {
      value = fingerprint;
    } else if (key === 'ts' || key === '_t') {
      value = Date.now().toString(36) + Math.random().toString(36).substring(2, 8);
    } else if (key.includes('utm')) {
      const utmValues = ['google', 'facebook', 'twitter', 'linkedin', 'email', 'direct', 'referral', 'social'];
      value = utmValues[Math.floor(Math.random() * utmValues.length)];
    } else {
      const length = 12 + Math.floor(Math.random() * 20);
      value = crypto.randomBytes(length).toString('base64url').replace(/=/g, '');
    }
    
    paramList.push(`${key}=${value}`);
  }

  // Multiple rounds of shuffling
  let shuffledParams = [...paramList];
  for (let i = 0; i < 3; i++) {
    shuffledParams = shuffledParams.sort(() => Math.random() - 0.5);
  }

  // Construct final URL with version parameter
  const protocol = req.protocol || 'https';
  const host = req.get('host');
  const version = `${Math.floor(Math.random()*99)}.${Math.floor(Math.random()*99)}.${Math.floor(Math.random()*999)}`;
  const url = `${protocol}://${host}${path}?p=${encoded}&${shuffledParams.join('&')}&v=${version}`;

  // Update stats
  stats.encodingStats.avgLayers = (stats.encodingStats.avgLayers * stats.encodingStats.totalEncoded + layers.length) / (stats.encodingStats.totalEncoded + 1);
  stats.encodingStats.avgLength = (stats.encodingStats.avgLength * stats.encodingStats.totalEncoded + url.length) / (stats.encodingStats.totalEncoded + 1);
  stats.encodingStats.avgComplexity = (stats.encodingStats.avgComplexity * stats.encodingStats.totalEncoded + complexity) / (stats.encodingStats.totalEncoded + 1);
  stats.encodingStats.totalEncoded++;

  const result = {
    url,
    metadata: {
      length: url.length,
      layers: layers.length,
      complexity,
      segments,
      params: paramList.length,
      encodedLength: encoded.length,
      iterations,
      encodingTime: Date.now() - startTime
    },
    encodingMetadata
  };

  // Cache the result
  encodingCache.set(cacheKey, result, 3600);

  logger.info(`[LONG LINK] Generated - Length: ${url.length} chars | Layers: ${layers.length} | Complexity: ${complexity} | Time: ${Date.now() - startTime}ms`);

  return result;
}

/**
 * Generate short link (original method)
 */
function generateShortLink(targetUrl, req) {
  const startTime = Date.now();
  const { encoded } = multiLayerEncode(targetUrl + '#' + Date.now());
  const id = crypto.randomBytes(16).toString('hex');
  const url = `${req.protocol}://${req.get('host')}/v/${id}`;
  
  return {
    url,
    metadata: {
      length: url.length,
      id,
      encodingTime: Date.now() - startTime
    }
  };
}

/**
 * Decode and extract target from long link with enhanced decoding
 */
async function decodeLongLink(req) {
  const startTime = Date.now();
  
  try {
    const query = req.url.split('?')[1] || '';
    const params = new URLSearchParams(query);
    const enc = params.get('p') || '';
    
    // Find metadata parameter
    let metadataEnc = '';
    for (const [key, value] of params.entries()) {
      if (key.startsWith('l') && !key.includes('_') && value.length > 100) {
        metadataEnc = value;
        break;
      }
    }

    if (!enc || !metadataEnc) {
      return { success: false, reason: 'missing_parameters' };
    }

    // Parse metadata
    let encodingMetadata;
    try {
      encodingMetadata = JSON.parse(Buffer.from(metadataEnc, 'base64url').toString());
    } catch (e) {
      return { success: false, reason: 'invalid_metadata' };
    }

    const { layers, metadata } = encodingMetadata;
    
    if (!layers || !Array.isArray(layers)) {
      return { success: false, reason: 'incomplete_metadata' };
    }

    // Decode the URL
    let decoded = advancedMultiLayerDecode(enc, { layers, ...metadata });

    // Extract original URL (remove fragments)
    const hashIdx = decoded.indexOf('#');
    if (hashIdx !== -1) decoded = decoded.substring(0, hashIdx);

    // Ensure URL has protocol
    if (!/^https?:\/\//i.test(decoded)) {
      decoded = 'https://' + decoded;
    }

    // Validate URL
    try {
      const urlObj = new URL(decoded);
      if (!['http:', 'https:'].includes(urlObj.protocol)) {
        return { success: false, reason: 'invalid_protocol' };
      }
      
      const decodeTime = Date.now() - startTime;
      
      return { 
        success: true, 
        target: decoded,
        decodeTime,
        metadata: {
          layers: layers.length,
          complexity: metadata?.complexity || 0
        }
      };
    } catch (e) {
      return { success: false, reason: 'invalid_url' };
    }
  } catch (err) {
    logger.error('Long link decode error:', err);
    return { success: false, reason: 'decode_error' };
  }
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
      botBlocks: stats.botBlocks,
      linkModes: stats.linkModes,
      encodingStats: stats.encodingStats
    },
    database: dbPool ? 'connected' : 'disabled',
    redis: redisClient?.status === 'ready' ? 'connected' : 'disabled',
    queues: {
      redirect: redirectQueue ? 'ready' : 'disabled',
      email: emailQueue ? 'ready' : 'disabled',
      analytics: analyticsQueue ? 'ready' : 'disabled',
      encoding: encodingQueue ? 'ready' : 'disabled'
    }
  };
  res.status(200).json(healthData);
});

// Health check for encoding system
app.get('/health/encoding', (req, res) => {
  const testString = 'https://test.com';
  const start = Date.now();
  
  try {
    const { encoded } = advancedMultiLayerEncode(testString, {
      minLayers: 2,
      maxLayers: 3,
      iterations: 1
    });
    
    res.json({
      status: 'healthy',
      duration: Date.now() - start,
      test: 'passed'
    });
  } catch (err) {
    res.status(503).json({
      status: 'unhealthy',
      error: err.message
    });
  }
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
      qr: qrCache.keys().length,
      encoding: encodingCache.keys().length
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
    linkModes: stats.linkModes,
    linkLengths: stats.linkLengths,
    encodingStats: stats.encodingStats,
    devices: stats.byDevice,
    realtime: stats.realtime,
    config: {
      linkTTL: LINK_TTL_SEC,
      linkTTLFormatted: formatDuration(LINK_TTL_SEC),
      maxLinks: MAX_LINKS,
      nodeEnv: NODE_ENV,
      linkLengthMode: LINK_LENGTH_MODE,
      allowLinkModeSwitch: ALLOW_LINK_MODE_SWITCH,
      longLinkSegments: LONG_LINK_SEGMENTS,
      longLinkParams: LONG_LINK_PARAMS,
      linkEncodingLayers: LINK_ENCODING_LAYERS,
      enableCompression: ENABLE_COMPRESSION,
      enableEncryption: ENABLE_ENCRYPTION,
      maxEncodingIterations: MAX_ENCODING_ITERATIONS
    },
    prometheus: await promClient.register.metrics()
  };
  
  res.set('Content-Type', promClient.register.contentType);
  res.send(await promClient.register.metrics());
});

// Generate Link - WITH LONG/SHORT LINK OPTION
app.post('/api/generate', csrfProtection, encodingLimiter, [
  body('url').optional().isURL().withMessage('Valid URL required'),
  body('password').optional().isString().isLength({ min: 6 }).withMessage('Password must be at least 6 characters'),
  body('maxClicks').optional().isInt({ min: 1, max: 10000 }).withMessage('Max clicks must be between 1 and 10000'),
  body('expiresIn').optional().isString(),
  body('notes').optional().isString().trim().escape(),
  body('linkMode').optional().isIn(['short', 'long', 'auto']).withMessage('Link mode must be short, long, or auto'),
  body('longLinkOptions').optional().isObject()
], async (req, res, next) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ error: errors.array()[0].msg });
    }

    const target = req.body.url || TARGET_URL;
    const password = req.body.password;
    const maxClicks = req.body.maxClicks;
    const expiresIn = req.body.expiresIn ? parseTTL(req.body.expiresIn) : LINK_TTL_SEC;
    const notes = req.body.notes ? sanitizeHtml(req.body.notes, { allowedTags: [], allowedAttributes: {} }) : '';
    
    let linkMode = req.body.linkMode || LINK_LENGTH_MODE;
    
    if (linkMode === 'auto') {
      linkMode = (target.length > 100 || req.body.forceLong) ? 'long' : 'short';
    }
    
    if (!ALLOW_LINK_MODE_SWITCH) {
      linkMode = LINK_LENGTH_MODE;
    }

    let generatedUrl;
    let linkMetadata = {};
    let cacheId;
    let encodingMetadata = {};

    if (linkMode === 'long') {
      const longLinkOptions = {
        segments: req.body.longLinkOptions?.segments || LONG_LINK_SEGMENTS,
        params: req.body.longLinkOptions?.params || LONG_LINK_PARAMS,
        minLayers: req.body.longLinkOptions?.minLayers || 4,
        maxLayers: req.body.longLinkOptions?.maxLayers || LINK_ENCODING_LAYERS,
        includeFingerprint: req.body.longLinkOptions?.includeFingerprint !== false,
        iterations: req.body.longLinkOptions?.iterations || MAX_ENCODING_ITERATIONS
      };
      
      // Use queue for complex encoding if available
      if (encodingQueue && longLinkOptions.iterations > 2 && longLinkOptions.maxLayers > 6) {
        const job = await encodingQueue.add({ targetUrl: target, req, options: longLinkOptions });
        const result = await job.finished();
        generatedUrl = result.url;
        linkMetadata = result.metadata;
        encodingMetadata = result.encodingMetadata;
      } else {
        const result = await generateLongLink(target, req, longLinkOptions);
        generatedUrl = result.url;
        linkMetadata = result.metadata;
        encodingMetadata = result.encodingMetadata;
      }
      
      cacheId = crypto.createHash('md5').update(generatedUrl).digest('hex');
    } else {
      const result = generateShortLink(target, req);
      generatedUrl = result.url;
      linkMetadata = result.metadata;
      cacheId = linkMetadata.id;
    }
    
    const linkData = {
      e: linkMode === 'long' ? null : multiLayerEncode(target + '#' + Date.now()).encoded,
      target,
      created: Date.now(),
      expiresAt: Date.now() + (expiresIn * 1000),
      passwordHash: password ? await bcrypt.hash(password, 10) : null,
      maxClicks: maxClicks ? parseInt(maxClicks) : null,
      currentClicks: 0,
      notes,
      linkMode,
      linkMetadata,
      encodingMetadata,
      metadata: {
        ...linkMetadata,
        userAgent: req.headers['user-agent'],
        creator: req.session.user || 'anonymous',
        ip: req.ip
      }
    };
    
    linkCache.set(cacheId, linkData, expiresIn);
    
    if (dbPool) {
      try {
        await dbPool.query(
          'INSERT INTO links (id, target_url, created_at, expires_at, creator_ip, password_hash, max_clicks, current_clicks, link_mode, link_metadata, encoding_metadata, metadata, encoding_complexity) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)',
          [cacheId, target, new Date(), new Date(Date.now() + (expiresIn * 1000)), req.ip, linkData.passwordHash, linkData.maxClicks, 0, linkMode, JSON.stringify(linkMetadata), JSON.stringify(encodingMetadata), JSON.stringify(linkData.metadata), encodingMetadata.complexity || 0]
        );
      } catch (dbErr) {
        logger.error('Database insert error:', dbErr);
      }
    }
    
    stats.generatedLinks++;
    linkGenerations.inc();
    stats.linkModes[linkMode] = (stats.linkModes[linkMode] || 0) + 1;
    
    const linkLength = generatedUrl.length;
    stats.linkLengths.total += linkLength;
    stats.linkLengths.avg = stats.linkLengths.total / stats.generatedLinks;
    stats.linkLengths.min = Math.min(stats.linkLengths.min, linkLength);
    stats.linkLengths.max = Math.max(stats.linkLengths.max, linkLength);
    
    linkModeCounter.labels(linkMode).inc();
    
    const response = {
      url: generatedUrl,
      mode: linkMode,
      expires: expiresIn,
      expires_human: formatDuration(expiresIn),
      id: cacheId,
      created: Date.now(),
      passwordProtected: !!password,
      maxClicks: linkData.maxClicks || null,
      notes: notes || null,
      linkLength: generatedUrl.length,
      metadata: linkMetadata,
      encodingDetails: linkMode === 'long' ? {
        layers: encodingMetadata.layers?.length || 0,
        complexity: encodingMetadata.complexity || 0,
        iterations: encodingMetadata.metadata?.iterations || 1,
        encodingTime: linkMetadata.encodingTime
      } : null
    };
    
    io.emit('link-generated', response);
    logRequest('generate', req, res, { 
      id: cacheId, 
      mode: linkMode,
      length: generatedUrl.length,
      layers: encodingMetadata.layers?.length,
      passwordProtected: !!password 
    });
    
    if (analyticsQueue) {
      analyticsQueue.add({ 
        type: 'generate', 
        data: { 
          id: cacheId, 
          mode: linkMode,
          length: generatedUrl.length,
          layers: encodingMetadata.layers?.length,
          passwordProtected: !!password 
        } 
      });
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

/**
 * Decode and redirect endpoint for long links
 */
app.get('/r/*', strictLimiter, async (req, res, next) => {
  try {
    const deviceInfo = req.deviceInfo;
    const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip || '0.0.0.0';
    
    const ipKey = `r:${ip}`;
    const requestCount = linkRequestCache.get(ipKey) || 0;
    
    if (requestCount >= 3) {
      logRequest('rate-limit', req, res, { path: 'r', count: requestCount });
      return res.redirect(BOT_URLS[Math.floor(Math.random() * BOT_URLS.length)]);
    }
    
    linkRequestCache.set(ipKey, requestCount + 1);

    const country = await getCountryCode(req);

    if (isLikelyBot(req)) {
      logRequest('bot-block', req, res, { reason: 'bot-detection', path: 'r' });
      return res.redirect(BOT_URLS[Math.floor(Math.random() * BOT_URLS.length)]);
    }

    const decodeResult = await decodeLongLink(req);
    
    let redirectTarget;
    
    if (decodeResult.success) {
      redirectTarget = decodeResult.target;
      logRequest('long-link-decode', req, res, { 
        success: true,
        layers: decodeResult.metadata.layers,
        complexity: decodeResult.metadata.complexity,
        decodeTime: decodeResult.decodeTime,
        target: redirectTarget.substring(0, 50)
      });
    } else {
      redirectTarget = TARGET_URL;
      logRequest('long-link-decode', req, res, { 
        success: false,
        reason: decodeResult.reason
      });
    }

    stats.successfulRedirects++;
    
    if (dbPool && analyticsQueue) {
      analyticsQueue.add({
        type: 'redirect',
        data: {
          path: 'r',
          ip,
          userAgent: req.headers['user-agent'],
          deviceInfo,
          country,
          target: redirectTarget,
          decodeSuccess: decodeResult.success,
          decodeLayers: decodeResult.metadata?.layers,
          decodeTime: decodeResult.decodeTime,
          linkMode: 'long'
        }
      });
    }

    if (deviceInfo.isMobile) {
      return res.send(`<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <meta http-equiv="refresh" content="0;url=${redirectTarget}">
  <style>body{background:#000;margin:0;padding:0}</style>
</head>
<body></body>
</html>`);
    }

    if (validatedConfig.DISABLE_DESKTOP_CHALLENGE) {
      return res.send(`<meta http-equiv="refresh" content="0;url=${redirectTarget}">`);
    }

    const hpSuffix = crypto.randomBytes(2).toString('hex');
    const nonce = res.locals.nonce;

    const challenge = `
      (function(){
        const T='${redirectTarget.replace(/'/g, "\\'")}';
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
    .spinner{width:40px;height:40px;border:3px solid #2a2a2a;border-top-color:#8a8a8a;border-radius:50%;margin:20px auto;animation:spin 1s linear infinite}
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

// Get All Links
async function getAllLinks() {
  if (!dbPool) {
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
          link_mode: data.linkMode || 'short',
          link_length: data.linkMetadata?.length || 0,
          encoding_layers: data.encodingMetadata?.layers?.length || 0,
          encoding_complexity: data.encodingMetadata?.complexity || 0,
          status: data.expiresAt > Date.now() ? 'active' : 'expired'
        });
      }
    }
    return links;
  }

  try {
    const result = await dbPool.query(
      `SELECT id, target_url, created_at, expires_at, current_clicks, max_clicks, 
              (password_hash IS NOT NULL) as password_protected, COALESCE(metadata->>'notes', '') as notes,
              link_mode, link_metadata->>'length' as link_length,
              jsonb_array_length(encoding_metadata->'layers') as encoding_layers,
              encoding_complexity,
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
    
    if (!/^[a-f0-9]{32,64}$/i.test(linkId)) {
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
      linkMode: linkData?.linkMode || 'short',
      linkLength: linkData?.linkMetadata?.length || 0,
      encodingLayers: linkData?.encodingMetadata?.layers?.length || 0,
      encodingComplexity: linkData?.encodingMetadata?.complexity || 0,
      uniqueVisitors: 0,
      countries: {},
      devices: {},
      recentClicks: []
    };
    
    if (dbPool && linkData) {
      try {
        const result = await dbPool.query(
          `SELECT 
            COUNT(*) as total_clicks,
            COUNT(DISTINCT ip) as unique_visitors,
            COALESCE(jsonb_object_agg(country, country_count) FILTER (WHERE country IS NOT NULL), '{}') as countries,
            COALESCE(jsonb_object_agg(device_type, device_count) FILTER (WHERE device_type IS NOT NULL), '{}') as devices,
            AVG(decoding_time_ms) as avg_decoding_time
          FROM (
            SELECT 
              country,
              device_type,
              decoding_time_ms,
              COUNT(*) as country_count,
              COUNT(*) as device_count
            FROM clicks 
            WHERE link_id = $1
            GROUP BY country, device_type, decoding_time_ms
          ) sub`,
          [linkId]
        );
        
        const recentResult = await dbPool.query(
          `SELECT ip, country, device_type, link_mode, encoding_layers, decoding_time_ms, created_at 
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
      } catch (dbErr) {
        logger.error('Error fetching stats:', dbErr);
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
      
      linkLengthMode: LINK_LENGTH_MODE,
      allowLinkModeSwitch: ALLOW_LINK_MODE_SWITCH,
      longLinkSegments: LONG_LINK_SEGMENTS,
      longLinkParams: LONG_LINK_PARAMS,
      linkEncodingLayers: LINK_ENCODING_LAYERS,
      
      enableCompression: ENABLE_COMPRESSION,
      enableEncryption: ENABLE_ENCRYPTION,
      maxEncodingIterations: MAX_ENCODING_ITERATIONS,
      encodingComplexityThreshold: ENCODING_COMPLEXITY_THRESHOLD,
      
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
    
    if (key === 'botThresholds') {
      logger.info('Bot thresholds updated:', value);
    } else if (key === 'linkLengthMode') {
      global.LINK_LENGTH_MODE = value;
    } else if (key === 'allowLinkModeSwitch') {
      global.ALLOW_LINK_MODE_SWITCH = value;
    } else if (key === 'longLinkSegments') {
      global.LONG_LINK_SEGMENTS = parseInt(value);
    } else if (key === 'longLinkParams') {
      global.LONG_LINK_PARAMS = parseInt(value);
    } else if (key === 'linkEncodingLayers') {
      global.LINK_ENCODING_LAYERS = parseInt(value);
    } else if (key === 'enableCompression') {
      global.ENABLE_COMPRESSION = value;
    } else if (key === 'enableEncryption') {
      global.ENABLE_ENCRYPTION = value;
    } else if (key === 'maxEncodingIterations') {
      global.MAX_ENCODING_ITERATIONS = parseInt(value);
    } else if (key === 'encodingComplexityThreshold') {
      global.ENCODING_COMPLEXITY_THRESHOLD = parseInt(value);
    }
    
    io.emit('settings-updated', { key, value });
    res.json({ success: true });
  } catch (err) {
    next(err);
  }
});

// Update link mode settings
app.post('/api/settings/link-mode', csrfProtection, async (req, res, next) => {
  try {
    if (!req.session.authenticated) {
      throw new AppError('Unauthorized', 401);
    }
    
    const { 
      linkLengthMode,
      allowLinkModeSwitch,
      longLinkSegments,
      longLinkParams,
      linkEncodingLayers,
      enableCompression,
      enableEncryption,
      maxEncodingIterations,
      encodingComplexityThreshold
    } = req.body;
    
    if (linkLengthMode && !['short', 'long', 'auto'].includes(linkLengthMode)) {
      throw new AppError('Invalid link mode', 400);
    }
    
    if (longLinkSegments && (longLinkSegments < 3 || longLinkSegments > 20)) {
      throw new AppError('Long link segments must be between 3 and 20', 400);
    }
    
    if (longLinkParams && (longLinkParams < 5 || longLinkParams > 30)) {
      throw new AppError('Long link params must be between 5 and 30', 400);
    }
    
    if (linkEncodingLayers && (linkEncodingLayers < 2 || linkEncodingLayers > 12)) {
      throw new AppError('Encoding layers must be between 2 and 12', 400);
    }
    
    if (maxEncodingIterations && (maxEncodingIterations < 1 || maxEncodingIterations > 5)) {
      throw new AppError('Encoding iterations must be between 1 and 5', 400);
    }
    
    if (encodingComplexityThreshold && (encodingComplexityThreshold < 10 || encodingComplexityThreshold > 100)) {
      throw new AppError('Encoding complexity threshold must be between 10 and 100', 400);
    }
    
    if (dbPool) {
      const updates = [];
      if (linkLengthMode) {
        updates.push(dbPool.query(
          'INSERT INTO settings (key, value, updated_by) VALUES ($1, $2, $3) ON CONFLICT (key) DO UPDATE SET value = $2, updated_at = CURRENT_TIMESTAMP, updated_by = $3',
          ['linkLengthMode', JSON.stringify(linkLengthMode), req.session.user]
        ));
      }
      
      if (allowLinkModeSwitch !== undefined) {
        updates.push(dbPool.query(
          'INSERT INTO settings (key, value, updated_by) VALUES ($1, $2, $3) ON CONFLICT (key) DO UPDATE SET value = $2, updated_at = CURRENT_TIMESTAMP, updated_by = $3',
          ['allowLinkModeSwitch', JSON.stringify(allowLinkModeSwitch), req.session.user]
        ));
      }
      
      if (longLinkSegments) {
        updates.push(dbPool.query(
          'INSERT INTO settings (key, value, updated_by) VALUES ($1, $2, $3) ON CONFLICT (key) DO UPDATE SET value = $2, updated_at = CURRENT_TIMESTAMP, updated_by = $3',
          ['longLinkSegments', JSON.stringify(longLinkSegments), req.session.user]
        ));
      }
      
      if (longLinkParams) {
        updates.push(dbPool.query(
          'INSERT INTO settings (key, value, updated_by) VALUES ($1, $2, $3) ON CONFLICT (key) DO UPDATE SET value = $2, updated_at = CURRENT_TIMESTAMP, updated_by = $3',
          ['longLinkParams', JSON.stringify(longLinkParams), req.session.user]
        ));
      }
      
      if (linkEncodingLayers) {
        updates.push(dbPool.query(
          'INSERT INTO settings (key, value, updated_by) VALUES ($1, $2, $3) ON CONFLICT (key) DO UPDATE SET value = $2, updated_at = CURRENT_TIMESTAMP, updated_by = $3',
          ['linkEncodingLayers', JSON.stringify(linkEncodingLayers), req.session.user]
        ));
      }
      
      if (enableCompression !== undefined) {
        updates.push(dbPool.query(
          'INSERT INTO settings (key, value, updated_by) VALUES ($1, $2, $3) ON CONFLICT (key) DO UPDATE SET value = $2, updated_at = CURRENT_TIMESTAMP, updated_by = $3',
          ['enableCompression', JSON.stringify(enableCompression), req.session.user]
        ));
      }
      
      if (enableEncryption !== undefined) {
        updates.push(dbPool.query(
          'INSERT INTO settings (key, value, updated_by) VALUES ($1, $2, $3) ON CONFLICT (key) DO UPDATE SET value = $2, updated_at = CURRENT_TIMESTAMP, updated_by = $3',
          ['enableEncryption', JSON.stringify(enableEncryption), req.session.user]
        ));
      }
      
      if (maxEncodingIterations) {
        updates.push(dbPool.query(
          'INSERT INTO settings (key, value, updated_by) VALUES ($1, $2, $3) ON CONFLICT (key) DO UPDATE SET value = $2, updated_at = CURRENT_TIMESTAMP, updated_by = $3',
          ['maxEncodingIterations', JSON.stringify(maxEncodingIterations), req.session.user]
        ));
      }
      
      if (encodingComplexityThreshold) {
        updates.push(dbPool.query(
          'INSERT INTO settings (key, value, updated_by) VALUES ($1, $2, $3) ON CONFLICT (key) DO UPDATE SET value = $2, updated_at = CURRENT_TIMESTAMP, updated_by = $3',
          ['encodingComplexityThreshold', JSON.stringify(encodingComplexityThreshold), req.session.user]
        ));
      }
      
      await Promise.all(updates);
    }
    
    if (linkLengthMode) global.LINK_LENGTH_MODE = linkLengthMode;
    if (allowLinkModeSwitch !== undefined) global.ALLOW_LINK_MODE_SWITCH = allowLinkModeSwitch;
    if (longLinkSegments) global.LONG_LINK_SEGMENTS = longLinkSegments;
    if (longLinkParams) global.LONG_LINK_PARAMS = longLinkParams;
    if (linkEncodingLayers) global.LINK_ENCODING_LAYERS = linkEncodingLayers;
    if (enableCompression !== undefined) global.ENABLE_COMPRESSION = enableCompression;
    if (enableEncryption !== undefined) global.ENABLE_ENCRYPTION = enableEncryption;
    if (maxEncodingIterations) global.MAX_ENCODING_ITERATIONS = maxEncodingIterations;
    if (encodingComplexityThreshold) global.ENCODING_COMPLEXITY_THRESHOLD = encodingComplexityThreshold;
    
    io.emit('settings-updated', { 
      type: 'link-mode',
      settings: {
        linkLengthMode,
        allowLinkModeSwitch,
        longLinkSegments,
        longLinkParams,
        linkEncodingLayers,
        enableCompression,
        enableEncryption,
        maxEncodingIterations,
        encodingComplexityThreshold
      }
    });
    
    res.json({ 
      success: true,
      message: 'Link mode settings updated successfully'
    });
  } catch (err) {
    next(err);
  }
});

// Test endpoint to compare short vs long links
app.get('/api/test/link-modes', async (req, res, next) => {
  try {
    if (!req.session.authenticated) {
      throw new AppError('Unauthorized', 401);
    }
    
    const testUrl = req.query.url || 'https://example.com/very/long/path/with/many/segments/that/might/need/encoding?param1=value1&param2=value2&param3=value3';
    
    const shortResult = generateShortLink(testUrl, req);
    
    const longResults = [];
    
    for (const segments of [4, 6, 8, 10]) {
      for (const params of [8, 12, 16, 20]) {
        for (const iterations of [1, 2, 3]) {
          const result = await generateLongLink(testUrl, req, {
            segments,
            params,
            minLayers: 4,
            maxLayers: 6,
            iterations
          });
          longResults.push({
            config: { segments, params, iterations },
            url: result.url,
            length: result.url.length,
            layers: result.metadata.layers,
            complexity: result.metadata.complexity,
            encodingTime: result.metadata.encodingTime,
            metadata: result.metadata
          });
        }
      }
    }
    
    res.json({
      originalUrl: testUrl,
      originalLength: testUrl.length,
      shortLink: {
        url: shortResult.url,
        length: shortResult.url.length,
        ratio: (shortResult.url.length / testUrl.length).toFixed(2),
        encodingTime: shortResult.metadata.encodingTime
      },
      longLinks: longResults.sort((a, b) => a.length - b.length),
      summary: {
        shortest: Math.min(...longResults.map(r => r.length)),
        longest: Math.max(...longResults.map(r => r.length)),
        average: longResults.reduce((sum, r) => sum + r.length, 0) / longResults.length,
        avgComplexity: longResults.reduce((sum, r) => sum + (r.complexity || 0), 0) / longResults.length,
        avgEncodingTime: longResults.reduce((sum, r) => sum + (r.encodingTime || 0), 0) / longResults.length
      }
    });
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

// Password Protected Link Verification
app.post('/v/:id/verify', express.json(), async (req, res, next) => {
  try {
    const linkId = req.params.id;
    const { password } = req.body;
    
    let linkData = linkCache.get(linkId);
    
    if (!linkData && dbPool) {
      const result = await dbPool.query(
        'SELECT * FROM links WHERE id = $1 AND expires_at > NOW()',
        [linkId]
      );
      
      if (result.rows.length > 0) {
        const row = result.rows[0];
        linkData = {
          target: row.target_url,
          passwordHash: row.password_hash,
          maxClicks: row.max_clicks,
          currentClicks: row.current_clicks,
          expiresAt: new Date(row.expires_at).getTime(),
          created: new Date(row.created_at).getTime(),
          notes: row.notes,
          linkMode: row.link_mode,
          linkMetadata: row.link_metadata,
          encodingMetadata: row.encoding_metadata
        };
        const ttl = Math.max(60, Math.floor((linkData.expiresAt - Date.now()) / 1000));
        linkCache.set(linkId, linkData, ttl);
      }
    }
    
    if (!linkData) {
      throw new AppError('Link not found or expired', 404);
    }
    
    if (!linkData.passwordHash) {
      return res.json({ success: true, target: linkData.target, redirect: true });
    }
    
    const valid = await bcrypt.compare(password, linkData.passwordHash);
    if (!valid) {
      throw new AppError('Invalid password', 401);
    }
    
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

// Verification Gate with Password Protection
app.get('/v/:id', strictLimiter, async (req, res, next) => {
  try {
    const linkId = req.params.id;
    const deviceInfo = req.deviceInfo;
    const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip || '0.0.0.0';
    const showQr = req.query.qr === 'true';
    const embed = req.query.embed === 'true';
    
    if (!/^[a-f0-9]{32,64}$/i.test(linkId)) {
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

    let data = linkCache.get(linkId);
    
    if (!data && dbPool) {
      const result = await dbPool.query(
        'SELECT * FROM links WHERE id = $1 AND expires_at > NOW()',
        [linkId]
      );
      
      if (result.rows.length > 0) {
        const row = result.rows[0];
        data = {
          target: row.target_url,
          passwordHash: row.password_hash,
          maxClicks: row.max_clicks,
          currentClicks: row.current_clicks,
          expiresAt: new Date(row.expires_at).getTime(),
          created: new Date(row.created_at).getTime(),
          notes: row.notes,
          linkMode: row.link_mode,
          linkMetadata: row.link_metadata,
          encodingMetadata: row.encoding_metadata
        };
        const ttl = Math.max(60, Math.floor((data.expiresAt - Date.now()) / 1000));
        linkCache.set(linkId, data, ttl);
      }
    }

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

    logRequest('redirect-attempt', req, res, { 
      target: data.target.substring(0, 50), 
      hasPassword: !!data.passwordHash,
      linkMode: data.linkMode || 'short',
      encodingLayers: data.encodingMetadata?.layers?.length
    });

    if (dbPool && redirectQueue) {
      redirectQueue.add({
        linkId,
        ip,
        userAgent: req.headers['user-agent'],
        deviceInfo,
        country,
        linkMode: data.linkMode || 'short',
        encodingLayers: data.encodingMetadata?.layers?.length
      });
    }

    if (embed) {
      return res.send(`
        <!DOCTYPE html>
        <html>
        <head>
          <title>Embedded Content - Redirector Pro</title>
          <style>
            body{margin:0;padding:0;overflow:hidden;background:#000}
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
      const nonce = res.locals.nonce;
      const error = req.query.error === 'true' ? 'Invalid password' : '';
      
      return res.send(`
        <!DOCTYPE html>
        <html>
        <head>
          <title>Password Protected - Redirector Pro</title>
          <meta name="viewport" content="width=device-width, initial-scale=1">
          <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
          <style>
            *{margin:0;padding:0;box-sizing:border-box}
            body{min-height:100vh;background:#000;color:#ddd;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;display:flex;align-items:center;justify-content:center;padding:20px}
            .login-wrapper{width:100%;max-width:1000px;background:#0a0a0a;border-radius:28px;overflow:hidden;box-shadow:0 40px 100px rgba(0,0,0,0.9),inset 0 0 80px rgba(20,20,20,0.6);display:flex;border:1px solid #111;animation:fadeIn 0.6s ease-out}
            @keyframes fadeIn{from{opacity:0;transform:scale(0.95)}to{opacity:1;transform:scale(1)}}
            .image-side{flex:1.3;background:#000;overflow:hidden}
            .image-side img{width:100%;height:100%;object-fit:cover;object-position:center;opacity:0.88;filter:contrast(1.15) brightness(0.92)}
            .form-side{flex:1;padding:3rem;display:flex;flex-direction:column;justify-content:center;background:linear-gradient(135deg,rgba(15,15,15,0.92),rgba(8,8,8,0.95));backdrop-filter:blur(10px)}
            .dots{font-size:2.2rem;letter-spacing:8px;opacity:0.3;margin-bottom:2rem;user-select:none;color:#888}
            h1{font-size:2.5rem;font-weight:400;letter-spacing:-1px;margin-bottom:0.5rem;background:linear-gradient(90deg,#e0e0e0,#b0b0b0);-webkit-background-clip:text;-webkit-text-fill-color:transparent}
            .subtitle{font-size:1rem;color:#888;margin-bottom:2rem;font-weight:300}
            .info-box{background:rgba(0,100,200,0.2);border-left:4px solid #3b82f6;padding:1rem;border-radius:12px;margin-bottom:1.5rem;font-size:0.9rem;color:#9ac7ff;border:1px solid rgba(59,130,246,0.2)}
            .info-box i{margin-right:0.5rem;color:#3b82f6}
            .alert{background:rgba(239,68,68,0.1);border-left:4px solid #ef4444;color:#fecaca;padding:1rem;border-radius:12px;margin-bottom:1.5rem;display:${error ? 'flex' : 'none'};align-items:center;gap:0.75rem;border:1px solid rgba(239,68,68,0.2);animation:shake 0.5s ease}
            @keyframes shake{0%,100%{transform:translateX(0)}10%,30%,50%,70%,90%{transform:translateX(-5px)}20%,40%,60%,80%{transform:translateX(5px)}}
            .form-group{margin-bottom:1.5rem}
            label{font-size:0.92rem;color:#aaa;margin-bottom:0.4rem;display:block;font-weight:400;letter-spacing:0.3px}
            .input-wrapper{position:relative}
            .input-icon{position:absolute;left:1rem;top:50%;transform:translateY(-50%);color:#666;font-size:1.1rem;transition:color 0.2s;z-index:1}
            input{width:100%;padding:1rem 1rem 1rem 3rem;background:rgba(20,20,20,0.7);border:1px solid #222;border-radius:12px;color:#eee;font-size:1rem;transition:all 0.22s;backdrop-filter:blur(4px)}
            input:hover{border-color:#333}
            input:focus{outline:none;border-color:#555;background:rgba(30,30,30,0.8);box-shadow:0 0 0 3px rgba(80,80,80,0.2)}
            input:focus + .input-icon{color:#888}
            input::placeholder{color:#444}
            .password-toggle{position:absolute;right:1rem;top:50%;transform:translateY(-50%);background:none;border:none;color:#666;font-size:1.2rem;cursor:pointer;padding:0.4rem;transition:color 0.2s;z-index:2}
            .password-toggle:hover{color:#aaa}
            button{width:100%;padding:1rem;background:linear-gradient(90deg,#5a5a5a 0%,#8c8c8c 50%,#5a5a5a 100%);color:white;font-size:1rem;font-weight:500;border:none;border-radius:14px;cursor:pointer;transition:all 0.3s;box-shadow:0 6px 20px rgba(0,0,0,0.5);background-size:200% 100%;position:relative;overflow:hidden;display:flex;align-items:center;justify-content:center;gap:0.5rem}
            button::before{content:'';position:absolute;top:50%;left:50%;width:0;height:0;border-radius:50%;background:rgba(255,255,255,0.2);transform:translate(-50%, -50%);transition:width 0.6s,height 0.6s}
            button:hover::before{width:300px;height:300px}
            button:hover{background-position:100% 0;transform:translateY(-2px);box-shadow:0 12px 35px rgba(100,100,100,0.3)}
            button:disabled{opacity:0.5;cursor:not-allowed;transform:none}
            .loading{display:none;text-align:center;margin-top:1.5rem;color:#888}
            .loading i{animation:spin 0.8s linear infinite}
            @keyframes spin{to{transform:rotate(360deg)}}
            .footer{text-align:center;margin-top:2rem;color:#555;font-size:0.85rem}
            .security-badge{display:flex;justify-content:center;gap:1rem;margin-top:1.5rem;font-size:0.75rem;color:#666}
            .security-badge i{color:#4ade80}
            @media (max-width:768px){.login-wrapper{flex-direction:column;max-width:450px}.image-side{height:200px;flex:none}.form-side{padding:2rem}h1{font-size:2rem}}
            @media (max-width:480px){.image-side{height:150px}.form-side{padding:1.5rem}h1{font-size:1.8rem}}
          </style>
        </head>
        <body>
          <div class="login-wrapper">
            <div class="image-side">
              <img src="https://img.freepik.com/free-photo/3d-rendering-abstract-black-white-background_23-2150914061.jpg" alt="Abstract black chrome background">
            </div>
            <div class="form-side">
              <div class="dots">•••</div>
              <h1>Protected Link</h1>
              <p class="subtitle">This link requires a password</p>
              <div class="info-box"><i class="fas fa-info-circle"></i><span>Enter the password to access the secured content</span></div>
              <div class="alert" id="errorAlert"><i class="fas fa-exclamation-circle"></i><span id="errorMessage">${error}</span></div>
              <form id="passwordForm">
                <div class="form-group">
                  <label for="password">Password</label>
                  <div class="input-wrapper">
                    <i class="fas fa-lock input-icon"></i>
                    <input type="password" id="password" placeholder="Enter your password" autofocus required>
                    <button type="button" class="password-toggle" id="togglePassword" tabindex="-1">
                      <i class="fa-regular fa-eye"></i>
                    </button>
                  </div>
                </div>
                <button type="submit" id="submitBtn"><span>Access Link</span><i class="fas fa-arrow-right"></i></button>
                <div class="loading" id="loading"><i class="fas fa-spinner"></i> Verifying...</div>
              </form>
              <div class="security-badge"><span><i class="fas fa-lock"></i> 256-bit SSL</span><span><i class="fas fa-shield"></i> Encrypted</span><span><i class="fas fa-clock"></i> Secure</span></div>
              <div class="footer"><i class="fas fa-shield-halved"></i> Redirector Pro • Secure Link Protection</div>
            </div>
          </div>
          <script nonce="${nonce}">
            const form=document.getElementById('passwordForm');const passwordInput=document.getElementById('password');const submitBtn=document.getElementById('submitBtn');const loading=document.getElementById('loading');const errorAlert=document.getElementById('errorAlert');const errorMessage=document.getElementById('errorMessage');const togglePassword=document.getElementById('togglePassword');
            togglePassword.addEventListener('click',()=>{const type=passwordInput.getAttribute('type')==='password'?'text':'password';passwordInput.setAttribute('type',type);togglePassword.querySelector('i').className=type==='password'?'fa-regular fa-eye':'fa-regular fa-eye-slash'});
            form.addEventListener('submit',async(e)=>{e.preventDefault();const password=passwordInput.value.trim();if(!password){showError('Please enter a password');return}
            submitBtn.disabled=true;loading.style.display='block';errorAlert.style.display='none';try{const response=await fetch('/v/${linkId}/verify',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password})});const data=await response.json();if(response.ok&&data.success){window.location.href=data.redirect?data.target:data.target}else{showError(data.error||'Invalid password');submitBtn.disabled=false;loading.style.display='none';passwordInput.value='';passwordInput.focus()}}catch(err){showError('Connection error. Please try again.');submitBtn.disabled=false;loading.style.display='none'}});
            function showError(message){errorMessage.textContent=message;errorAlert.style.display='flex';setTimeout(()=>{errorAlert.style.display='none'},3000)}
            passwordInput.addEventListener('keypress',(e)=>{if(e.key==='Enter'&&!submitBtn.disabled){form.dispatchEvent(new Event('submit'))}});
            passwordInput.addEventListener('input',()=>{errorAlert.style.display='none'});
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
            body{min-height:100vh;background:#000;color:#ddd;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;display:flex;align-items:center;justify-content:center;margin:0;padding:20px}
            .card{background:#0a0a0a;padding:2rem;border-radius:24px;text-align:center;max-width:400px;border:1px solid #1a1a1a;box-shadow:0 25px 50px -12px rgba(0,0,0,0.5)}
            h2{font-size:1.5rem;margin-bottom:1rem;color:#e0e0e0;font-weight:400}
            img{max-width:100%;height:auto;border-radius:16px;margin:1rem 0;border:1px solid #2a2a2a}
            p{color:#888;margin:0.5rem 0}
            .countdown{color:#4ade80;font-weight:bold;margin-top:1rem}
          </style>
        </head>
        <body>
          <div class="card">
            <h2>📱 Scan QR Code</h2>
            <img src="${qrData}" alt="QR Code">
            <p>Or continue to website...</p>
            <div class="countdown">Redirecting in <span id="countdown">5</span> seconds</div>
          </div>
          <script nonce="${res.locals.nonce}">let time=5;const interval=setInterval(()=>{time--;document.getElementById('countdown').textContent=time;if(time<=0){clearInterval(interval);window.location.href='${data.target}'}},1000);</script>
        </body>
        </html>
      `);
    }

    if (deviceInfo.isMobile) {
      stats.successfulRedirects++;
      return res.send(`<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <meta http-equiv="refresh" content="0;url=${data.target}">
  <style>body{background:#000;margin:0;padding:0}</style>
</head>
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
    .spinner{width:40px;height:40px;border:3px solid #2a2a2a;border-top-color:#8a8a8a;border-radius:50%;margin:20px auto;animation:spin 1s linear infinite}
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
    body{background:#000;color:#ddd;font-family:-apple-system,sans-serif;padding:10px;margin:0;min-height:100vh;display:flex;align-items:center}
    .card{background:#0a0a0a;padding:20px;border-radius:24px;text-align:center;max-width:400px;margin:0 auto;border:1px solid #1a1a1a}
    h1{font-size:1.5rem;margin:0 0 10px;color:#e0e0e0;font-weight:400}
    p{color:#888;margin-bottom:20px}
    .btn{background:linear-gradient(90deg,#5a5a5a 0%,#8c8c8c 50%,#5a5a5a 100%);color:white;padding:12px 24px;border-radius:25px;text-decoration:none;display:inline-block;font-weight:500;transition:transform 0.2s}
    .btn:hover{transform:translateY(-2px)}
    .icon{font-size:3rem;margin-bottom:10px;display:block;color:#666}
  ` : `
    *{box-sizing:border-box}
    body{background:#000;color:#ddd;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;padding:20px}
    .card{background:#0a0a0a;border-radius:28px;padding:2.5rem;text-align:center;max-width:480px;border:1px solid #1a1a1a;box-shadow:0 25px 50px -12px rgba(0,0,0,0.5);animation:fadeIn 0.5s ease}
    @keyframes fadeIn{from{opacity:0;transform:translateY(20px)}to{opacity:1;transform:translateY(0)}}
    h1{font-size:2rem;margin-bottom:1rem;color:#e0e0e0;font-weight:400}
    p{color:#888;margin-bottom:2rem;font-size:1.1rem}
    .btn{background:linear-gradient(90deg,#5a5a5a 0%,#8c8c8c 50%,#5a5a5a 100%);color:white;padding:1rem 2rem;border-radius:50px;font-weight:500;text-decoration:none;display:inline-block;transition:transform 0.2s, box-shadow 0.2s}
    .btn:hover{transform:translateY(-2px);box-shadow:0 10px 20px rgba(100,100,100,0.3)}
    .icon{font-size:4rem;margin-bottom:1rem;display:block;color:#666}
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
  
  req.session.regenerate(async (err) => {
    if (err) {
      logger.error('Session regeneration error:', err);
    }
    
    const csrfToken = crypto.randomBytes(32).toString('hex');
    req.session.csrfToken = csrfToken;
    
    const nonce = crypto.randomBytes(16).toString('hex');
    
    try {
      const loginHtmlPath = path.join(__dirname, 'public', 'login.html');
      let html = await fs.readFile(loginHtmlPath, 'utf8');
      
      html = html
        .replace(
          '<input type="hidden" id="csrfToken" value="">',
          `<input type="hidden" id="csrfToken" value="${csrfToken}">`
        )
        .replace(
          '{{NONCE}}',
          nonce
        );
      
      res.setHeader(
        'Content-Security-Policy',
        `default-src 'self'; script-src 'self' 'nonce-${nonce}' https://cdn.socket.io https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; font-src 'self' https://cdnjs.cloudflare.com data:; img-src 'self' data: https:; connect-src 'self' ws: wss: https://cdn.socket.io https://cdn.jsdelivr.net;`
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
        if (dbErr.code === '42P01') {
          logger.warn('blocked_ips table not found, skipping IP block check');
        } else {
          logger.error('Database error checking blocked IP:', dbErr);
        }
      }
    }
    
    if (req.url.includes('?') || Object.keys(req.query).length > 0) {
      logger.error('Login POST with query parameters', { ip, url: req.url });
      throw new AppError('Invalid request format', 400);
    }
    
    const attemptData = loginAttempts.get(ip) || { count: 0, lastAttempt: Date.now() };
    attemptData.count++;
    attemptData.lastAttempt = Date.now();
    loginAttempts.set(ip, attemptData);
    
    if (attemptData.count > 10) {
      logger.error(`Excessive login attempts from ${ip}: ${attemptData.count}`);
      
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
      await new Promise(resolve => setTimeout(resolve, 2000));
    }
    
    if (!username || !password) {
      throw new AppError('Username and password required', 400);
    }
    
    if (username === ADMIN_USERNAME && await bcrypt.compare(password, ADMIN_PASSWORD_HASH)) {
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
        
        if (remember) {
          req.session.cookie.maxAge = 30 * 24 * 60 * 60 * 1000;
        } else {
          req.session.cookie.maxAge = 24 * 60 * 60 * 1000;
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
    const dashboardPath = path.join(__dirname, 'public', 'index.html');
    let html = await fs.readFile(dashboardPath, 'utf8');
    
    const replacements = {
      '{{METRICS_API_KEY}}': METRICS_API_KEY,
      '{{TARGET_URL}}': TARGET_URL,
      '{{csrfToken}}': req.session.csrfToken,
      '{{dbPoolStatus}}': dbPool ? 'connected' : 'disconnected',
      '{{redisStatus}}': redisClient?.status === 'ready' ? 'connected' : 'disconnected',
      '{{redirectQueueStatus}}': redirectQueue ? 'connected' : 'disconnected',
      '{{encodingQueueStatus}}': encodingQueue ? 'connected' : 'disconnected',
      '{{bullBoardPath}}': validatedConfig.BULL_BOARD_PATH,
      '{{linkLengthMode}}': LINK_LENGTH_MODE,
      '{{allowLinkModeSwitch}}': ALLOW_LINK_MODE_SWITCH,
      '{{longLinkSegments}}': LONG_LINK_SEGMENTS,
      '{{longLinkParams}}': LONG_LINK_PARAMS,
      '{{linkEncodingLayers}}': LINK_ENCODING_LAYERS,
      '{{enableCompression}}': ENABLE_COMPRESSION,
      '{{enableEncryption}}': ENABLE_ENCRYPTION,
      '{{maxEncodingIterations}}': MAX_ENCODING_ITERATIONS,
      '{{encodingComplexityThreshold}}': ENCODING_COMPLEXITY_THRESHOLD
    };
    
    for (const [key, value] of Object.entries(replacements)) {
      html = html.replace(new RegExp(key.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'g'), value);
    }
    
    const nonce = crypto.randomBytes(16).toString('hex');
    res.locals.nonce = nonce;
    
    res.setHeader(
      'Content-Security-Policy',
      `default-src 'self'; script-src 'self' 'nonce-${nonce}' https://cdn.socket.io https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://fonts.googleapis.com https://fonts.gstatic.com; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://fonts.googleapis.com https://fonts.gstatic.com; font-src 'self' https://cdnjs.cloudflare.com https://fonts.gstatic.com data:; img-src 'self' data: https:; connect-src 'self' ws: wss: https://cdn.socket.io https://cdn.jsdelivr.net;`
    );
    
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
  encodingCache.flushAll();
  
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
      `SELECT id, link_id, ip, country, device_type, link_mode, encoding_layers, decoding_time_ms, created_at 
       FROM clicks 
       WHERE link_id = $1 
       ORDER BY created_at DESC`,
      [linkId]
    );
    
    if (format === 'csv') {
      const headers = ['id', 'link_id', 'ip', 'country', 'device_type', 'link_mode', 'encoding_layers', 'decoding_time_ms', 'created_at'];
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
    logger.error('Export error:', err);
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
    blockedIPs: [],
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
    if (encodingQueue) await encodingQueue.close();
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
(async () => {
  try {
    await fs.mkdir('logs', { recursive: true });
    await fs.mkdir('public', { recursive: true });
    
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
      console.log(`  🔗 Link Mode: ${LINK_LENGTH_MODE} (${ALLOW_LINK_MODE_SWITCH ? 'switchable' : 'fixed'})`);
      console.log(`  📏 Long Link Segments: ${LONG_LINK_SEGMENTS} | Params: ${LONG_LINK_PARAMS} | Layers: ${LINK_ENCODING_LAYERS}`);
      console.log(`  🔐 Encryption: ${ENABLE_ENCRYPTION ? 'Enabled' : 'Disabled'}`);
      console.log(`  📦 Compression: ${ENABLE_COMPRESSION ? 'Enabled' : 'Disabled'}`);
      console.log(`  🔄 Max Iterations: ${MAX_ENCODING_ITERATIONS}`);
      console.log(`  📊 Complexity Threshold: ${ENCODING_COMPLEXITY_THRESHOLD}`);
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
        version: '3.0.0',
        linkMode: LINK_LENGTH_MODE,
        encoding: {
          layers: LINK_ENCODING_LAYERS,
          compression: ENABLE_COMPRESSION,
          encryption: ENABLE_ENCRYPTION,
          iterations: MAX_ENCODING_ITERATIONS,
          complexityThreshold: ENCODING_COMPLEXITY_THRESHOLD
        }
      });
      
      fs.appendFile(REQUEST_LOG_FILE, JSON.stringify({
        t: Date.now(),
        type: 'startup',
        version: '3.0.0-enterprise',
        port: PORT,
        nodeEnv: NODE_ENV,
        linkMode: LINK_LENGTH_MODE,
        encoding: {
          layers: LINK_ENCODING_LAYERS,
          compression: ENABLE_COMPRESSION,
          encryption: ENABLE_ENCRYPTION
        }
      }) + '\n').catch(() => {});
    });
  } catch (err) {
    logger.error('Failed to start server:', err);
    process.exit(1);
  }
})();

server.keepAliveTimeout = 30000;
server.headersTimeout = 31000;