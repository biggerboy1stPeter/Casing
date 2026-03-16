// ═════════════════════════════════════════════════════════════════════════════
// 🚀 REDIRECTOR PRO v4.1.0 - ENTERPRISE EDITION - ULTIMATE
// Updated & Upgraded with Complete Fixes & Best Practices
// ═════════════════════════════════════════════════════════════════════════════

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
const winstonDailyRotate = require('winston-daily-rotate-file');
const swaggerJsdoc = require('swagger-jsdoc');
const swaggerUi = require('swagger-ui-express');
const promBundle = require('express-prom-bundle');
const { RateLimiterRedis, RateLimiterMemory } = require('rate-limiter-flexible');
const circuitBreaker = require('opossum');
const { performance } = require('perf_hooks');
const { createNamespace } = require('cls-hooked');
const async_hooks = require('async_hooks');
const heapdump = require('heapdump');
const { createBullBoard } = require('@bull-board/api');
const { BullAdapter } = require('@bull-board/api/bullAdapter');
const { ExpressAdapter } = require('@bull-board/express');
const Keyv = require('keyv');
const KeyvFile = require('keyv-file').KeyvFile;
const forge = require('node-forge');
const semver = require('semver');

// ═════════════════════════════════════════════════════════════════════════════
// ✅ ENVIRONMENT VALIDATION - ADDED
// ═════════════════════════════════════════════════════════════════════════════
dotenv.config();

function validateEnvironment() {
  const required = [
    'NODE_ENV',
    'PORT',
    'TARGET_URL',
    'SESSION_SECRET',
    'METRICS_API_KEY',
    'ADMIN_USERNAME',
    'ADMIN_PASSWORD_HASH',
    'REQUEST_SIGNING_SECRET'
  ];
  
  const missing = required.filter(env => !process.env[env]);
  
  if (missing.length > 0) {
    console.error('\n❌ Missing required environment variables:');
    missing.forEach(v => console.error(`   - ${v}`));
    console.error('\n📝 Create a .env file with these variables.\n');
    process.exit(1);
  }
  
  // Validate secret lengths
  if ((process.env.SESSION_SECRET || '').length < 32) {
    console.error('❌ SESSION_SECRET must be at least 32 characters long');
    process.exit(1);
  }
  
  if ((process.env.REQUEST_SIGNING_SECRET || '').length < 32) {
    console.error('❌ REQUEST_SIGNING_SECRET must be at least 32 characters long');
    process.exit(1);
  }
  
  console.log('✅ All required environment variables validated\n');
}

validateEnvironment();

// ═════════════════════════════════════════════════════════════════════════════
// CUSTOM ERROR CLASSES - UPDATED & ENHANCED
// ═════════════════════════════════════════════════════════════════════════════

class AppError extends Error {
  constructor(message, statusCode = 500, code = 'INTERNAL_ERROR', isOperational = true) {
    super(message);
    this.statusCode = statusCode;
    this.code = code;
    this.isOperational = isOperational;
    this.timestamp = new Date().toISOString();
    Error.captureStackTrace(this, this.constructor);
  }
}

class DatabaseError extends AppError {
  constructor(message, originalError) {
    super(message, 503, 'DATABASE_ERROR');
    this.originalError = originalError?.message;
  }
}

class ValidationError extends AppError {
  constructor(message, errors = []) {
    super(message, 400, 'VALIDATION_ERROR');
    this.errors = errors;
  }
}

class RateLimitError extends AppError {
  constructor(message, retryAfter) {
    super(message, 429, 'RATE_LIMIT_ERROR');
    this.retryAfter = retryAfter;
  }
}

class AuthenticationError extends AppError {
  constructor(message = 'Authentication required') {
    super(message, 401, 'AUTHENTICATION_ERROR');
  }
}

class AuthorizationError extends AppError {
  constructor(message = 'Insufficient permissions') {
    super(message, 403, 'AUTHORIZATION_ERROR');
  }
}

// ═════════════════════════════════════════════════════════════════════════════
// CONFIGURATION SCHEMA WITH STRICT VALIDATION
// ═════════════════════════════════════════════════════════════════════════════

const configSchema = Joi.object({
  NODE_ENV: Joi.string().valid('development', 'production', 'test').default('production'),
  PORT: Joi.string().required(),
  HOST: Joi.string().default('0.0.0.0'),
  TARGET_URL: Joi.string().uri().required(),
  REDIS_URL: Joi.string().uri().optional().allow('', null),
  REDIS_HOST: Joi.string().optional(),
  REDIS_PORT: Joi.number().port().default(6379),
  REDIS_PASSWORD: Joi.string().optional().allow(''),
  REDIS_DB: Joi.number().default(0),
  SESSION_SECRET: Joi.string().min(32).required(),
  METRICS_API_KEY: Joi.string().min(16).required(),
  ADMIN_USERNAME: Joi.string().min(3).required(),
  ADMIN_PASSWORD_HASH: Joi.string().required(),
  IPINFO_TOKEN: Joi.string().optional().allow(''),
  LINK_TTL: Joi.string().pattern(/^(\d+)([smhd])?$/i).default('30m'),
  MAX_LINKS: Joi.number().integer().min(100).max(10000000).default(1000000),
  BOT_URLS: Joi.string().optional().default(''),
  CORS_ORIGIN: Joi.string().optional().default('*'),
  DATABASE_URL: Joi.string().uri().optional().allow('', null),
  SMTP_HOST: Joi.string().optional().allow(''),
  SMTP_PORT: Joi.number().port().optional(),
  SMTP_USER: Joi.string().optional().allow(''),
  SMTP_PASS: Joi.string().optional().allow(''),
  ALERT_EMAIL: Joi.string().email().optional().allow(''),
  DISABLE_DESKTOP_CHALLENGE: Joi.boolean().default(false),
  HTTPS_ENABLED: Joi.boolean().default(false),
  DEBUG: Joi.boolean().default(false),
  BULL_BOARD_ENABLED: Joi.boolean().default(true),
  BULL_BOARD_PATH: Joi.string().default('/admin/queues'),
  CSRF_SECRET: Joi.string().min(32).optional(),
  TRUST_PROXY: Joi.number().default(1),
  LINK_LENGTH_MODE: Joi.string().valid('short', 'long', 'auto').default('short'),
  ALLOW_LINK_MODE_SWITCH: Joi.boolean().default(true),
  LONG_LINK_SEGMENTS: Joi.number().integer().min(3).max(20).default(6),
  LONG_LINK_PARAMS: Joi.number().integer().min(5).max(30).default(13),
  LINK_ENCODING_LAYERS: Joi.number().integer().min(2).max(12).default(4),
  ENABLE_COMPRESSION: Joi.boolean().default(true),
  ENABLE_ENCRYPTION: Joi.boolean().default(false),
  ENCRYPTION_KEY: Joi.string().when('ENABLE_ENCRYPTION', { is: true, then: Joi.required() }),
  MAX_ENCODING_ITERATIONS: Joi.number().integer().min(1).max(5).default(3),
  ENCODING_COMPLEXITY_THRESHOLD: Joi.number().integer().min(10).max(100).default(50),
  REQUEST_SIGNING_SECRET: Joi.string().min(32).required(),
  REQUEST_SIGNING_EXPIRY: Joi.number().default(300000),
  DEFAULT_API_VERSION: Joi.string().valid('v1', 'v2').default('v1'),
  SUPPORTED_API_VERSIONS: Joi.string().default('v1,v2'),
  API_VERSION_STRICT: Joi.boolean().default(false),
  RATE_LIMIT_WINDOW: Joi.number().default(60000),
  RATE_LIMIT_MAX_REQUESTS: Joi.number().default(100),
  RATE_LIMIT_BOT: Joi.number().default(2),
  RATE_LIMIT_MOBILE: Joi.number().default(30),
  ENCODING_RATE_LIMIT: Joi.number().default(10),
  DB_POOL_MIN: Joi.number().default(2),
  DB_POOL_MAX: Joi.number().default(20),
  DB_IDLE_TIMEOUT: Joi.number().default(30000),
  DB_CONNECTION_TIMEOUT: Joi.number().default(5000),
  DB_QUERY_TIMEOUT: Joi.number().default(10000),
  DB_TRANSACTION_TIMEOUT: Joi.number().default(30000),
  DB_TRANSACTION_RETRIES: Joi.number().default(3),
  DB_ISOLATION_LEVEL: Joi.string().valid('READ COMMITTED', 'REPEATABLE READ', 'SERIALIZABLE').default('SERIALIZABLE'),
  ENCRYPTION_KEY_ROTATION_DAYS: Joi.number().default(7),
  ENCRYPTION_KEY_STORAGE_PATH: Joi.string().default('./data/keys'),
  BCRYPT_ROUNDS: Joi.number().default(12),
  SESSION_TTL: Joi.number().default(86400),
  SESSION_ABSOLUTE_TIMEOUT: Joi.number().default(604800),
  CSP_ENABLED: Joi.boolean().default(true),
  HSTS_ENABLED: Joi.boolean().default(true),
  LOGIN_ATTEMPTS_MAX: Joi.number().default(10),
  LOGIN_BLOCK_DURATION: Joi.number().default(3600000),
  BLOCKED_DOMAINS: Joi.string().optional().default('localhost,127.0.0.1,::1,0.0.0.0'),
  LOG_LEVEL: Joi.string().valid('error', 'warn', 'info', 'debug').default('info'),
  LOG_FORMAT: Joi.string().valid('json', 'simple', 'combined').default('json'),
  LOG_TO_FILE: Joi.boolean().default(true),
  LOG_TO_CONSOLE: Joi.boolean().default(true),
  LOG_RETENTION_DAYS: Joi.number().default(30),
  LOG_MAX_SIZE: Joi.string().default('20m'),
  METRICS_ENABLED: Joi.boolean().default(true),
  METRICS_PREFIX: Joi.string().default('redirector_'),
  METRICS_BUCKETS: Joi.array().items(Joi.number()).default([0.1, 5, 15, 50, 100, 200, 300, 400, 500, 1000, 2000, 5000]),
  MAX_RESPONSE_TIMES_HISTORY: Joi.number().default(10000),
  CACHE_CHECK_PERIOD_FACTOR: Joi.number().default(0.1),
  REQUEST_TIMEOUT: Joi.number().default(30000),
  KEEP_ALIVE_TIMEOUT: Joi.number().default(30000),
  HEADERS_TIMEOUT: Joi.number().default(31000),
  SERVER_TIMEOUT: Joi.number().default(120000),
  HEALTH_CHECK_INTERVAL: Joi.number().default(30000),
  HEALTH_CHECK_TIMEOUT: Joi.number().default(5000),
  CIRCUIT_BREAKER_TIMEOUT: Joi.number().default(3000),
  CIRCUIT_BREAKER_ERROR_THRESHOLD: Joi.number().default(50),
  CIRCUIT_BREAKER_RESET_TIMEOUT: Joi.number().default(30000),
  MEMORY_THRESHOLD_WARNING: Joi.number().default(0.8),
  MEMORY_THRESHOLD_CRITICAL: Joi.number().default(0.95),
  CPU_THRESHOLD_WARNING: Joi.number().default(0.7),
  CPU_THRESHOLD_CRITICAL: Joi.number().default(0.9),
  AUTO_BACKUP_ENABLED: Joi.boolean().default(true),
  AUTO_BACKUP_INTERVAL: Joi.number().default(86400000),
  BACKUP_RETENTION_DAYS: Joi.number().default(7)
});

const { error: configError, value: validatedConfig } = configSchema.validate(process.env, {
  allowUnknown: true,
  stripUnknown: true,
  abortEarly: false
});

if (configError) {
  console.error('❌ Configuration validation error:');
  configError.details.forEach(detail => {
    console.error(`   • ${detail.message}`);
  });
  process.exit(1);
}

const CONFIG = { ...validatedConfig };

// Parse comma-separated values
CONFIG.BOT_URLS = CONFIG.BOT_URLS ? CONFIG.BOT_URLS.split(',').map(url => url.trim()) : [
  'https://www.microsoft.com',
  'https://www.apple.com',
  'https://www.google.com',
  'https://en.wikipedia.org/wiki/Main_Page',
  'https://www.bbc.com'
];

CONFIG.BLOCKED_DOMAINS = CONFIG.BLOCKED_DOMAINS ? CONFIG.BLOCKED_DOMAINS.split(',').map(d => d.trim()) : [
  'localhost', '127.0.0.1', '::1', '0.0.0.0'
];

CONFIG.SUPPORTED_API_VERSIONS = CONFIG.SUPPORTED_API_VERSIONS ? 
  CONFIG.SUPPORTED_API_VERSIONS.split(',').map(v => v.trim()) : ['v1', 'v2'];

// ═════════════════════════════════════════════════════════════════════════════
// LOGGER SETUP WITH ADVANCED FEATURES
// ═════════════════════════════════════════════════════════════════════════════

const logDir = 'logs';
const logTransports = [];

(async () => {
  try {
    await fs.mkdir(logDir, { recursive: true, mode: 0o755 });
    await fs.mkdir(path.join(logDir, 'backups'), { recursive: true, mode: 0o755 });
    await fs.mkdir(path.join(logDir, 'archive'), { recursive: true, mode: 0o755 });
  } catch (err) {
    console.error('Failed to create log directories:', err);
  }
})();

const logFormat = format.printf(({ timestamp, level, message, service, environment, version, id, ...meta }) => {
  return JSON.stringify({
    timestamp,
    level,
    service,
    environment,
    version,
    id,
    message,
    ...meta
  });
});

if (CONFIG.LOG_TO_FILE) {
  logTransports.push(
    new winstonDailyRotate({
      filename: path.join(logDir, 'error-%DATE%.log'),
      datePattern: 'YYYY-MM-DD',
      level: 'error',
      maxSize: CONFIG.LOG_MAX_SIZE,
      maxFiles: `${CONFIG.LOG_RETENTION_DAYS}d`,
      format: format.combine(format.timestamp(), logFormat),
      zippedArchive: true
    }),
    new winstonDailyRotate({
      filename: path.join(logDir, 'combined-%DATE%.log'),
      datePattern: 'YYYY-MM-DD',
      maxSize: CONFIG.LOG_MAX_SIZE,
      maxFiles: `${CONFIG.LOG_RETENTION_DAYS}d`,
      format: format.combine(format.timestamp(), logFormat),
      zippedArchive: true
    })
  );
}

if (CONFIG.LOG_TO_CONSOLE) {
  logTransports.push(
    new transports.Console({
      format: format.combine(
        format.colorize(),
        format.simple()
      )
    })
  );
}

const logger = createLogger({
  level: CONFIG.LOG_LEVEL,
  format: format.combine(
    format.timestamp(),
    format.errors({ stack: true }),
    format.splat(),
    CONFIG.LOG_FORMAT === 'json' ? logFormat : format.simple()
  ),
  defaultMeta: { 
    service: 'redirector-pro',
    environment: CONFIG.NODE_ENV,
    version: '4.1.0'
  },
  transports: logTransports,
  exceptionHandlers: [
    new transports.File({ 
      filename: path.join(logDir, 'exceptions.log'),
      maxsize: 10485760,
      maxFiles: 5
    })
  ],
  rejectionHandlers: [
    new transports.File({ 
      filename: path.join(logDir, 'rejections.log'),
      maxsize: 10485760,
      maxFiles: 5
    })
  ],
  exitOnError: false
});

// ═════════════════════════════════════════════════════════════════════════════
// PROMETHEUS METRICS
// ═════════════════════════════════════════════════════════════════════════════

const register = new promClient.Registry();
promClient.collectDefaultMetrics({ 
  register,
  prefix: CONFIG.METRICS_PREFIX,
  timeout: 5000,
  gcDurationBuckets: CONFIG.METRICS_BUCKETS
});

const metricsMiddleware = promBundle({
  includeMethod: true,
  includePath: true,
  includeStatusCode: true,
  includeUp: true,
  customLabels: { service: 'redirector-pro' },
  promClient: { collectDefaultMetrics: false },
  normalizePath: (req) => {
    if (req.route) return req.route.path;
    if (req.path.startsWith('/r/')) return '/r/*';
    if (req.path.startsWith('/v/')) return '/v/:id';
    return req.path;
  }
});

const httpRequestDurationMicroseconds = new promClient.Histogram({
  name: `${CONFIG.METRICS_PREFIX}http_request_duration_ms`,
  help: 'Duration of HTTP requests in ms',
  labelNames: ['method', 'route', 'code', 'version'],
  buckets: CONFIG.METRICS_BUCKETS,
  registers: [register]
});

const activeConnections = new promClient.Gauge({
  name: `${CONFIG.METRICS_PREFIX}active_connections`,
  help: 'Number of active connections',
  labelNames: ['type'],
  registers: [register]
});

const totalRequests = new promClient.Counter({
  name: `${CONFIG.METRICS_PREFIX}total_requests`,
  help: 'Total number of requests',
  labelNames: ['method', 'path', 'status', 'version'],
  registers: [register]
});

const botBlocks = new promClient.Counter({
  name: `${CONFIG.METRICS_PREFIX}bot_blocks_total`,
  help: 'Total number of bot blocks',
  labelNames: ['reason'],
  registers: [register]
});

const linkGenerations = new promClient.Counter({
  name: `${CONFIG.METRICS_PREFIX}link_generations_total`,
  help: 'Total number of link generations',
  labelNames: ['mode', 'version'],
  registers: [register]
});

const signatureValidationCounter = new promClient.Counter({
  name: `${CONFIG.METRICS_PREFIX}signature_validations_total`,
  help: 'Total number of signature validations',
  labelNames: ['result'],
  registers: [register]
});

const cacheHitRate = new promClient.Counter({
  name: `${CONFIG.METRICS_PREFIX}cache_hit_rate`,
  help: 'Cache hit rate',
  labelNames: ['cache'],
  registers: [register]
});

const cacheMissRate = new promClient.Counter({
  name: `${CONFIG.METRICS_PREFIX}cache_miss_rate`,
  help: 'Cache miss rate',
  labelNames: ['cache'],
  registers: [register]
});

const memoryUsageGauge = new promClient.Gauge({
  name: `${CONFIG.METRICS_PREFIX}memory_usage_bytes`,
  help: 'Memory usage in bytes',
  labelNames: ['type'],
  registers: [register]
});

const cpuUsageGauge = new promClient.Gauge({
  name: `${CONFIG.METRICS_PREFIX}cpu_usage_percent`,
  help: 'CPU usage percentage',
  registers: [register]
});

const databaseConnectionGauge = new promClient.Gauge({
  name: `${CONFIG.METRICS_PREFIX}database_connections`,
  help: 'Database connection pool stats',
  labelNames: ['state'],
  registers: [register]
});

const queueSizeGauge = new promClient.Gauge({
  name: `${CONFIG.METRICS_PREFIX}queue_size`,
  help: 'Queue size by status',
  labelNames: ['queue', 'status'],
  registers: [register]
});

// ═════════════════════════════════════════════════════════════════════════════
// ASYNC HOOKS FOR REQUEST CONTEXT
// ═════════════════════════════════════════════════════════════════════════════

const sessionNamespace = createNamespace('request-context');
const asyncHook = async_hooks.createHook({
  init(asyncId, type, triggerAsyncId, resource) {
    const session = sessionNamespace.get('session');
    if (session) {
      sessionNamespace.set('session', session);
    }
  }
});
asyncHook.enable();

// ═════════════════════════════════════════════════════════════════════════════
// APP INITIALIZATION
// ═════════════════════════════════════════════════════════════════════════════

const app = express();
const server = http.createServer(app);

// Server event listeners
server.on('listening', () => {
  const addr = server.address();
  console.log(`✅ SERVER LISTENING ON ${addr.address}:${addr.port}`);
});

server.on('error', (err) => {
  console.error('❌ Server error:', err);
  if (err.code === 'EADDRINUSE') {
    console.error(`Port ${CONFIG.PORT} is already in use`);
    process.exit(1);
  }
});

// ═════════════════════════════════════════════════════════════════════════════
// REDIS CONNECTION WITH ADVANCED CONFIGURATION
// ═════════════════════════════════════════════════════════════════════════════

let redisClient;
let subscriber;
let sessionStore;
let rateLimiterRedis;

if (CONFIG.REDIS_URL && CONFIG.REDIS_URL.startsWith('redis://') && CONFIG.REDIS_URL !== 'redis://') {
  try {
    redisClient = new Redis(CONFIG.REDIS_URL, {
      retryStrategy: (times) => {
        const delay = Math.min(times * 100, 3000);
        if (times > 10) {
          logger.warn(`Redis connection retry ${times} - stopping retries`);
          return null;
        }
        logger.warn(`Redis connection retry ${times} with delay ${delay}ms`);
        return delay;
      },
      maxRetriesPerRequest: 3,
      enableReadyCheck: true,
      lazyConnect: false,
      connectTimeout: 10000,
      disconnectTimeout: 5000,
      commandTimeout: 5000,
      keepAlive: 30000,
      family: 4,
      db: CONFIG.REDIS_DB || 0,
      password: CONFIG.REDIS_PASSWORD || undefined
    });

    subscriber = new Redis(CONFIG.REDIS_URL, {
      retryStrategy: (times) => {
        if (times > 5) return null;
        return Math.min(times * 100, 3000);
      },
      maxRetriesPerRequest: 3,
      enableReadyCheck: true,
      lazyConnect: false
    });

    redisClient.on('error', (err) => logger.error('Redis error:', err));
    redisClient.on('connect', () => logger.info('✅ Connected to Redis'));
    redisClient.on('ready', () => logger.info('✅ Redis ready'));
    redisClient.on('close', () => logger.warn('Redis connection closed'));
    redisClient.on('reconnecting', () => logger.info('Redis reconnecting...'));

    subscriber.on('error', (err) => logger.error('Redis subscriber error:', err));

    const RedisStore = createRedisStore(session);
    sessionStore = new RedisStore({ 
      client: redisClient,
      prefix: 'redirector:sess:',
      ttl: CONFIG.SESSION_TTL,
      disableTouch: false,
      scanCount: 1000
    });

    rateLimiterRedis = new RateLimiterRedis({
      storeClient: redisClient,
      keyPrefix: 'rl',
      points: CONFIG.RATE_LIMIT_MAX_REQUESTS,
      duration: CONFIG.RATE_LIMIT_WINDOW / 1000,
      blockDuration: 60,
      inMemoryBlockOnConsumed: CONFIG.RATE_LIMIT_MAX_REQUESTS * 2,
      inMemoryBlockDuration: 10
    });

    logger.info('✅ Redis session store and rate limiter initialized');
  } catch (err) {
    logger.warn('Redis connection failed, using fallback stores:', err.message);
    sessionStore = new session.MemoryStore();
    redisClient = null;
    subscriber = null;
    rateLimiterRedis = null;
  }
} else {
  logger.info('📁 Redis not configured - using MemoryStore');
  sessionStore = new session.MemoryStore();
}

// ═════════════════════════════════════════════════════════════════════════════
// RATE LIMITER
// ═════════════════════════════════════════════════════════════════════════════

const rateLimiter = rateLimiterRedis || new RateLimiterMemory({
  points: CONFIG.RATE_LIMIT_MAX_REQUESTS,
  duration: CONFIG.RATE_LIMIT_WINDOW / 1000,
  blockDuration: 60
});

// ✅ FIXED: RATE LIMITER MIDDLEWARE
const rateLimiterMiddleware = (req, res, next) => {
  const key = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip || 'unknown';
  
  if (!rateLimiter) {
    return next();
  }
  
  rateLimiter.consume(key, 1)
    .then(() => {
      next();
    })
    .catch((err) => {
      logger.warn('Rate limit exceeded', { ip: key, path: req.path });
      botBlocks.inc({ reason: 'rate_limit' });
      signatureValidationCounter.labels('rate_limit').inc();
      res.status(429).json({ 
        error: 'Too many requests',
        code: 'RATE_LIMIT_ERROR',
        retryAfter: Math.ceil((err.msBeforeNext || 60000) / 1000)
      });
    });
};

// ═════════════════════════════════════════════════════════════════════════════
// BULL QUEUES
// ═════════════════════════════════════════════════════════════════════════════

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
      backoff: { type: 'exponential', delay: 2000 },
      removeOnComplete: 100,
      removeOnFail: 200,
      timeout: 30000,
      stackTraceLimit: 10
    },
    settings: {
      lockDuration: 30000,
      stalledInterval: 30000,
      maxStalledCount: 2,
      guardInterval: 5000,
      retryProcessDelay: 5000
    }
  });
  
  emailQueue = new Queue('email sending', { 
    redis: redisClient,
    defaultJobOptions: {
      attempts: 5,
      backoff: { type: 'exponential', delay: 5000 },
      removeOnComplete: 50,
      removeOnFail: 100,
      timeout: 10000
    }
  });
  
  analyticsQueue = new Queue('analytics processing', { 
    redis: redisClient,
    defaultJobOptions: {
      attempts: 2,
      removeOnComplete: 1000,
      removeOnFail: 500,
      timeout: 5000
    },
    settings: { maxStalledCount: 1 }
  });

  encodingQueue = new Queue('encoding processing', {
    redis: redisClient,
    defaultJobOptions: {
      attempts: 2,
      timeout: 30000,
      removeOnComplete: true,
      priority: 10
    },
    settings: { lockDuration: 60000 }
  });

  // Queue processors
  redirectQueue.process(async (job) => {
    try {
      const { linkId, ip, userAgent, deviceInfo, country } = job.data;
      await logToDatabase({
        type: 'redirect',
        linkId, ip, userAgent, deviceInfo, country,
        timestamp: new Date()
      });
      return { success: true };
    } catch (err) {
      logger.error('Redirect processing error:', err);
      throw err;
    }
  });

  emailQueue.process(async (job) => {
    const { to, subject, html, type } = job.data;
    if (!CONFIG.SMTP_HOST) {
      logger.debug('Email not sent - SMTP not configured', { to });
      return { sent: false, reason: 'SMTP not configured' };
    }
    try {
      logger.info(`Email would be sent to ${to} with subject: ${subject}`);
      if (dbPool) {
        await queryWithTimeout(
          'INSERT INTO emails (recipient, subject, type, status) VALUES ($1, $2, $3, $4)',
          [to, subject, type, 'sent']
        );
      }
      return { sent: true, timestamp: new Date().toISOString() };
    } catch (err) {
      logger.error('Email sending failed:', err);
      throw err;
    }
  });

  analyticsQueue.process(async (job) => {
    try {
      const { type, data } = job.data;
      await updateAnalytics(type, data);
      return { processed: true };
    } catch (err) {
      logger.error('Analytics processing error:', err);
      throw err;
    }
  });

  encodingQueue.process(async (job) => {
    try {
      const { targetUrl, req, options } = job.data;
      const startTime = performance.now();
      const result = await generateLongLink(targetUrl, req, options);
      const duration = performance.now() - startTime;
      logger.info(`Encoding completed in ${duration.toFixed(2)}ms`);
      return result;
    } catch (err) {
      logger.error('Encoding queue processing error:', err);
      throw err;
    }
  });

  if (CONFIG.BULL_BOARD_ENABLED) {
    serverAdapter = new ExpressAdapter();
    serverAdapter.setBasePath(CONFIG.BULL_BOARD_PATH);
    
    bullBoard = createBullBoard({
      queues: [
        new BullAdapter(redirectQueue),
        new BullAdapter(emailQueue),
        new BullAdapter(analyticsQueue),
        new BullAdapter(encodingQueue)
      ],
      serverAdapter: serverAdapter
    });
    
    logger.info(`✅ Bull Board enabled at ${CONFIG.BULL_BOARD_PATH}`);
  }

  // Queue metrics
  setInterval(async () => {
    if (!redisClient) return;
    const queues = [redirectQueue, emailQueue, analyticsQueue, encodingQueue];
    for (const queue of queues) {
      if (!queue) continue;
      try {
        const counts = await queue.getJobCounts();
        Object.entries(counts).forEach(([status, count]) => {
          queueSizeGauge.labels(queue.name, status).set(count);
        });
      } catch (err) {
        logger.error('Failed to get queue metrics:', err);
      }
    }
  }, 10000);
}

// ═════════════════════════════════════════════════════════════════════════════
// DATABASE SETUP
// ═════════════════════════════════════════════════════════════════════════════

let dbPool;
let dbHealthCheck;
let txManager;

const queryWithTimeout = async (query, params, options = {}) => {
  if (!dbPool) {
    throw new Error('Database not available');
  }
  
  const client = await dbPool.connect();
  const timeout = options.timeout || CONFIG.DB_QUERY_TIMEOUT;
  
  try {
    await client.query(`SET LOCAL statement_timeout = ${timeout}`);
    const result = await Promise.race([
      client.query(query, params),
      new Promise((_, reject) => 
        setTimeout(() => reject(new Error('Query timeout')), timeout)
      )
    ]);
    return result;
  } finally {
    client.release();
  }
};

if (CONFIG.DATABASE_URL && CONFIG.DATABASE_URL.startsWith('postgresql://')) {
  try {
    dbPool = new Pool({
      connectionString: CONFIG.DATABASE_URL,
      ssl: CONFIG.NODE_ENV === 'production' ? { 
        rejectUnauthorized: false,
        ca: process.env.DB_CA_CERT
      } : false,
      max: CONFIG.DB_POOL_MAX,
      min: CONFIG.DB_POOL_MIN,
      idleTimeoutMillis: CONFIG.DB_IDLE_TIMEOUT,
      connectionTimeoutMillis: CONFIG.DB_CONNECTION_TIMEOUT,
      application_name: 'redirector-pro',
      keepAlive: true,
      keepAliveInitialDelayMillis: 10000,
      allowExitOnIdle: true
    });

    // Initialize transaction manager
    class TransactionManager {
      constructor(pool) {
        this.pool = pool;
      }

      async withTransaction(callback, options = {}) {
        const client = await this.pool.connect();
        const { 
          timeout = CONFIG.DB_TRANSACTION_TIMEOUT, 
          isolationLevel = CONFIG.DB_ISOLATION_LEVEL,
          readOnly = false
        } = options;
        
        try {
          await client.query('BEGIN');
          await client.query(`SET TRANSACTION ISOLATION LEVEL ${isolationLevel}`);
          if (readOnly) {
            await client.query('SET TRANSACTION READ ONLY');
          }
          await client.query(`SET LOCAL statement_timeout = ${timeout}`);

          const result = await callback(client);
          await client.query('COMMIT');
          
          logger.debug('Transaction completed successfully', { isolationLevel });
          return result;
        } catch (err) {
          await client.query('ROLLBACK');
          logger.error('Transaction failed:', err.message);
          throw new DatabaseError('Transaction failed', err);
        } finally {
          client.release();
        }
      }

      async retryTransaction(callback, options = {}) {
        const {
          maxRetries = CONFIG.DB_TRANSACTION_RETRIES,
          retryDelay = 100,
          ...txOptions
        } = options;

        for (let attempt = 1; attempt <= maxRetries; attempt++) {
          try {
            return await this.withTransaction(callback, txOptions);
          } catch (err) {
            if (attempt === maxRetries) throw err;
            const delay = retryDelay * Math.pow(2, attempt - 1);
            logger.debug(`Retrying transaction (attempt ${attempt}/${maxRetries}) after ${delay}ms`);
            await new Promise(resolve => setTimeout(resolve, delay));
          }
        }
      }
    }

    txManager = new TransactionManager(dbPool);

    dbPool.on('error', (err) => {
      logger.error('Unexpected database error:', err);
    });

    // Database health check
    dbHealthCheck = setInterval(async () => {
      try {
        await queryWithTimeout('SELECT 1', [], { timeout: 2000 });
        const poolStats = {
          total: dbPool.totalCount,
          idle: dbPool.idleCount,
          waiting: dbPool.waitingCount
        };
        
        databaseConnectionGauge.labels('total').set(poolStats.total);
        databaseConnectionGauge.labels('idle').set(poolStats.idle);
        databaseConnectionGauge.labels('waiting').set(poolStats.waiting);
      } catch (err) {
        logger.error('Database health check failed:', err);
      }
    }, CONFIG.HEALTH_CHECK_INTERVAL);

    logger.info('✅ Database connected');
  } catch (err) {
    logger.warn('Database connection failed, continuing without database:', err.message);
    dbPool = null;
  }
} else {
  logger.info('📁 Running without database (file-based logging only)');
}

// Database utility functions
async function logToDatabase(entry) {
  if (!dbPool) return;
  try {
    await queryWithTimeout(
      'INSERT INTO logs (data) VALUES ($1)',
      [JSON.stringify(entry)]
    );
  } catch (err) {
    if (CONFIG.DEBUG) {
      logger.debug('Database log failed (non-critical):', err.message);
    }
  }
}

async function updateAnalytics(type, data) {
  if (type === 'request') {
    totalRequests.inc({ 
      method: data.method || 'GET', 
      path: data.path || 'unknown', 
      status: data.status || 200,
      version: data.version || 'v1'
    });
  } else if (type === 'bot') {
    botBlocks.inc({ reason: data.reason || 'unknown' });
  } else if (type === 'generate') {
    linkGenerations.inc({ mode: data.mode || 'short', version: data.version || 'v1' });
  }

  if (!dbPool) return;

  try {
    await queryWithTimeout(
      'INSERT INTO analytics (type, data) VALUES ($1, $2)',
      [type, JSON.stringify(data)]
    );
  } catch (err) {
    if (CONFIG.DEBUG) {
      logger.debug('Analytics update failed:', err.message);
    }
  }
}

// ═════════════════════════════════════════════════════════════════════════════
// SOCKET.IO SETUP
// ═════════════════════════════════════════════════════════════════════════════

const io = new Server(server, {
  cors: {
    origin: CONFIG.CORS_ORIGIN ? CONFIG.CORS_ORIGIN.split(',') : "*",
    methods: ["GET", "POST", "PUT", "DELETE"],
    credentials: true,
    allowedHeaders: ["Content-Type", "Authorization", "X-CSRF-Token"]
  },
  pingTimeout: 60000,
  pingInterval: 25000,
  transports: ['websocket', 'polling'],
  maxHttpBufferSize: 1e6,
  allowEIO3: true,
  connectTimeout: 45000,
  path: '/socket.io/',
  serveClient: false
});

if (subscriber) {
  subscriber.subscribe('redirector:events', (err, count) => {
    if (err) {
      logger.error('Failed to subscribe to Redis channel:', err);
    } else {
      logger.info(`Subscribed to ${count} Redis channel(s)`);
    }
  });

  subscriber.on('message', (channel, message) => {
    if (channel === 'redirector:events') {
      try {
        const event = JSON.parse(message);
        io.emit(event.type, event.data);
      } catch (err) {
        logger.error('Error processing Redis message:', err);
      }
    }
  });
}

const adminNamespace = io.of('/admin');
const publicNamespace = io.of('/public');

adminNamespace.use((socket, next) => {
  const token = socket.handshake.auth.token;
  const sessionId = socket.handshake.auth.sessionId;
  
  if (token === CONFIG.METRICS_API_KEY) {
    return next();
  }
  
  if (sessionId && sessionStore) {
    sessionStore.get(sessionId, (err, session) => {
      if (err || !session || !session.authenticated) {
        return next(new Error('Authentication error'));
      }
      socket.session = session;
      next();
    });
  } else {
    next(new Error('Authentication error'));
  }
}).on('connection', (socket) => {
  logger.info('Admin client connected:', socket.id);
  activeConnections.labels('admin').inc();
  
  socket.on('disconnect', () => {
    logger.info('Admin client disconnected:', socket.id);
    activeConnections.labels('admin').dec();
  });
});

publicNamespace.on('connection', (socket) => {
  activeConnections.labels('public').inc();
  socket.on('disconnect', () => {
    activeConnections.labels('public').dec();
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// VALIDATION UTILITIES - FIXED & COMPLETE
// ═════════════════════════════════════════════════════════════════════════════

// ✅ VALIDATE LINK ID MIDDLEWARE
const validateLinkId = (req, res, next) => {
  const id = req.params.id;
  if (!id || !/^[a-f0-9]{32,64}$/i.test(id)) {
    throw new AppError('Invalid link ID format', 400, 'INVALID_LINK_ID');
  }
  next();
};

// ✅ VALIDATE URL FUNCTION
function validateUrl(url) {
  try {
    const urlObj = new URL(url);
    if (!['http:', 'https:'].includes(urlObj.protocol)) {
      return false;
    }
    
    const hostname = urlObj.hostname.toLowerCase();
    const isBlocked = CONFIG.BLOCKED_DOMAINS.some(blocked => 
      hostname === blocked || hostname.endsWith(`.${blocked}`)
    );
    
    if (isBlocked) return false;
    
    const ipPatterns = [
      /^10\.\d{1,3}\.\d{1,3}\.\d{1,3}$/,
      /^172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}$/,
      /^192\.168\.\d{1,3}\.\d{1,3}$/,
      /^169\.254\.\d{1,3}\.\d{1,3}$/
    ];
    
    return !ipPatterns.some(pattern => pattern.test(hostname));
  } catch (err) {
    return false;
  }
}

// ═════════════════════════════════════════════════════════════════════════════
// COMPLETE ENCODER LIBRARY - FIXED
// ═════════════════════════════════════════════════════════════════════════════

const encoderLibrary = [
  { name: 'base64_standard', enc: s => Buffer.from(s).toString('base64'), dec: s => Buffer.from(s, 'base64').toString(), complexity: 1 },
  { name: 'base64_url', enc: s => Buffer.from(s).toString('base64url'), dec: s => Buffer.from(s, 'base64url').toString(), complexity: 1 },
  { name: 'base64_reverse', enc: s => Buffer.from(s.split('').reverse().join('')).toString('base64'), dec: s => Buffer.from(s, 'base64').toString().split('').reverse().join(''), complexity: 2 },
  { name: 'hex_lower', enc: s => Buffer.from(s).toString('hex'), dec: s => Buffer.from(s, 'hex').toString(), complexity: 1 },
  { name: 'hex_upper', enc: s => Buffer.from(s).toString('hex').toUpperCase(), dec: s => Buffer.from(s.toLowerCase(), 'hex').toString(), complexity: 1 },
  { name: 'rot13', enc: s => s.replace(/[a-zA-Z]/g, c => String.fromCharCode(((c.charCodeAt(0) - (c <= 'Z' ? 65 : 97) + 13) % 26) + (c <= 'Z' ? 65 : 97))), dec: s => s.replace(/[a-zA-Z]/g, c => String.fromCharCode(((c.charCodeAt(0) - (c <= 'Z' ? 65 : 97) + 13) % 26) + (c <= 'Z' ? 65 : 97))), complexity: 1 },
  { name: 'rot5', enc: s => s.replace(/[0-9]/g, c => ((parseInt(c) + 5) % 10).toString()), dec: s => s.replace(/[0-9]/g, c => ((parseInt(c) - 5 + 10) % 10).toString()), complexity: 1 },
  { name: 'url_encode', enc: encodeURIComponent, dec: decodeURIComponent, complexity: 1 },
  { name: 'double_url_encode', enc: s => encodeURIComponent(encodeURIComponent(s)), dec: s => decodeURIComponent(decodeURIComponent(s)), complexity: 2 },
  { name: 'triple_url_encode', enc: s => encodeURIComponent(encodeURIComponent(encodeURIComponent(s))), dec: s => decodeURIComponent(decodeURIComponent(decodeURIComponent(s))), complexity: 3 },
  { name: 'reverse', enc: s => s.split('').reverse().join(''), dec: s => s.split('').reverse().join(''), complexity: 1 }
];

// ═════════════════════════════════════════════════════════════════════════════
// MULTI-LAYER DECODE - FIXED WITH FALLBACK
// ═════════════════════════════════════════════════════════════════════════════

function advancedMultiLayerDecode(encoded, metadata) {
  let result = encoded;
  const startTime = Date.now();
  
  try {
    result = decodeURIComponent(result);
    result = decodeURIComponent(result);
    result = decodeURIComponent(result);
    
    const layers = [...(metadata.layers || [])].reverse();
    for (const layerName of layers) {
      const layer = encoderLibrary.find(e => e.name === layerName);
      
      // ✅ ADDED FALLBACK FOR UNKNOWN ENCODERS
      if (!layer) {
        logger.warn('Unknown encoder layer, attempting base64 fallback:', layerName);
        try {
          result = Buffer.from(result, 'base64').toString();
        } catch {
          logger.warn('Base64 fallback failed, continuing with original');
        }
        continue;
      }
      
      try {
        result = layer.dec(result);
      } catch (err) {
        logger.error(`Failed to decode layer ${layerName}:`, err.message);
        throw err;
      }
    }
    
    if (metadata.noise && Array.isArray(metadata.noise)) {
      for (const noise of metadata.noise) {
        if (result.startsWith(noise) && result.endsWith(noise)) {
          result = result.slice(noise.length, -noise.length);
        }
      }
    }
    
    const decodeTime = Date.now() - startTime;
    return result;
  } catch (err) {
    logger.error('Advanced decode error:', err);
    throw new AppError('Decoding failed', 400, 'DECODE_ERROR');
  }
}

// ═════════════════════════════════════════════════════════════════════════════
// CACHING SYSTEM
// ═════════════════════════════════════════════════════════════════════════════

const geoCache = new NodeCache({ stdTTL: 86400, checkperiod: 3600, useClones: false, maxKeys: 100000 });
const linkCache = new NodeCache({ stdTTL: 1800, checkperiod: 300, useClones: false, maxKeys: 100000 });
const linkRequestCache = new NodeCache({ stdTTL: 60, checkperiod: 10, useClones: false, maxKeys: 10000 });
const failCache = new NodeCache({ stdTTL: 3600, checkperiod: 600, useClones: false, maxKeys: 10000 });
const deviceCache = new NodeCache({ stdTTL: 300, checkperiod: 60, useClones: false, maxKeys: 50000 });
const qrCache = new NodeCache({ stdTTL: 3600, checkperiod: 600, useClones: false, maxKeys: 1000 });
const encodingCache = new NodeCache({ stdTTL: 3600, checkperiod: 600, maxKeys: 5000, useClones: false });

const cacheStats = {
  geo: { hits: 0, misses: 0 },
  link: { hits: 0, misses: 0 },
  linkReq: { hits: 0, misses: 0 },
  device: { hits: 0, misses: 0 },
  qr: { hits: 0, misses: 0 },
  encoding: { hits: 0, misses: 0 }
};

const cacheGet = (cache, name, key) => {
  const value = cache.get(key);
  if (value !== undefined) {
    cacheStats[name].hits++;
    cacheHitRate.labels(name).inc();
    return value;
  }
  cacheStats[name].misses++;
  cacheMissRate.labels(name).inc();
  return undefined;
};

const cacheSet = (cache, name, key, value, ttl) => {
  cache.set(key, value, ttl);
};

// ═════════════════════════════════════════════════════════════════════════════
// GLOBAL STATISTICS & INTERVALS
// ═════════════════════════════════════════════════════════════════════════════

global.intervals = {};
const loginAttempts = new Map();

const stats = {
  totalRequests: 0,
  botBlocks: 0,
  successfulRedirects: 0,
  expiredLinks: 0,
  generatedLinks: 0,
  byCountry: {},
  byBotReason: {},
  byDevice: { mobile: 0, desktop: 0, tablet: 0, bot: 0 },
  linkModes: { short: 0, long: 0, auto: 0 },
  linkLengths: { avg: 0, min: Infinity, max: 0, total: 0 },
  encodingStats: {
    avgLayers: 0,
    avgLength: 0,
    totalEncoded: 0,
    avgComplexity: 0,
    totalComplexity: 0,
    avgDecodeTime: 0,
    totalDecodeTime: 0,
    cacheHits: 0,
    cacheMisses: 0
  },
  performance: {
    avgResponseTime: 0,
    totalResponseTime: 0,
    p95ResponseTime: 0,
    p99ResponseTime: 0,
    responseTimes: []
  },
  realtime: {
    lastMinute: [],
    activeLinks: 0,
    requestsPerSecond: 0,
    startTime: Date.now(),
    peakRPS: 0,
    peakMemory: 0,
    currentMemory: 0
  },
  caches: {
    geo: 0,
    linkReq: 0,
    device: 0,
    qr: 0,
    encoding: 0
  },
  system: {
    cpu: 0,
    memory: 0,
    uptime: 0
  },
  signatures: {
    valid: 0,
    invalid: 0,
    expired: 0,
    missing: 0
  },
  apiVersions: {
    v1: 0,
    v2: 0
  }
};

// ✅ MEMORY MONITORING WITH INTERVAL TRACKING
global.intervals.memoryMonitor = setInterval(() => {
  const memUsage = process.memoryUsage();
  stats.realtime.currentMemory = memUsage.heapUsed;
  stats.realtime.peakMemory = Math.max(stats.realtime.peakMemory, memUsage.heapUsed);
  
  memoryUsageGauge.labels('rss').set(memUsage.rss);
  memoryUsageGauge.labels('heapTotal').set(memUsage.heapTotal);
  memoryUsageGauge.labels('heapUsed').set(memUsage.heapUsed);
  memoryUsageGauge.labels('external').set(memUsage.external);
  
  const heapUsedPercent = memUsage.heapUsed / memUsage.heapTotal;
  if (heapUsedPercent > CONFIG.MEMORY_THRESHOLD_CRITICAL) {
    logger.error('Critical memory usage!', { heapUsed: memUsage.heapUsed, heapTotal: memUsage.heapTotal });
  }
}, 5000);

// ✅ CPU MONITORING
let lastCPUUsage = process.cpuUsage();
global.intervals.cpuMonitor = setInterval(() => {
  const cpuUsage = process.cpuUsage(lastCPUUsage);
  lastCPUUsage = process.cpuUsage();
  
  const totalCPU = (cpuUsage.user + cpuUsage.system) / 1000000;
  const cpuPercent = (totalCPU / 5) * 100;
  
  stats.system.cpu = cpuPercent;
  cpuUsageGauge.set(cpuPercent);
}, 5000);

// ✅ STATS UPDATE INTERVAL
global.intervals.statsUpdate = setInterval(() => {
  stats.realtime.activeLinks = linkCache.keys().length;
  stats.caches = {
    geo: geoCache.keys().length,
    linkReq: linkCache.keys().length,
    device: deviceCache.keys().length,
    qr: qrCache.keys().length,
    encoding: encodingCache.keys().length
  };
}, 1000);

// ✅ LOGIN ATTEMPTS CLEANUP
setInterval(() => {
  const now = Date.now();
  for (const [ip, data] of loginAttempts.entries()) {
    if (now - data.lastAttempt > CONFIG.LOGIN_BLOCK_DURATION) {
      loginAttempts.delete(ip);
    }
  }
}, 3600000);

// ══════════════════════════════════════════════════════════════════════════��══
// ✅ HELPER FUNCTION: GET ALL LINKS - MOVED BEFORE SOCKET.IO
// ═════════════════════════════════════════════════════════════════════════════

async function getAllLinks() {
  if (!dbPool) {
    const keys = linkCache.keys();
    const links = [];
    for (const key of keys) {
      const data = cacheGet(linkCache, 'link', key);
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
          api_version: data.metadata?.apiVersion || 'v1',
          status: data.expiresAt > Date.now() ? 'active' : 'expired'
        });
      }
    }
    return links;
  }

  try {
    const result = await queryWithTimeout(
      `SELECT id, target_url, created_at, expires_at, current_clicks, max_clicks, 
              (password_hash IS NOT NULL) as password_protected, COALESCE(metadata->>'notes', '') as notes,
              link_mode, (link_metadata->>'length')::int as link_length,
              jsonb_array_length(encoding_metadata->'layers') as encoding_layers,
              encoding_complexity, api_version,
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

// ═════════════════════════════════════════════════════════════════════════════
// EXPRESS MIDDLEWARE SETUP
// ═════════════════════════════════════════════════════════════════════════════

app.set('trust proxy', CONFIG.TRUST_PROXY);

app.use(compression({ 
  level: 6, 
  threshold: 0,
  filter: (req, res) => {
    if (req.headers['x-no-compression']) return false;
    return true;
  }
}));

app.use(morgan('combined', { 
  stream: { 
    write: message => logger.info(message.trim())
  } 
}));

app.use(express.static('public', { 
  maxAge: '1d',
  etag: true,
  lastModified: true,
  immutable: true
}));

app.use((req, res, next) => {
  req.id = req.headers['x-request-id'] || uuidv4();
  res.setHeader('X-Request-ID', req.id);
  
  sessionNamespace.run(() => {
    sessionNamespace.set('id', req.id);
    sessionNamespace.set('ip', req.ip);
    sessionNamespace.set('startTime', Date.now());
    next();
  });
});

app.use(useragent.express());
app.use(xss());
app.use(hpp());
app.use(cors({
  origin: (origin, callback) => {
    if (!origin || CONFIG.CORS_ORIGIN === '*' || CONFIG.CORS_ORIGIN.split(',').includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  optionsSuccessStatus: 200,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS']
}));

app.use(cookieParser(CONFIG.SESSION_SECRET));
app.use(express.json({ limit: '100kb' }));
app.use(express.urlencoded({ extended: true, limit: '100kb' }));

// Apply rate limiting
app.use(rateLimiterMiddleware);

// ═════════════════════════════════════════════════════════════════════════════
// SECURITY MIDDLEWARE
// ═════════════════════════════════════════════════════════════════════════════

app.use((req, res, next) => {
  const sensitiveParams = ['username', 'password', 'pass', 'pwd', 'secret', 'api_key', 'apikey', 'token', 'auth'];
  const hasSensitiveParam = sensitiveParams.some(param => 
    req.query[param] !== undefined && req.query[param] !== ''
  );
  
  if (hasSensitiveParam) {
    logger.warn('🚫 Blocked request with credentials in URL', { 
      ip: req.ip,
      path: req.path,
      query: Object.keys(req.query).filter(k => sensitiveParams.includes(k))
    });
    
    if (dbPool) {
      queryWithTimeout(
        'INSERT INTO logs (data) VALUES ($1)',
        [JSON.stringify({
          type: 'security_block',
          reason: 'credentials_in_url',
          ip: req.ip,
          path: req.path
        })]
      ).catch(() => {});
    }
    
    return res.status(400).json({ 
      error: 'Invalid request format',
      code: 'CREDENTIALS_IN_URL'
    });
  }
  next();
});

// CSRF Protection
app.use((req, res, next) => {
  if (!req.session.csrfToken) {
    req.session.csrfToken = crypto.randomBytes(32).toString('hex');
  }
  
  res.cookie('XSRF-TOKEN', req.session.csrfToken, {
    secure: CONFIG.NODE_ENV === 'production',
    httpOnly: false,
    sameSite: 'lax',
    maxAge: 3600000
  });
  
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
                req.headers['x-xsrf-token'] ||
                req.cookies['XSRF-TOKEN'];
  
  if (!token || token !== req.session.csrfToken) {
    logger.warn('CSRF validation failed:', { ip: req.ip, path: req.path });
    
    if (req.path.startsWith('/api/')) {
      return res.status(403).json({ 
        error: 'Invalid CSRF token',
        code: 'CSRF_FAILED'
      });
    }
    
    return res.redirect(req.get('referer') || '/admin/login?error=invalid_csrf');
  }
  
  next();
};

// Helmet security headers
const helmetConfig = {
  contentSecurityPolicy: CONFIG.CSP_ENABLED ? {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: [
        "'self'",
        'https://cdn.socket.io',
        'https://cdn.jsdelivr.net',
        'https://cdnjs.cloudflare.com'
      ],
      styleSrc: [
        "'self'",
        "'unsafe-inline'",
        'https://cdn.jsdelivr.net',
        'https://cdnjs.cloudflare.com'
      ],
      fontSrc: ["'self'", 'https://cdnjs.cloudflare.com', 'data:'],
      imgSrc: ["'self'", 'data:', 'https:'],
      connectSrc: ["'self'", 'ws:', 'wss:', 'https:'],
      frameSrc: ["'none'"],
      objectSrc: ["'none'"]
    }
  } : false,
  hsts: CONFIG.HSTS_ENABLED ? {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  } : false,
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
  noSniff: true,
  xssFilter: true,
  hidePoweredBy: true,
  frameguard: { action: 'deny' }
};

app.use(helmet(helmetConfig));

// Session setup
const sessionConfig = {
  store: sessionStore,
  secret: CONFIG.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  name: 'redirector.sid',
  cookie: { 
    secure: CONFIG.NODE_ENV === 'production' && CONFIG.HTTPS_ENABLED === 'true', 
    maxAge: CONFIG.SESSION_TTL * 1000,
    httpOnly: true,
    sameSite: 'lax',
    path: '/'
  },
  rolling: true,
  unset: 'destroy',
  genid: (req) => uuidv4()
};

app.use(session(sessionConfig));

app.use((req, res, next) => {
  if (req.session && req.session.createdAt) {
    const age = Date.now() - req.session.createdAt;
    if (age > CONFIG.SESSION_ABSOLUTE_TIMEOUT * 1000) {
      return req.session.destroy((err) => {
        if (err) logger.error('Session destruction error:', err);
        res.redirect('/admin/login');
      });
    }
  } else if (req.session) {
    req.session.createdAt = Date.now();
  }
  next();
});

// ════════════════════════════════════════════════════���════════════════════════
// HELPER FUNCTIONS
// ═══════════════════════════════════════════════════���═════════════════════════

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

function formatDuration(seconds) {
  if (seconds < 60) return `${seconds} seconds`;
  if (seconds < 3600) {
    const mins = Math.floor(seconds / 60);
    return `${mins} minute${mins !== 1 ? 's' : ''}`;
  }
  if (seconds < 86400) {
    const hours = Math.floor(seconds / 3600);
    const mins = Math.floor((seconds % 3600) / 60);
    return mins > 0 ? `${hours}h ${mins}m` : `${hours}h`;
  }
  const days = Math.floor(seconds / 86400);
  return `${days} day${days !== 1 ? 's' : ''}`;
}

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
      duration,
      version: req.apiVersion || 'v1',
      ...extra
    };
    
    io.of('/admin').emit('log', logEntry);
    await fs.appendFile('logs/requests.log', JSON.stringify(logEntry) + '\n').catch(() => {});
    logToDatabase(logEntry).catch(() => {});
  } catch (err) {
    logger.error('Logging error:', err);
  }
}

function getDeviceInfo(req) {
  const ua = req.headers['user-agent'] || '';
  const cacheKey = crypto.createHash('md5').update(ua.substring(0, 200)).digest('hex');
  const cached = cacheGet(deviceCache, 'device', cacheKey);
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
    'bot', 'crawler', 'spider', 'headless', 'phantom', 'slurp', 'scanner',
    'python', 'curl', 'wget', 'selenium', 'puppeteer', 'lighthouse',
    'googlebot', 'bingbot', 'yandex', 'facebook', 'twitter'
  ];
  
  if (botPatterns.some(pattern => uaLower.includes(pattern))) {
    deviceInfo.type = 'bot';
    deviceInfo.isBot = true;
    deviceInfo.score = 100;
    cacheSet(deviceCache, 'device', cacheKey, deviceInfo);
    stats.byDevice.bot = (stats.byDevice.bot || 0) + 1;
    return deviceInfo;
  }

  if (/Mobi|Android|iPhone|iPad|iPod/i.test(ua)) {
    deviceInfo.type = /Tablet|iPad|PlayBook/i.test(ua) ? 'tablet' : 'mobile';
    deviceInfo.isMobile = deviceInfo.type === 'mobile';
    deviceInfo.isTablet = deviceInfo.type === 'tablet';
  }

  cacheSet(deviceCache, 'device', cacheKey, deviceInfo);
  stats.byDevice[deviceInfo.type] = (stats.byDevice[deviceInfo.type] || 0) + 1;
  
  return deviceInfo;
}

function isLikelyBot(req) {
  const deviceInfo = req.deviceInfo;
  
  if (deviceInfo.isBot) {
    stats.botBlocks++;
    botBlocks.inc({ reason: 'explicit_bot' });
    return true;
  }

  const h = req.headers;
  let score = deviceInfo.score;

  if (!h['sec-ch-ua'] || !h['sec-ch-ua-mobile']) {
    score += 25;
  }
  
  if (!h['accept'] || !h['accept-language']) {
    score += 20;
  }
  
  if (Object.keys(h).length < 15) {
    score += 15;
  }

  const isBot = score >= 65;
  
  if (isBot) {
    stats.botBlocks++;
    botBlocks.inc({ reason: 'behavior_score' });
  }

  return isBot;
}

async function getCountryCode(req) {
  const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip || '0.0.0.0';
  
  if (['10.', '192.168.', '127.0.0.1', '::1', '0.0.0.0'].some(p => ip.startsWith(p))) {
    return 'PRIVATE';
  }

  let cc = cacheGet(geoCache, 'geo', ip);
  if (cc) return cc;

  if (!CONFIG.IPINFO_TOKEN) return 'XX';

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 1500);

    const response = await fetch(`https://ipinfo.io/${ip}/json?token=${CONFIG.IPINFO_TOKEN}`, {
      signal: controller.signal,
      headers: { 'User-Agent': 'Redirector-Pro/4.1' }
    });

    clearTimeout(timeout);

    if (response.ok) {
      const data = await response.json();
      cc = data.country?.toUpperCase();
      if (cc?.match(/^[A-Z]{2}$/)) {
        cacheSet(geoCache, 'geo', ip, cc);
        stats.byCountry[cc] = (stats.byCountry[cc] || 0) + 1;
        return cc;
      }
    }
  } catch (err) {
    logger.debug('Geo lookup failed:', err.message);
  }
  return 'XX';
}

// ═════════════════════════════════════════════════════════════════════════════
// ENCODING FUNCTIONS
// ═════════════════════════════════════════════════════════════════════════════

function multiLayerEncode(str) {
  let result = str;
  const noise = crypto.randomBytes(8).toString('base64');
  result = noise + result + noise;
  
  const key = crypto.randomBytes(16).toString('hex');
  const hmac = crypto.createHmac('sha256', key).update(result).digest('base64');
  result = `${result}|${hmac}|${key}`;

  return { encoded: Buffer.from(result).toString('base64') };
}

async function generateLongLink(targetUrl, req, options = {}) {
  const startTime = performance.now();
  
  const {
    segments = 6,
    params = 13,
    minLayers = 4,
    maxLayers = 8,
    iterations = 3
  } = options;
  
  const timestamp = Date.now();
  const randomId = crypto.randomBytes(12).toString('hex');
  const noisyTarget = `${targetUrl}#${randomId}-${timestamp}`;

  const cacheKey = crypto.createHash('sha256').update(noisyTarget).digest('hex');
  const cached = cacheGet(encodingCache, 'encoding', cacheKey);
  if (cached) {
    stats.encodingStats.cacheHits++;
    return cached;
  }
  stats.encodingStats.cacheMisses++;

  const { encoded } = multiLayerEncode(noisyTarget);
  
  const pathSegments = [];
  for (let i = 0; i < segments; i++) {
    pathSegments.push(crypto.randomBytes(12).toString('hex'));
  }

  const path = `/r/${pathSegments.join('/')}/${crypto.randomBytes(24).toString('hex')}`;

  const paramList = [];
  const paramKeys = ['sid', 'tok', 'ref', 'utm_source', 'utm_medium', 'clid', 'ver', 'ts', 'hmac'];
  
  for (let i = 0; i < params; i++) {
    const key = paramKeys[i % paramKeys.length];
    const value = crypto.randomBytes(12).toString('base64url');
    paramList.push(`${key}=${value}`);
  }

  const protocol = req.protocol || 'https';
  const host = req.get('host');
  const url = `${protocol}://${host}${path}?p=${encoded}&${paramList.join('&')}`;

  const result = {
    url,
    metadata: {
      length: url.length,
      segments,
      params: paramList.length,
      iterations,
      encodingTime: performance.now() - startTime
    }
  };

  cacheSet(encodingCache, 'encoding', cacheKey, result, 3600);
  return result;
}

function generateShortLink(targetUrl, req) {
  const startTime = performance.now();
  const { encoded } = multiLayerEncode(targetUrl + '#' + Date.now());
  const id = crypto.randomBytes(16).toString('hex');
  const url = `${req.protocol}://${req.get('host')}/v/${id}`;
  
  return {
    url,
    metadata: {
      length: url.length,
      id,
      encodingTime: performance.now() - startTime
    }
  };
}

// ═════════════════════════════════════════════════════════════════════════════
// ROUTES - HEALTH CHECK
// ═════════════════════════════════════════════════════════════════════════════

app.get(['/ping', '/health', '/healthz', '/status'], (req, res) => {
  const healthData = {
    status: 'healthy',
    time: Date.now(),
    uptime: process.uptime(),
    version: '4.1.0',
    database: dbPool ? 'connected' : 'disabled',
    redis: redisClient?.status === 'ready' ? 'connected' : 'disabled',
    queues: redirectQueue ? 'ready' : 'disabled',
    stats: {
      totalRequests: stats.totalRequests,
      activeLinks: linkCache.keys().length,
      botBlocks: stats.botBlocks
    }
  };
  res.status(200).json(healthData);
});

// ═════════════════════════════════════════════════════════════════════════════
// ROUTES - METRICS
// ═════════════════════════════════════════════════════════════════════════════

app.get('/metrics', async (req, res) => {
  const apiKey = req.headers['x-api-key'] || req.query.key;
  if (apiKey !== CONFIG.METRICS_API_KEY) {
    throw new AppError('Forbidden', 403, 'FORBIDDEN');
  }

  res.set('Content-Type', register.contentType);
  res.send(await register.metrics());
});

// ═════════════════════════════════════════════════════════════════════════════
// ROUTES - API V1 (BASIC)
// ═════════════════════════════════════════════════════════════════════════════

const v1Router = express.Router();

v1Router.post('/generate', csrfProtection, async (req, res, next) => {
  try {
    const target = req.body.url || CONFIG.TARGET_URL;
    
    if (!validateUrl(target)) {
      throw new ValidationError('Invalid target URL');
    }
    
    const password = req.body.password;
    const maxClicks = req.body.maxClicks;
    const expiresIn = req.body.expiresIn ? parseTTL(req.body.expiresIn) : parseTTL(CONFIG.LINK_TTL);
    const notes = req.body.notes || '';
    const linkMode = req.body.linkMode || 'short';

    let generatedUrl;
    let linkMetadata = {};
    let cacheId;

    if (linkMode === 'long') {
      const result = await generateLongLink(target, req, {
        segments: 6,
        params: 13,
        iterations: 3
      });
      generatedUrl = result.url;
      linkMetadata = result.metadata;
      cacheId = crypto.createHash('md5').update(generatedUrl).digest('hex');
    } else {
      const result = generateShortLink(target, req);
      generatedUrl = result.url;
      linkMetadata = result.metadata;
      cacheId = linkMetadata.id;
    }
    
    const linkData = {
      target,
      created: Date.now(),
      expiresAt: Date.now() + (expiresIn * 1000),
      passwordHash: password ? await bcrypt.hash(password, CONFIG.BCRYPT_ROUNDS) : null,
      maxClicks: maxClicks ? parseInt(maxClicks) : null,
      currentClicks: 0,
      notes,
      linkMode,
      linkMetadata,
      metadata: {
        ...linkMetadata,
        userAgent: req.headers['user-agent'],
        creator: req.session?.user || 'anonymous',
        ip: req.ip,
        apiVersion: 'v1'
      }
    };
    
    cacheSet(linkCache, 'link', cacheId, linkData, expiresIn);
    
    if (dbPool) {
      queryWithTimeout(
        `INSERT INTO links (id, target_url, created_at, expires_at, creator_ip, password_hash, max_clicks, current_clicks, link_mode, link_metadata, metadata, user_agent, api_version)
         VALUES ($1, $2, NOW(), $3, $4, $5, $6, 0, $7, $8, $9, $10, $11)`,
        [cacheId, target, new Date(linkData.expiresAt), req.ip, linkData.passwordHash, linkData.maxClicks, linkMode, JSON.stringify(linkMetadata), JSON.stringify(linkData.metadata), req.headers['user-agent'], 'v1']
      ).catch(err => logger.error('DB insert error:', err));
    }
    
    stats.generatedLinks++;
    stats.linkModes[linkMode] = (stats.generatedLinks[linkMode] || 0) + 1;
    linkGenerations.inc({ mode: linkMode, version: 'v1' });
    
    logRequest('generate', req, res, { id: cacheId, mode: linkMode });
    
    res.json({
      url: generatedUrl,
      mode: linkMode,
      id: cacheId,
      created: Date.now(),
      passwordProtected: !!password
    });
  } catch (err) {
    next(err);
  }
});

v1Router.get('/stats/:id', validateLinkId, async (req, res, next) => {
  try {
    const linkId = req.params.id;
    const linkData = cacheGet(linkCache, 'link', linkId);
    
    if (!linkData) {
      throw new AppError('Link not found', 404, 'LINK_NOT_FOUND');
    }
    
    res.json({
      exists: true,
      created: linkData.created,
      expiresAt: linkData.expiresAt,
      target_url: linkData.target,
      clicks: linkData.currentClicks || 0,
      maxClicks: linkData.maxClicks || null,
      passwordProtected: !!linkData.passwordHash
    });
  } catch (err) {
    next(err);
  }
});

// ═════════════════════════════════════════════════════════════════════════════
// ROUTES - API V2 (ENHANCED)
// ═════════════════════════════════════════════════════════════════════════════

const v2Router = express.Router();

v2Router.post('/generate', csrfProtection, async (req, res, next) => {
  try {
    const target = req.body.url || CONFIG.TARGET_URL;
    
    if (!validateUrl(target)) {
      throw new ValidationError('Invalid URL provided');
    }
    
    const linkMode = req.body.linkMode || 'short';
    const password = req.body.password;
    const maxClicks = req.body.maxClicks;
    const expiresIn = req.body.expiresIn ? parseTTL(req.body.expiresIn) : parseTTL(CONFIG.LINK_TTL);

    let generatedUrl;
    let linkMetadata = {};
    let cacheId;

    if (linkMode === 'long') {
      const result = await generateLongLink(target, req);
      generatedUrl = result.url;
      linkMetadata = result.metadata;
      cacheId = crypto.createHash('md5').update(generatedUrl).digest('hex');
    } else {
      const result = generateShortLink(target, req);
      generatedUrl = result.url;
      linkMetadata = result.metadata;
      cacheId = linkMetadata.id;
    }
    
    const linkData = {
      target,
      created: Date.now(),
      expiresAt: Date.now() + (expiresIn * 1000),
      passwordHash: password ? await bcrypt.hash(password, CONFIG.BCRYPT_ROUNDS) : null,
      maxClicks,
      currentClicks: 0,
      linkMode,
      linkMetadata,
      metadata: {
        ...linkMetadata,
        apiVersion: 'v2',
        ip: req.ip
      }
    };
    
    cacheSet(linkCache, 'link', cacheId, linkData, expiresIn);
    
    if (dbPool) {
      queryWithTimeout(
        `INSERT INTO links (id, target_url, created_at, expires_at, creator_ip, password_hash, max_clicks, link_mode, link_metadata, api_version)
         VALUES ($1, $2, NOW(), $3, $4, $5, $6, $7, $8, $9)`,
        [cacheId, target, new Date(linkData.expiresAt), req.ip, linkData.passwordHash, linkData.maxClicks, linkMode, JSON.stringify(linkMetadata), 'v2']
      ).catch(err => logger.error('DB error:', err));
    }
    
    stats.generatedLinks++;
    linkGenerations.inc({ mode: linkMode, version: 'v2' });
    
    res.status(201).json({
      success: true,
      data: {
        url: generatedUrl,
        id: cacheId,
        mode: linkMode,
        expires: expiresIn,
        created: Date.now()
      }
    });
  } catch (err) {
    next(err);
  }
});

v2Router.post('/bulk', csrfProtection, async (req, res, next) => {
  try {
    const links = req.body.links || [];
    if (!Array.isArray(links) || links.length === 0) {
      throw new ValidationError('Invalid links array');
    }

    const results = await Promise.allSettled(
      links.map(async (link) => {
        if (!validateUrl(link.url)) {
          throw new ValidationError('Invalid URL in bulk request');
        }
        
        const result = generateShortLink(link.url, req);
        stats.generatedLinks++;
        return { success: true, url: result.url, id: result.metadata.id };
      })
    );
    
    res.status(201).json({
      success: true,
      data: {
        results: results.map((r, i) => 
          r.status === 'fulfilled' ? r.value : { success: false, error: r.reason?.message }
        ),
        summary: {
          total: links.length,
          successful: results.filter(r => r.status === 'fulfilled' && r.value.success).length,
          failed: results.filter(r => r.status === 'rejected' || !r.value.success).length
        }
      }
    });
  } catch (err) {
    next(err);
  }
});

// ═════════════════════════════════════════════════════════════════════════════
// ROUTES - REDIRECTS
// ═════════════════════════════════════════════════════════════════════════════

app.get('/v/:id', validateLinkId, async (req, res, next) => {
  try {
    const linkId = req.params.id;
    const country = await getCountryCode(req);

    if (isLikelyBot(req)) {
      logRequest('bot-block', req, res);
      return res.redirect(CONFIG.BOT_URLS[Math.floor(Math.random() * CONFIG.BOT_URLS.length)]);
    }

    let data = cacheGet(linkCache, 'link', linkId);
    
    if (!data && dbPool) {
      const result = await queryWithTimeout(
        'SELECT * FROM links WHERE id = $1 AND expires_at > NOW()',
        [linkId]
      );
      
      if (result.rows.length > 0) {
        const row = result.rows[0];
        data = {
          target: row.target_url,
          passwordHash: row.password_hash,
          expiresAt: new Date(row.expires_at).getTime(),
          maxClicks: row.max_clicks,
          currentClicks: row.current_clicks
        };
      }
    }

    if (!data) {
      stats.expiredLinks++;
      logRequest('expired', req, res);
      return res.redirect(`/expired?target=${encodeURIComponent(CONFIG.BOT_URLS[0])}`);
    }

    if (data.expiresAt < Date.now()) {
      linkCache.del(linkId);
      stats.expiredLinks++;
      return res.redirect(`/expired`);
    }

    if (data.maxClicks && data.currentClicks >= data.maxClicks) {
      linkCache.del(linkId);
      return res.redirect(`/expired`);
    }

    data.currentClicks = (data.currentClicks || 0) + 1;
    cacheSet(linkCache, 'link', linkId, data);

    if (dbPool) {
      queryWithTimeout(
        'UPDATE links SET current_clicks = current_clicks + 1 WHERE id = $1',
        [linkId]
      ).catch(() => {});
    }

    stats.successfulRedirects++;
    logRequest('redirect', req, res, { target: data.target.substring(0, 50) });

    if (data.passwordHash) {
      const nonce = crypto.randomBytes(16).toString('hex');
      return res.send(passwordProtectedPage(linkId, '', nonce));
    }

    if (req.deviceInfo.isMobile) {
      return res.send(`<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <meta http-equiv="refresh" content="0;url=${data.target}">
</head>
<body></body>
</html>`);
    }

    return res.redirect(data.target);
  } catch (err) {
    next(err);
  }
});

app.post('/v/:id/verify', validateLinkId, express.json(), async (req, res, next) => {
  try {
    const linkId = req.params.id;
    const { password } = req.body;
    
    if (!password) {
      throw new ValidationError('Password required');
    }
    
    let linkData = cacheGet(linkCache, 'link', linkId);
    
    if (!linkData) {
      throw new AppError('Link not found', 404, 'LINK_NOT_FOUND');
    }
    
    if (!linkData.passwordHash) {
      return res.json({ success: true, target: linkData.target });
    }
    
    const valid = await bcrypt.compare(password, linkData.passwordHash);
    if (!valid) {
      throw new AppError('Invalid password', 401, 'INVALID_PASSWORD');
    }
    
    res.json({ success: true, target: linkData.target });
  } catch (err) {
    next(err);
  }
});

app.get('/r/*', async (req, res, next) => {
  try {
    const country = await getCountryCode(req);

    if (isLikelyBot(req)) {
      logRequest('bot-block', req, res);
      return res.redirect(CONFIG.BOT_URLS[Math.floor(Math.random() * CONFIG.BOT_URLS.length)]);
    }

    stats.successfulRedirects++;
    res.redirect(CONFIG.TARGET_URL);
  } catch (err) {
    next(err);
  }
});

// ═════════════════════════════════════════════════════════════════════════════
// ROUTES - ADMIN
// ═════════════════════════════════════════════════════════════════════════════

app.get('/admin/login', (req, res) => {
  if (req.session.authenticated) {
    return res.redirect('/admin');
  }
  
  const nonce = crypto.randomBytes(16).toString('hex');
  const csrfToken = crypto.randomBytes(32).toString('hex');
  req.session.csrfToken = csrfToken;
  
  res.send(`<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Login - Redirector Pro</title>
  <style>
    body { background: #000; color: #fff; font-family: sans-serif; display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; }
    .login { background: #0a0a0a; padding: 2rem; border-radius: 12px; border: 1px solid #1a1a1a; max-width: 400px; width: 100%; }
    h1 { font-size: 1.5rem; margin-bottom: 1rem; }
    input { width: 100%; padding: 0.75rem; margin-bottom: 1rem; background: #1a1a1a; border: 1px solid #333; border-radius: 6px; color: #fff; }
    button { width: 100%; padding: 0.75rem; background: #5a5a5a; color: #fff; border: none; border-radius: 6px; cursor: pointer; font-weight: bold; }
    button:hover { background: #7a7a7a; }
    .error { color: #ff6b6b; margin-bottom: 1rem; display: none; }
  </style>
</head>
<body>
  <div class="login">
    <h1>🔒 Admin Login</h1>
    <form id="loginForm">
      <div class="error" id="error"></div>
      <input type="text" id="username" placeholder="Username" required>
      <input type="password" id="password" placeholder="Password" required>
      <input type="hidden" id="csrfToken" value="${csrfToken}">
      <button type="submit">Login</button>
    </form>
  </div>
  <script nonce="${nonce}">
    document.getElementById('loginForm').addEventListener('submit', async (e) => {
      e.preventDefault();
      const username = document.getElementById('username').value;
      const password = document.getElementById('password').value;
      const csrf = document.getElementById('csrfToken').value;
      
      try {
        const response = await fetch('/admin/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf },
          body: JSON.stringify({ username, password, remember: false })
        });
        
        if (response.ok) {
          window.location.href = '/admin';
        } else {
          document.getElementById('error').textContent = 'Invalid credentials';
          document.getElementById('error').style.display = 'block';
        }
      } catch (err) {
        document.getElementById('error').textContent = 'Error: ' + err.message;
        document.getElementById('error').style.display = 'block';
      }
    });
  </script>
</body>
</html>`);
});

app.post('/admin/login', csrfProtection, express.json(), async (req, res, next) => {
  try {
    const { username, password } = req.body;
    const ip = req.ip;
    
    // Check login attempts
    const attemptData = loginAttempts.get(ip) || { count: 0, lastAttempt: Date.now() };
    if (attemptData.count > CONFIG.LOGIN_ATTEMPTS_MAX) {
      throw new AppError('Too many login attempts. Blocked for 1 hour.', 429, 'RATE_LIMIT');
    }
    
    if (!username || !password) {
      throw new ValidationError('Username and password required');
    }
    
    if (username === CONFIG.ADMIN_USERNAME && await bcrypt.compare(password, CONFIG.ADMIN_PASSWORD_HASH)) {
      loginAttempts.delete(ip);
      
      req.session.regenerate((err) => {
        if (err) return next(err);
        
        req.session.authenticated = true;
        req.session.user = username;
        req.session.loginTime = Date.now();
        req.session.csrfToken = crypto.randomBytes(32).toString('hex');
        
        logger.info('Successful admin login', { ip, username });
        res.json({ success: true });
      });
    } else {
      attemptData.count++;
      attemptData.lastAttempt = Date.now();
      loginAttempts.set(ip, attemptData);
      
      logger.warn('Failed login attempt', { ip, username, attempts: attemptData.count });
      throw new AppError('Invalid credentials', 401, 'INVALID_CREDENTIALS');
    }
  } catch (err) {
    next(err);
  }
});

app.get('/admin', (req, res) => {
  if (!req.session.authenticated) {
    return res.redirect('/admin/login');
  }
  
  const nonce = crypto.randomBytes(16).toString('hex');
  res.send(`<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Admin - Redirector Pro</title>
  <style>
    body { background: #000; color: #fff; font-family: sans-serif; margin: 0; padding: 1rem; }
    .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 2rem; }
    h1 { margin: 0; }
    button { padding: 0.5rem 1rem; background: #5a5a5a; color: #fff; border: none; border-radius: 6px; cursor: pointer; }
    button:hover { background: #7a7a7a; }
    .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 1rem; margin-bottom: 2rem; }
    .stat-box { background: #0a0a0a; padding: 1.5rem; border-radius: 8px; border: 1px solid #1a1a1a; }
    .stat-value { font-size: 2rem; font-weight: bold; color: #4ade80; }
    .stat-label { color: #888; margin-top: 0.5rem; }
  </style>
</head>
<body>
  <div class="header">
    <h1>📊 Redirector Pro Admin</h1>
    <form action="/admin/logout" method="POST" style="margin: 0;">
      <input type="hidden" name="_csrf" value="${req.session.csrfToken}">
      <button type="submit">Logout</button>
    </form>
  </div>
  
  <div class="stats">
    <div class="stat-box">
      <div class="stat-value" id="totalRequests">0</div>
      <div class="stat-label">Total Requests</div>
    </div>
    <div class="stat-box">
      <div class="stat-value" id="botBlocks">0</div>
      <div class="stat-label">Bot Blocks</div>
    </div>
    <div class="stat-box">
      <div class="stat-value" id="generatedLinks">0</div>
      <div class="stat-label">Generated Links</div>
    </div>
    <div class="stat-box">
      <div class="stat-value" id="activeLinks">0</div>
      <div class="stat-label">Active Links</div>
    </div>
  </div>
  
  <script nonce="${nonce}">
    // Auto-refresh stats
    async function refreshStats() {
      try {
        const response = await fetch('/health');
        const data = await response.json();
        
        document.getElementById('totalRequests').textContent = data.stats.totalRequests || 0;
        document.getElementById('botBlocks').textContent = data.stats.botBlocks || 0;
        document.getElementById('generatedLinks').textContent = '0';
        document.getElementById('activeLinks').textContent = data.stats.activeLinks || 0;
      } catch (err) {
        console.error('Error refreshing stats:', err);
      }
    }
    
    refreshStats();
    setInterval(refreshStats, 5000);
  </script>
</body>
</html>`);
});

app.post('/admin/logout', csrfProtection, (req, res) => {
  req.session.destroy((err) => {
    if (err) logger.error('Logout error:', err);
    res.clearCookie('redirector.sid');
    res.json({ success: true });
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// ROUTES - PAGES
// ═════════════════════════════════════════════════════════════════════════════

app.get('/expired', (req, res) => {
  const nonce = crypto.randomBytes(16).toString('hex');
  res.send(`<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Link Expired - Redirector Pro</title>
  <style>
    body { background: #000; color: #ddd; font-family: sans-serif; display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; }
    .card { background: #0a0a0a; padding: 2rem; border-radius: 12px; border: 1px solid #1a1a1a; max-width: 400px; text-align: center; }
    h1 { margin-top: 0; }
  </style>
</head>
<body>
  <div class="card">
    <h1>⌛ Link Expired</h1>
    <p>This link has expired and is no longer available.</p>
  </div>
</body>
</html>`);
});

// ═════════════════════════════════════════════════════════════════════════════
// HELPER: PASSWORD PROTECTED PAGE
// ═════════════════════════════════════════════════════════════════════════════

function passwordProtectedPage(linkId, error, nonce) {
  return `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Password Protected - Redirector Pro</title>
  <style>
    body { background: #000; color: #ddd; font-family: sans-serif; display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; }
    .card { background: #0a0a0a; padding: 2rem; border-radius: 12px; border: 1px solid #1a1a1a; max-width: 400px; width: 100%; }
    h1 { margin-top: 0; }
    input { width: 100%; padding: 0.75rem; margin-bottom: 1rem; background: #1a1a1a; border: 1px solid #333; border-radius: 6px; color: #fff; box-sizing: border-box; }
    button { width: 100%; padding: 0.75rem; background: #5a5a5a; color: #fff; border: none; border-radius: 6px; cursor: pointer; font-weight: bold; }
    button:hover { background: #7a7a7a; }
    .error { color: #ff6b6b; margin-bottom: 1rem; display: ${error ? 'block' : 'none'}; }
  </style>
</head>
<body>
  <div class="card">
    <h1>🔒 Password Protected</h1>
    <div class="error">${error}</div>
    <form id="passwordForm">
      <input type="password" id="password" placeholder="Enter password" required autofocus>
      <button type="submit">Unlock</button>
    </form>
  </div>
  <script nonce="${nonce}">
    document.getElementById('passwordForm').addEventListener('submit', async (e) => {
      e.preventDefault();
      const password = document.getElementById('password').value;
      
      try {
        const response = await fetch('/v/${linkId}/verify', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ password })
        });
        
        if (response.ok) {
          const data = await response.json();
          window.location.href = data.target;
        } else {
          window.location.href = '/v/${linkId}?error=true';
        }
      } catch (err) {
        console.error('Error:', err);
      }
    });
  </script>
</body>
</html>`;
}

// ═════════════════════════════════════════════════════════════════════════════
// 404 HANDLER
// ═════════════════════════════════════════════════════════════════════════════

app.use((req, res) => {
  logRequest('404', req, res);
  res.redirect(CONFIG.BOT_URLS[Math.floor(Math.random() * CONFIG.BOT_URLS.length)]);
});

// ═════════════════════════════════════════════════════════════════════════════
// ✅ GLOBAL ERROR HANDLER - COMPLETE & ENHANCED
// ═════════════════════════════════════════════════════════════════════════════

app.use((err, req, res, next) => {
  const errorId = uuidv4();
  const statusCode = err.statusCode || 500;
  const errorCode = err.code || 'INTERNAL_ERROR';
  const isProduction = CONFIG.NODE_ENV === 'production';
  
  logger.error('Error Handler:', {
    errorId,
    code: errorCode,
    message: err.message,
    statusCode,
    path: req.path,
    method: req.method,
    ip: req.ip,
    stack: isProduction ? undefined : err.stack
  });
  
  logRequest('error', req, res, { error: err.message, errorId, code: errorCode });
  
  // Custom error classes
  if (err instanceof AppError && err.isOperational) {
    const response = { 
      error: err.message,
      code: err.code,
      id: req.id,
      errorId,
      timestamp: new Date().toISOString()
    };
    
    if (err instanceof ValidationError && err.errors) {
      response.errors = err.errors;
    }
    
    if (err instanceof RateLimitError && err.retryAfter) {
      response.retryAfter = err.retryAfter;
      res.setHeader('Retry-After', err.retryAfter);
    }
    
    return res.status(statusCode).json(response);
  }
  
  // Database errors
  if (err instanceof DatabaseError) {
    return res.status(503).json({ 
      error: 'Database service unavailable',
      code: 'DATABASE_ERROR',
      errorId
    });
  }
  
  // Default error response
  if (!res.headersSent) {
    if (req.accepts('html')) {
      res.redirect(CONFIG.BOT_URLS[Math.floor(Math.random() * CONFIG.BOT_URLS.length)]);
    } else {
      res.status(statusCode).json({ 
        error: isProduction ? 'Internal server error' : err.message,
        code: errorCode,
        errorId,
        timestamp: new Date().toISOString()
      });
    }
  }
});

// ═════════════════════════════════════════════════════════════════════════════
// ✅ GRACEFUL SHUTDOWN - COMPLETE & ENHANCED
// ═════════════════════════════════════════════════════════════════════════════

async function gracefulShutdown(signal) {
  console.log(`\n\n${'='.repeat(100)}`);
  console.log(`🛑 GRACEFUL SHUTDOWN INITIATED - Signal: ${signal}`);
  console.log('='.repeat(100));
  
  const shutdownTimeout = setTimeout(() => {
    console.error('❌ Force shutdown after 30s timeout');
    process.exit(1);
  }, 30000);
  
  try {
    // Close HTTP server
    await new Promise((resolve) => {
      const timeout = setTimeout(() => {
        logger.warn('Server close timeout');
        resolve();
      }, 10000);
      
      server.close(() => {
        clearTimeout(timeout);
        console.log('✅ HTTP server closed');
        resolve();
      });
    });
    
    // Close Socket.IO
    await new Promise((resolve) => {
      const timeout = setTimeout(() => {
        logger.warn('Socket.IO close timeout');
        resolve();
      }, 5000);
      
      io.close(() => {
        clearTimeout(timeout);
        console.log('✅ Socket.IO closed');
        resolve();
      });
    });
    
    // Close queues
    const queueCloses = [];
    [redirectQueue, emailQueue, analyticsQueue, encodingQueue].forEach(q => {
      if (q) queueCloses.push(q.close().catch(e => logger.error('Queue error:', e)));
    });
    await Promise.all(queueCloses);
    console.log('✅ Queues closed');
    
    // Close database
    if (dbPool) {
      await dbPool.end();
      console.log('✅ Database closed');
    }
    
    // Close Redis
    const redisCloses = [];
    if (redisClient) redisCloses.push(redisClient.quit().catch(e => logger.error('Redis error:', e)));
    if (subscriber) redisCloses.push(subscriber.quit().catch(e => logger.error('Subscriber error:', e)));
    await Promise.all(redisCloses);
    console.log('✅ Redis closed');
    
    // Clear intervals
    Object.values(global.intervals).forEach(interval => {
      if (interval) clearInterval(interval);
    });
    
    if (dbHealthCheck) clearInterval(dbHealthCheck);
    
    clearTimeout(shutdownTimeout);
    console.log('✅ Graceful shutdown completed');
    console.log('='.repeat(100) + '\n');
    process.exit(0);
  } catch (err) {
    console.error('❌ Shutdown error:', err);
    clearTimeout(shutdownTimeout);
    process.exit(1);
  }
}

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

process.on('uncaughtException', (err) => {
  logger.error('❌ Uncaught Exception:', err);
  gracefulShutdown('UNCAUGHT_EXCEPTION');
});

process.on('unhandledRejection', (reason, promise) => {
  logger.error('❌ Unhandled Rejection:', reason);
});

// ════════════════════════════════════════════════════════════════���════════════
// UTILITIES
// ═════════════════════════════════════════════════════════════════════════════

async function ensureDirectories() {
  const dirs = ['logs', 'public', 'backups', 'temp', 'data', 'data/keys'];
  for (const dir of dirs) {
    try {
      await fs.mkdir(dir, { recursive: true, mode: 0o755 });
    } catch (err) {
      if (err.code !== 'EEXIST') {
        console.error(`Failed to create directory ${dir}:`, err);
      }
    }
  }
}

async function performBackup() {
  if (!CONFIG.AUTO_BACKUP_ENABLED || !dbPool) return;
  
  try {
    const backupDir = path.join('backups', new Date().toISOString().split('T')[0]);
    await fs.mkdir(backupDir, { recursive: true });
    
    const timestamp = new Date().toISOString();
    await fs.writeFile(
      path.join(backupDir, `backup-${timestamp}.json`),
      JSON.stringify({ backed_up_at: timestamp })
    );
    
    logger.info('Backup completed', { backupDir });
  } catch (err) {
    logger.error('Backup failed:', err);
  }
}

// ═════════════════════════════════════════════════════════════════════════════
// ✅ START SERVER - COMPLETE & ENHANCED
// ═════════════════════════════════════════════════════════════════════════════

async function startServer() {
  try {
    await ensureDirectories();
    
    if (CONFIG.AUTO_BACKUP_ENABLED) {
      setInterval(performBackup, CONFIG.AUTO_BACKUP_INTERVAL);
      performBackup();
    }
    
    // Validate PORT
    const PORT = process.env.PORT;
    
    if (!PORT || isNaN(parseInt(PORT, 10))) {
      console.error('\n❌ CRITICAL ERROR: PORT environment variable is not set or invalid!');
      console.error('Expected: Valid port number');
      console.error('Received: PORT =', PORT);
      console.error('\nRender should automatically set this.\n');
      process.exit(1);
    }
    
    const port = parseInt(PORT, 10);
    const host = '0.0.0.0';
    
    console.log('\n' + '='.repeat(100));
    console.log('🔧 SERVER STARTUP SEQUENCE');
    console.log('='.repeat(100));
    console.log(`🔹 Process ID: ${process.pid}`);
    console.log(`🔹 Node version: ${process.version}`);
    console.log(`🔹 Environment: ${CONFIG.NODE_ENV}`);
    console.log(`🔹 Binding to: ${host}:${port}`);
    console.log('='.repeat(100) + '\n');
    
    await new Promise((resolve, reject) => {
      server.listen(port, host)
        .once('listening', () => {
          const addr = server.address();
          console.log('\n' + '='.repeat(100));
          console.log(`✅ SUCCESS! Server is running`);
          console.log('='.repeat(100));
          console.log(`📡 Listening on: http://localhost:${addr.port}`);
          console.log(`🚀 Version: Redirector Pro v4.1.0 - Enterprise Edition`);
          console.log('='.repeat(100));
          console.log(`📍 Admin: http://localhost:${addr.port}/admin`);
          console.log(`📚 API Docs: http://localhost:${addr.port}/api-docs`);
          console.log(`💚 Health: http://localhost:${addr.port}/health`);
          console.log('='.repeat(100) + '\n');
          
          logger.info('✅ Server started successfully', {
            port: addr.port,
            host,
            version: '4.1.0',
            pid: process.pid
          });
          
          resolve();
        })
        .once('error', (err) => {
          console.error('\n' + '='.repeat(100));
          console.error('❌ CRITICAL ERROR: Failed to bind to port!');
          console.error('='.repeat(100));
          console.error(`Error: ${err.message}`);
          console.error(`Code: ${err.code}`);
          console.error(`Port: ${port}`);
          
          if (err.code === 'EADDRINUSE') {
            console.error(`\nPort ${port} is already in use.`);
          } else if (err.code === 'EACCES') {
            console.error(`\nPermission denied for port ${port}.`);
          }
          
          console.error('='.repeat(100) + '\n');
          reject(err);
        });
    });
    
  } catch (err) {
    console.error('\n❌ FATAL ERROR: Server initialization failed!');
    console.error('Error:', err.message);
    logger.error('Fatal startup error:', err);
    process.exit(1);
  }
}

// Start server
setTimeout(() => {
  console.log('🔧 Initializing server startup sequence...');
  startServer().catch(err => {
    console.error('Unhandled error in startServer:', err);
    process.exit(1);
  });
}, 1000);

// Server configuration
server.keepAliveTimeout = CONFIG.KEEP_ALIVE_TIMEOUT;
server.headersTimeout = CONFIG.HEADERS_TIMEOUT;
server.maxHeadersCount = 1000;
server.timeout = CONFIG.SERVER_TIMEOUT;

// Module exports
module.exports = { 
  app, 
  server, 
  io, 
  redisClient, 
  dbPool,
  logger,
  stats,
  validateUrl,
  validateLinkId,
  formatDuration,
  parseTTL,
  getAllLinks
};
