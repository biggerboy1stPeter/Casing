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
const { v4: uuidv4 } = require('uuid'); // Single import
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
const { createHash } = require('crypto'); // Already imported crypto, but specific import is fine
const { performance } = require('perf_hooks');
const { createNamespace } = require('cls-hooked');
const async_hooks = require('async_hooks');
const heapdump = require('heapdump');
const { createBullBoard } = require('@bull-board/api');
const { BullAdapter } = require('@bull-board/api/bullAdapter');
const { ExpressAdapter } = require('@bull-board/express');

// Note: '@datadog/pprof' is commented out as it might not be installed
// const createGraph = require('@datadog/pprof');

// Load environment variables with validation
dotenv.config();

// ─── Configuration Schema with Strict Validation ─────────────────────────────
const configSchema = Joi.object({
  NODE_ENV: Joi.string().valid('development', 'production', 'test').default('production'),
  PORT: Joi.number().port().default(10000),
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
  RATE_LIMIT_BOT: Joi.number().default(2),
  RATE_LIMIT_MOBILE: Joi.number().default(30),
  ENCODING_RATE_LIMIT: Joi.number().default(10),
  
  // Database
  DB_POOL_MIN: Joi.number().default(2),
  DB_POOL_MAX: Joi.number().default(20),
  DB_IDLE_TIMEOUT: Joi.number().default(30000),
  DB_CONNECTION_TIMEOUT: Joi.number().default(5000),
  DB_QUERY_TIMEOUT: Joi.number().default(10000),
  
  // Security
  BCRYPT_ROUNDS: Joi.number().default(12),
  SESSION_TTL: Joi.number().default(86400),
  SESSION_ABSOLUTE_TIMEOUT: Joi.number().default(604800), // 7 days
  CSP_ENABLED: Joi.boolean().default(true),
  HSTS_ENABLED: Joi.boolean().default(true),
  LOGIN_ATTEMPTS_MAX: Joi.number().default(10),
  LOGIN_BLOCK_DURATION: Joi.number().default(3600000), // 1 hour
  
  // Logging
  LOG_LEVEL: Joi.string().valid('error', 'warn', 'info', 'debug').default('info'),
  LOG_FORMAT: Joi.string().valid('json', 'simple', 'combined').default('json'),
  LOG_TO_FILE: Joi.boolean().default(true),
  LOG_TO_CONSOLE: Joi.boolean().default(true),
  LOG_RETENTION_DAYS: Joi.number().default(30),
  LOG_MAX_SIZE: Joi.string().default('20m'),
  
  // Metrics
  METRICS_ENABLED: Joi.boolean().default(true),
  METRICS_PREFIX: Joi.string().default('redirector_'),
  METRICS_BUCKETS: Joi.array().items(Joi.number()).default([0.1, 5, 15, 50, 100, 200, 300, 400, 500, 1000, 2000, 5000]),
  
  // Performance
  MAX_RESPONSE_TIMES_HISTORY: Joi.number().default(10000),
  CACHE_CHECK_PERIOD_FACTOR: Joi.number().default(0.1),
  REQUEST_TIMEOUT: Joi.number().default(30000),
  KEEP_ALIVE_TIMEOUT: Joi.number().default(30000),
  HEADERS_TIMEOUT: Joi.number().default(31000),
  SERVER_TIMEOUT: Joi.number().default(120000),
  
  // Health checks
  HEALTH_CHECK_INTERVAL: Joi.number().default(30000),
  HEALTH_CHECK_TIMEOUT: Joi.number().default(5000),
  
  // Circuit breaker
  CIRCUIT_BREAKER_TIMEOUT: Joi.number().default(3000),
  CIRCUIT_BREAKER_ERROR_THRESHOLD: Joi.number().default(50),
  CIRCUIT_BREAKER_RESET_TIMEOUT: Joi.number().default(30000),
  
  // Monitoring
  MEMORY_THRESHOLD_WARNING: Joi.number().default(0.8), // 80%
  MEMORY_THRESHOLD_CRITICAL: Joi.number().default(0.95), // 95%
  CPU_THRESHOLD_WARNING: Joi.number().default(0.7), // 70%
  CPU_THRESHOLD_CRITICAL: Joi.number().default(0.9), // 90%
  
  // Backup
  AUTO_BACKUP_ENABLED: Joi.boolean().default(true),
  AUTO_BACKUP_INTERVAL: Joi.number().default(86400000), // 24 hours
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

// ─── Global Configuration Variables ─────────────────────────────────────────
const CONFIG = { ...validatedConfig };

// Allow runtime config reload
const reloadConfig = async () => {
  try {
    dotenv.config({ override: true });
    const { error, value } = configSchema.validate(process.env, {
      allowUnknown: true,
      stripUnknown: true,
      abortEarly: false
    });
    
    if (!error) {
      Object.assign(CONFIG, value);
      logger.info('✅ Configuration reloaded successfully');
      return { success: true };
    } else {
      logger.error('Configuration reload failed:', error.details);
      return { success: false, errors: error.details };
    }
  } catch (err) {
    logger.error('Configuration reload error:', err);
    return { success: false, error: err.message };
  }
};

// ─── Logger Setup with Advanced Features ────────────────────────────────────
const logDir = 'logs';
const logTransports = [];

// Ensure log directory exists with proper permissions
(async () => {
  try {
    await fs.mkdir(logDir, { recursive: true, mode: 0o755 });
    await fs.mkdir(path.join(logDir, 'backups'), { recursive: true, mode: 0o755 });
    await fs.mkdir(path.join(logDir, 'archive'), { recursive: true, mode: 0o755 });
  } catch (err) {
    console.error('Failed to create log directories:', err);
  }
})();

// Custom log format with request ID
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
    }),
    new winstonDailyRotate({
      filename: path.join(logDir, 'audit-%DATE%.log'),
      datePattern: 'YYYY-MM-DD',
      level: 'info',
      maxSize: CONFIG.LOG_MAX_SIZE,
      maxFiles: `${CONFIG.LOG_RETENTION_DAYS * 3}d`,
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
    version: '4.0.0'
  },
  transports: logTransports,
  exceptionHandlers: [
    new transports.File({ 
      filename: path.join(logDir, 'exceptions.log'),
      maxsize: 10485760, // 10MB
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

// ─── Prometheus Metrics with Custom Registry ───────────────────────────────
const register = new promClient.Registry();
promClient.collectDefaultMetrics({ 
  register,
  prefix: CONFIG.METRICS_PREFIX,
  timeout: 5000,
  gcDurationBuckets: CONFIG.METRICS_BUCKETS
});

// HTTP metrics middleware
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

// Custom metrics
const httpRequestDurationMicroseconds = new promClient.Histogram({
  name: `${CONFIG.METRICS_PREFIX}http_request_duration_ms`,
  help: 'Duration of HTTP requests in ms',
  labelNames: ['method', 'route', 'code'],
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
  labelNames: ['method', 'path', 'status'],
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
  labelNames: ['mode'],
  registers: [register]
});

const linkModeCounter = new promClient.Counter({
  name: `${CONFIG.METRICS_PREFIX}link_mode_total`,
  help: 'Total number of links by mode',
  labelNames: ['mode'],
  registers: [register]
});

const encodingComplexityGauge = new promClient.Gauge({
  name: `${CONFIG.METRICS_PREFIX}encoding_complexity`,
  help: 'Encoding complexity metrics',
  labelNames: ['type'],
  registers: [register]
});

const encodingDurationHistogram = new promClient.Histogram({
  name: `${CONFIG.METRICS_PREFIX}encoding_duration_seconds`,
  help: 'Time spent encoding links',
  labelNames: ['mode', 'layers', 'iterations'],
  buckets: [0.1, 0.5, 1, 2, 5, 10],
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

const businessMetrics = {
  linkCreationRate: new promClient.Gauge({
    name: `${CONFIG.METRICS_PREFIX}link_creation_rate`,
    help: 'Links created per minute',
    labelNames: ['mode'],
    registers: [register]
  }),
  botDetectionRate: new promClient.Gauge({
    name: `${CONFIG.METRICS_PREFIX}bot_detection_rate`,
    help: 'Bot detections per minute',
    labelNames: ['reason'],
    registers: [register]
  }),
  redirectRate: new promClient.Gauge({
    name: `${CONFIG.METRICS_PREFIX}redirect_rate`,
    help: 'Redirects per minute',
    labelNames: ['mode', 'status'],
    registers: [register]
  }),
  encodingQuality: new promClient.Gauge({
    name: `${CONFIG.METRICS_PREFIX}encoding_quality`,
    help: 'Encoding quality metrics',
    labelNames: ['metric'],
    registers: [register]
  })
};

// ─── Async Hook for Request Context ─────────────────────────────────────────
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

// ─── App Initialization ─────────────────────────────────────────────────────
const app = express();
const server = http.createServer(app);

// ─── Circuit Breakers ──────────────────────────────────────────────────────
const circuitBreakerOptions = {
  timeout: CONFIG.CIRCUIT_BREAKER_TIMEOUT,
  errorThresholdPercentage: CONFIG.CIRCUIT_BREAKER_ERROR_THRESHOLD,
  resetTimeout: CONFIG.CIRCUIT_BREAKER_RESET_TIMEOUT,
  rollingCountTimeout: 10000,
  rollingCountBuckets: 10,
  name: 'service',
  volumeThreshold: 10
};

const databaseBreaker = new circuitBreaker(async (query, params) => {
  return await queryWithTimeout(query, params);
}, circuitBreakerOptions);

const redisBreaker = new circuitBreaker(async (command, ...args) => {
  return await redisClient[command](...args);
}, { ...circuitBreakerOptions, name: 'redis' });

const encodingBreaker = new circuitBreaker(async (target, req, options) => {
  return await generateLongLink(target, req, options);
}, { ...circuitBreakerOptions, name: 'encoding', timeout: 10000 });

// ─── Redis Connection with Advanced Configuration ──────────────────────────
let redisClient;
let subscriber;
let sessionStore;
let rateLimiterRedis;

if (CONFIG.REDIS_URL && CONFIG.REDIS_URL.startsWith('redis://')) {
  try {
    redisClient = new Redis(CONFIG.REDIS_URL, {
      retryStrategy: (times) => {
        const delay = Math.min(times * 100, 3000);
        logger.warn(`Redis connection retry ${times} with delay ${delay}ms`);
        return delay;
      },
      maxRetriesPerRequest: 5,
      enableReadyCheck: true,
      lazyConnect: false,
      connectTimeout: 10000,
      disconnectTimeout: 5000,
      commandTimeout: 5000,
      keepAlive: 30000,
      family: 4,
      db: CONFIG.REDIS_DB,
      password: CONFIG.REDIS_PASSWORD || undefined
    });

    subscriber = new Redis(CONFIG.REDIS_URL, {
      retryStrategy: (times) => Math.min(times * 100, 3000),
      maxRetriesPerRequest: 3,
      enableReadyCheck: true,
      lazyConnect: false
    });

    redisClient.on('error', (err) => {
      logger.error('Redis error:', err);
    });

    redisClient.on('connect', () => {
      logger.info('✅ Connected to Redis');
    });

    redisClient.on('ready', () => {
      logger.info('✅ Redis ready');
    });

    redisClient.on('close', () => {
      logger.warn('Redis connection closed');
    });

    redisClient.on('reconnecting', () => {
      logger.info('Redis reconnecting...');
    });

    subscriber.on('error', (err) => {
      logger.error('Redis subscriber error:', err);
    });

    // Initialize Redis session store
    const RedisStore = createRedisStore(session);
    sessionStore = new RedisStore({ 
      client: redisClient,
      prefix: 'redirector:sess:',
      ttl: CONFIG.SESSION_TTL,
      disableTouch: false,
      scanCount: 1000,
      serializer: {
        stringify: (obj) => JSON.stringify(obj),
        parse: (str) => JSON.parse(str)
      }
    });

    // Initialize rate limiter with Redis
    rateLimiterRedis = new RateLimiterRedis({
      storeClient: redisClient,
      keyPrefix: 'rl',
      points: CONFIG.RATE_LIMIT_MAX_REQUESTS,
      duration: CONFIG.RATE_LIMIT_WINDOW / 1000,
      blockDuration: 60,
      inMemoryBlockOnConsumed: CONFIG.RATE_LIMIT_MAX_REQUESTS * 2,
      inMemoryBlockDuration: 10
    });

  } catch (err) {
    logger.warn('Redis connection failed, using fallback stores:', err.message);
    sessionStore = new session.MemoryStore();
    redisClient = null;
    subscriber = null;
    rateLimiterRedis = null;
  }
} else {
  logger.warn('⚠️ Redis not configured - using MemoryStore and Memory rate limiter');
  sessionStore = new session.MemoryStore();
}

// ─── Rate Limiter (Flexible) ──────────────────────────────────────────────
const rateLimiter = rateLimiterRedis || new RateLimiterMemory({
  points: CONFIG.RATE_LIMIT_MAX_REQUESTS,
  duration: CONFIG.RATE_LIMIT_WINDOW / 1000,
  blockDuration: 60
});

const rateLimiterMiddleware = (req, res, next) => {
  const key = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip || 'unknown';
  
  rateLimiter.consume(key)
    .then(() => {
      next();
    })
    .catch(() => {
      logger.warn('Rate limit exceeded', { ip: key, path: req.path });
      res.status(429).json({ 
        error: 'Too many requests',
        retryAfter: Math.ceil(rateLimiter.msBeforeNext / 1000)
      });
    });
};

// ─── Bull Queues with Enhanced Configuration ───────────────────────────────
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
      backoff: {
        type: 'exponential',
        delay: 5000
      },
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
    settings: {
      maxStalledCount: 1
    }
  });

  encodingQueue = new Queue('encoding processing', {
    redis: redisClient,
    defaultJobOptions: {
      attempts: 2,
      timeout: 30000,
      removeOnComplete: true,
      priority: 10
    },
    settings: {
      lockDuration: 60000
    }
  });

  // Queue event handlers
  redirectQueue.on('completed', (job) => {
    logger.debug('Redirect job completed', { jobId: job.id });
  });

  redirectQueue.on('failed', (job, err) => {
    logger.error('Redirect job failed', { jobId: job.id, error: err.message });
  });

  // Queue processors with error handling
  redirectQueue.process(async (job) => {
    const { linkId, ip, userAgent, deviceInfo, country, linkMode, encodingLayers } = job.data;
    
    try {
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
      
      // Update click count in cache and DB
      const linkData = linkCache.get(linkId);
      if (linkData) {
        linkData.currentClicks = (linkData.currentClicks || 0) + 1;
        linkCache.set(linkId, linkData);
      }
      
      if (dbPool) {
        await queryWithTimeout(
          'UPDATE links SET current_clicks = current_clicks + 1, last_accessed = NOW() WHERE id = $1',
          [linkId]
        );
      }
      
      return { success: true };
    } catch (err) {
      logger.error('Redirect processing error:', err);
      throw err;
    }
  });

  emailQueue.process(async (job) => {
    const { to, subject, html, type } = job.data;
    
    if (!CONFIG.SMTP_HOST) {
      logger.debug('Email not sent - SMTP not configured', { to, subject });
      return { sent: false, reason: 'SMTP not configured' };
    }
    
    try {
      // Implement actual email sending here
      logger.info(`Email would be sent to ${to} with subject: ${subject}`);
      
      // Log email in database
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
    const { type, data } = job.data;
    
    try {
      await updateAnalytics(type, data);
      
      // Update business metrics
      if (type === 'generate') {
        businessMetrics.linkCreationRate.labels(data.mode || 'short').inc();
      } else if (type === 'bot') {
        businessMetrics.botDetectionRate.labels(data.reason || 'unknown').inc();
      } else if (type === 'redirect') {
        businessMetrics.redirectRate.labels(data.linkMode || 'short', 'success').inc();
      }
      
      return { processed: true };
    } catch (err) {
      logger.error('Analytics processing error:', err);
      throw err;
    }
  });

  encodingQueue.process(async (job) => {
    const { targetUrl, req, options } = job.data;
    const startTime = performance.now();
    
    try {
      const result = await encodingBreaker.fire(targetUrl, req, options);
      
      encodingDurationHistogram
        .labels('long', options.maxLayers || CONFIG.LINK_ENCODING_LAYERS, options.iterations || CONFIG.MAX_ENCODING_ITERATIONS)
        .observe((performance.now() - startTime) / 1000);
      
      return result;
    } catch (err) {
      logger.error('Encoding queue processing error:', err);
      throw err;
    }
  });

  // Bull Board for queue monitoring
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
      serverAdapter: serverAdapter,
      options: {
        uiConfig: {
          boardTitle: 'Redirector Pro Queues',
          boardLogo: {
            path: 'https://cdn.jsdelivr.net/npm/heroicons@1.0.6/outline/clock.svg',
            width: 30,
            height: 30
          },
          favIcon: {
            path: 'https://cdn.jsdelivr.net/npm/heroicons@1.0.6/outline/clock.svg'
          }
        }
      }
    });
    
    logger.info(`✅ Bull Board enabled at ${CONFIG.BULL_BOARD_PATH}`);
  }

  // Queue metrics collection
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

// ─── Database Connection with Advanced Pool Management ─────────────────────
let dbPool;
let dbHealthCheck;

const queryWithTimeout = async (query, params, timeout = CONFIG.DB_QUERY_TIMEOUT) => {
  if (!dbPool) {
    throw new Error('Database not available');
  }
  
  const client = await dbPool.connect();
  
  try {
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
      statement_timeout: CONFIG.DB_QUERY_TIMEOUT,
      query_timeout: CONFIG.DB_QUERY_TIMEOUT,
      allowExitOnIdle: true
    });

    dbPool.on('error', (err) => {
      logger.error('Unexpected database error:', err);
    });

    dbPool.on('connect', (client) => {
      logger.debug('Database client connected');
    });

    dbPool.on('acquire', () => {
      databaseConnectionGauge.labels('acquired').inc();
    });

    dbPool.on('remove', () => {
      databaseConnectionGauge.labels('removed').inc();
    });

    // Create tables with proper schema and error handling
    const createTables = async () => {
      try {
        logger.info('📦 Creating database tables...');
        
        // Enable UUID extension
        await queryWithTimeout('CREATE EXTENSION IF NOT EXISTS "uuid-ossp";');
        
        // Create tables with proper constraints
        const tables = [
          `CREATE TABLE IF NOT EXISTS links (
            id VARCHAR(64) PRIMARY KEY,
            target_url TEXT NOT NULL,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
            creator_ip INET,
            password_hash TEXT,
            max_clicks INTEGER,
            current_clicks INTEGER DEFAULT 0,
            last_accessed TIMESTAMP WITH TIME ZONE,
            status VARCHAR(20) DEFAULT 'active',
            link_mode VARCHAR(10) DEFAULT 'short',
            link_metadata JSONB DEFAULT '{}',
            encoding_metadata JSONB DEFAULT '{}',
            metadata JSONB DEFAULT '{}',
            encoding_complexity INTEGER DEFAULT 0,
            user_agent TEXT,
            referer TEXT,
            CHECK (status IN ('active', 'expired', 'completed'))
          )`,
          
          `CREATE TABLE IF NOT EXISTS clicks (
            id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
            link_id VARCHAR(64) REFERENCES links(id) ON DELETE CASCADE,
            ip INET,
            user_agent TEXT,
            device_type VARCHAR(20),
            country VARCHAR(2),
            city TEXT,
            region TEXT,
            postal TEXT,
            latitude DECIMAL(10,8),
            longitude DECIMAL(11,8),
            timezone TEXT,
            isp TEXT,
            org TEXT,
            asn TEXT,
            referer TEXT,
            link_mode VARCHAR(10),
            encoding_layers INTEGER,
            decoding_time_ms INTEGER,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
          )`,

          `CREATE TABLE IF NOT EXISTS logs (
            id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
            data JSONB NOT NULL,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
          )`,

          `CREATE TABLE IF NOT EXISTS analytics (
            id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
            type VARCHAR(50) NOT NULL,
            data JSONB NOT NULL,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
          )`,

          `CREATE TABLE IF NOT EXISTS settings (
            key VARCHAR(100) PRIMARY KEY,
            value JSONB NOT NULL,
            updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            updated_by VARCHAR(100)
          )`,

          `CREATE TABLE IF NOT EXISTS blocked_ips (
            ip INET PRIMARY KEY,
            reason TEXT,
            expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
          )`,

          `CREATE TABLE IF NOT EXISTS daily_stats (
            date DATE PRIMARY KEY,
            total_requests INTEGER DEFAULT 0,
            unique_visitors INTEGER DEFAULT 0,
            bot_blocks INTEGER DEFAULT 0,
            links_created INTEGER DEFAULT 0,
            clicks INTEGER DEFAULT 0,
            data JSONB DEFAULT '{}',
            updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
          )`,

          `CREATE TABLE IF NOT EXISTS emails (
            id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
            recipient TEXT NOT NULL,
            subject TEXT,
            type VARCHAR(50),
            status VARCHAR(20),
            sent_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            error TEXT
          )`,

          `CREATE TABLE IF NOT EXISTS rate_limits (
            id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
            ip INET NOT NULL,
            endpoint VARCHAR(100),
            count INTEGER DEFAULT 1,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
          )`,

          `CREATE TABLE IF NOT EXISTS user_sessions (
            id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
            session_id VARCHAR(255) UNIQUE NOT NULL,
            user_id VARCHAR(100),
            ip INET,
            user_agent TEXT,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
            revoked_at TIMESTAMP WITH TIME ZONE
          )`
        ];

        for (const tableQuery of tables) {
          try {
            await queryWithTimeout(tableQuery);
          } catch (err) {
            logger.warn('Table creation error:', err.message);
          }
        }

        logger.info('✅ Tables created successfully');

        // Create indexes for performance
        const indexes = [
          { name: 'idx_links_expires', query: 'CREATE INDEX IF NOT EXISTS idx_links_expires ON links(expires_at) WHERE status = \'active\';' },
          { name: 'idx_links_status', query: 'CREATE INDEX IF NOT EXISTS idx_links_status ON links(status);' },
          { name: 'idx_links_mode', query: 'CREATE INDEX IF NOT EXISTS idx_links_mode ON links(link_mode);' },
          { name: 'idx_links_created', query: 'CREATE INDEX IF NOT EXISTS idx_links_created ON links(created_at DESC);' },
          { name: 'idx_clicks_link_id', query: 'CREATE INDEX IF NOT EXISTS idx_clicks_link_id ON clicks(link_id);' },
          { name: 'idx_clicks_ip', query: 'CREATE INDEX IF NOT EXISTS idx_clicks_ip ON clicks(ip);' },
          { name: 'idx_clicks_created', query: 'CREATE INDEX IF NOT EXISTS idx_clicks_created ON clicks(created_at DESC);' },
          { name: 'idx_clicks_country', query: 'CREATE INDEX IF NOT EXISTS idx_clicks_country ON clicks(country);' },
          { name: 'idx_clicks_device', query: 'CREATE INDEX IF NOT EXISTS idx_clicks_device ON clicks(device_type);' },
          { name: 'idx_analytics_type', query: 'CREATE INDEX IF NOT EXISTS idx_analytics_type ON analytics(type, created_at DESC);' },
          { name: 'idx_blocked_ips_expires', query: 'CREATE INDEX IF NOT EXISTS idx_blocked_ips_expires ON blocked_ips(expires_at);' },
          { name: 'idx_daily_stats_date', query: 'CREATE INDEX IF NOT EXISTS idx_daily_stats_date ON daily_stats(date DESC);' },
          { name: 'idx_user_sessions_session', query: 'CREATE INDEX IF NOT EXISTS idx_user_sessions_session ON user_sessions(session_id) WHERE revoked_at IS NULL;' },
          { name: 'idx_rate_limits_ip', query: 'CREATE INDEX IF NOT EXISTS idx_rate_limits_ip ON rate_limits(ip, created_at);' }
        ];

        for (const index of indexes) {
          try {
            await queryWithTimeout(index.query);
            logger.debug(`✅ Created index ${index.name}`);
          } catch (err) {
            logger.warn(`Could not create ${index.name}: ${err.message}`);
          }
        }

        logger.info('✅ Database initialization completed');
      } catch (err) {
        logger.error('Database initialization error:', err);
        throw err;
      }
    };

    // Run migrations
    createTables().catch(err => {
      logger.error('Failed to initialize database:', err);
    });

    // Health check
    dbHealthCheck = setInterval(async () => {
      try {
        await queryWithTimeout('SELECT 1', [], 2000);
        
        // Update connection pool metrics
        const poolStats = {
          total: dbPool.totalCount,
          idle: dbPool.idleCount,
          waiting: dbPool.waitingCount
        };
        
        databaseConnectionGauge.labels('total').set(poolStats.total);
        databaseConnectionGauge.labels('idle').set(poolStats.idle);
        databaseConnectionGauge.labels('waiting').set(poolStats.waiting);
        
        if (poolStats.waiting > CONFIG.DB_POOL_MAX * 0.8) {
          logger.warn('Database pool waiting count high:', poolStats.waiting);
        }
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
  // Update metrics
  if (type === 'request') {
    totalRequests.inc({ method: data.method || 'GET', path: data.path || 'unknown', status: data.status || 200 });
  } else if (type === 'bot') {
    botBlocks.inc({ reason: data.reason || 'unknown' });
  } else if (type === 'generate') {
    linkGenerations.inc({ mode: data.mode || 'short' });
    if (data.mode) {
      linkModeCounter.labels(data.mode).inc();
    }
  }

  if (!dbPool) return;

  try {
    await queryWithTimeout(
      'INSERT INTO analytics (type, data) VALUES ($1, $2)',
      [type, JSON.stringify(data)]
    );
    
    // Update daily stats
    const today = new Date().toISOString().split('T')[0];
    await queryWithTimeout(`
      INSERT INTO daily_stats (date, total_requests, unique_visitors, bot_blocks, links_created, clicks, data)
      VALUES ($1, 
        CASE WHEN $2 = 'request' THEN 1 ELSE 0 END,
        CASE WHEN $2 = 'request' AND $3->>'unique' = 'true' THEN 1 ELSE 0 END,
        CASE WHEN $2 = 'bot' THEN 1 ELSE 0 END,
        CASE WHEN $2 = 'generate' THEN 1 ELSE 0 END,
        CASE WHEN $2 = 'redirect' THEN 1 ELSE 0 END,
        jsonb_build_object('last_updated', NOW())
      )
      ON CONFLICT (date) DO UPDATE SET
        total_requests = daily_stats.total_requests + (CASE WHEN $2 = 'request' THEN 1 ELSE 0 END),
        bot_blocks = daily_stats.bot_blocks + (CASE WHEN $2 = 'bot' THEN 1 ELSE 0 END),
        links_created = daily_stats.links_created + (CASE WHEN $2 = 'generate' THEN 1 ELSE 0 END),
        clicks = daily_stats.clicks + (CASE WHEN $2 = 'redirect' THEN 1 ELSE 0 END),
        data = jsonb_set(daily_stats.data, '{last_updated}', to_jsonb(NOW())),
        updated_at = NOW()
    `, [today, type, JSON.stringify(data)]);
  } catch (err) {
    if (CONFIG.DEBUG) {
      logger.debug('Analytics update failed:', err.message);
    }
  }
}

// ─── Socket.IO Setup with Authentication and Namespaces ────────────────────
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
  serveClient: false,
  adapter: redisClient ? require('socket.io-redis')({ 
    pubClient: redisClient, 
    subClient: subscriber,
    key: 'socket.io'
  }) : undefined
});

// Redis pub/sub for cross-instance communication
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

// Socket.IO namespaces
const adminNamespace = io.of('/admin');
const publicNamespace = io.of('/public');

// Admin namespace authentication
adminNamespace.use((socket, next) => {
  const token = socket.handshake.auth.token;
  const sessionId = socket.handshake.auth.sessionId;
  
  if (token === CONFIG.METRICS_API_KEY) {
    return next();
  }
  
  // Check session
  if (sessionId) {
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
  
  // Send initial data
  socket.emit('stats', stats);
  socket.emit('config', getConfigForClient());
  
  // Get all links
  getAllLinks().then(links => {
    socket.emit('links', links);
  }).catch(err => {
    logger.error('Failed to fetch links:', err);
  });

  socket.on('disconnect', () => {
    logger.info('Admin client disconnected:', socket.id);
    activeConnections.labels('admin').dec();
  });

  socket.on('command', async (cmd) => {
    try {
      const result = await handleAdminCommand(cmd, socket);
      if (result) {
        socket.emit('commandResult', result);
      }
    } catch (err) {
      socket.emit('notification', { type: 'error', message: err.message });
    }
  });
});

// Public namespace (for real-time updates)
publicNamespace.on('connection', (socket) => {
  activeConnections.labels('public').inc();
  
  socket.on('disconnect', () => {
    activeConnections.labels('public').dec();
  });
});

// ─── Session Setup with Enhanced Security ───────────────────────────────────
app.set('trust proxy', CONFIG.TRUST_PROXY);
app.use(compression({ 
  level: 6, 
  threshold: 0,
  filter: (req, res) => {
    if (req.headers['x-no-compression']) return false;
    return compression.filter(req, res);
  }
}));

// Request logging with Morgan
app.use(morgan(CONFIG.LOG_FORMAT === 'json' ? 'combined' : 'dev', { 
  stream: { 
    write: message => {
      logger.info(message.trim());
      // Also log to audit file
      logger.log('audit', message.trim());
    }
  } 
}));

// Static files with caching
app.use(express.static('public', { 
  maxAge: '1d',
  etag: true,
  lastModified: true,
  immutable: true,
  setHeaders: (res, path) => {
    if (path.endsWith('.html')) {
      res.setHeader('Cache-Control', 'public, max-age=0, must-revalidate');
    }
    if (path.endsWith('.js') || path.endsWith('.css')) {
      res.setHeader('Cache-Control', 'public, max-age=31536000, immutable');
    }
  }
}));

// Request ID middleware
app.use((req, res, next) => {
  req.id = req.headers['x-request-id'] || uuidv4();
  res.setHeader('X-Request-ID', req.id);
  
  // Create request context
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
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token', 'X-Request-ID']
}));
app.use(cookieParser(CONFIG.SESSION_SECRET));

// Session configuration
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
    path: '/',
    domain: CONFIG.NODE_ENV === 'production' ? process.env.DOMAIN : undefined
  },
  rolling: true,
  unset: 'destroy',
  genid: (req) => {
    return uuidv4();
  }
};

// Add session absolute timeout
const sessionAbsoluteTimeout = (req, res, next) => {
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
};

app.use(session(sessionConfig));
app.use(sessionAbsoluteTimeout);

// Session rotation middleware
app.use((req, res, next) => {
  if (req.session && req.session.authenticated) {
    // Rotate session ID every hour
    const lastRotation = req.session.lastRotation || 0;
    if (Date.now() - lastRotation > 3600000) {
      const oldId = req.session.id;
      req.session.regenerate((err) => {
        if (err) {
          logger.error('Session rotation error:', err);
          return next(err);
        }
        req.session.lastRotation = Date.now();
        req.session.authenticated = true;
        req.session.user = req.session.user;
        
        // Log session rotation
        if (dbPool) {
          queryWithTimeout(
            'INSERT INTO user_sessions (session_id, user_id, ip, user_agent) VALUES ($1, $2, $3, $4) ON CONFLICT (session_id) DO UPDATE SET created_at = NOW()',
            [req.session.id, req.session.user, req.ip, req.headers['user-agent']]
          ).catch(() => {});
        }
        
        logger.info('Session rotated', { oldId, newId: req.session.id });
        next();
      });
    } else {
      next();
    }
  } else {
    next();
  }
});

// ─── Security Middleware - Block URL Parameters with Credentials ───────────
app.use((req, res, next) => {
  // Block any requests with username or password in query parameters
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
    
    // Log to database for security audit
    if (dbPool) {
      queryWithTimeout(
        'INSERT INTO logs (data) VALUES ($1)',
        [JSON.stringify({
          type: 'security_block',
          reason: 'credentials_in_url',
          ip: req.ip,
          path: req.path,
          params: Object.keys(req.query)
        })]
      ).catch(() => {});
    }
    
    if (req.path === '/admin/login') {
      return res.redirect('/admin/login?error=invalid_request');
    }
    
    return res.status(400).json({ 
      error: 'Invalid request format - credentials should not be in URL',
      code: 'CREDENTIALS_IN_URL',
      id: req.id
    });
  }
  next();
});

// ─── CSRF Protection with Double Submit Cookie ────────────────────────────
app.use((req, res, next) => {
  if (!req.session.csrfToken) {
    req.session.csrfToken = crypto.randomBytes(32).toString('hex');
  }
  
  // Set CSRF token in cookie and header
  res.cookie('XSRF-TOKEN', req.session.csrfToken, {
    secure: CONFIG.NODE_ENV === 'production',
    httpOnly: false,
    sameSite: 'lax',
    maxAge: 3600000 // 1 hour
  });
  
  res.locals.csrfToken = req.session.csrfToken;
  res.setHeader('X-CSRF-Token', req.session.csrfToken);
  next();
});

const csrfProtection = (req, res, next) => {
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
    return next();
  }
  
  // Check multiple sources
  const token = req.body._csrf || 
                req.query._csrf || 
                req.headers['csrf-token'] || 
                req.headers['xsrf-token'] ||
                req.headers['x-csrf-token'] ||
                req.headers['x-xsrf-token'] ||
                req.cookies['XSRF-TOKEN'];
  
  if (!token || token !== req.session.csrfToken) {
    logger.warn('CSRF validation failed:', { 
      id: req.id, 
      ip: req.ip, 
      path: req.path,
      method: req.method
    });
    
    // Log to database
    if (dbPool) {
      queryWithTimeout(
        'INSERT INTO logs (data) VALUES ($1)',
        [JSON.stringify({
          type: 'security_block',
          reason: 'csrf_failed',
          ip: req.ip,
          path: req.path,
          method: req.method
        })]
      ).catch(() => {});
    }
    
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

// ─── Input Validation Helpers ─────────────────────────────────────────────
const validateLinkId = (req, res, next) => {
  const { id } = req.params;
  if (!/^[a-f0-9]{32,64}$/i.test(id)) {
    throw new AppError('Invalid link ID format', 400, 'INVALID_LINK_ID');
  }
  next();
};

const validateUrl = (url) => {
  try {
    const parsed = new URL(url);
    if (!['http:', 'https:'].includes(parsed.protocol)) {
      return false;
    }
    // Block localhost/internal URLs
    const hostname = parsed.hostname.toLowerCase();
    if (hostname === 'localhost' || 
        hostname === '127.0.0.1' || 
        hostname === '::1' ||
        hostname.endsWith('.local') ||
        hostname.startsWith('10.') ||
        hostname.startsWith('192.168.') ||
        hostname.startsWith('172.16.')) {
      return false;
    }
    return true;
  } catch {
    return false;
  }
};

// ─── Bull Board Middleware ────────────────────────────────────────────────
if (serverAdapter && CONFIG.BULL_BOARD_ENABLED) {
  app.use(CONFIG.BULL_BOARD_PATH, (req, res, next) => {
    if (!req.session.authenticated) {
      return res.status(401).send('Unauthorized');
    }
    next();
  });
  
  app.use(CONFIG.BULL_BOARD_PATH, serverAdapter.getRouter());
}

// ─── Config Parsing ────────────────────────────────────────────────────────
const TARGET_URL = CONFIG.TARGET_URL;
const BOT_URLS = CONFIG.BOT_URLS ? 
  CONFIG.BOT_URLS.split(',').map(url => url.trim()) : [
    'https://www.microsoft.com',
    'https://www.apple.com',
    'https://www.google.com',
    'https://en.wikipedia.org/wiki/Main_Page',
    'https://www.bbc.com'
  ];

const LOG_FILE = 'logs/clicks.log';
const REQUEST_LOG_FILE = 'logs/requests.log';
const PORT = CONFIG.PORT;
const HOST = CONFIG.HOST;

const ADMIN_USERNAME = CONFIG.ADMIN_USERNAME;
const ADMIN_PASSWORD_HASH = CONFIG.ADMIN_PASSWORD_HASH;

// Link mode configuration
let LINK_LENGTH_MODE = CONFIG.LINK_LENGTH_MODE;
let ALLOW_LINK_MODE_SWITCH = CONFIG.ALLOW_LINK_MODE_SWITCH;
let LONG_LINK_SEGMENTS = CONFIG.LONG_LINK_SEGMENTS;
let LONG_LINK_PARAMS = CONFIG.LONG_LINK_PARAMS;
let LINK_ENCODING_LAYERS = CONFIG.LINK_ENCODING_LAYERS;

// Enhanced encoding options
let ENABLE_COMPRESSION = CONFIG.ENABLE_COMPRESSION;
let ENABLE_ENCRYPTION = CONFIG.ENABLE_ENCRYPTION;
const ENCRYPTION_KEY = CONFIG.ENCRYPTION_KEY;
let MAX_ENCODING_ITERATIONS = CONFIG.MAX_ENCODING_ITERATIONS;
let ENCODING_COMPLEXITY_THRESHOLD = CONFIG.ENCODING_COMPLEXITY_THRESHOLD;

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

const LINK_TTL_SEC = parseTTL(CONFIG.LINK_TTL);
const METRICS_API_KEY = CONFIG.METRICS_API_KEY;
const IPINFO_TOKEN = CONFIG.IPINFO_TOKEN;
const NODE_ENV = CONFIG.NODE_ENV;
const MAX_LINKS = CONFIG.MAX_LINKS;

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

// Cache instances with better configuration and monitoring
const geoCache = new NodeCache({ 
  stdTTL: 86400, 
  checkperiod: 3600, 
  useClones: false, 
  maxKeys: 100000,
  deleteOnExpire: true,
  errorOnMissing: false
});

const linkCache = new NodeCache({ 
  stdTTL: LINK_TTL_SEC, 
  checkperiod: Math.min(300, Math.floor(LINK_TTL_SEC * CONFIG.CACHE_CHECK_PERIOD_FACTOR)), 
  useClones: false, 
  maxKeys: MAX_LINKS,
  deleteOnExpire: true,
  errorOnMissing: false
});

const linkRequestCache = new NodeCache({ 
  stdTTL: 60, 
  checkperiod: 10, 
  useClones: false, 
  maxKeys: 10000,
  errorOnMissing: false
});

const failCache = new NodeCache({ 
  stdTTL: 3600, 
  checkperiod: 600, 
  useClones: false, 
  maxKeys: 10000,
  errorOnMissing: false
});

const deviceCache = new NodeCache({ 
  stdTTL: 300, 
  checkperiod: 60, 
  useClones: false, 
  maxKeys: 50000,
  errorOnMissing: false
});

const qrCache = new NodeCache({ 
  stdTTL: 3600, 
  checkperiod: 600, 
  useClones: false, 
  maxKeys: 1000,
  errorOnMissing: false
});

const encodingCache = new NodeCache({ 
  stdTTL: 3600, 
  checkperiod: 600, 
  maxKeys: 5000,
  useClones: false,
  errorOnMissing: false
});

// Cache monitoring
const cacheStats = {
  geo: { hits: 0, misses: 0 },
  link: { hits: 0, misses: 0 },
  linkReq: { hits: 0, misses: 0 },
  device: { hits: 0, misses: 0 },
  qr: { hits: 0, misses: 0 },
  encoding: { hits: 0, misses: 0 }
};

// Wrap cache get with stats
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

// Login attempt tracking with Redis for distributed environments
const loginAttempts = redisClient ? 
  new Map() : // Fallback to memory if no Redis
  new Map();

// Clean up old login attempts every hour
setInterval(() => {
  const now = Date.now();
  for (const [ip, data] of loginAttempts.entries()) {
    if (now - data.lastAttempt > CONFIG.LOGIN_BLOCK_DURATION) {
      loginAttempts.delete(ip);
    }
  }
}, 3600000);

// Stats Tracking with more comprehensive metrics
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
  }
};

// Memory monitoring
setInterval(() => {
  const memUsage = process.memoryUsage();
  stats.realtime.currentMemory = memUsage.heapUsed;
  stats.realtime.peakMemory = Math.max(stats.realtime.peakMemory, memUsage.heapUsed);
  
  // Update Prometheus metrics
  memoryUsageGauge.labels('rss').set(memUsage.rss);
  memoryUsageGauge.labels('heapTotal').set(memUsage.heapTotal);
  memoryUsageGauge.labels('heapUsed').set(memUsage.heapUsed);
  memoryUsageGauge.labels('external').set(memUsage.external);
  
  // Check thresholds
  const heapUsedPercent = memUsage.heapUsed / memUsage.heapTotal;
  if (heapUsedPercent > CONFIG.MEMORY_THRESHOLD_CRITICAL) {
    logger.error('Critical memory usage!', {
      heapUsed: memUsage.heapUsed,
      heapTotal: memUsage.heapTotal,
      percent: heapUsedPercent
    });
    
    // Trigger heap dump for debugging
    if (CONFIG.NODE_ENV === 'development') {
      const filename = `heapdump-${Date.now()}.heapsnapshot`;
      heapdump.writeSnapshot(path.join('logs', filename), (err, filename) => {
        if (err) logger.error('Heap dump failed:', err);
        else logger.info('Heap dump saved:', filename);
      });
    }
  } else if (heapUsedPercent > CONFIG.MEMORY_THRESHOLD_WARNING) {
    logger.warn('High memory usage!', {
      heapUsed: memUsage.heapUsed,
      heapTotal: memUsage.heapTotal,
      percent: heapUsedPercent
    });
  }
}, 5000);

// CPU monitoring
let lastCPUUsage = process.cpuUsage();
setInterval(() => {
  const cpuUsage = process.cpuUsage(lastCPUUsage);
  lastCPUUsage = process.cpuUsage();
  
  const totalCPU = (cpuUsage.user + cpuUsage.system) / 1000000; // Convert to seconds
  const cpuPercent = (totalCPU / 5) * 100; // Over 5 second interval
  
  stats.system.cpu = cpuPercent;
  cpuUsageGauge.set(cpuPercent);
  
  if (cpuPercent > CONFIG.CPU_THRESHOLD_CRITICAL) {
    logger.error('Critical CPU usage!', { cpuPercent });
  } else if (cpuPercent > CONFIG.CPU_THRESHOLD_WARNING) {
    logger.warn('High CPU usage!', { cpuPercent });
  }
}, 5000);

// Admin command handler
async function handleAdminCommand(cmd, socket) {
  switch(cmd.action) {
    case 'clearCache':
      linkCache.flushAll();
      geoCache.flushAll();
      deviceCache.flushAll();
      qrCache.flushAll();
      encodingCache.flushAll();
      Object.keys(cacheStats).forEach(k => {
        cacheStats[k].hits = 0;
        cacheStats[k].misses = 0;
      });
      stats.caches = { geo: 0, linkReq: 0, device: 0, qr: 0, encoding: 0 };
      socket.emit('notification', { type: 'success', message: 'Cache cleared successfully' });
      break;
      
    case 'getStats':
      socket.emit('stats', stats);
      break;
      
    case 'getConfig':
      socket.emit('config', getConfigForClient());
      break;
      
    case 'getLinks':
      const links = await getAllLinks();
      socket.emit('links', links);
      break;
      
    case 'getCacheStats':
      socket.emit('cacheStats', cacheStats);
      break;
      
    case 'getSystemMetrics':
      socket.emit('systemMetrics', {
        memory: process.memoryUsage(),
        cpu: stats.system.cpu,
        uptime: process.uptime(),
        connections: stats.realtime.activeLinks,
        rps: stats.realtime.requestsPerSecond
      });
      break;
      
    case 'reloadConfig':
      const result = await reloadConfig();
      if (result.success) {
        socket.emit('notification', { type: 'success', message: 'Configuration reloaded' });
      } else {
        socket.emit('notification', { type: 'error', message: 'Config reload failed' });
      }
      break;
      
    default:
      socket.emit('notification', { type: 'error', message: 'Unknown command' });
  }
}

function getConfigForClient() {
  return {
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
    uptime: process.uptime(),
    version: '4.0.0',
    nodeEnv: NODE_ENV,
    databaseEnabled: !!dbPool,
    redisEnabled: !!redisClient,
    queuesEnabled: !!redirectQueue
  };
}

// Update realtime stats
setInterval(() => {
  stats.realtime.activeLinks = linkCache.keys().length;
  
  // Keep last minute data bounded
  if (stats.realtime.lastMinute.length > 60) {
    stats.realtime.lastMinute = stats.realtime.lastMinute.slice(-60);
  }
  
  stats.caches = {
    geo: geoCache.keys().length,
    linkReq: linkCache.keys().length,
    device: deviceCache.keys().length,
    qr: qrCache.keys().length,
    encoding: encodingCache.keys().length
  };
  
  const now = Date.now();
  const lastSecond = stats.realtime.lastMinute.filter(t => now - t.time < 1000);
  stats.realtime.requestsPerSecond = lastSecond.reduce((sum, t) => sum + t.requests, 0);
  
  if (stats.realtime.requestsPerSecond > stats.realtime.peakRPS) {
    stats.realtime.peakRPS = stats.realtime.requestsPerSecond;
  }
  
  // Calculate business metrics rates
  if (dbPool) {
    queryWithTimeout(
      `SELECT 
        COUNT(*) FILTER (WHERE type = 'generate' AND created_at > NOW() - INTERVAL '1 minute') as generate_count,
        COUNT(*) FILTER (WHERE type = 'bot' AND created_at > NOW() - INTERVAL '1 minute') as bot_count,
        COUNT(*) FILTER (WHERE type = 'redirect' AND created_at > NOW() - INTERVAL '1 minute') as redirect_count
       FROM analytics`
    ).then(result => {
      if (result.rows[0]) {
        businessMetrics.linkCreationRate.labels('all').set(result.rows[0].generate_count);
        businessMetrics.botDetectionRate.labels('all').set(result.rows[0].bot_count);
        businessMetrics.redirectRate.labels('all', 'success').set(result.rows[0].redirect_count);
      }
    }).catch(err => {
      logger.error('Failed to fetch business metrics:', err);
    });
  }
  
  io.of('/admin').emit('stats', stats);
}, 1000);

// Calculate percentiles with bounded array
setInterval(() => {
  if (stats.performance.responseTimes.length > 0) {
    const sorted = [...stats.performance.responseTimes].sort((a, b) => a - b);
    const p95Index = Math.floor(sorted.length * 0.95);
    const p99Index = Math.floor(sorted.length * 0.99);
    stats.performance.p95ResponseTime = sorted[p95Index] || 0;
    stats.performance.p99ResponseTime = sorted[p99Index] || 0;
    
    // Keep only last 10000 response times
    if (stats.performance.responseTimes.length > CONFIG.MAX_RESPONSE_TIMES_HISTORY) {
      stats.performance.responseTimes = stats.performance.responseTimes.slice(-CONFIG.MAX_RESPONSE_TIMES_HISTORY);
    }
  }
}, 60000);

// Device Detection with enhanced patterns and caching
function getDeviceInfo(req) {
  const ua = req.headers['user-agent'] || '';
  
  const cacheKey = createHash('md5').update(ua.substring(0, 200)).digest('hex');
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
  
  // Enhanced bot detection patterns
  const botPatterns = [
    'headless', 'phantom', 'slurp', 'zgrab', 'scanner', 'bot', 'crawler', 
    'spider', 'burp', 'sqlmap', 'curl', 'wget', 'python', 'perl', 'ruby', 
    'go-http-client', 'java', 'okhttp', 'scrapy', 'httpclient', 'axios',
    'node-fetch', 'php', 'libwww', 'wget', 'fetch', 'ahrefs', 'semrush',
    'puppeteer', 'selenium', 'playwright', 'cypress', 'headless', 'pupeteer',
    'chrome-lighthouse', 'lighthouse', 'pagespeed', 'webpage', 'gtmetrix',
    'googlebot', 'bingbot', 'slurp', 'duckduckbot', 'baiduspider',
    'yandexbot', 'facebookexternalhit', 'twitterbot', 'linkedinbot',
    'whatsapp', 'telegram', 'slack', 'discord', 'skype', 'facebook',
    'instagram', 'pinterest', 'reddit', 'tumblr', 'flipboard'
  ];
  
  // Check for bot patterns
  if (botPatterns.some(pattern => uaLower.includes(pattern))) {
    deviceInfo.type = 'bot';
    deviceInfo.isBot = true;
    deviceInfo.score = 100;
    cacheSet(deviceCache, 'device', cacheKey, deviceInfo);
    stats.byDevice.bot = (stats.byDevice.bot || 0) + 1;
    return deviceInfo;
  }

  // Mobile/tablet detection
  if (result.device.type === 'mobile' || /Mobi|Android|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(ua)) {
    if (result.device.type === 'tablet' || /Tablet|iPad|PlayBook|Silk|Kindle|(Android(?!.*Mobile))/i.test(ua)) {
      deviceInfo.type = 'tablet';
      deviceInfo.isTablet = true;
    } else {
      deviceInfo.type = 'mobile';
      deviceInfo.isMobile = true;
    }
  }

  // Calculate trust score for mobile devices
  if (deviceInfo.isMobile) {
    if (deviceInfo.brand !== 'unknown') deviceInfo.score -= 10;
    if (deviceInfo.model !== 'unknown') deviceInfo.score -= 10;
    if (deviceInfo.os !== 'unknown') deviceInfo.score -= 5;
    if (deviceInfo.browser !== 'unknown') deviceInfo.score -= 5;
    
    if (deviceInfo.browser.includes('Safari') || 
        deviceInfo.browser.includes('Chrome') || 
        deviceInfo.browser.includes('Firefox') ||
        deviceInfo.browser.includes('Edge')) {
      deviceInfo.score -= 15;
    }
    
    if (deviceInfo.os.includes('iOS') || 
        deviceInfo.os.includes('Android') ||
        deviceInfo.os.includes('iPadOS')) {
      deviceInfo.score -= 15;
    }
    
    if (deviceInfo.brand.includes('Apple') || 
        deviceInfo.brand.includes('Samsung') || 
        deviceInfo.brand.includes('Huawei') ||
        deviceInfo.brand.includes('Xiaomi') ||
        deviceInfo.brand.includes('Google') ||
        deviceInfo.brand.includes('OnePlus') ||
        deviceInfo.brand.includes('Oppo') ||
        deviceInfo.brand.includes('Vivo') ||
        deviceInfo.brand.includes('Motorola') ||
        deviceInfo.brand.includes('Nokia')) {
      deviceInfo.score -= 20;
    }
  }

  cacheSet(deviceCache, 'device', cacheKey, deviceInfo);
  stats.byDevice[deviceInfo.type] = (stats.byDevice[deviceInfo.type] || 0) + 1;
  
  return deviceInfo;
}

// Custom Error Class
class AppError extends Error {
  constructor(message, statusCode, code = 'INTERNAL_ERROR', isOperational = true) {
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
  constructor(message) {
    super(message, 400, 'VALIDATION_ERROR');
  }
}

class RateLimitError extends AppError {
  constructor(message, retryAfter) {
    super(message, 429, 'RATE_LIMIT_ERROR');
    this.retryAfter = retryAfter;
  }
}

// Request middleware
app.use((req, res, next) => {
  // Set request context
  sessionNamespace.set('id', req.id);
  sessionNamespace.set('ip', req.ip);
  sessionNamespace.set('startTime', Date.now());
  
  req.startTime = Date.now();
  req.deviceInfo = getDeviceInfo(req);
  res.locals.nonce = crypto.randomBytes(16).toString('hex');
  res.locals.startTime = Date.now();
  res.locals.deviceInfo = req.deviceInfo;
  
  // Security headers
  res.setHeader('X-Request-ID', req.id);
  res.setHeader('X-Device-Type', req.deviceInfo.type);
  res.setHeader('X-Powered-By', 'Redirector-Pro');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
  
  totalRequests.inc({ method: req.method, path: req.path, status: 'pending' });
  stats.totalRequests++;
  
  // Add to realtime stats
  const now = Date.now();
  if (stats.realtime.lastMinute.length === 0 || now - stats.realtime.lastMinute[stats.realtime.lastMinute.length - 1].time > 1000) {
    stats.realtime.lastMinute.push({
      time: now,
      requests: 1,
      blocks: 0,
      successes: 0
    });
  } else {
    stats.realtime.lastMinute[stats.realtime.lastMinute.length - 1].requests++;
  }
  
  if (analyticsQueue) {
    analyticsQueue.add({ 
      type: 'request', 
      data: { 
        id: req.id, 
        device: req.deviceInfo.type,
        path: req.path,
        method: req.method
      } 
    }).catch(() => {});
  }
  
  next();
});

// Response time tracking
app.use(responseTime((req, res, time) => {
  if (req.route?.path) {
    httpRequestDurationMicroseconds
      .labels(req.method, req.route.path, res.statusCode)
      .observe(time);
  }
  
  // Update metrics with final status
  totalRequests.inc({ method: req.method, path: req.path, status: res.statusCode });
  
  // Track performance metrics
  stats.performance.totalResponseTime += time;
  stats.performance.avgResponseTime = stats.performance.totalResponseTime / stats.totalRequests;
  stats.performance.responseTimes.push(time);
  
  // Trim response times array if needed
  if (stats.performance.responseTimes.length > CONFIG.MAX_RESPONSE_TIMES_HISTORY) {
    stats.performance.responseTimes = stats.performance.responseTimes.slice(-CONFIG.MAX_RESPONSE_TIMES_HISTORY);
  }
}));

// Helmet configuration
const helmetConfig = {
  contentSecurityPolicy: CONFIG.CSP_ENABLED ? {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: [
        "'self'",
        (req, res) => `'nonce-${res.locals.nonce}'`,
        'https://cdn.socket.io',
        'https://cdn.jsdelivr.net',
        'https://cdnjs.cloudflare.com',
        'https://fonts.googleapis.com',
        'https://fonts.gstatic.com',
        'https://code.jquery.com',
        'https://unpkg.com',
        'https://www.google.com',
        'https://www.gstatic.com'
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
        'https:',
        'http:'
      ],
      connectSrc: [
        "'self'",
        'ws:',
        'wss:',
        'https://cdn.socket.io',
        'https://cdn.jsdelivr.net',
        'https://ipinfo.io',
        'https://api.ipify.org'
      ],
      frameSrc: ["'none'"],
      objectSrc: ["'none'"],
      upgradeInsecureRequests: NODE_ENV === 'production' ? [] : null
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
  frameguard: { action: 'deny' },
  ieNoOpen: true,
  dnsPrefetchControl: { allow: false },
  permittedCrossDomainPolicies: { permittedPolicies: 'none' },
  expectCt: {
    maxAge: 86400,
    enforce: true,
    reportUri: '/report-ct-violation'
  }
};

app.use(helmet(helmetConfig));

// Body parsers with limits
app.use(express.json({ limit: '100kb' }));
app.use(express.urlencoded({ extended: true, limit: '100kb' }));

// Rate Limiting with express-slow-down and express-rate-limit
const speedLimiter = slowDown({
  windowMs: 15 * 60 * 1000,
  delayAfter: 50,
  delayMs: (hits) => hits * 100,
  skip: (req) => req.deviceInfo?.isBot
});

const strictLimiter = rateLimit({
  windowMs: CONFIG.RATE_LIMIT_WINDOW || 60000,
  max: (req) => {
    if (req.deviceInfo?.isBot) return CONFIG.RATE_LIMIT_BOT || 2;
    if (req.deviceInfo?.isMobile) return CONFIG.RATE_LIMIT_MOBILE || 30;
    if (req.deviceInfo?.isTablet) return 25;
    return CONFIG.RATE_LIMIT_MAX || 15;
  },
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: true,
  keyGenerator: (req) => {
    return req.headers['x-forwarded-for']?.split(',')[0] || req.ip || 'unknown';
  },
  handler: (req, res) => {
    logRequest('rate-limit', req, res, { limit: req.rateLimit.limit });
    botBlocks.inc({ reason: 'rate_limit' });
    res.redirect(BOT_URLS[Math.floor(Math.random() * BOT_URLS.length)]);
  }
});

const encodingLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: CONFIG.ENCODING_RATE_LIMIT,
  keyGenerator: (req) => req.session?.user || req.ip || 'unknown',
  handler: (req, res) => {
    res.status(429).json({ 
      error: 'Too many encoding requests. Please slow down.',
      retryAfter: Math.ceil(60000 / 1000)
    });
  }
});

const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => req.session?.user || req.ip || 'unknown'
});

app.use(speedLimiter);
app.use(rateLimiterMiddleware);
app.use('/api/', apiLimiter);

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
    
    // Emit to admin namespace
    io.of('/admin').emit('log', logEntry);
    
    // Write to file asynchronously (don't await)
    fs.appendFile(REQUEST_LOG_FILE, JSON.stringify(logEntry) + '\n').catch(() => {});
    
    // Log to database asynchronously
    logToDatabase(logEntry).catch(() => {});
    
    if (CONFIG.DEBUG) {
      logger.debug(`[${type}] ${ip} ${req.method} ${req.path} (${duration}ms)`);
    }
  } catch (err) {
    logger.error('Logging error:', err);
  }
}

// Bot Detection with enhanced scoring
function isLikelyBot(req) {
  const deviceInfo = req.deviceInfo;
  
  if (deviceInfo.isBot) {
    stats.botBlocks++;
    botBlocks.inc({ reason: 'explicit_bot' });
    if (analyticsQueue) {
      analyticsQueue.add({ type: 'bot', data: { reason: 'explicit_bot' } }).catch(() => {});
    }
    return true;
  }

  const h = req.headers;
  let score = deviceInfo.score;
  const reasons = [];

  // Mobile-specific checks
  if (deviceInfo.isMobile) {
    if (deviceInfo.brand !== 'unknown') score -= 20;
    if (deviceInfo.os.includes('iOS') || deviceInfo.os.includes('Android')) score -= 30;
    if (deviceInfo.browser.includes('Safari') || deviceInfo.browser.includes('Chrome') || deviceInfo.browser.includes('Firefox')) score -= 20;
    if (!h['sec-ch-ua-mobile']) score += 5;
    if (!h['accept-language']) score += 10;
    if (!h['accept']) score += 5;
    
    if (CONFIG.DEBUG) {
      logger.debug(`[MOBILE-DEVICE] ${deviceInfo.brand} ${deviceInfo.model} | Score: ${score}`);
    }
    
    return score >= 20;
  }

  // Desktop checks
  if (!h['sec-ch-ua'] || !h['sec-ch-ua-mobile'] || !h['sec-ch-ua-platform']) {
    score += 25;
    reasons.push('missing_sec_headers');
  }
  
  if (!h['accept'] || !h['accept-language'] || (h['accept-language'] && h['accept-language'].length < 5)) {
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

  // Check for headless Chrome patterns
  if (h['user-agent'] && h['user-agent'].includes('HeadlessChrome')) {
    score += 30;
    reasons.push('headless_chrome');
  }

  // Check for automation tools
  if (h['user-agent'] && (h['user-agent'].includes('selenium') || h['user-agent'].includes('webdriver'))) {
    score += 40;
    reasons.push('automation_tool');
  }

  // Check for missing cookies
  if (!req.cookies || Object.keys(req.cookies).length === 0) {
    score += 15;
    reasons.push('no_cookies');
  }

  const botThreshold = 65;
  const isBot = score >= botThreshold;
  
  if (isBot) {
    stats.botBlocks++;
    botBlocks.inc({ reason: reasons[0] || 'unknown' });
    reasons.forEach(r => stats.byBotReason[r] = (stats.byBotReason[r] || 0) + 1);
    
    if (analyticsQueue) {
      analyticsQueue.add({ type: 'bot', data: { score, reasons } }).catch(() => {});
    }
  }
  
  if (CONFIG.DEBUG) {
    logger.debug(`[BOT-SCORE] ${score} | ${reasons.join(',') || 'clean'} | Threshold:${botThreshold} | IsBot:${isBot} | Device:${deviceInfo.type}`);
  }

  return isBot;
}

// Geolocation with failover and circuit breaker
async function getCountryCode(req) {
  const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip || '0.0.0.0';
  
  if (ip.startsWith('10.') || ip.startsWith('192.168.') || ip === '127.0.0.1' || ip === '::1' || ip === '0.0.0.0') {
    return 'PRIVATE';
  }

  let cc = cacheGet(geoCache, 'geo', ip);
  if (cc) return cc;

  const failKey = `fail:${ip}`;
  if (cacheGet(failCache, 'fail', failKey) >= 3 || !IPINFO_TOKEN) {
    return 'XX';
  }

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 1500);

    const response = await fetch(`https://ipinfo.io/${ip}/json?token=${IPINFO_TOKEN}`, {
      signal: controller.signal,
      headers: { 'User-Agent': 'Redirector-Pro/4.0' }
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
    cacheSet(failCache, 'fail', failKey, (cacheGet(failCache, 'fail', failKey) || 0) + 1);
  } catch (err) {
    logger.debug('Geo lookup failed:', err.message);
    cacheSet(failCache, 'fail', failKey, (cacheGet(failCache, 'fail', failKey) || 0) + 1);
  }
  return 'XX';
}

// ─── ENHANCED ENCODING/DECODING SYSTEM ──────────────────────────────────────

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
  },
  
  // Base32
  { 
    name: 'base32', 
    enc: s => {
      // Note: This requires 'base32-encode' package
      // For now, fallback to base64
      return Buffer.from(s).toString('base64');
    },
    dec: s => {
      return Buffer.from(s, 'base64').toString();
    },
    complexity: 3
  },
  
  // ROT47 (for ASCII printable characters)
  { 
    name: 'rot47', 
    enc: s => s.replace(/[!-~]/g, c => 
      String.fromCharCode(33 + ((c.charCodeAt(0) - 33 + 47) % 94))
    ),
    dec: s => s.replace(/[!-~]/g, c => 
      String.fromCharCode(33 + ((c.charCodeAt(0) - 33 - 47 + 94) % 94))
    ),
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
    version: '4.0.0'
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
  businessMetrics.encodingQuality.labels('complexity').set(encodingMetadata.complexity);
  businessMetrics.encodingQuality.labels('layers').set(encodingLayers.length);
  businessMetrics.encodingQuality.labels('iterations').set(iterations);
  
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
    throw new AppError('Decoding failed', 400, 'DECODE_ERROR');
  }
}

/**
 * Generate long tracking link with enhanced encoding
 */
async function generateLongLink(targetUrl, req, options = {}) {
  const startTime = performance.now();
  
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
  const cached = cacheGet(encodingCache, 'encoding', cacheKey);
  if (cached) {
    stats.encodingStats.cacheHits++;
    logger.debug('Using cached encoding result');
    return cached;
  }
  stats.encodingStats.cacheMisses++;

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
      encodingTime: performance.now() - startTime
    },
    encodingMetadata
  };

  // Cache the result
  cacheSet(encodingCache, 'encoding', cacheKey, result, 3600);

  logger.info(`[LONG LINK] Generated - Length: ${url.length} chars | Layers: ${layers.length} | Complexity: ${complexity} | Time: ${performance.now() - startTime}ms`);

  return result;
}

/**
 * Generate short link (original method)
 */
function generateShortLink(targetUrl, req) {
  const startTime = performance.now();
  const { encoded } = multiLayerEncode(targetUrl + '#' + Date.now());
  const id = crypto.randomBytes(16).toString('hex');
  const url = `${req.protocol}://${req.get('host')}/v/${id}`;
  
  stats.encodingStats.totalEncoded++;
  
  return {
    url,
    metadata: {
      length: url.length,
      id,
      encodingTime: performance.now() - startTime
    }
  };
}

/**
 * Decode and extract target from long link with enhanced decoding
 */
async function decodeLongLink(req) {
  const startTime = performance.now();
  
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
      
      const decodeTime = performance.now() - startTime;
      
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

// Detailed health check
app.get('/health/full', async (req, res) => {
  if (!req.session.authenticated) {
    throw new AppError('Unauthorized', 401);
  }
  
  const checks = {
    database: false,
    redis: false,
    queues: false,
    encoding: false,
    caches: false,
    diskSpace: false
  };
  
  // Database check
  if (dbPool) {
    try {
      await queryWithTimeout('SELECT 1', [], 2000);
      checks.database = true;
    } catch (err) {
      checks.database = err.message;
    }
  } else {
    checks.database = 'disabled';
  }
  
  // Redis check
  if (redisClient) {
    try {
      const result = await redisBreaker.fire('ping');
      checks.redis = result === 'PONG';
    } catch (err) {
      checks.redis = err.message;
    }
  } else {
    checks.redis = 'disabled';
  }
  
  // Queue check
  if (redirectQueue) {
    try {
      const counts = await redirectQueue.getJobCounts();
      checks.queues = counts;
    } catch (err) {
      checks.queues = err.message;
    }
  } else {
    checks.queues = 'disabled';
  }
  
  // Encoding check
  try {
    const testString = 'https://test.com';
    const { encoded } = advancedMultiLayerEncode(testString, {
      minLayers: 2,
      maxLayers: 3,
      iterations: 1
    });
    checks.encoding = encoded.length > 0;
  } catch (err) {
    checks.encoding = err.message;
  }
  
  // Cache check
  try {
    const testKey = 'health-check';
    cacheSet(linkCache, 'link', testKey, 'test', 1);
    const testValue = cacheGet(linkCache, 'link', testKey);
    checks.caches = testValue === 'test';
    linkCache.del(testKey);
  } catch (err) {
    checks.caches = err.message;
  }
  
  // Disk space check
  try {
    const stats = await fs.statfs('/');
    const freePercent = (stats.bfree / stats.blocks) * 100;
    checks.diskSpace = freePercent > 10; // At least 10% free space
  } catch (err) {
    checks.diskSpace = err.message;
  }
  
  const allHealthy = Object.values(checks).every(v => v === true || v === 'disabled');
  
  res.status(allHealthy ? 200 : 503).json({
    status: allHealthy ? 'healthy' : 'degraded',
    checks,
    timestamp: Date.now(),
    uptime: process.uptime()
  });
});

// Health check for encoding system
app.get('/health/encoding', (req, res) => {
  const testString = 'https://test.com';
  const start = performance.now();
  
  try {
    const { encoded } = advancedMultiLayerEncode(testString, {
      minLayers: 2,
      maxLayers: 3,
      iterations: 1
    });
    
    res.json({
      status: 'healthy',
      duration: performance.now() - start,
      test: 'passed',
      resultLength: encoded.length
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
    throw new AppError('Forbidden', 403, 'FORBIDDEN');
  }

  const metrics = {
    version: '4.0.0',
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
    cacheStats,
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
    config: getConfigForClient(),
    prometheus: await register.metrics()
  };
  
  res.set('Content-Type', register.contentType);
  res.send(await register.metrics());
});

// Generate Link - WITH LONG/SHORT LINK OPTION
app.post('/api/generate', csrfProtection, encodingLimiter, [
  body('url').optional().custom(validateUrl).withMessage('Valid URL required'),
  body('password').optional().isString().isLength({ min: 6 }).withMessage('Password must be at least 6 characters'),
  body('maxClicks').optional().isInt({ min: 1, max: 10000 }).withMessage('Max clicks must be between 1 and 10000'),
  body('expiresIn').optional().isString(),
  body('notes').optional().isString().trim().customSanitizer(v => sanitizeHtml(v, { allowedTags: [], allowedAttributes: {} })),
  body('linkMode').optional().isIn(['short', 'long', 'auto']).withMessage('Link mode must be short, long, or auto'),
  body('longLinkOptions').optional().isObject()
], async (req, res, next) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw new ValidationError(errors.array()[0].msg);
    }

    const target = req.body.url || TARGET_URL;
    
    // Validate target URL
    if (!validateUrl(target)) {
      throw new ValidationError('Invalid target URL');
    }
    
    const password = req.body.password;
    const maxClicks = req.body.maxClicks;
    const expiresIn = req.body.expiresIn ? parseTTL(req.body.expiresIn) : LINK_TTL_SEC;
    const notes = req.body.notes || '';
    
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
      if (encodingQueue && (longLinkOptions.iterations > 2 || longLinkOptions.maxLayers > 6)) {
        const job = await encodingQueue.add({ targetUrl: target, req, options: longLinkOptions });
        const result = await job.finished();
        generatedUrl = result.url;
        linkMetadata = result.metadata;
        encodingMetadata = result.encodingMetadata;
      } else {
        const result = await encodingBreaker.fire(target, req, longLinkOptions);
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
      passwordHash: password ? await bcrypt.hash(password, CONFIG.BCRYPT_ROUNDS) : null,
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
    
    cacheSet(linkCache, 'link', cacheId, linkData, expiresIn);
    
    if (dbPool) {
      try {
        await queryWithTimeout(
          `INSERT INTO links 
           (id, target_url, created_at, expires_at, creator_ip, password_hash, max_clicks, current_clicks, link_mode, link_metadata, encoding_metadata, metadata, encoding_complexity, user_agent, referer) 
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)`,
          [cacheId, target, new Date(), new Date(Date.now() + (expiresIn * 1000)), req.ip, linkData.passwordHash, linkData.maxClicks, 0, linkMode, JSON.stringify(linkMetadata), JSON.stringify(encodingMetadata), JSON.stringify(linkData.metadata), encodingMetadata.complexity || 0, req.headers['user-agent'], req.headers['referer']]
        );
      } catch (dbErr) {
        logger.error('Database insert error:', dbErr);
        // Don't fail the request if DB insert fails
      }
    }
    
    stats.generatedLinks++;
    linkGenerations.inc({ mode: linkMode });
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
    
    io.of('/admin').emit('link-generated', response);
    
    // Publish to Redis for cross-instance communication
    if (subscriber) {
      subscriber.publish('redirector:events', JSON.stringify({
        type: 'link-generated',
        data: response
      })).catch(() => {});
    }
    
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
      }).catch(() => {});
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
    const requestCount = cacheGet(linkRequestCache, 'linkReq', ipKey) || 0;
    
    if (requestCount >= 3) {
      logRequest('rate-limit', req, res, { path: 'r', count: requestCount });
      botBlocks.inc({ reason: 'rate_limit' });
      return res.redirect(BOT_URLS[Math.floor(Math.random() * BOT_URLS.length)]);
    }
    
    cacheSet(linkRequestCache, 'linkReq', ipKey, requestCount + 1);

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
      }).catch(() => {});
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

    if (CONFIG.DISABLE_DESKTOP_CHALLENGE) {
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
app.get('/api/stats/:id', validateLinkId, async (req, res, next) => {
  try {
    const linkId = req.params.id;
    
    const linkData = cacheGet(linkCache, 'link', linkId);
    
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
        const result = await queryWithTimeout(
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
        
        const recentResult = await queryWithTimeout(
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
app.delete('/api/links/:id', csrfProtection, validateLinkId, async (req, res, next) => {
  try {
    const linkId = req.params.id;
    
    if (!req.session.authenticated) {
      throw new AppError('Unauthorized', 401, 'UNAUTHORIZED');
    }
    
    linkCache.del(linkId);
    
    if (dbPool) {
      await queryWithTimeout('DELETE FROM links WHERE id = $1', [linkId]);
    }
    
    io.of('/admin').emit('link-deleted', { id: linkId });
    
    // Publish to Redis for cross-instance communication
    if (subscriber) {
      subscriber.publish('redirector:events', JSON.stringify({
        type: 'link-deleted',
        data: { id: linkId }
      })).catch(() => {});
    }
    
    res.json({ success: true });
  } catch (err) {
    next(err);
  }
});

// Update Link
app.put('/api/links/:id', csrfProtection, validateLinkId, async (req, res, next) => {
  try {
    const linkId = req.params.id;
    const { maxClicks, notes, status } = req.body;
    
    if (!req.session.authenticated) {
      throw new AppError('Unauthorized', 401, 'UNAUTHORIZED');
    }
    
    const linkData = cacheGet(linkCache, 'link', linkId);
    if (!linkData) {
      throw new AppError('Link not found', 404, 'LINK_NOT_FOUND');
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
    
    cacheSet(linkCache, 'link', linkId, linkData, Math.max(1, Math.floor((linkData.expiresAt - Date.now()) / 1000)));
    
    if (dbPool) {
      await queryWithTimeout(
        'UPDATE links SET max_clicks = $1, metadata = metadata || $2 WHERE id = $3',
        [maxClicks, JSON.stringify({ notes: linkData.notes }), linkId]
      );
    }
    
    io.of('/admin').emit('link-updated', { id: linkId, ...linkData });
    
    // Publish to Redis for cross-instance communication
    if (subscriber) {
      subscriber.publish('redirector:events', JSON.stringify({
        type: 'link-updated',
        data: { id: linkId, ...linkData }
      })).catch(() => {});
    }
    
    res.json({ success: true });
  } catch (err) {
    next(err);
  }
});

// Get Settings
app.get('/api/settings', async (req, res, next) => {
  try {
    if (!req.session.authenticated) {
      throw new AppError('Unauthorized', 401, 'UNAUTHORIZED');
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
      desktopChallenge: !CONFIG.DISABLE_DESKTOP_CHALLENGE,
      
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
      },
      
      rateLimits: {
        window: CONFIG.RATE_LIMIT_WINDOW,
        max: CONFIG.RATE_LIMIT_MAX_REQUESTS,
        bot: CONFIG.RATE_LIMIT_BOT,
        mobile: CONFIG.RATE_LIMIT_MOBILE,
        encoding: CONFIG.ENCODING_RATE_LIMIT
      },
      
      session: {
        ttl: CONFIG.SESSION_TTL,
        absoluteTimeout: CONFIG.SESSION_ABSOLUTE_TIMEOUT
      }
    };
    
    if (dbPool) {
      const dbSettings = await queryWithTimeout('SELECT key, value FROM settings');
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
      throw new AppError('Unauthorized', 401, 'UNAUTHORIZED');
    }
    
    const { key, value } = req.body;
    
    // Validate key
    const allowedKeys = ['botThresholds', 'linkLengthMode', 'allowLinkModeSwitch', 'longLinkSegments', 
                        'longLinkParams', 'linkEncodingLayers', 'enableCompression', 'enableEncryption', 
                        'maxEncodingIterations', 'encodingComplexityThreshold'];
    
    if (!allowedKeys.includes(key)) {
      throw new ValidationError('Invalid setting key');
    }
    
    if (dbPool) {
      await queryWithTimeout(
        'INSERT INTO settings (key, value, updated_by) VALUES ($1, $2, $3) ON CONFLICT (key) DO UPDATE SET value = $2, updated_at = CURRENT_TIMESTAMP, updated_by = $3',
        [key, JSON.stringify(value), req.session.user]
      );
    }
    
    // Apply settings changes
    switch(key) {
      case 'botThresholds':
        logger.info('Bot thresholds updated:', value);
        break;
      case 'linkLengthMode':
        LINK_LENGTH_MODE = value;
        break;
      case 'allowLinkModeSwitch':
        ALLOW_LINK_MODE_SWITCH = value;
        break;
      case 'longLinkSegments':
        LONG_LINK_SEGMENTS = parseInt(value);
        break;
      case 'longLinkParams':
        LONG_LINK_PARAMS = parseInt(value);
        break;
      case 'linkEncodingLayers':
        LINK_ENCODING_LAYERS = parseInt(value);
        break;
      case 'enableCompression':
        ENABLE_COMPRESSION = value;
        break;
      case 'enableEncryption':
        ENABLE_ENCRYPTION = value;
        break;
      case 'maxEncodingIterations':
        MAX_ENCODING_ITERATIONS = parseInt(value);
        break;
      case 'encodingComplexityThreshold':
        ENCODING_COMPLEXITY_THRESHOLD = parseInt(value);
        break;
    }
    
    io.of('/admin').emit('settings-updated', { key, value });
    
    // Publish to Redis for cross-instance communication
    if (subscriber) {
      subscriber.publish('redirector:events', JSON.stringify({
        type: 'settings-updated',
        data: { key, value }
      })).catch(() => {});
    }
    
    res.json({ success: true });
  } catch (err) {
    next(err);
  }
});

// Update link mode settings
app.post('/api/settings/link-mode', csrfProtection, async (req, res, next) => {
  try {
    if (!req.session.authenticated) {
      throw new AppError('Unauthorized', 401, 'UNAUTHORIZED');
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
    
    // Validate inputs
    if (linkLengthMode && !['short', 'long', 'auto'].includes(linkLengthMode)) {
      throw new ValidationError('Invalid link mode');
    }
    
    if (longLinkSegments !== undefined && (longLinkSegments < 3 || longLinkSegments > 20)) {
      throw new ValidationError('Long link segments must be between 3 and 20');
    }
    
    if (longLinkParams !== undefined && (longLinkParams < 5 || longLinkParams > 30)) {
      throw new ValidationError('Long link params must be between 5 and 30');
    }
    
    if (linkEncodingLayers !== undefined && (linkEncodingLayers < 2 || linkEncodingLayers > 12)) {
      throw new ValidationError('Encoding layers must be between 2 and 12');
    }
    
    if (maxEncodingIterations !== undefined && (maxEncodingIterations < 1 || maxEncodingIterations > 5)) {
      throw new ValidationError('Encoding iterations must be between 1 and 5');
    }
    
    if (encodingComplexityThreshold !== undefined && (encodingComplexityThreshold < 10 || encodingComplexityThreshold > 100)) {
      throw new ValidationError('Encoding complexity threshold must be between 10 and 100');
    }
    
    if (dbPool) {
      const updates = [];
      
      if (linkLengthMode) {
        updates.push(queryWithTimeout(
          'INSERT INTO settings (key, value, updated_by) VALUES ($1, $2, $3) ON CONFLICT (key) DO UPDATE SET value = $2, updated_at = CURRENT_TIMESTAMP, updated_by = $3',
          ['linkLengthMode', JSON.stringify(linkLengthMode), req.session.user]
        ));
      }
      
      if (allowLinkModeSwitch !== undefined) {
        updates.push(queryWithTimeout(
          'INSERT INTO settings (key, value, updated_by) VALUES ($1, $2, $3) ON CONFLICT (key) DO UPDATE SET value = $2, updated_at = CURRENT_TIMESTAMP, updated_by = $3',
          ['allowLinkModeSwitch', JSON.stringify(allowLinkModeSwitch), req.session.user]
        ));
      }
      
      if (longLinkSegments) {
        updates.push(queryWithTimeout(
          'INSERT INTO settings (key, value, updated_by) VALUES ($1, $2, $3) ON CONFLICT (key) DO UPDATE SET value = $2, updated_at = CURRENT_TIMESTAMP, updated_by = $3',
          ['longLinkSegments', JSON.stringify(longLinkSegments), req.session.user]
        ));
      }
      
      if (longLinkParams) {
        updates.push(queryWithTimeout(
          'INSERT INTO settings (key, value, updated_by) VALUES ($1, $2, $3) ON CONFLICT (key) DO UPDATE SET value = $2, updated_at = CURRENT_TIMESTAMP, updated_by = $3',
          ['longLinkParams', JSON.stringify(longLinkParams), req.session.user]
        ));
      }
      
      if (linkEncodingLayers) {
        updates.push(queryWithTimeout(
          'INSERT INTO settings (key, value, updated_by) VALUES ($1, $2, $3) ON CONFLICT (key) DO UPDATE SET value = $2, updated_at = CURRENT_TIMESTAMP, updated_by = $3',
          ['linkEncodingLayers', JSON.stringify(linkEncodingLayers), req.session.user]
        ));
      }
      
      if (enableCompression !== undefined) {
        updates.push(queryWithTimeout(
          'INSERT INTO settings (key, value, updated_by) VALUES ($1, $2, $3) ON CONFLICT (key) DO UPDATE SET value = $2, updated_at = CURRENT_TIMESTAMP, updated_by = $3',
          ['enableCompression', JSON.stringify(enableCompression), req.session.user]
        ));
      }
      
      if (enableEncryption !== undefined) {
        updates.push(queryWithTimeout(
          'INSERT INTO settings (key, value, updated_by) VALUES ($1, $2, $3) ON CONFLICT (key) DO UPDATE SET value = $2, updated_at = CURRENT_TIMESTAMP, updated_by = $3',
          ['enableEncryption', JSON.stringify(enableEncryption), req.session.user]
        ));
      }
      
      if (maxEncodingIterations) {
        updates.push(queryWithTimeout(
          'INSERT INTO settings (key, value, updated_by) VALUES ($1, $2, $3) ON CONFLICT (key) DO UPDATE SET value = $2, updated_at = CURRENT_TIMESTAMP, updated_by = $3',
          ['maxEncodingIterations', JSON.stringify(maxEncodingIterations), req.session.user]
        ));
      }
      
      if (encodingComplexityThreshold) {
        updates.push(queryWithTimeout(
          'INSERT INTO settings (key, value, updated_by) VALUES ($1, $2, $3) ON CONFLICT (key) DO UPDATE SET value = $2, updated_at = CURRENT_TIMESTAMP, updated_by = $3',
          ['encodingComplexityThreshold', JSON.stringify(encodingComplexityThreshold), req.session.user]
        ));
      }
      
      await Promise.all(updates);
    }
    
    // Apply updates to global variables
    if (linkLengthMode) LINK_LENGTH_MODE = linkLengthMode;
    if (allowLinkModeSwitch !== undefined) ALLOW_LINK_MODE_SWITCH = allowLinkModeSwitch;
    if (longLinkSegments) LONG_LINK_SEGMENTS = longLinkSegments;
    if (longLinkParams) LONG_LINK_PARAMS = longLinkParams;
    if (linkEncodingLayers) LINK_ENCODING_LAYERS = linkEncodingLayers;
    if (enableCompression !== undefined) ENABLE_COMPRESSION = enableCompression;
    if (enableEncryption !== undefined) ENABLE_ENCRYPTION = enableEncryption;
    if (maxEncodingIterations) MAX_ENCODING_ITERATIONS = maxEncodingIterations;
    if (encodingComplexityThreshold) ENCODING_COMPLEXITY_THRESHOLD = encodingComplexityThreshold;
    
    io.of('/admin').emit('settings-updated', { 
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
    
    // Publish to Redis for cross-instance communication
    if (subscriber) {
      subscriber.publish('redirector:events', JSON.stringify({
        type: 'settings-updated',
        data: { 
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
        }
      })).catch(() => {});
    }
    
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
      throw new AppError('Unauthorized', 401, 'UNAUTHORIZED');
    }
    
    const testUrl = req.query.url || 'https://example.com/very/long/path/with/many/segments/that/might/need/encoding?param1=value1&param2=value2&param3=value3';
    
    // Validate test URL
    if (!validateUrl(testUrl)) {
      throw new ValidationError('Invalid test URL');
    }
    
    const shortResult = generateShortLink(testUrl, req);
    
    const longResults = [];
    
    // Test different configurations
    const configs = [
      { segments: 4, params: 8, iterations: 1 },
      { segments: 6, params: 12, iterations: 2 },
      { segments: 8, params: 16, iterations: 3 },
      { segments: 10, params: 20, iterations: 3 }
    ];
    
    for (const config of configs) {
      try {
        const result = await encodingBreaker.fire(testUrl, req, {
          segments: config.segments,
          params: config.params,
          minLayers: 4,
          maxLayers: 6,
          iterations: config.iterations
        });
        
        longResults.push({
          config,
          url: result.url,
          length: result.url.length,
          layers: result.metadata.layers,
          complexity: result.metadata.complexity,
          encodingTime: result.metadata.encodingTime,
          metadata: result.metadata
        });
      } catch (err) {
        logger.error('Long link generation failed for config:', config, err);
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
    analyticsQueue.add({ type: 'success', data: { id: req.id } }).catch(() => {});
  }
  
  businessMetrics.redirectRate.labels('all', 'success').inc();
  res.json({ ok: true });
});

// Password Protected Link Verification
app.post('/v/:id/verify', express.json(), validateLinkId, async (req, res, next) => {
  try {
    const linkId = req.params.id;
    const { password } = req.body;
    
    if (!password) {
      throw new ValidationError('Password required');
    }
    
    let linkData = cacheGet(linkCache, 'link', linkId);
    
    if (!linkData && dbPool) {
      const result = await queryWithTimeout(
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
        cacheSet(linkCache, 'link', linkId, linkData, ttl);
      }
    }
    
    if (!linkData) {
      throw new AppError('Link not found or expired', 404, 'LINK_NOT_FOUND');
    }
    
    if (!linkData.passwordHash) {
      return res.json({ success: true, target: linkData.target, redirect: true });
    }
    
    const valid = await bcrypt.compare(password, linkData.passwordHash);
    if (!valid) {
      throw new AppError('Invalid password', 401, 'INVALID_PASSWORD');
    }
    
    linkData.lastAccessed = Date.now();
    cacheSet(linkCache, 'link', linkId, linkData);
    
    if (dbPool) {
      await queryWithTimeout('UPDATE links SET last_accessed = CURRENT_TIMESTAMP WHERE id = $1', [linkId]);
    }
    
    res.json({ success: true, target: linkData.target });
  } catch (err) {
    next(err);
  }
});

// Verification Gate with Password Protection
app.get('/v/:id', strictLimiter, validateLinkId, async (req, res, next) => {
  try {
    const linkId = req.params.id;
    const deviceInfo = req.deviceInfo;
    const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip || '0.0.0.0';
    const showQr = req.query.qr === 'true';
    const embed = req.query.embed === 'true';
    
    const linkKey = `${linkId}:${ip}`;
    const requestCount = cacheGet(linkRequestCache, 'linkReq', linkKey) || 0;
    
    if (requestCount >= 5) {
      logRequest('rate-limit', req, res, { linkId, count: requestCount });
      botBlocks.inc({ reason: 'rate_limit' });
      return res.redirect(BOT_URLS[Math.floor(Math.random() * BOT_URLS.length)]);
    }
    
    cacheSet(linkRequestCache, 'linkReq', linkKey, requestCount + 1);

    const country = await getCountryCode(req);

    if (isLikelyBot(req)) {
      logRequest('bot-block', req, res, { reason: 'bot-detection' });
      return res.redirect(BOT_URLS[Math.floor(Math.random() * BOT_URLS.length)]);
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
        cacheSet(linkCache, 'link', linkId, data, ttl);
      }
    }

    if (!data) {
      stats.expiredLinks++;
      logRequest('expired', req, res, { linkId });
      
      if (dbPool) {
        await queryWithTimeout(
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
    cacheSet(linkCache, 'link', linkId, data);

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
      }).catch(() => {});
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
      
      return res.send(passwordProtectedPage(linkId, error, nonce));
    }

    if (showQr) {
      const qrData = await QRCode.toDataURL(data.target);
      return res.send(qrCodePage(data.target, qrData, nonce));
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

    if (CONFIG.DISABLE_DESKTOP_CHALLENGE) {
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

// Helper functions for pages
function passwordProtectedPage(linkId, error, nonce) {
  return `
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
  `;
}

function qrCodePage(target, qrData, nonce) {
  return `
    <!DOCTYPE html>
    <html>
    <head>
      <title>QR Code - Redirector Pro</title>
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <meta http-equiv="refresh" content="5;url=${target}">
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
      <script nonce="${nonce}">let time=5;const interval=setInterval(()=>{time--;document.getElementById('countdown').textContent=time;if(time<=0){clearInterval(interval);window.location.href='${target}'}},1000);</script>
    </body>
    </html>
  `;
}

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
    
    // Validate URL
    if (!validateUrl(url)) {
      throw new ValidationError('Invalid URL');
    }
    
    const cacheKey = crypto.createHash('md5').update(`${url}:${size}:${format}`).digest('hex');
    let qrData = cacheGet(qrCache, 'qr', cacheKey);
    
    if (!qrData) {
      if (format === 'png') {
        qrData = await QRCode.toBuffer(url, { 
          width: size,
          margin: 2,
          type: 'png',
          errorCorrectionLevel: 'M',
          color: { dark: '#000000', light: '#ffffff' }
        });
      } else {
        qrData = await QRCode.toDataURL(url, { 
          width: size,
          margin: 2,
          color: { dark: '#000000', light: '#ffffff' },
          errorCorrectionLevel: 'M'
        });
      }
      cacheSet(qrCache, 'qr', cacheKey, qrData, 3600);
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
    
    // Validate URL
    if (!validateUrl(url)) {
      throw new ValidationError('Invalid URL');
    }
    
    const qrBuffer = await QRCode.toBuffer(url, { 
      width: size,
      margin: 2,
      type: 'png',
      errorCorrectionLevel: 'M',
      color: { dark: '#000000', light: '#ffffff' }
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
  // Block requests with query parameters
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
    
    // Check if IP is blocked
    if (dbPool) {
      try {
        const blocked = await queryWithTimeout(
          'SELECT * FROM blocked_ips WHERE ip = $1 AND expires_at > NOW()',
          [ip]
        );
        if (blocked.rows.length > 0) {
          logger.error(`Blocked IP attempted login: ${ip}`);
          throw new AppError('Access denied', 403, 'IP_BLOCKED');
        }
      } catch (dbErr) {
        if (dbErr.code === '42P01') {
          logger.warn('blocked_ips table not found, skipping IP block check');
        } else {
          logger.error('Database error checking blocked IP:', dbErr);
        }
      }
    }
    
    // Check login attempts
    const attemptData = loginAttempts.get(ip) || { count: 0, lastAttempt: Date.now() };
    attemptData.count++;
    attemptData.lastAttempt = Date.now();
    loginAttempts.set(ip, attemptData);
    
    if (attemptData.count > CONFIG.LOGIN_ATTEMPTS_MAX) {
      logger.error(`Excessive login attempts from ${ip}: ${attemptData.count}`);
      
      if (dbPool) {
        try {
          await queryWithTimeout(
            'INSERT INTO blocked_ips (ip, reason, expires_at) VALUES ($1, $2, NOW() + INTERVAL \'1 hour\') ON CONFLICT (ip) DO UPDATE SET expires_at = NOW() + INTERVAL \'1 hour\'',
            [ip, 'Excessive login attempts']
          );
        } catch (dbErr) {
          logger.error('Failed to block IP in database:', dbErr);
        }
      }
      
      throw new AppError('Too many login attempts. IP blocked for 1 hour.', 429, 'RATE_LIMIT');
    }
    
    // Add delay for failed attempts
    if (attemptData.count > 5) {
      await new Promise(resolve => setTimeout(resolve, 2000));
    }
    
    if (!username || !password) {
      throw new ValidationError('Username and password required');
    }
    
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
        req.session.createdAt = Date.now();
        req.session.csrfToken = crypto.randomBytes(32).toString('hex');
        
        if (remember) {
          req.session.cookie.maxAge = 30 * 24 * 60 * 60 * 1000; // 30 days
        } else {
          req.session.cookie.maxAge = 24 * 60 * 60 * 1000; // 1 day
        }
        
        // Log session in database
        if (dbPool) {
          queryWithTimeout(
            'INSERT INTO user_sessions (session_id, user_id, ip, user_agent) VALUES ($1, $2, $3, $4)',
            [req.session.id, username, ip, req.headers['user-agent']]
          ).catch(() => {});
        }
        
        logger.info('Successful admin login', { ip, username });
        res.json({ success: true });
      });
    } else {
      logger.warn('Failed login attempt', { ip, username, attemptCount: attemptData.count });
      throw new AppError('Invalid credentials', 401, 'INVALID_CREDENTIALS');
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
      '{{bullBoardPath}}': CONFIG.BULL_BOARD_PATH,
      '{{linkLengthMode}}': LINK_LENGTH_MODE,
      '{{allowLinkModeSwitch}}': ALLOW_LINK_MODE_SWITCH,
      '{{longLinkSegments}}': LONG_LINK_SEGMENTS,
      '{{longLinkParams}}': LONG_LINK_PARAMS,
      '{{linkEncodingLayers}}': LINK_ENCODING_LAYERS,
      '{{enableCompression}}': ENABLE_COMPRESSION,
      '{{enableEncryption}}': ENABLE_ENCRYPTION,
      '{{maxEncodingIterations}}': MAX_ENCODING_ITERATIONS,
      '{{encodingComplexityThreshold}}': ENCODING_COMPLEXITY_THRESHOLD,
      '{{version}}': '4.0.0'
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
  // Log session revocation
  if (dbPool && req.session.id) {
    queryWithTimeout(
      'UPDATE user_sessions SET revoked_at = NOW() WHERE session_id = $1',
      [req.session.id]
    ).catch(() => {});
  }
  
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
    throw new AppError('Unauthorized', 401, 'UNAUTHORIZED');
  }
  
  linkCache.flushAll();
  geoCache.flushAll();
  deviceCache.flushAll();
  qrCache.flushAll();
  encodingCache.flushAll();
  
  // Reset cache stats
  Object.keys(cacheStats).forEach(k => {
    cacheStats[k].hits = 0;
    cacheStats[k].misses = 0;
  });
  
  logger.info('Cache cleared by admin');
  res.json({ success: true });
});

app.get('/admin/export-logs', async (req, res, next) => {
  if (!req.session.authenticated) {
    throw new AppError('Unauthorized', 401, 'UNAUTHORIZED');
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
app.get('/api/export/:id', validateLinkId, async (req, res, next) => {
  try {
    const linkId = req.params.id;
    const format = req.query.format || 'json';
    
    if (!req.session.authenticated) {
      throw new AppError('Unauthorized', 401, 'UNAUTHORIZED');
    }
    
    if (!dbPool) {
      throw new AppError('Database not available', 503, 'DATABASE_UNAVAILABLE');
    }
    
    const result = await queryWithTimeout(
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
app.get('/admin/security/monitor', async (req, res) => {
  if (!req.session.authenticated) {
    throw new AppError('Unauthorized', 401, 'UNAUTHORIZED');
  }
  
  const now = Date.now();
  const activeAttacks = [];
  
  for (const [ip, data] of loginAttempts.entries()) {
    if (now - data.lastAttempt < CONFIG.LOGIN_BLOCK_DURATION) {
      activeAttacks.push({
        ip,
        attempts: data.count,
        lastAttempt: new Date(data.lastAttempt).toISOString()
      });
    }
  }
  
  // Get blocked IPs from database
  const getBlockedIPs = async () => {
    if (dbPool) {
      try {
        const result = await queryWithTimeout(
          'SELECT ip, reason, expires_at FROM blocked_ips WHERE expires_at > NOW() ORDER BY expires_at DESC'
        );
        return result.rows;
      } catch (err) {
        logger.error('Error fetching blocked IPs:', err);
        return [];
      }
    }
    return [];
  };
  
  // Get active sessions
  const getActiveSessions = async () => {
    if (dbPool) {
      try {
        const result = await queryWithTimeout(
          `SELECT session_id, user_id, ip, user_agent, created_at 
           FROM user_sessions 
           WHERE revoked_at IS NULL AND created_at > NOW() - INTERVAL '24 hours'
           ORDER BY created_at DESC`
        );
        return result.rows;
      } catch (err) {
        logger.error('Error fetching sessions:', err);
        return [];
      }
    }
    return [];
  };
  
  const [blockedIPs, activeSessions] = await Promise.all([
    getBlockedIPs(),
    getActiveSessions()
  ]);
  
  res.json({
    blockedIPs,
    activeAttacks: activeAttacks.sort((a, b) => b.attempts - a.attempts),
    totalAttempts: Array.from(loginAttempts.values()).reduce((sum, d) => sum + d.count, 0),
    activeSessions,
    rateLimitStats: {
      current: rateLimiterRedis ? await rateLimiterRedis.get() : 'memory',
      points: CONFIG.RATE_LIMIT_MAX_REQUESTS,
      duration: CONFIG.RATE_LIMIT_WINDOW / 1000
    }
  });
});

// Configuration reload endpoint
app.post('/admin/reload-config', csrfProtection, async (req, res) => {
  if (!req.session.authenticated) {
    throw new AppError('Unauthorized', 401, 'UNAUTHORIZED');
  }
  
  const result = await reloadConfig();
  if (result.success) {
    // Update global variables
    LINK_LENGTH_MODE = CONFIG.LINK_LENGTH_MODE;
    ALLOW_LINK_MODE_SWITCH = CONFIG.ALLOW_LINK_MODE_SWITCH;
    LONG_LINK_SEGMENTS = CONFIG.LONG_LINK_SEGMENTS;
    LONG_LINK_PARAMS = CONFIG.LONG_LINK_PARAMS;
    LINK_ENCODING_LAYERS = CONFIG.LINK_ENCODING_LAYERS;
    ENABLE_COMPRESSION = CONFIG.ENABLE_COMPRESSION;
    ENABLE_ENCRYPTION = CONFIG.ENABLE_ENCRYPTION;
    MAX_ENCODING_ITERATIONS = CONFIG.MAX_ENCODING_ITERATIONS;
    ENCODING_COMPLEXITY_THRESHOLD = CONFIG.ENCODING_COMPLEXITY_THRESHOLD;
    
    res.json({ success: true, message: 'Configuration reloaded successfully' });
  } else {
    res.status(400).json({ success: false, errors: result.errors });
  }
});

// Swagger documentation
const swaggerOptions = {
  definition: {
    openapi: '3.0.0',
    info: {
      title: 'Redirector Pro API',
      version: '4.0.0',
      description: 'Enterprise-grade redirect service with anti-bot protection',
      contact: {
        name: 'Support',
        email: 'support@redirector.pro'
      }
    },
    servers: [
      {
        url: `http://${HOST}:${PORT}`,
        description: 'Current server'
      }
    ],
    components: {
      securitySchemes: {
        apiKey: {
          type: 'apiKey',
          name: 'X-API-Key',
          in: 'header'
        },
        csrfToken: {
          type: 'apiKey',
          name: 'X-CSRF-Token',
          in: 'header'
        }
      }
    },
    security: [
      { apiKey: [] }
    ]
  },
  apis: ['./server.js'],
};

const swaggerSpecs = swaggerJsdoc(swaggerOptions);
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpecs, {
  explorer: true,
  customCss: '.swagger-ui .topbar { display: none }',
  customSiteTitle: 'Redirector Pro API Docs'
}));

// CSP violation report endpoint
app.post('/report-ct-violation', express.json({ type: 'application/csp-report' }), (req, res) => {
  logger.warn('CSP violation:', req.body);
  res.status(204).end();
});

// 404 Handler
app.use((req, res) => {
  logRequest('404', req, res);
  res.redirect(BOT_URLS[Math.floor(Math.random() * BOT_URLS.length)]);
});

// Global Error Handler
app.use((err, req, res, next) => {
  const errorId = uuidv4();
  
  // Determine error type and status
  const statusCode = err.statusCode || 500;
  const errorCode = err.code || 'INTERNAL_ERROR';
  const isOperational = err.isOperational || false;
  
  // Log error
  logger.error('Error:', {
    errorId,
    code: errorCode,
    message: err.message,
    stack: err.stack,
    id: req.id,
    path: req.path,
    method: req.method,
    ip: req.ip,
    userAgent: req.headers['user-agent'],
    isOperational
  });
  
  // Log to file
  logRequest('error', req, res, { 
    error: err.message, 
    errorId,
    code: errorCode
  });
  
  // Update metrics
  totalRequests.inc({ method: req.method, path: req.path, status: statusCode });
  
  // Handle operational errors
  if (err instanceof AppError && err.isOperational) {
    const response = { 
      error: err.message,
      code: err.code,
      id: req.id,
      errorId
    };
    
    // Add retry after for rate limit errors
    if (err instanceof RateLimitError && err.retryAfter) {
      response.retryAfter = err.retryAfter;
      res.setHeader('Retry-After', err.retryAfter);
    }
    
    return res.status(statusCode).json(response);
  }
  
  // Handle database errors
  if (err instanceof DatabaseError) {
    return res.status(503).json({ 
      error: 'Database service unavailable',
      code: 'DATABASE_ERROR',
      id: req.id,
      errorId
    });
  }
  
  // Handle validation errors
  if (err instanceof ValidationError) {
    return res.status(400).json({ 
      error: err.message,
      code: 'VALIDATION_ERROR',
      id: req.id,
      errorId
    });
  }
  
  // Fallback for unhandled errors
  if (!res.headersSent) {
    if (req.accepts('html')) {
      res.redirect(BOT_URLS[Math.floor(Math.random() * BOT_URLS.length)]);
    } else {
      res.status(500).json({ 
        error: 'Internal server error',
        code: 'INTERNAL_ERROR',
        id: req.id,
        errorId
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
    // Stop accepting new connections
    server.close(() => {
      logger.info('HTTP server closed');
    });
    
    // Close Socket.IO connections
    await new Promise((resolve) => {
      io.close(() => {
        logger.info('Socket.IO closed');
        resolve();
      });
    });
    
    // Close queue connections
    const queueCloses = [];
    if (redirectQueue) queueCloses.push(redirectQueue.close());
    if (emailQueue) queueCloses.push(emailQueue.close());
    if (analyticsQueue) queueCloses.push(analyticsQueue.close());
    if (encodingQueue) queueCloses.push(encodingQueue.close());
    
    await Promise.all(queueCloses);
    logger.info('Queues closed');
    
    // Close database pool
    if (dbPool) {
      await dbPool.end();
      logger.info('Database pool closed');
      
      // Clear health check interval
      if (dbHealthCheck) {
        clearInterval(dbHealthCheck);
      }
    }
    
    // Close Redis connections
    const redisCloses = [];
    if (redisClient) redisCloses.push(redisClient.quit());
    if (subscriber) redisCloses.push(subscriber.quit());
    
    await Promise.all(redisCloses);
    logger.info('Redis connections closed');
    
    // Clear intervals
    const intervals = [
      'dbHealthCheck',
      'cacheCleanup',
      'metricsUpdate',
      'queueMetrics'
    ];
    
    intervals.forEach(interval => {
      if (global[interval]) {
        clearInterval(global[interval]);
      }
    });
    
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

// Create necessary directories
async function ensureDirectories() {
  const dirs = ['logs', 'public', 'backups', 'temp', 'uploads', 'heapdumps'];
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

// Backup function
async function performBackup() {
  if (!CONFIG.AUTO_BACKUP_ENABLED || !dbPool) return;
  
  try {
    const backupDir = path.join('backups', new Date().toISOString().split('T')[0]);
    await fs.mkdir(backupDir, { recursive: true });
    
    // Backup links table
    const links = await queryWithTimeout('SELECT * FROM links');
    await fs.writeFile(
      path.join(backupDir, 'links.json'),
      JSON.stringify(links.rows, null, 2)
    );
    
    // Backup settings
    const settings = await queryWithTimeout('SELECT * FROM settings');
    await fs.writeFile(
      path.join(backupDir, 'settings.json'),
      JSON.stringify(settings.rows, null, 2)
    );
    
    logger.info('Backup completed', { backupDir });
    
    // Clean old backups
    const files = await fs.readdir('backups');
    const now = Date.now();
    for (const file of files) {
      const filePath = path.join('backups', file);
      const stat = await fs.stat(filePath);
      const age = (now - stat.mtimeMs) / (1000 * 60 * 60 * 24);
      if (age > CONFIG.BACKUP_RETENTION_DAYS) {
        await fs.rm(filePath, { recursive: true, force: true });
        logger.info('Removed old backup:', filePath);
      }
    }
  } catch (err) {
    logger.error('Backup failed:', err);
  }
}

// Start Server
ensureDirectories().then(() => {
  // Start backup schedule
  if (CONFIG.AUTO_BACKUP_ENABLED) {
    setInterval(performBackup, CONFIG.AUTO_BACKUP_INTERVAL);
    performBackup(); // Initial backup
  }
  
  server.listen(PORT, HOST, () => {
    console.log('\n' + '='.repeat(100));
    console.log(`  🚀 Redirector Pro v4.0.0 - Enterprise Edition - ULTIMATE`);
    console.log('='.repeat(100));
    console.log(`  📡 Host: ${HOST}:${PORT}`);
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
    console.log(`  📍 Admin UI: http://${HOST === '0.0.0.0' ? 'localhost' : HOST}:${PORT}/admin`);
    console.log(`  🔐 Default admin: ${ADMIN_USERNAME} / [protected]`);
    console.log(`  📊 Real-time monitoring: Active`);
    console.log(`  💾 Database: ${dbPool ? 'Connected' : 'Disabled'}`);
    console.log(`  🔄 Redis: ${redisClient?.status === 'ready' ? 'Connected' : 'Disabled'}`);
    console.log(`  📨 Queues: ${redirectQueue ? 'Enabled' : 'Disabled'}`);
    console.log(`  🛡️  Circuit Breakers: Enabled`);
    console.log(`  📈 Prometheus Metrics: ${CONFIG.METRICS_ENABLED ? 'Enabled' : 'Disabled'}`);
    console.log(`  📚 API Docs: http://${HOST === '0.0.0.0' ? 'localhost' : HOST}:${PORT}/api-docs`);
    
    if (serverAdapter && CONFIG.BULL_BOARD_ENABLED) {
      console.log(`  📊 Bull Board: http://${HOST === '0.0.0.0' ? 'localhost' : HOST}:${PORT}${CONFIG.BULL_BOARD_PATH}`);
    }
    
    console.log('='.repeat(100) + '\n');
    
    logger.info('Server started', {
      port: PORT,
      host: HOST,
      nodeEnv: NODE_ENV,
      version: '4.0.0',
      linkMode: LINK_LENGTH_MODE,
      encoding: {
        layers: LINK_ENCODING_LAYERS,
        compression: ENABLE_COMPRESSION,
        encryption: ENABLE_ENCRYPTION,
        iterations: MAX_ENCODING_ITERATIONS,
        complexityThreshold: ENCODING_COMPLEXITY_THRESHOLD
      }
    });
    
    // Log startup to file
    fs.appendFile(REQUEST_LOG_FILE, JSON.stringify({
      t: Date.now(),
      type: 'startup',
      version: '4.0.0-ultimate',
      port: PORT,
      host: HOST,
      nodeEnv: NODE_ENV,
      linkMode: LINK_LENGTH_MODE,
      encoding: {
        layers: LINK_ENCODING_LAYERS,
        compression: ENABLE_COMPRESSION,
        encryption: ENABLE_ENCRYPTION
      }
    }) + '\n').catch(() => {});
  });
});

// Server configuration
server.keepAliveTimeout = CONFIG.KEEP_ALIVE_TIMEOUT;
server.headersTimeout = CONFIG.HEADERS_TIMEOUT;
server.maxHeadersCount = 1000;
server.timeout = CONFIG.SERVER_TIMEOUT;
server.maxConnections = 10000;

// Export for testing
module.exports = { app, server, io, redisClient, dbPool };