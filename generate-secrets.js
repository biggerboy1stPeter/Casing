#!/usr/bin/env node

/**
 * Generate Secrets Script v3.0 - Enterprise Edition
 * 
 * Enhanced with support for:
 * - Encryption key rotation
 * - Request signing secrets
 * - API versioning keys
 * - Database transaction settings
 * - Bull queue authentication
 * - Multi-factor authentication
 * - Backup codes generation
 * - Webhook signing secrets
 * 
 * Usage:
 *   node generate-secrets.js                    # Interactive mode
 *   node generate-secrets.js --write            # Generate and write to .env
 *   node generate-secrets.js --all              # Generate all possible secrets
 *   node generate-secrets.js --rotate           # Rotate existing secrets
 *   node generate-secrets.js --help              # Show help
 */

const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const fs = require('fs');
const path = require('path');
const readline = require('readline');
const os = require('os');
const { promisify } = require('util');
const zlib = require('zlib');

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

const ENV_FILE = path.join(process.cwd(), '.env');
const ENV_EXAMPLE_FILE = path.join(process.cwd(), '.env.example');
const ENV_LOCAL_FILE = path.join(process.cwd(), '.env.local');
const ENV_PROD_FILE = path.join(process.cwd(), '.env.production');
const ENV_DEV_FILE = path.join(process.cwd(), '.env.development');
const SECRETS_DIR = path.join(process.cwd(), 'secrets');
const KEYS_DIR = path.join(process.cwd(), 'keys');
const BACKUP_DIR = path.join(process.cwd(), 'backups', 'secrets');

// Colors for console output
const colors = {
  reset: '\x1b[0m',
  bright: '\x1b[1m',
  dim: '\x1b[2m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m',
  white: '\x1b[37m'
};

function log(color, message) {
  console.log(colors[color] + message + colors.reset);
}

function showHelp() {
  console.log(`
${colors.bright}🔐 GENERATE SECRETS SCRIPT v3.0 - ENTERPRISE EDITION${colors.reset}

${colors.bright}Usage:${colors.reset}
  node generate-secrets.js [options] [password]

${colors.bright}Basic Options:${colors.reset}
  --write           Write generated values directly to .env file
  --force           Force overwrite existing values in .env
  --example         Create .env.example file with template
  --help            Show this help message

${colors.bright}Feature Options:${colors.reset}
  --all             Generate all possible configurations
  --basic           Generate only essential secrets
  --redis           Add Redis configuration with auth
  --postgres        Add PostgreSQL configuration with auth
  --jwt             Generate JWT secrets and keys
  --docker          Generate docker-compose compatible secrets
  --kubernetes      Generate Kubernetes secrets YAML
  --aws             Generate AWS Secrets Manager compatible format
  --gcp             Generate Google Cloud Secret Manager format
  --azure           Generate Azure Key Vault format
  --hashicorp       Generate HashiCorp Vault format

${colors.bright}Security Options:${colors.reset}
  --rotate          Rotate existing secrets (generate new ones)
  --encrypt         Encrypt sensitive values with master key
  --backup          Backup existing .env file
  --validate        Validate existing .env file
  --audit           Audit current secrets for strength
  --mfa             Generate MFA/2FA secrets and backup codes
  --pgp             Generate PGP keys for encryption
  --ssh             Generate SSH key pair

${colors.bright}Import/Export:${colors.reset}
  --export <file>   Export secrets as encrypted JSON
  --import <file>   Import secrets from encrypted JSON file
  --merge <file>    Merge secrets from file without overwriting

${colors.bright}Environment:${colors.reset}
  --local           Write to .env.local instead of .env
  --dev             Write to .env.development
  --prod            Write to .env.production
  --test            Write to .env.test

${colors.bright}Advanced Features:${colors.reset}
  --request-signing Generate request signing secrets
  --key-rotation    Configure encryption key rotation
  --api-versioning  Generate API versioning keys
  --database-tx     Generate database transaction settings
  --bull-queue      Generate Bull Queue authentication
  --webhooks        Generate webhook signing secrets
  --rate-limiting   Generate rate limiting configuration
  --circuit-breaker Generate circuit breaker settings
  --monitoring      Generate monitoring and alerting config

${colors.bright}Examples:${colors.reset}
  node generate-secrets.js --write --basic
  node generate-secrets.js --write --all
  node generate-secrets.js --validate
  node generate-secrets.js --rotate --write
  node generate-secrets.js --export secrets.enc
  node generate-secrets.js --import secrets.enc
  node generate-secrets.js --aws --write
  node generate-secrets.js --kubernetes --write
  node generate-secrets.js --request-signing --key-rotation --write

${colors.bright}Generated Secrets:${colors.reset}
  ┌─────────────────────┬─────────────────────────────────┐
  │ Secret              │ Description                     │
  ├─────────────────────┼─────────────────────────────────┤
  │ SESSION_SECRET      │ Session encryption (32 bytes)   │
  │ METRICS_API_KEY     │ Prometheus metrics access       │
  │ ADMIN_PASSWORD_HASH │ Bcrypt hash of admin password   │
  │ JWT_SECRET          │ JWT signing (64 bytes)          │
  │ ENCRYPTION_KEY      │ AES-256 encryption key          │
  │ API_KEY             │ API access key                  │
  │ WEBHOOK_SECRET      │ Webhook signing                 │
  │ CSRF_SECRET         │ CSRF protection                 │
  │ OTP_SECRET          │ 2FA/MFA secret                  │
  │ REQUEST_SIGNING_KEY │ Request signature verification  │
  │ QUEUE_AUTH_TOKEN    │ Bull Queue authentication       │
  │ BACKUP_CODES        │ Recovery codes (5)              │
  └─────────────────────┴─────────────────────────────────┘
  `);
  process.exit(0);
}

// ============================================================================
// GENERATION FUNCTIONS
// ============================================================================

function generateSessionSecret() {
  return crypto.randomBytes(32).toString('hex');
}

function generateMetricsKey() {
  return crypto.randomBytes(32).toString('hex');
}

function generateJWTSecret() {
  return crypto.randomBytes(64).toString('hex');
}

function generateEncryptionKey() {
  return crypto.randomBytes(32).toString('base64');
}

function generateAPIKey() {
  return 'rp_' + crypto.randomBytes(24).toString('base64').replace(/[^a-zA-Z0-9]/g, '').substring(0, 32);
}

function generateWebhookSecret() {
  return 'whsec_' + crypto.randomBytes(32).toString('hex');
}

function generateCSRFSecret() {
  return crypto.randomBytes(32).toString('hex');
}

function generateRedisPassword() {
  return crypto.randomBytes(24).toString('hex');
}

function generatePostgresPassword() {
  return crypto.randomBytes(16).toString('hex');
}

function generatePasswordHash(password, rounds = 12) {
  return bcrypt.hashSync(password, rounds);
}

function generateOTPSecret() {
  return crypto.randomBytes(20).toString('hex');
}

function generateSalt() {
  return crypto.randomBytes(16).toString('hex');
}

function generateBackupCodes(count = 5) {
  const codes = [];
  for (let i = 0; i < count; i++) {
    const code = crypto.randomBytes(6).toString('hex').toUpperCase().match(/.{4}/g).join('-');
    codes.push(code);
  }
  return codes;
}

function generateRequestSigningKey() {
  return crypto.randomBytes(32).toString('hex');
}

function generateQueueAuthToken() {
  return 'qt_' + crypto.randomBytes(24).toString('base64').replace(/[^a-zA-Z0-9]/g, '');
}

function generateDatabaseEncryptionKey() {
  return crypto.randomBytes(32).toString('hex');
}

function generateSSHKeyPair() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 4096,
    publicKeyEncoding: {
      type: 'spki',
      format: 'pem'
    },
    privateKeyEncoding: {
      type: 'pkcs8',
      format: 'pem'
    }
  });
  return { privateKey, publicKey };
}

function generatePGPKeyPair() {
  // Simulate PGP key generation (in production use openpgp or similar)
  const keyId = crypto.randomBytes(8).toString('hex').toUpperCase();
  return {
    keyId: keyId,
    fingerprint: crypto.randomBytes(20).toString('hex').toUpperCase(),
    publicKey: `-----BEGIN PGP PUBLIC KEY BLOCK-----\nVersion: Generated\n\n${crypto.randomBytes(256).toString('base64')}\n-----END PGP PUBLIC KEY BLOCK-----`,
    privateKey: `-----BEGIN PGP PRIVATE KEY BLOCK-----\nVersion: Generated\n\n${crypto.randomBytes(512).toString('base64')}\n-----END PGP PRIVATE KEY BLOCK-----`
  };
}

function generateJWTRS256Keys() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: {
      type: 'spki',
      format: 'pem'
    },
    privateKeyEncoding: {
      type: 'pkcs8',
      format: 'pem'
    }
  });
  return { privateKey, publicKey };
}

function generateHMACSecret() {
  return crypto.randomBytes(64).toString('hex');
}

function generateTLSConfig() {
  return {
    cert: `-----BEGIN CERTIFICATE-----\n${crypto.randomBytes(256).toString('base64')}\n-----END CERTIFICATE-----`,
    key: `-----BEGIN PRIVATE KEY-----\n${crypto.randomBytes(128).toString('base64')}\n-----END PRIVATE KEY-----`,
    ca: `-----BEGIN CERTIFICATE-----\n${crypto.randomBytes(256).toString('base64')}\n-----END CERTIFICATE-----`
  };
}

// ============================================================================
// ENCRYPTION FUNCTIONS
// ============================================================================

function encryptValue(value, key) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-gcm', Buffer.from(key, 'base64'), iv);
  let encrypted = cipher.update(value, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  const authTag = cipher.getAuthTag();
  return {
    encrypted,
    iv: iv.toString('hex'),
    authTag: authTag.toString('hex')
  };
}

function decryptValue(encrypted, iv, authTag, key) {
  const decipher = crypto.createDecipheriv(
    'aes-256-gcm',
    Buffer.from(key, 'base64'),
    Buffer.from(iv, 'hex')
  );
  decipher.setAuthTag(Buffer.from(authTag, 'hex'));
  let decrypted = decipher.update(encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

function encryptFile(inputPath, outputPath, key) {
  const input = fs.readFileSync(inputPath, 'utf8');
  const encrypted = encryptValue(input, key);
  fs.writeFileSync(outputPath, JSON.stringify(encrypted));
  log('green', `✅ Encrypted: ${outputPath}`);
}

function decryptFile(inputPath, outputPath, key) {
  const data = JSON.parse(fs.readFileSync(inputPath, 'utf8'));
  const decrypted = decryptValue(data.encrypted, data.iv, data.authTag, key);
  fs.writeFileSync(outputPath, decrypted);
  log('green', `✅ Decrypted: ${outputPath}`);
}

// ============================================================================
// FILE OPERATIONS
// ============================================================================

function readEnvFile(filePath = ENV_FILE) {
  if (!fs.existsSync(filePath)) {
    return {};
  }
  
  const content = fs.readFileSync(filePath, 'utf8');
  const env = {};
  
  content.split('\n').forEach(line => {
    if (line.startsWith('#') || !line.trim()) return;
    
    const match = line.match(/^([^=]+)=(.*)$/);
    if (match) {
      const key = match[1].trim();
      let value = match[2].trim();
      // Remove quotes if present
      if (value.startsWith('"') && value.endsWith('"')) {
        value = value.slice(1, -1);
      } else if (value.startsWith("'") && value.endsWith("'")) {
        value = value.slice(1, -1);
      }
      env[key] = value;
    }
  });
  
  return env;
}

function backupEnvFile() {
  if (!fs.existsSync(ENV_FILE)) return null;
  
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const backupPath = path.join(BACKUP_DIR, `.env.backup.${timestamp}`);
  
  if (!fs.existsSync(BACKUP_DIR)) {
    fs.mkdirSync(BACKUP_DIR, { recursive: true, mode: 0o700 });
  }
  
  fs.copyFileSync(ENV_FILE, backupPath);
  fs.chmodSync(backupPath, 0o600);
  log('green', `✅ Backup created: ${backupPath}`);
  
  // Compress old backups
  compressOldBackups();
  
  return backupPath;
}

function compressOldBackups() {
  const files = fs.readdirSync(BACKUP_DIR);
  const now = Date.now();
  
  files.forEach(file => {
    const filePath = path.join(BACKUP_DIR, file);
    const stat = fs.statSync(filePath);
    const age = (now - stat.mtimeMs) / (1000 * 60 * 60 * 24);
    
    // Compress files older than 7 days
    if (age > 7 && !file.endsWith('.gz')) {
      const content = fs.readFileSync(filePath);
      const compressed = zlib.gzipSync(content);
      fs.writeFileSync(filePath + '.gz', compressed);
      fs.unlinkSync(filePath);
      log('dim', `Compressed: ${file} -> ${file}.gz`);
    }
  });
}

function validateEnvFile(env) {
  const required = [
    'SESSION_SECRET',
    'METRICS_API_KEY',
    'ADMIN_PASSWORD_HASH',
    'ADMIN_USERNAME'
  ];
  
  const warnings = [];
  const errors = [];
  
  required.forEach(key => {
    if (!env[key]) {
      errors.push(`Missing required variable: ${key}`);
    }
  });
  
  if (env.SESSION_SECRET && env.SESSION_SECRET.length < 32) {
    warnings.push('SESSION_SECRET should be at least 32 characters');
  }
  
  if (env.METRICS_API_KEY && env.METRICS_API_KEY.length < 16) {
    warnings.push('METRICS_API_KEY should be at least 16 characters');
  }
  
  if (env.ENCRYPTION_KEY && Buffer.from(env.ENCRYPTION_KEY, 'base64').length !== 32) {
    warnings.push('ENCRYPTION_KEY should be a valid 32-byte base64 key');
  }
  
  if (env.JWT_SECRET && env.JWT_SECRET.length < 64) {
    warnings.push('JWT_SECRET should be at least 64 characters for security');
  }
  
  if (env.REQUEST_SIGNING_KEY && env.REQUEST_SIGNING_KEY.length < 32) {
    warnings.push('REQUEST_SIGNING_KEY should be at least 32 characters');
  }
  
  if (env.ENCRYPTION_KEY_ROTATION_DAYS && 
      (parseInt(env.ENCRYPTION_KEY_ROTATION_DAYS) < 1 || parseInt(env.ENCRYPTION_KEY_ROTATION_DAYS) > 365)) {
    warnings.push('ENCRYPTION_KEY_ROTATION_DAYS should be between 1 and 365');
  }
  
  if (env.PORT && (isNaN(parseInt(env.PORT)) || parseInt(env.PORT) < 1 || parseInt(env.PORT) > 65535)) {
    errors.push('PORT must be a valid port number (1-65535)');
  }
  
  if (env.NODE_ENV && !['development', 'production', 'test'].includes(env.NODE_ENV)) {
    warnings.push('NODE_ENV should be development, production, or test');
  }
  
  if (env.TARGET_URL && !env.TARGET_URL.match(/^https?:\/\/.+/)) {
    warnings.push('TARGET_URL should be a valid URL (http:// or https://)');
  }
  
  if (env.LINK_TTL && !env.LINK_TTL.match(/^\d+[smhd]?$/)) {
    warnings.push('LINK_TTL should be in format: 30m, 1h, 7d, etc.');
  }
  
  if (env.DATABASE_URL && !env.DATABASE_URL.startsWith('postgresql://')) {
    warnings.push('DATABASE_URL should start with postgresql://');
  }
  
  if (env.REDIS_URL && !env.REDIS_URL.startsWith('redis://') && !env.REDIS_URL.startsWith('rediss://')) {
    warnings.push('REDIS_URL should start with redis:// or rediss://');
  }
  
  if (env.ENCRYPTION_KEY_ROTATION_INTERVAL && 
      !['daily', 'weekly', 'monthly', 'quarterly'].includes(env.ENCRYPTION_KEY_ROTATION_INTERVAL)) {
    warnings.push('ENCRYPTION_KEY_ROTATION_INTERVAL should be daily, weekly, monthly, or quarterly');
  }
  
  return { errors, warnings };
}

function auditSecrets(env) {
  const audit = {
    timestamp: new Date().toISOString(),
    overall: 'PASS',
    checks: [],
    recommendations: []
  };
  
  // Check password hash strength
  if (env.ADMIN_PASSWORD_HASH) {
    const hashParts = env.ADMIN_PASSWORD_HASH.split('$');
    if (hashParts.length >= 3) {
      const rounds = parseInt(hashParts[2]);
      if (rounds < 12) {
        audit.checks.push({
          name: 'Password Hash Rounds',
          status: 'WARN',
          message: `Using ${rounds} rounds, recommend at least 12`
        });
        audit.recommendations.push('Increase BCRYPT_ROUNDS to 12 or higher');
      }
    }
  }
  
  // Check session secret entropy
  if (env.SESSION_SECRET) {
    const entropy = Buffer.from(env.SESSION_SECRET, 'hex').length;
    if (entropy < 32) {
      audit.checks.push({
        name: 'Session Secret Entropy',
        status: 'FAIL',
        message: `Only ${entropy} bytes, need 32 bytes minimum`
      });
      audit.overall = 'FAIL';
    }
  }
  
  // Check encryption key
  if (env.ENABLE_ENCRYPTION === 'true' && !env.ENCRYPTION_KEY) {
    audit.checks.push({
      name: 'Encryption Key',
      status: 'FAIL',
      message: 'Encryption enabled but no key provided'
    });
    audit.overall = 'FAIL';
  }
  
  // Check key rotation settings
  if (env.ENABLE_ENCRYPTION === 'true' && !env.ENCRYPTION_KEY_ROTATION_DAYS) {
    audit.recommendations.push('Enable automatic encryption key rotation with ENCRYPTION_KEY_ROTATION_DAYS');
  }
  
  // Check request signing
  if (!env.REQUEST_SIGNING_KEY) {
    audit.recommendations.push('Generate a REQUEST_SIGNING_KEY for API request verification');
  }
  
  // Check CSRF protection
  if (!env.CSRF_SECRET) {
    audit.recommendations.push('Generate a CSRF_SECRET for form protection');
  }
  
  // Check for production settings
  if (env.NODE_ENV === 'production') {
    if (!env.REDIS_URL || !env.REDIS_URL.includes('rediss://')) {
      audit.recommendations.push('Use Redis with TLS (rediss://) in production');
    }
    
    if (env.DATABASE_URL && !env.DATABASE_URL.includes('sslmode=require')) {
      audit.recommendations.push('Add sslmode=require to DATABASE_URL for production');
    }
    
    if (!env.CSP_ENABLED || env.CSP_ENABLED !== 'true') {
      audit.recommendations.push('Enable CSP in production for better security');
    }
    
    if (!env.HSTS_ENABLED || env.HSTS_ENABLED !== 'true') {
      audit.recommendations.push('Enable HSTS in production for HTTPS enforcement');
    }
  }
  
  return audit;
}

function writeEnvFile(env, filePath = ENV_FILE, force = false) {
  const sections = {
    'REQUIRED SECURITY VARIABLES': [
      'SESSION_SECRET',
      'METRICS_API_KEY',
      'ADMIN_PASSWORD_HASH',
      'ADMIN_USERNAME',
      'JWT_SECRET',
      'ENCRYPTION_KEY',
      'API_KEY',
      'WEBHOOK_SECRET',
      'CSRF_SECRET',
      'OTP_SECRET',
      'BACKUP_CODES'
    ],
    'REQUEST SIGNING & API SECURITY': [
      'REQUEST_SIGNING_KEY',
      'REQUEST_SIGNING_EXPIRY',
      'API_VERSION_STRICT',
      'DEFAULT_API_VERSION',
      'SUPPORTED_API_VERSIONS',
      'CSRF_SECRET',
      'CSRF_ENABLED'
    ],
    'ENCRYPTION KEY ROTATION': [
      'ENABLE_ENCRYPTION',
      'ENCRYPTION_KEY_ROTATION_DAYS',
      'ENCRYPTION_KEY_STORAGE_PATH',
      'ENCRYPTION_KEY_BACKUP_PATH',
      'ENCRYPTION_KEY_ROTATION_INTERVAL',
      'ENCRYPTION_KEY_HISTORY_LIMIT'
    ],
    'DATABASE TRANSACTIONS': [
      'DB_TRANSACTION_TIMEOUT',
      'DB_TRANSACTION_RETRIES',
      'DB_ISOLATION_LEVEL',
      'DB_TRANSACTION_MONITORING',
      'DB_AUDIT_LOGS',
      'DB_CONNECTION_TIMEOUT',
      'DB_STATEMENT_TIMEOUT'
    ],
    'SERVER CONFIGURATION': [
      'PORT',
      'NODE_ENV',
      'HOST',
      'CORS_ORIGIN',
      'TRUST_PROXY',
      'BODY_LIMIT',
      'REQUEST_TIMEOUT',
      'KEEP_ALIVE_TIMEOUT',
      'HEADERS_TIMEOUT',
      'SERVER_TIMEOUT'
    ],
    'LINK CONFIGURATION': [
      'TARGET_URL',
      'LINK_TTL',
      'MAX_LINKS',
      'BOT_URLS',
      'DISABLE_DESKTOP_CHALLENGE',
      'ALLOW_CUSTOM_TARGETS',
      'LINK_LENGTH_MODE',
      'ALLOW_LINK_MODE_SWITCH',
      'LONG_LINK_SEGMENTS',
      'LONG_LINK_PARAMS',
      'LINK_ENCODING_LAYERS',
      'ENABLE_COMPRESSION',
      'ENABLE_ENCRYPTION',
      'MAX_ENCODING_ITERATIONS',
      'ENCODING_COMPLEXITY_THRESHOLD'
    ],
    'BULL QUEUE CONFIGURATION': [
      'QUEUE_ENABLED',
      'QUEUE_CONCURRENCY',
      'QUEUE_REDIS_URL',
      'QUEUE_AUTH_TOKEN',
      'QUEUE_PREFIX',
      'BULL_BOARD_ENABLED',
      'BULL_BOARD_PATH',
      'BULL_BOARD_AUTH_ENABLED',
      'BULL_BOARD_USERNAME',
      'BULL_BOARD_PASSWORD_HASH'
    ],
    'DATABASE CONFIGURATION': [
      'DATABASE_URL',
      'DB_HOST',
      'DB_PORT',
      'DB_NAME',
      'DB_USER',
      'DB_PASSWORD',
      'DB_POOL_MIN',
      'DB_POOL_MAX',
      'DB_IDLE_TIMEOUT',
      'DB_CONNECTION_TIMEOUT',
      'DB_QUERY_TIMEOUT',
      'DB_ENCRYPTION_KEY',
      'DB_SSL_MODE'
    ],
    'REDIS CONFIGURATION': [
      'REDIS_URL',
      'REDIS_HOST',
      'REDIS_PORT',
      'REDIS_PASSWORD',
      'REDIS_DB',
      'REDIS_PREFIX',
      'REDIS_TLS_ENABLED'
    ],
    'EXTERNAL SERVICES': [
      'IPINFO_TOKEN',
      'GA_TRACKING_ID',
      'SENTRY_DSN',
      'DISCORD_WEBHOOK',
      'SLACK_WEBHOOK',
      'TELEGRAM_BOT_TOKEN',
      'TELEGRAM_CHAT_ID'
    ],
    'EMAIL CONFIGURATION': [
      'SMTP_HOST',
      'SMTP_PORT',
      'SMTP_USER',
      'SMTP_PASS',
      'SMTP_FROM',
      'ALERT_EMAIL'
    ],
    'RATE LIMITING': [
      'RATE_LIMIT_WINDOW',
      'RATE_LIMIT_MAX_REQUESTS',
      'RATE_LIMIT_MOBILE',
      'RATE_LIMIT_DESKTOP',
      'RATE_LIMIT_BOT',
      'ENCODING_RATE_LIMIT',
      'RATE_LIMIT_REDIS_ENABLED'
    ],
    'SECURITY': [
      'BCRYPT_ROUNDS',
      'SESSION_TTL',
      'SESSION_ABSOLUTE_TIMEOUT',
      'CSP_ENABLED',
      'HSTS_ENABLED',
      'CORS_ENABLED',
      'LOGIN_ATTEMPTS_MAX',
      'LOGIN_BLOCK_DURATION',
      'MFA_ENABLED'
    ],
    'LOGGING': [
      'LOG_LEVEL',
      'LOG_FORMAT',
      'LOG_TO_FILE',
      'LOG_TO_CONSOLE',
      'LOG_RETENTION_DAYS',
      'LOG_MAX_SIZE',
      'DEBUG',
      'METRICS_ENABLED',
      'METRICS_PREFIX',
      'AUDIT_LOG_ENABLED'
    ],
    'CIRCUIT BREAKER': [
      'CIRCUIT_BREAKER_TIMEOUT',
      'CIRCUIT_BREAKER_ERROR_THRESHOLD',
      'CIRCUIT_BREAKER_RESET_TIMEOUT',
      'CIRCUIT_BREAKER_VOLUME_THRESHOLD'
    ],
    'PERFORMANCE': [
      'MAX_RESPONSE_TIMES_HISTORY',
      'CACHE_CHECK_PERIOD_FACTOR',
      'COMPRESSION_LEVEL',
      'COMPRESSION_THRESHOLD'
    ],
    'HEALTH CHECKS': [
      'HEALTH_CHECK_INTERVAL',
      'HEALTH_CHECK_TIMEOUT',
      'HEALTH_CHECK_DETAILED'
    ],
    'MONITORING': [
      'MEMORY_THRESHOLD_WARNING',
      'MEMORY_THRESHOLD_CRITICAL',
      'CPU_THRESHOLD_WARNING',
      'CPU_THRESHOLD_CRITICAL',
      'ALERT_ON_MEMORY_THRESHOLD',
      'ALERT_ON_CPU_THRESHOLD'
    ],
    'BACKUP': [
      'AUTO_BACKUP_ENABLED',
      'AUTO_BACKUP_INTERVAL',
      'BACKUP_RETENTION_DAYS',
      'BACKUP_ENCRYPTION_ENABLED',
      'BACKUP_COMPRESSION_ENABLED'
    ],
    'WEBHOOKS': [
      'WEBHOOK_URL',
      'WEBHOOK_EVENTS',
      'WEBHOOK_RETRY_COUNT',
      'WEBHOOK_TIMEOUT'
    ]
  };

  let content = `# ============================================================================
# REDIRECTOR PRO v4.1.0 - ENTERPRISE EDITION CONFIGURATION
# ============================================================================
# Generated: ${new Date().toISOString()}
# Host: ${os.hostname()}
# User: ${os.userInfo().username}
# Node: ${process.version}
# Platform: ${os.platform()} ${os.release()}
# ============================================================================

`;

  Object.entries(sections).forEach(([sectionName, keys]) => {
    const sectionVars = keys.filter(key => env[key] !== undefined && env[key] !== '');
    if (sectionVars.length > 0) {
      content += `\n# ─── ${sectionName} ${'─'.repeat(Math.max(0, 70 - sectionName.length - 8))}\n`;
      sectionVars.forEach(key => {
        const value = env[key];
        // Quote values that contain special characters
        const needsQuoting = value.includes(' ') || value.includes('#') || value.includes('=');
        content += `${key}=${needsQuoting ? `"${value}"` : value}\n`;
      });
    }
  });

  const allKeys = Object.keys(env);
  const usedKeys = Object.values(sections).flat();
  const extraKeys = allKeys.filter(key => !usedKeys.includes(key) && env[key] !== '');
  
  if (extraKeys.length > 0) {
    content += `\n# ─── ADDITIONAL VARIABLES ${'─'.repeat(Math.max(0, 70 - 21))}\n`;
    extraKeys.forEach(key => {
      const value = env[key];
      const needsQuoting = value.includes(' ') || value.includes('#') || value.includes('=');
      content += `${key}=${needsQuoting ? `"${value}"` : value}\n`;
    });
  }

  // Add footer with security notice
  content += `\n# ============================================================================
# SECURITY NOTICE
# ============================================================================
# This file contains sensitive information. Keep it secure and never commit
# to version control. The file permissions are set to 600 (owner read/write only).
# ============================================================================
`;

  if (fs.existsSync(filePath) && !force) {
    log('yellow', `⚠️  ${filePath} already exists. Use --force to overwrite.`);
    backupEnvFile();
    return false;
  }
  
  const dir = path.dirname(filePath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true, mode: 0o755 });
  }
  
  fs.writeFileSync(filePath, content);
  fs.chmodSync(filePath, 0o600);
  
  log('green', `✅ Secrets written to ${filePath}`);
  return true;
}

function createEnvExample() {
  const example = `# ============================================================================
# REDIRECTOR PRO v4.1.0 - ENTERPRISE EDITION - ENVIRONMENT EXAMPLE
# ============================================================================
# Copy this file to .env and fill in your values
# Run 'node generate-secrets.js --write' to generate secure values
# ============================================================================

# ─── REQUIRED SECURITY VARIABLES ──────────────────────────────────────────
SESSION_SECRET=your-32-byte-hex-secret-here
METRICS_API_KEY=your-32-byte-hex-key-here
ADMIN_PASSWORD_HASH=your-bcrypt-hash-here
ADMIN_USERNAME=admin
JWT_SECRET=your-jwt-secret-here
ENCRYPTION_KEY=your-encryption-key-here
API_KEY=rp_your-api-key-here
WEBHOOK_SECRET=whsec_your-webhook-secret
CSRF_SECRET=your-32-byte-hex-csrf-secret-here
OTP_SECRET=your-otp-secret-here
BACKUP_CODES=xxxx-xxxx-xxxx-xxxx,xxxx-xxxx-xxxx-xxxx,xxxx-xxxx-xxxx-xxxx

# ─── REQUEST SIGNING & API SECURITY ───────────────────────────────────────
REQUEST_SIGNING_KEY=your-32-byte-signing-key
REQUEST_SIGNING_EXPIRY=300000
API_VERSION_STRICT=false
DEFAULT_API_VERSION=v1
SUPPORTED_API_VERSIONS=v1,v2
CSRF_ENABLED=true

# ─── ENCRYPTION KEY ROTATION ──────────────────────────────────────────────
ENABLE_ENCRYPTION=false
ENCRYPTION_KEY_ROTATION_DAYS=7
ENCRYPTION_KEY_STORAGE_PATH=./data/keys
ENCRYPTION_KEY_BACKUP_PATH=./backups/keys
ENCRYPTION_KEY_ROTATION_INTERVAL=weekly
ENCRYPTION_KEY_HISTORY_LIMIT=10

# ─── DATABASE TRANSACTIONS ────────────────────────────────────────────────
DB_TRANSACTION_TIMEOUT=30000
DB_TRANSACTION_RETRIES=3
DB_ISOLATION_LEVEL=SERIALIZABLE
DB_TRANSACTION_MONITORING=true
DB_AUDIT_LOGS=true
DB_STATEMENT_TIMEOUT=10000

# ─── SERVER CONFIGURATION ─────────────────────────────────────────────────
PORT=10000
NODE_ENV=production
HOST=0.0.0.0
CORS_ORIGIN=*
TRUST_PROXY=1
BODY_LIMIT=100kb
REQUEST_TIMEOUT=30000
KEEP_ALIVE_TIMEOUT=30000
HEADERS_TIMEOUT=31000
SERVER_TIMEOUT=120000

# ─── LINK CONFIGURATION ───────────────────────────────────────────────────
TARGET_URL=https://example.com
LINK_TTL=30m
MAX_LINKS=1000000
BOT_URLS=https://www.google.com,https://www.microsoft.com,https://www.apple.com
DISABLE_DESKTOP_CHALLENGE=false
ALLOW_CUSTOM_TARGETS=true
LINK_LENGTH_MODE=short
ALLOW_LINK_MODE_SWITCH=true
LONG_LINK_SEGMENTS=6
LONG_LINK_PARAMS=13
LINK_ENCODING_LAYERS=4
ENABLE_COMPRESSION=true
ENABLE_ENCRYPTION=false
MAX_ENCODING_ITERATIONS=3
ENCODING_COMPLEXITY_THRESHOLD=50

# ─── BULL QUEUE CONFIGURATION ─────────────────────────────────────────────
QUEUE_ENABLED=false
QUEUE_CONCURRENCY=5
QUEUE_REDIS_URL=redis://localhost:6379
QUEUE_AUTH_TOKEN=qt_your-queue-auth-token
QUEUE_PREFIX=redirector
BULL_BOARD_ENABLED=true
BULL_BOARD_PATH=/admin/queues
BULL_BOARD_AUTH_ENABLED=true
BULL_BOARD_USERNAME=admin
BULL_BOARD_PASSWORD_HASH=your-bcrypt-hash-here

# ─── DATABASE CONFIGURATION ───────────────────────────────────────────────
DATABASE_URL=postgresql://user:password@localhost:5432/redirector
DB_HOST=localhost
DB_PORT=5432
DB_NAME=redirector
DB_USER=postgres
DB_PASSWORD=your-db-password
DB_POOL_MIN=2
DB_POOL_MAX=20
DB_IDLE_TIMEOUT=30000
DB_CONNECTION_TIMEOUT=5000
DB_QUERY_TIMEOUT=10000
DB_ENCRYPTION_KEY=your-db-encryption-key
DB_SSL_MODE=prefer

# ─── REDIS CONFIGURATION ──────────────────────────────────────────────────
REDIS_URL=redis://:password@localhost:6379/0
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=your-redis-password
REDIS_DB=0
REDIS_PREFIX=redirector:
REDIS_TLS_ENABLED=false

# ─── EXTERNAL SERVICES ────────────────────────────────────────────────────
IPINFO_TOKEN=your-ipinfo-token-here
GA_TRACKING_ID=UA-XXXXXXXXX-X
SENTRY_DSN=https://key@sentry.io/project
DISCORD_WEBHOOK=https://discord.com/api/webhooks/...
SLACK_WEBHOOK=https://hooks.slack.com/services/...
TELEGRAM_BOT_TOKEN=123456789:ABCdefGHIjklMNOpqrsTUVwxyz
TELEGRAM_CHAT_ID=-123456789

# ─── EMAIL CONFIGURATION ──────────────────────────────────────────────────
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@gmail.com
SMTP_PASS=your-app-password
SMTP_FROM=noreply@redirector.pro
ALERT_EMAIL=admin@example.com

# ─── RATE LIMITING ────────────────────────────────────────────────────────
RATE_LIMIT_WINDOW=60000
RATE_LIMIT_MAX_REQUESTS=100
RATE_LIMIT_MOBILE=30
RATE_LIMIT_DESKTOP=15
RATE_LIMIT_BOT=2
ENCODING_RATE_LIMIT=10
RATE_LIMIT_REDIS_ENABLED=false

# ─── SECURITY ─────────────────────────────────────────────────────────────
BCRYPT_ROUNDS=12
SESSION_TTL=86400
SESSION_ABSOLUTE_TIMEOUT=604800
CSP_ENABLED=true
HSTS_ENABLED=true
CORS_ENABLED=true
LOGIN_ATTEMPTS_MAX=10
LOGIN_BLOCK_DURATION=3600000
MFA_ENABLED=false

# ─── LOGGING ──────────────────────────────────────────────────────────────
LOG_LEVEL=info
LOG_FORMAT=json
LOG_TO_FILE=true
LOG_TO_CONSOLE=true
LOG_RETENTION_DAYS=30
LOG_MAX_SIZE=20m
DEBUG=false
METRICS_ENABLED=true
METRICS_PREFIX=redirector_
AUDIT_LOG_ENABLED=true

# ─── CIRCUIT BREAKER ──────────────────────────────────────────────────────
CIRCUIT_BREAKER_TIMEOUT=3000
CIRCUIT_BREAKER_ERROR_THRESHOLD=50
CIRCUIT_BREAKER_RESET_TIMEOUT=30000
CIRCUIT_BREAKER_VOLUME_THRESHOLD=10

# ─── PERFORMANCE ──────────────────────────────────────────────────────────
MAX_RESPONSE_TIMES_HISTORY=10000
CACHE_CHECK_PERIOD_FACTOR=0.1
COMPRESSION_LEVEL=6
COMPRESSION_THRESHOLD=1024

# ─── HEALTH CHECKS ────────────────────────────────────────────────────────
HEALTH_CHECK_INTERVAL=30000
HEALTH_CHECK_TIMEOUT=5000
HEALTH_CHECK_DETAILED=true

# ─── MONITORING ───────────────────────────────────────────────────────────
MEMORY_THRESHOLD_WARNING=0.8
MEMORY_THRESHOLD_CRITICAL=0.95
CPU_THRESHOLD_WARNING=0.7
CPU_THRESHOLD_CRITICAL=0.9
ALERT_ON_MEMORY_THRESHOLD=true
ALERT_ON_CPU_THRESHOLD=true

# ─── BACKUP ───────────────────────────────────────────────────────────────
AUTO_BACKUP_ENABLED=true
AUTO_BACKUP_INTERVAL=86400000
BACKUP_RETENTION_DAYS=7
BACKUP_ENCRYPTION_ENABLED=true
BACKUP_COMPRESSION_ENABLED=true

# ─── WEBHOOKS ─────────────────────────────────────────────────────────────
WEBHOOK_URL=https://api.example.com/webhook
WEBHOOK_EVENTS=link.created,link.clicked,bot.detected,key.rotated
WEBHOOK_RETRY_COUNT=3
WEBHOOK_TIMEOUT=5000

# ─── GENERATE SECURE VALUES ───────────────────────────────────────────────
# Run: node generate-secrets.js --write --all
# This will generate all required secure values
`;

  fs.writeFileSync(ENV_EXAMPLE_FILE, example);
  log('green', `✅ Created ${ENV_EXAMPLE_FILE}`);
  
  const envFiles = {
    [ENV_DEV_FILE]: `# Development environment
NODE_ENV=development
DEBUG=true
LOG_LEVEL=debug
CSP_ENABLED=false
HSTS_ENABLED=false
METRICS_ENABLED=false
AUTO_BACKUP_ENABLED=false
`,
    [ENV_PROD_FILE]: `# Production environment
NODE_ENV=production
DEBUG=false
LOG_LEVEL=info
CSP_ENABLED=true
HSTS_ENABLED=true
METRICS_ENABLED=true
AUTO_BACKUP_ENABLED=true
`,
    [ENV_LOCAL_FILE]: `# Local overrides
# Add local-only configuration here
# This file is gitignored by default

# Example overrides:
# PORT=9000
# DEBUG=true
# LOG_LEVEL=debug
`
  };
  
  Object.entries(envFiles).forEach(([file, content]) => {
    if (!fs.existsSync(file)) {
      fs.writeFileSync(file, content);
      fs.chmodSync(file, 0o600);
      log('green', `✅ Created ${file}`);
    }
  });
}

function exportSecrets(filePath, env, encryptionKey = null) {
  const secrets = {
    metadata: {
      generated: new Date().toISOString(),
      hostname: os.hostname(),
      user: os.userInfo().username,
      node: process.version,
      platform: `${os.platform()} ${os.release()}`,
      version: '3.0'
    },
    secrets: {}
  };
  
  Object.entries(env).forEach(([key, value]) => {
    if (key.includes('PASSWORD') || key.includes('SECRET') || key.includes('KEY') || key.includes('TOKEN')) {
      secrets.secrets[key] = {
        value: value,
        masked: value.substring(0, 8) + '...',
        length: value.length,
        type: 'sensitive'
      };
    } else {
      secrets.secrets[key] = {
        value: value,
        type: 'normal'
      };
    }
  });
  
  const output = JSON.stringify(secrets, null, 2);
  
  if (encryptionKey) {
    const encrypted = encryptValue(output, encryptionKey);
    fs.writeFileSync(filePath, JSON.stringify(encrypted));
    log('green', `✅ Encrypted secrets exported to ${filePath}`);
  } else {
    fs.writeFileSync(filePath, output);
    fs.chmodSync(filePath, 0o600);
    log('green', `✅ Secrets exported to ${filePath}`);
    log('yellow', '⚠️  File contains sensitive information. Keep it secure!');
  }
}

function importSecrets(filePath, encryptionKey = null) {
  if (!fs.existsSync(filePath)) {
    log('red', `❌ File not found: ${filePath}`);
    process.exit(1);
  }
  
  const content = fs.readFileSync(filePath, 'utf8');
  let data;
  
  try {
    if (encryptionKey) {
      const encrypted = JSON.parse(content);
      const decrypted = decryptValue(encrypted.encrypted, encrypted.iv, encrypted.authTag, encryptionKey);
      data = JSON.parse(decrypted);
    } else {
      data = JSON.parse(content);
    }
  } catch (err) {
    log('red', `❌ Failed to parse import file: ${err.message}`);
    process.exit(1);
  }
  
  const env = readEnvFile();
  
  Object.entries(data.secrets).forEach(([key, value]) => {
    if (value.type === 'sensitive' || value.type === 'normal') {
      env[key] = value.value;
    }
  });
  
  log('green', `✅ Secrets imported from ${filePath}`);
  return env;
}

function generateKubernetesSecrets(env, secrets) {
  const k8sSecrets = {
    apiVersion: 'v1',
    kind: 'Secret',
    metadata: {
      name: 'redirector-pro-secrets',
      namespace: 'default',
      labels: {
        app: 'redirector-pro',
        version: '4.1.0'
      },
      annotations: {
        'generated-at': new Date().toISOString()
      }
    },
    type: 'Opaque',
    data: {}
  };
  
  // Base64 encode all secrets for Kubernetes
  const secretKeys = [
    'SESSION_SECRET', 'METRICS_API_KEY', 'JWT_SECRET', 'ENCRYPTION_KEY',
    'API_KEY', 'WEBHOOK_SECRET', 'CSRF_SECRET', 'OTP_SECRET',
    'REQUEST_SIGNING_KEY', 'QUEUE_AUTH_TOKEN', 'DB_PASSWORD', 'REDIS_PASSWORD',
    'SMTP_PASS', 'IPINFO_TOKEN'
  ];
  
  secretKeys.forEach(key => {
    if (env[key]) {
      k8sSecrets.data[key.toLowerCase()] = Buffer.from(env[key]).toString('base64');
    }
  });
  
  if (secrets.passwordHash) {
    k8sSecrets.data['admin-password-hash'] = Buffer.from(secrets.passwordHash).toString('base64');
  }
  
  const outputPath = path.join(process.cwd(), 'k8s-secrets.yaml');
  fs.writeFileSync(outputPath, `# Kubernetes Secrets for Redirector Pro
# Generated: ${new Date().toISOString()}
# Apply with: kubectl apply -f k8s-secrets.yaml
---
${JSON.stringify(k8sSecrets, null, 2)}
`);
  
  log('green', `✅ Kubernetes secrets created: ${outputPath}`);
}

function generateAWSSecrets(env, secrets) {
  const awsSecrets = {
    'redirector-pro/session': env.SESSION_SECRET,
    'redirector-pro/metrics': env.METRICS_API_KEY,
    'redirector-pro/jwt': env.JWT_SECRET,
    'redirector-pro/encryption': env.ENCRYPTION_KEY,
    'redirector-pro/api-key': env.API_KEY,
    'redirector-pro/webhook': env.WEBHOOK_SECRET,
    'redirector-pro/csrf': env.CSRF_SECRET,
    'redirector-pro/otp': env.OTP_SECRET,
    'redirector-pro/signing': env.REQUEST_SIGNING_KEY,
    'redirector-pro/queue': env.QUEUE_AUTH_TOKEN,
    'redirector-pro/db-password': env.DB_PASSWORD,
    'redirector-pro/redis-password': env.REDIS_PASSWORD,
    'redirector-pro/smtp-pass': env.SMTP_PASS,
    'redirector-pro/admin-hash': secrets.passwordHash
  };
  
  const outputPath = path.join(process.cwd(), 'aws-secrets.json');
  fs.writeFileSync(outputPath, JSON.stringify(awsSecrets, null, 2));
  log('green', `✅ AWS Secrets Manager format created: ${outputPath}`);
  log('yellow', '⚠️  Import using: aws secretsmanager create-secret --name <name> --secret-string file://aws-secrets.json');
}

function generateDockerSecrets(env, secrets) {
  if (!fs.existsSync(SECRETS_DIR)) {
    fs.mkdirSync(SECRETS_DIR, { recursive: true, mode: 0o700 });
  }
  
  const dockerSecrets = {
    'session_secret': secrets.sessionSecret,
    'metrics_key': secrets.metricsKey,
    'jwt_secret': secrets.jwtSecret,
    'encryption_key': secrets.encryptionKey,
    'api_key': secrets.apiKey,
    'webhook_secret': secrets.webhookSecret,
    'csrf_secret': secrets.csrfSecret,
    'otp_secret': secrets.otpSecret,
    'signing_key': env.REQUEST_SIGNING_KEY || secrets.requestSigningKey,
    'queue_token': env.QUEUE_AUTH_TOKEN || secrets.queueAuthToken,
    'redis_password': env.REDIS_PASSWORD || '',
    'db_password': env.DB_PASSWORD || '',
    'smtp_password': env.SMTP_PASS || '',
    'ipinfo_token': env.IPINFO_TOKEN || '',
    'admin_password_hash': secrets.passwordHash
  };
  
  Object.entries(dockerSecrets).forEach(([name, value]) => {
    if (value) {
      const filePath = path.join(SECRETS_DIR, name);
      fs.writeFileSync(filePath, value);
      fs.chmodSync(filePath, 0o600);
      log('green', `✅ Docker secret created: ${filePath}`);
    }
  });
  
  // Create docker-compose secrets block
  const composeSecrets = Object.keys(dockerSecrets)
    .filter(name => dockerSecrets[name])
    .map(name => `  ${name}:\n    file: ./secrets/${name}`)
    .join('\n');
  
  const composeFile = path.join(process.cwd(), 'docker-compose.secrets.yml');
  const composeContent = `# Docker Compose Secrets
# Generated: ${new Date().toISOString()}
# Run: docker-compose -f docker-compose.yml -f docker-compose.secrets.yml up

secrets:
${composeSecrets}

services:
  app:
    secrets:
${Object.keys(dockerSecrets).filter(name => dockerSecrets[name]).map(name => `      - ${name}`).join('\n')}
`;
  
  fs.writeFileSync(composeFile, composeContent);
  log('green', `✅ Docker compose secrets file created: ${composeFile}`);
}

function generateHashiCorpVaultFormat(env, secrets) {
  const vaultSecrets = {
    data: {
      'session': env.SESSION_SECRET,
      'metrics': env.METRICS_API_KEY,
      'jwt': env.JWT_SECRET,
      'encryption': env.ENCRYPTION_KEY,
      'api-key': env.API_KEY,
      'webhook': env.WEBHOOK_SECRET,
      'csrf': env.CSRF_SECRET,
      'otp': env.OTP_SECRET,
      'signing': env.REQUEST_SIGNING_KEY,
      'queue': env.QUEUE_AUTH_TOKEN,
      'db-password': env.DB_PASSWORD,
      'redis-password': env.REDIS_PASSWORD,
      'admin-hash': secrets.passwordHash
    }
  };
  
  const outputPath = path.join(process.cwd(), 'vault-secrets.json');
  fs.writeFileSync(outputPath, JSON.stringify(vaultSecrets, null, 2));
  log('green', `✅ HashiCorp Vault format created: ${outputPath}`);
}

function validatePassword(password) {
  if (password.length < 8) {
    return 'Password must be at least 8 characters';
  }
  if (!/[A-Z]/.test(password)) {
    return 'Password should contain at least one uppercase letter';
  }
  if (!/[0-9]/.test(password)) {
    return 'Password should contain at least one number';
  }
  if (!/[!@#$%^&*]/.test(password)) {
    return 'Password should contain at least one special character (!@#$%^&*)';
  }
  return null;
}

async function promptForPassword() {
  return new Promise((resolve) => {
    rl.question(colors.yellow + '🔐 Enter admin password (min 8 chars, uppercase, number, special): ' + colors.reset, (password) => {
      const validationError = validatePassword(password);
      if (validationError) {
        log('red', `❌ ${validationError}`);
        resolve(promptForPassword());
      } else {
        rl.question(colors.yellow + '🔐 Confirm password: ' + colors.reset, (confirm) => {
          if (password === confirm) {
            resolve(password);
          } else {
            log('red', '❌ Passwords do not match');
            resolve(promptForPassword());
          }
        });
      }
    });
  });
}

async function promptForVar(varName, defaultValue = '', description = '') {
  return new Promise((resolve) => {
    const desc = description ? ` (${description})` : '';
    const prompt = defaultValue 
      ? `${varName}${desc} [${defaultValue}]: `
      : `${varName}${desc}: `;
    
    rl.question(colors.cyan + prompt + colors.reset, (value) => {
      resolve(value || defaultValue);
    });
  });
}

async function promptForRedis() {
  log('cyan', '\n📀 Configuring Redis (optional)...');
  const env = {};
  
  env.REDIS_HOST = await promptForVar('REDIS_HOST', 'localhost');
  env.REDIS_PORT = await promptForVar('REDIS_PORT', '6379');
  env.REDIS_DB = await promptForVar('REDIS_DB', '0');
  env.REDIS_PREFIX = await promptForVar('REDIS_PREFIX', 'redirector:');
  env.REDIS_TLS_ENABLED = await promptForVar('Enable Redis TLS? (true/false)', 'false');
  
  const usePassword = await promptForVar('Set Redis password?', 'yes');
  if (usePassword.toLowerCase().startsWith('y')) {
    env.REDIS_PASSWORD = generateRedisPassword();
    log('green', `✅ Generated Redis password: ${env.REDIS_PASSWORD}`);
    
    const protocol = env.REDIS_TLS_ENABLED === 'true' ? 'rediss' : 'redis';
    const encodedPassword = encodeURIComponent(env.REDIS_PASSWORD);
    env.REDIS_URL = `${protocol}://:${encodedPassword}@${env.REDIS_HOST}:${env.REDIS_PORT}/${env.REDIS_DB}`;
    log('green', `✅ Redis URL generated: ${env.REDIS_URL.replace(/:([^@]+)@/, ':****@')}`);
  } else {
    const protocol = env.REDIS_TLS_ENABLED === 'true' ? 'rediss' : 'redis';
    env.REDIS_URL = `${protocol}://${env.REDIS_HOST}:${env.REDIS_PORT}/${env.REDIS_DB}`;
  }
  
  return env;
}

async function promptForPostgres() {
  log('cyan', '\n🐘 Configuring PostgreSQL (optional)...');
  const env = {};
  
  env.DB_HOST = await promptForVar('DB_HOST', 'localhost');
  env.DB_PORT = await promptForVar('DB_PORT', '5432');
  env.DB_NAME = await promptForVar('DB_NAME', 'redirector');
  env.DB_USER = await promptForVar('DB_USER', 'postgres');
  env.DB_SSL_MODE = await promptForVar('DB SSL Mode (disable/prefer/require)', 'prefer');
  
  const password = generatePostgresPassword();
  env.DB_PASSWORD = await promptForVar('DB_PASSWORD', password);
  
  env.DB_POOL_MIN = await promptForVar('DB_POOL_MIN', '2');
  env.DB_POOL_MAX = await promptForVar('DB_POOL_MAX', '20');
  env.DB_IDLE_TIMEOUT = await promptForVar('DB_IDLE_TIMEOUT', '30000');
  env.DB_CONNECTION_TIMEOUT = await promptForVar('DB_CONNECTION_TIMEOUT', '5000');
  env.DB_QUERY_TIMEOUT = await promptForVar('DB_QUERY_TIMEOUT', '10000');
  env.DB_ENCRYPTION_KEY = generateDatabaseEncryptionKey();
  
  log('green', `✅ Generated database encryption key`);
  
  const encodedPassword = encodeURIComponent(env.DB_PASSWORD);
  env.DATABASE_URL = `postgresql://${env.DB_USER}:${encodedPassword}@${env.DB_HOST}:${env.DB_PORT}/${env.DB_NAME}?sslmode=${env.DB_SSL_MODE}`;
  log('green', `✅ PostgreSQL URL generated: ${env.DATABASE_URL.replace(/:([^@]+)@/, ':****@')}`);
  
  return env;
}

async function promptForQueue() {
  log('cyan', '\n📨 Configuring Bull Queue (optional)...');
  const env = {};
  
  env.QUEUE_ENABLED = await promptForVar('Enable Bull Queue?', 'false');
  
  if (env.QUEUE_ENABLED === 'true') {
    env.QUEUE_CONCURRENCY = await promptForVar('Queue concurrency', '5');
    env.QUEUE_PREFIX = await promptForVar('Queue prefix', 'redirector');
    env.QUEUE_AUTH_TOKEN = generateQueueAuthToken();
    log('green', `✅ Generated queue auth token: ${env.QUEUE_AUTH_TOKEN}`);
    
    env.BULL_BOARD_ENABLED = await promptForVar('Enable Bull Board UI?', 'true');
    if (env.BULL_BOARD_ENABLED === 'true') {
      env.BULL_BOARD_PATH = await promptForVar('Bull Board path', '/admin/queues');
      env.BULL_BOARD_AUTH_ENABLED = await promptForVar('Protect Bull Board with auth?', 'true');
      if (env.BULL_BOARD_AUTH_ENABLED === 'true') {
        env.BULL_BOARD_USERNAME = await promptForVar('Bull Board username', 'admin');
        // Would need to generate password hash, but we'll skip for now
      }
    }
  }
  
  return env;
}

async function promptForKeyRotation() {
  log('cyan', '\n🔄 Configuring Encryption Key Rotation...');
  const env = {};
  
  env.ENABLE_ENCRYPTION = await promptForVar('Enable encryption?', 'false');
  
  if (env.ENABLE_ENCRYPTION === 'true') {
    env.ENCRYPTION_KEY_ROTATION_DAYS = await promptForVar('Key rotation interval (days)', '7');
    env.ENCRYPTION_KEY_STORAGE_PATH = await promptForVar('Key storage path', './data/keys');
    env.ENCRYPTION_KEY_BACKUP_PATH = await promptForVar('Key backup path', './backups/keys');
    env.ENCRYPTION_KEY_HISTORY_LIMIT = await promptForVar('Key history limit', '10');
    
    const interval = parseInt(env.ENCRYPTION_KEY_ROTATION_DAYS);
    if (interval <= 1) env.ENCRYPTION_KEY_ROTATION_INTERVAL = 'daily';
    else if (interval <= 7) env.ENCRYPTION_KEY_ROTATION_INTERVAL = 'weekly';
    else if (interval <= 31) env.ENCRYPTION_KEY_ROTATION_INTERVAL = 'monthly';
    else env.ENCRYPTION_KEY_ROTATION_INTERVAL = 'quarterly';
  }
  
  return env;
}

async function promptForRequestSigning() {
  log('cyan', '\n📝 Configuring Request Signing...');
  const env = {};
  
  env.REQUEST_SIGNING_KEY = generateRequestSigningKey();
  env.REQUEST_SIGNING_EXPIRY = await promptForVar('Signature expiry (ms)', '300000');
  
  log('green', `✅ Generated request signing key: ${env.REQUEST_SIGNING_KEY.substring(0, 8)}...`);
  
  return env;
}

async function promptForAPIVersioning() {
  log('cyan', '\n🔢 Configuring API Versioning...');
  const env = {};
  
  env.DEFAULT_API_VERSION = await promptForVar('Default API version', 'v1');
  env.SUPPORTED_API_VERSIONS = await promptForVar('Supported versions (comma-separated)', 'v1,v2');
  env.API_VERSION_STRICT = await promptForVar('Strict versioning?', 'false');
  
  return env;
}

async function promptForDatabaseTransactions() {
  log('cyan', '\n💾 Configuring Database Transactions...');
  const env = {};
  
  env.DB_TRANSACTION_TIMEOUT = await promptForVar('Transaction timeout (ms)', '30000');
  env.DB_TRANSACTION_RETRIES = await promptForVar('Transaction retries', '3');
  env.DB_ISOLATION_LEVEL = await promptForVar('Isolation level', 'SERIALIZABLE');
  env.DB_TRANSACTION_MONITORING = await promptForVar('Enable transaction monitoring?', 'true');
  env.DB_AUDIT_LOGS = await promptForVar('Enable audit logs?', 'true');
  
  return env;
}

async function main() {
  const args = process.argv.slice(2);
  
  if (args.includes('--help')) {
    showHelp();
  }
  
  if (args.includes('--example')) {
    createEnvExample();
    process.exit(0);
  }
  
  if (args.includes('--validate')) {
    const env = readEnvFile();
    const { errors, warnings } = validateEnvFile(env);
    const audit = auditSecrets(env);
    
    if (errors.length > 0) {
      errors.forEach(err => log('red', `❌ ${err}`));
      process.exit(1);
    }
    
    if (warnings.length > 0) {
      warnings.forEach(warn => log('yellow', `⚠️ ${warn}`));
    }
    
    if (audit.checks.length > 0) {
      log('yellow', '\n📊 Audit Results:');
      audit.checks.forEach(check => {
        const color = check.status === 'PASS' ? 'green' : check.status === 'WARN' ? 'yellow' : 'red';
        log(color, `  ${check.status}: ${check.name} - ${check.message}`);
      });
    }
    
    if (audit.recommendations.length > 0) {
      log('cyan', '\n💡 Recommendations:');
      audit.recommendations.forEach(rec => log('cyan', `  • ${rec}`));
    }
    
    if (errors.length === 0 && audit.overall === 'PASS') {
      log('green', '\n✅ Environment file is valid and secure');
    } else {
      log('yellow', '\n⚠️ Environment file has issues that should be addressed');
    }
    
    process.exit(0);
  }
  
  const exportIndex = args.indexOf('--export');
  if (exportIndex !== -1 && args[exportIndex + 1]) {
    const env = readEnvFile();
    const encryptionKey = args.includes('--encrypt') ? env.ENCRYPTION_KEY : null;
    exportSecrets(args[exportIndex + 1], env, encryptionKey);
    process.exit(0);
  }
  
  const importIndex = args.indexOf('--import');
  if (importIndex !== -1 && args[importIndex + 1]) {
    const encryptionKey = args.includes('--encrypt') ? readEnvFile().ENCRYPTION_KEY : null;
    const env = importSecrets(args[importIndex + 1], encryptionKey);
    writeEnvFile(env, ENV_FILE, true);
    process.exit(0);
  }
  
  const mergeIndex = args.indexOf('--merge');
  if (mergeIndex !== -1 && args[mergeIndex + 1]) {
    const currentEnv = readEnvFile();
    const mergeEnv = importSecrets(args[mergeIndex + 1]);
    const mergedEnv = { ...currentEnv, ...mergeEnv };
    writeEnvFile(mergedEnv, ENV_FILE, true);
    process.exit(0);
  }
  
  const writeToFile = args.includes('--write');
  const forceOverwrite = args.includes('--force');
  const backup = args.includes('--backup');
  const generateAll = args.includes('--all');
  const generateBasic = args.includes('--basic') || !generateAll;
  
  const configureRedis = args.includes('--redis') || generateAll;
  const configurePostgres = args.includes('--postgres') || generateAll;
  const generateJWT = args.includes('--jwt') || generateAll;
  const generateDocker = args.includes('--docker') || generateAll;
  const generateK8s = args.includes('--kubernetes') || generateAll;
  const generateAWS = args.includes('--aws') || generateAll;
  const generateVault = args.includes('--hashicorp') || generateAll;
  const encryptSecrets = args.includes('--encrypt');
  const rotateSecrets = args.includes('--rotate');
  const requestSigning = args.includes('--request-signing') || generateAll;
  const keyRotation = args.includes('--key-rotation') || generateAll;
  const apiVersioning = args.includes('--api-versioning') || generateAll;
  const databaseTx = args.includes('--database-tx') || generateAll;
  const bullQueue = args.includes('--bull-queue') || generateAll;
  const webhooks = args.includes('--webhooks') || generateAll;
  const rateLimiting = args.includes('--rate-limiting') || generateAll;
  const circuitBreaker = args.includes('--circuit-breaker') || generateAll;
  const monitoring = args.includes('--monitoring') || generateAll;
  const mfa = args.includes('--mfa') || generateAll;
  const pgp = args.includes('--pgp') || generateAll;
  const ssh = args.includes('--ssh') || generateAll;
  
  if (rotateSecrets && fs.existsSync(ENV_FILE)) {
    log('yellow', '🔄 Rotating secrets...');
    backupEnvFile();
  }
  
  let password = args.find(arg => !arg.startsWith('--') && arg !== password);
  
  console.log('\n' + '='.repeat(80));
  log('bright', '🔐 REDIRECTOR PRO v4.1.0 - ENTERPRISE SECRETS GENERATOR v3.0');
  console.log('='.repeat(80) + '\n');

  log('cyan', '📡 Generating secure values...\n');
  
  const secrets = {
    sessionSecret: generateSessionSecret(),
    metricsKey: generateMetricsKey(),
    jwtSecret: generateJWTSecret(),
    encryptionKey: generateEncryptionKey(),
    apiKey: generateAPIKey(),
    webhookSecret: generateWebhookSecret(),
    csrfSecret: generateCSRFSecret(),
    salt: generateSalt(),
    otpSecret: generateOTPSecret(),
    backupCodes: generateBackupCodes(10),
    requestSigningKey: generateRequestSigningKey(),
    queueAuthToken: generateQueueAuthToken()
  };
  
  if (pgp) {
    secrets.pgpKeys = generatePGPKeyPair();
  }
  
  if (ssh) {
    secrets.sshKeys = generateSSHKeyPair();
  }
  
  if (!password) {
    password = await promptForPassword();
  } else {
    const validationError = validatePassword(password);
    if (validationError) {
      log('red', `❌ ${validationError}`);
      process.exit(1);
    }
  }
  
  const passwordHash = generatePasswordHash(password, 12);
  secrets.passwordHash = passwordHash;
  
  log('green', '✅ Generated successfully!\n');
  
  console.log(colors.bright + 'Essential Secrets:' + colors.reset);
  console.log('  SESSION_SECRET=' + colors.dim + secrets.sessionSecret + colors.reset);
  console.log('  METRICS_API_KEY=' + colors.dim + secrets.metricsKey + colors.reset);
  console.log('  ENCRYPTION_KEY=' + colors.dim + secrets.encryptionKey + colors.reset);
  console.log('  API_KEY=' + colors.dim + secrets.apiKey + colors.reset);
  console.log('  WEBHOOK_SECRET=' + colors.dim + secrets.webhookSecret + colors.reset);
  console.log('  CSRF_SECRET=' + colors.dim + secrets.csrfSecret + colors.reset);
  
  if (generateJWT) {
    console.log('\n' + colors.bright + 'JWT Secrets:' + colors.reset);
    console.log('  JWT_SECRET=' + colors.dim + secrets.jwtSecret + colors.reset);
  }
  
  if (requestSigning) {
    console.log('\n' + colors.bright + 'Request Signing:' + colors.reset);
    console.log('  REQUEST_SIGNING_KEY=' + colors.dim + secrets.requestSigningKey + colors.reset);
    console.log('  REQUEST_SIGNING_EXPIRY=300000');
  }
  
  if (bullQueue) {
    console.log('\n' + colors.bright + 'Queue Authentication:' + colors.reset);
    console.log('  QUEUE_AUTH_TOKEN=' + colors.dim + secrets.queueAuthToken + colors.reset);
  }
  
  if (mfa) {
    console.log('\n' + colors.bright + 'MFA/2FA Configuration:' + colors.reset);
    console.log('  OTP_SECRET=' + colors.dim + secrets.otpSecret + colors.reset);
    console.log('  BACKUP_CODES=' + colors.dim + secrets.backupCodes.join(', ') + colors.reset);
    console.log('  MFA_ENABLED=false');
  }
  
  console.log('\n' + colors.bright + 'Admin Credentials:' + colors.reset);
  console.log('  ADMIN_USERNAME=admin');
  console.log('  ADMIN_PASSWORD_HASH=' + colors.dim + passwordHash + colors.reset);
  console.log('  ADMIN_PASSWORD=' + colors.yellow + password + colors.reset + ' ' + colors.dim + '(save this securely!)' + colors.reset);
  
  if (pgp && secrets.pgpKeys) {
    console.log('\n' + colors.bright + 'PGP Keys Generated (saved to keys/ directory)' + colors.reset);
    if (!fs.existsSync(KEYS_DIR)) {
      fs.mkdirSync(KEYS_DIR, { recursive: true, mode: 0o700 });
    }
    fs.writeFileSync(path.join(KEYS_DIR, 'pgp-public.key'), secrets.pgpKeys.publicKey);
    fs.writeFileSync(path.join(KEYS_DIR, 'pgp-private.key'), secrets.pgpKeys.privateKey);
    fs.chmodSync(path.join(KEYS_DIR, 'pgp-private.key'), 0o600);
    log('green', '  ✅ PGP keys saved to keys/ directory');
  }
  
  if (ssh && secrets.sshKeys) {
    console.log('\n' + colors.bright + 'SSH Keys Generated (saved to keys/ directory)' + colors.reset);
    fs.writeFileSync(path.join(KEYS_DIR, 'ssh-private.key'), secrets.sshKeys.privateKey);
    fs.writeFileSync(path.join(KEYS_DIR, 'ssh-public.key'), secrets.sshKeys.publicKey);
    fs.chmodSync(path.join(KEYS_DIR, 'ssh-private.key'), 0o600);
    log('green', '  ✅ SSH keys saved to keys/ directory');
  }
  
  console.log('\n' + '='.repeat(80));
  
  const env = readEnvFile();
  
  // Required security variables
  env.SESSION_SECRET = secrets.sessionSecret;
  env.METRICS_API_KEY = secrets.metricsKey;
  env.ADMIN_PASSWORD_HASH = passwordHash;
  env.ADMIN_USERNAME = env.ADMIN_USERNAME || 'admin';
  env.ENCRYPTION_KEY = secrets.encryptionKey;
  env.API_KEY = secrets.apiKey;
  env.WEBHOOK_SECRET = secrets.webhookSecret;
  env.CSRF_SECRET = secrets.csrfSecret;
  env.OTP_SECRET = secrets.otpSecret;
  env.BACKUP_CODES = secrets.backupCodes.join(',');
  
  if (generateJWT) {
    env.JWT_SECRET = secrets.jwtSecret;
  }
  
  if (requestSigning) {
    env.REQUEST_SIGNING_KEY = secrets.requestSigningKey;
    env.REQUEST_SIGNING_EXPIRY = env.REQUEST_SIGNING_EXPIRY || '300000';
  }
  
  if (bullQueue) {
    env.QUEUE_AUTH_TOKEN = secrets.queueAuthToken;
    env.QUEUE_ENABLED = env.QUEUE_ENABLED || 'false';
    env.QUEUE_CONCURRENCY = env.QUEUE_CONCURRENCY || '5';
    env.QUEUE_PREFIX = env.QUEUE_PREFIX || 'redirector';
    env.BULL_BOARD_ENABLED = env.BULL_BOARD_ENABLED || 'true';
    env.BULL_BOARD_PATH = env.BULL_BOARD_PATH || '/admin/queues';
  }
  
  if (mfa) {
    env.MFA_ENABLED = env.MFA_ENABLED || 'false';
  }
  
  if (apiVersioning) {
    env.DEFAULT_API_VERSION = env.DEFAULT_API_VERSION || 'v1';
    env.SUPPORTED_API_VERSIONS = env.SUPPORTED_API_VERSIONS || 'v1,v2';
    env.API_VERSION_STRICT = env.API_VERSION_STRICT || 'false';
    env.CSRF_ENABLED = env.CSRF_ENABLED || 'true';
  }
  
  if (keyRotation) {
    const rotationEnv = await promptForKeyRotation();
    Object.assign(env, rotationEnv);
  }
  
  if (databaseTx) {
    const txEnv = await promptForDatabaseTransactions();
    Object.assign(env, txEnv);
  }
  
  if (configureRedis) {
    const redisEnv = await promptForRedis();
    Object.assign(env, redisEnv);
  }
  
  if (configurePostgres) {
    const pgEnv = await promptForPostgres();
    Object.assign(env, pgEnv);
  }
  
  if (bullQueue && !configureRedis) {
    // If queue enabled but Redis not configured, prompt for it
    const redisEnv = await promptForRedis();
    Object.assign(env, redisEnv);
    env.QUEUE_REDIS_URL = env.REDIS_URL;
  }
  
  if (rateLimiting) {
    env.RATE_LIMIT_WINDOW = env.RATE_LIMIT_WINDOW || '60000';
    env.RATE_LIMIT_MAX_REQUESTS = env.RATE_LIMIT_MAX_REQUESTS || '100';
    env.RATE_LIMIT_MOBILE = env.RATE_LIMIT_MOBILE || '30';
    env.RATE_LIMIT_DESKTOP = env.RATE_LIMIT_DESKTOP || '15';
    env.RATE_LIMIT_BOT = env.RATE_LIMIT_BOT || '2';
    env.ENCODING_RATE_LIMIT = env.ENCODING_RATE_LIMIT || '10';
    env.RATE_LIMIT_REDIS_ENABLED = env.RATE_LIMIT_REDIS_ENABLED || 'false';
  }
  
  if (circuitBreaker) {
    env.CIRCUIT_BREAKER_TIMEOUT = env.CIRCUIT_BREAKER_TIMEOUT || '3000';
    env.CIRCUIT_BREAKER_ERROR_THRESHOLD = env.CIRCUIT_BREAKER_ERROR_THRESHOLD || '50';
    env.CIRCUIT_BREAKER_RESET_TIMEOUT = env.CIRCUIT_BREAKER_RESET_TIMEOUT || '30000';
    env.CIRCUIT_BREAKER_VOLUME_THRESHOLD = env.CIRCUIT_BREAKER_VOLUME_THRESHOLD || '10';
  }
  
  if (monitoring) {
    env.MEMORY_THRESHOLD_WARNING = env.MEMORY_THRESHOLD_WARNING || '0.8';
    env.MEMORY_THRESHOLD_CRITICAL = env.MEMORY_THRESHOLD_CRITICAL || '0.95';
    env.CPU_THRESHOLD_WARNING = env.CPU_THRESHOLD_WARNING || '0.7';
    env.CPU_THRESHOLD_CRITICAL = env.CPU_THRESHOLD_CRITICAL || '0.9';
    env.ALERT_ON_MEMORY_THRESHOLD = env.ALERT_ON_MEMORY_THRESHOLD || 'true';
    env.ALERT_ON_CPU_THRESHOLD = env.ALERT_ON_CPU_THRESHOLD || 'true';
    env.AUDIT_LOG_ENABLED = env.AUDIT_LOG_ENABLED || 'true';
  }
  
  if (webhooks) {
    env.WEBHOOK_RETRY_COUNT = env.WEBHOOK_RETRY_COUNT || '3';
    env.WEBHOOK_TIMEOUT = env.WEBHOOK_TIMEOUT || '5000';
  }
  
  // Server configuration
  env.PORT = env.PORT || '10000';
  env.NODE_ENV = env.NODE_ENV || 'production';
  env.HOST = env.HOST || '0.0.0.0';
  env.CORS_ORIGIN = env.CORS_ORIGIN || '*';
  env.TRUST_PROXY = env.TRUST_PROXY || '1';
  env.BODY_LIMIT = env.BODY_LIMIT || '100kb';
  env.REQUEST_TIMEOUT = env.REQUEST_TIMEOUT || '30000';
  env.KEEP_ALIVE_TIMEOUT = env.KEEP_ALIVE_TIMEOUT || '30000';
  env.HEADERS_TIMEOUT = env.HEADERS_TIMEOUT || '31000';
  env.SERVER_TIMEOUT = env.SERVER_TIMEOUT || '120000';
  
  // Link configuration
  env.TARGET_URL = env.TARGET_URL || 'https://example.com';
  env.LINK_TTL = env.LINK_TTL || '30m';
  env.MAX_LINKS = env.MAX_LINKS || '1000000';
  env.BOT_URLS = env.BOT_URLS || 'https://www.google.com,https://www.microsoft.com,https://www.apple.com';
  env.DISABLE_DESKTOP_CHALLENGE = env.DISABLE_DESKTOP_CHALLENGE || 'false';
  env.ALLOW_CUSTOM_TARGETS = env.ALLOW_CUSTOM_TARGETS || 'true';
  env.LINK_LENGTH_MODE = env.LINK_LENGTH_MODE || 'short';
  env.ALLOW_LINK_MODE_SWITCH = env.ALLOW_LINK_MODE_SWITCH || 'true';
  env.LONG_LINK_SEGMENTS = env.LONG_LINK_SEGMENTS || '6';
  env.LONG_LINK_PARAMS = env.LONG_LINK_PARAMS || '13';
  env.LINK_ENCODING_LAYERS = env.LINK_ENCODING_LAYERS || '4';
  env.ENABLE_COMPRESSION = env.ENABLE_COMPRESSION || 'true';
  env.MAX_ENCODING_ITERATIONS = env.MAX_ENCODING_ITERATIONS || '3';
  env.ENCODING_COMPLEXITY_THRESHOLD = env.ENCODING_COMPLEXITY_THRESHOLD || '50';
  
  // Logging
  env.LOG_LEVEL = env.LOG_LEVEL || 'info';
  env.LOG_FORMAT = env.LOG_FORMAT || 'json';
  env.LOG_TO_FILE = env.LOG_TO_FILE || 'true';
  env.LOG_TO_CONSOLE = env.LOG_TO_CONSOLE || 'true';
  env.LOG_RETENTION_DAYS = env.LOG_RETENTION_DAYS || '30';
  env.LOG_MAX_SIZE = env.LOG_MAX_SIZE || '20m';
  env.DEBUG = env.DEBUG || 'false';
  env.METRICS_ENABLED = env.METRICS_ENABLED || 'true';
  env.METRICS_PREFIX = env.METRICS_PREFIX || 'redirector_';
  
  // Security
  env.BCRYPT_ROUNDS = env.BCRYPT_ROUNDS || '12';
  env.SESSION_TTL = env.SESSION_TTL || '86400';
  env.SESSION_ABSOLUTE_TIMEOUT = env.SESSION_ABSOLUTE_TIMEOUT || '604800';
  env.CSP_ENABLED = env.CSP_ENABLED || 'true';
  env.HSTS_ENABLED = env.HSTS_ENABLED || 'true';
  env.CORS_ENABLED = env.CORS_ENABLED || 'true';
  env.LOGIN_ATTEMPTS_MAX = env.LOGIN_ATTEMPTS_MAX || '10';
  env.LOGIN_BLOCK_DURATION = env.LOGIN_BLOCK_DURATION || '3600000';
  
  // Performance
  env.MAX_RESPONSE_TIMES_HISTORY = env.MAX_RESPONSE_TIMES_HISTORY || '10000';
  env.CACHE_CHECK_PERIOD_FACTOR = env.CACHE_CHECK_PERIOD_FACTOR || '0.1';
  env.COMPRESSION_LEVEL = env.COMPRESSION_LEVEL || '6';
  env.COMPRESSION_THRESHOLD = env.COMPRESSION_THRESHOLD || '1024';
  
  // Health checks
  env.HEALTH_CHECK_INTERVAL = env.HEALTH_CHECK_INTERVAL || '30000';
  env.HEALTH_CHECK_TIMEOUT = env.HEALTH_CHECK_TIMEOUT || '5000';
  env.HEALTH_CHECK_DETAILED = env.HEALTH_CHECK_DETAILED || 'true';
  
  // Backup
  env.AUTO_BACKUP_ENABLED = env.AUTO_BACKUP_ENABLED || 'true';
  env.AUTO_BACKUP_INTERVAL = env.AUTO_BACKUP_INTERVAL || '86400000';
  env.BACKUP_RETENTION_DAYS = env.BACKUP_RETENTION_DAYS || '7';
  env.BACKUP_ENCRYPTION_ENABLED = env.BACKUP_ENCRYPTION_ENABLED || 'true';
  env.BACKUP_COMPRESSION_ENABLED = env.BACKUP_COMPRESSION_ENABLED || 'true';
  
  if (encryptSecrets && env.ENCRYPTION_KEY) {
    const sensitiveKeys = [
      'DB_PASSWORD', 'REDIS_PASSWORD', 'SMTP_PASS', 'WEBHOOK_SECRET', 
      'API_KEY', 'JWT_SECRET', 'REQUEST_SIGNING_KEY', 'QUEUE_AUTH_TOKEN'
    ];
    
    sensitiveKeys.forEach(key => {
      if (env[key]) {
        const encryptedValue = encryptValue(env[key], env.ENCRYPTION_KEY);
        env[`${key}_ENC`] = JSON.stringify(encryptedValue);
        log('yellow', `🔒 Encrypted ${key}`);
      }
    });
  }
  
  if (writeToFile) {
    let targetFile = ENV_FILE;
    if (args.includes('--local')) {
      targetFile = ENV_LOCAL_FILE;
    } else if (args.includes('--prod')) {
      targetFile = ENV_PROD_FILE;
    } else if (args.includes('--dev')) {
      targetFile = ENV_DEV_FILE;
    } else if (args.includes('--test')) {
      targetFile = path.join(process.cwd(), '.env.test');
    }
    
    if (backup) {
      backupEnvFile();
    }
    
    const written = writeEnvFile(env, targetFile, forceOverwrite);
    
    if (written) {
      if (generateDocker) {
        generateDockerSecrets(env, secrets);
      }
      
      if (generateK8s) {
        generateKubernetesSecrets(env, secrets);
      }
      
      if (generateAWS) {
        generateAWSSecrets(env, secrets);
      }
      
      if (generateVault) {
        generateHashiCorpVaultFormat(env, secrets);
      }
    }
  } else {
    log('yellow', '\n📋 Copy the values above to your .env file');
    
    console.log('\n' + colors.bright + 'Complete configuration summary:' + colors.reset);
    console.log('-'.repeat(60));
    
    const summaryKeys = Object.keys(env).filter(key => !key.includes('PASSWORD') && !key.includes('SECRET') && !key.includes('KEY') && !key.includes('TOKEN'));
    summaryKeys.slice(0, 20).forEach(key => {
      console.log(`${key}=${env[key]}`);
    });
    
    if (summaryKeys.length > 20) {
      console.log(`... and ${summaryKeys.length - 20} more variables`);
    }
    console.log('-'.repeat(60));
    
    console.log('\n' + colors.bright + 'Run with --write to save to file' + colors.reset);
  }
  
  console.log('\n' + '='.repeat(80));
  log('yellow', '⚠️  IMPORTANT SECURITY NOTES:');
  console.log('   • Store these values in a secure password manager');
  console.log('   • Never commit .env files to version control');
  console.log('   • Use different passwords in production vs development');
  console.log('   • Enable MFA for admin accounts');
  console.log('   • Regularly rotate secrets (every 90 days)');
  console.log('   • Monitor audit logs for suspicious activity');
  console.log('   • Set up automated database backups');
  console.log('   • Configure Redis with TLS in production');
  console.log('   • Enable encryption key rotation for long-term security');
  console.log('   • Use request signing for API v2 endpoints');
  console.log('='.repeat(80) + '\n');
  
  log('cyan', '📋 Next steps:');
  console.log('   1. Review the generated configuration');
  console.log('   2. Test with: npm run dev');
  console.log('   3. Deploy with: npm run prod');
  console.log('   4. Monitor with: npm run pm2');
  console.log('   5. Backup with: npm run backup');
  console.log('   6. Check API docs at: http://localhost:10000/api-docs');
  console.log('   7. Monitor queues at: http://localhost:10000/admin/queues');
  console.log('   8. Rotate keys with: npm run keys:rotate');
  console.log('   9. Audit security with: npm run security:audit\n');
  
  log('green', '✨ Generation complete! Your enterprise secrets are ready.\n');
  
  rl.close();
}

process.on('SIGINT', () => {
  console.log('\n');
  log('yellow', '⚠️  Generation cancelled');
  process.exit(0);
});

main().catch(err => {
  log('red', `\n❌ Error: ${err.message}`);
  console.error(err);
  process.exit(1);
});
