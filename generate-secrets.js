#!/usr/bin/env node

/**
 * Generate Secrets Script
 * 
 * Run this script to generate secure values for your .env file
 * 
 * Usage:
 *   node generate-secrets.js                    # Interactive mode
 *   node generate-secrets.js mypassword         # Generate with specific password
 *   node generate-secrets.js --write            # Generate and write to .env
 *   node generate-secrets.js --write mypassword # Generate with password and write to .env
 *   node generate-secrets.js --help              # Show help
 */

const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const fs = require('fs');
const path = require('path');
const readline = require('readline');
const os = require('os');
const { execSync } = require('child_process');

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
${colors.bright}🔐 GENERATE SECRETS SCRIPT v2.1 - Enterprise Edition${colors.reset}

${colors.bright}Usage:${colors.reset}
  node generate-secrets.js [options] [password]

${colors.bright}Options:${colors.reset}
  --write           Write generated values directly to .env file
  --force           Force overwrite existing values in .env
  --example         Create .env.example file with template
  --redis           Add Redis configuration to .env
  --postgres        Add PostgreSQL configuration to .env
  --jwt             Generate JWT secrets
  --docker          Generate docker-compose compatible secrets
  --all             Generate all possible configurations
  --encrypt         Encrypt sensitive values
  --backup          Backup existing .env file
  --rotate          Rotate existing secrets (generate new ones)
  --validate        Validate existing .env file
  --export <file>   Export secrets as JSON
  --import <file>   Import secrets from JSON file
  --help            Show this help message

${colors.bright}Examples:${colors.reset}
  node generate-secrets.js
  node generate-secrets.js --write
  node generate-secrets.js --write --all
  node generate-secrets.js --validate
  node generate-secrets.js --rotate --write
  node generate-secrets.js --export secrets.json
  node generate-secrets.js --import secrets.json
  node generate-secrets.js --docker --write

${colors.bright}Output:${colors.reset}
  - SESSION_SECRET: Random 32-byte hex string
  - METRICS_API_KEY: Random 32-byte hex string  
  - ADMIN_PASSWORD_HASH: Bcrypt hash of password
  - JWT_SECRET: JWT signing secret
  - ENCRYPTION_KEY: AES-256 encryption key
  - API_KEY: Random API key
  - WEBHOOK_SECRET: Webhook signing secret
  - CSRF_SECRET: CSRF protection secret
  - DATABASE_URL: PostgreSQL connection string
  - REDIS_URL: Redis connection string
  `);
  process.exit(0);
}

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
  return 'rp_' + crypto.randomBytes(24).toString('base64').replace(/[^a-zA-Z0-9]/g, '');
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
      value = value.replace(/^["']|["']$/g, '');
      env[key] = value;
    }
  });
  
  return env;
}

function backupEnvFile() {
  if (fs.existsSync(ENV_FILE)) {
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const backupPath = path.join(process.cwd(), `.env.backup.${timestamp}`);
    fs.copyFileSync(ENV_FILE, backupPath);
    log('green', `✅ Backup created: ${backupPath}`);
    return backupPath;
  }
  return null;
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
  
  if (env.PORT && (isNaN(parseInt(env.PORT)) || parseInt(env.PORT) < 1 || parseInt(env.PORT) > 65535)) {
    errors.push('PORT must be a valid port number (1-65535)');
  }
  
  if (env.NODE_ENV && !['development', 'production', 'test'].includes(env.NODE_ENV)) {
    warnings.push('NODE_ENV should be development, production, or test');
  }
  
  if (env.TARGET_URL && !env.TARGET_URL.match(/^https?:\/\/.+/)) {
    warnings.push('TARGET_URL should be a valid URL');
  }
  
  if (env.LINK_TTL && !env.LINK_TTL.match(/^\d+[smhd]?$/)) {
    warnings.push('LINK_TTL should be in format: 30m, 1h, 7d, etc.');
  }
  
  return { errors, warnings };
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
      'CSRF_SECRET'
    ],
    'SERVER CONFIGURATION': [
      'PORT',
      'NODE_ENV',
      'HOST',
      'CORS_ORIGIN',
      'TRUST_PROXY',
      'BODY_LIMIT'
    ],
    'LINK CONFIGURATION': [
      'TARGET_URL',
      'LINK_TTL',
      'MAX_LINKS',
      'BOT_URLS',
      'DISABLE_DESKTOP_CHALLENGE',
      'ALLOW_CUSTOM_TARGETS'
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
      'DB_IDLE_TIMEOUT'
    ],
    'REDIS CONFIGURATION': [
      'REDIS_URL',
      'REDIS_HOST',
      'REDIS_PORT',
      'REDIS_PASSWORD',
      'REDIS_DB',
      'REDIS_PREFIX'
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
      'RATE_LIMIT_MAX',
      'RATE_LIMIT_MOBILE',
      'RATE_LIMIT_DESKTOP',
      'RATE_LIMIT_BOT'
    ],
    'SECURITY': [
      'BCRYPT_ROUNDS',
      'SESSION_TTL',
      'CSP_ENABLED',
      'HSTS_ENABLED',
      'CORS_ENABLED'
    ],
    'LOGGING': [
      'LOG_LEVEL',
      'LOG_FORMAT',
      'LOG_TO_FILE',
      'LOG_TO_CONSOLE',
      'DEBUG',
      'METRICS_ENABLED'
    ],
    'QUEUE CONFIGURATION': [
      'QUEUE_ENABLED',
      'QUEUE_CONCURRENCY',
      'QUEUE_REDIS_URL'
    ],
    'WEBHOOKS': [
      'WEBHOOK_URL',
      'WEBHOOK_EVENTS'
    ],
    '2FA/MFA': [
      'OTP_SECRET',
      'MFA_ENABLED',
      'BACKUP_CODES'
    ]
  };

  let content = `# ============================================================================
# REDIRECTOR PRO - ENTERPRISE EDITION CONFIGURATION
# ============================================================================
# Generated: ${new Date().toISOString()}
# Host: ${os.hostname()}
# User: ${os.userInfo().username}
# Run 'node generate-secrets.js --help' for more information
# ============================================================================

`;

  Object.entries(sections).forEach(([sectionName, keys]) => {
    const sectionVars = keys.filter(key => env[key] !== undefined);
    if (sectionVars.length > 0) {
      content += `\n# ─── ${sectionName} ${'─'.repeat(Math.max(0, 60 - sectionName.length - 8))}\n`;
      sectionVars.forEach(key => {
        const value = env[key];
        content += `${key}=${value}\n`;
      });
    }
  });

  const allKeys = Object.keys(env);
  const usedKeys = Object.values(sections).flat();
  const extraKeys = allKeys.filter(key => !usedKeys.includes(key));
  
  if (extraKeys.length > 0) {
    content += `\n# ─── ADDITIONAL VARIABLES ${'─'.repeat(Math.max(0, 60 - 21))}\n`;
    extraKeys.forEach(key => {
      content += `${key}=${env[key]}\n`;
    });
  }

  if (fs.existsSync(filePath) && !force) {
    log('yellow', `⚠️  ${filePath} already exists. Use --force to overwrite.`);
    const backup = backupEnvFile();
    if (backup) {
      log('green', `✅ Backup created`);
    }
  }
  
  const dir = path.dirname(filePath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  
  fs.writeFileSync(filePath, content);
  log('green', `✅ Secrets written to ${filePath}`);
  
  fs.chmodSync(filePath, 0o600);
}

function createEnvExample() {
  const example = `# ============================================================================
# REDIRECTOR PRO - ENTERPRISE EDITION - ENVIRONMENT EXAMPLE
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

# ─── SERVER CONFIGURATION ─────────────────────────────────────────────────
PORT=10000
NODE_ENV=production
HOST=0.0.0.0
CORS_ORIGIN=*
TRUST_PROXY=1
BODY_LIMIT=50kb

# ─── LINK CONFIGURATION ───────────────────────────────────────────────────
TARGET_URL=https://example.com
LINK_TTL=30m
MAX_LINKS=1000000
BOT_URLS=https://www.microsoft.com,https://www.apple.com,https://www.google.com
DISABLE_DESKTOP_CHALLENGE=false
ALLOW_CUSTOM_TARGETS=true

# ─── DATABASE CONFIGURATION (PostgreSQL) ──────────────────────────────────
DATABASE_URL=postgresql://user:password@localhost:5432/redirector
DB_HOST=localhost
DB_PORT=5432
DB_NAME=redirector
DB_USER=postgres
DB_PASSWORD=your-db-password
DB_POOL_MIN=2
DB_POOL_MAX=10
DB_IDLE_TIMEOUT=30000

# ─── REDIS CONFIGURATION ──────────────────────────────────────────────────
REDIS_URL=redis://:password@localhost:6379/0
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=your-redis-password
REDIS_DB=0
REDIS_PREFIX=redirector:

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
RATE_LIMIT_MAX=100
RATE_LIMIT_MOBILE=30
RATE_LIMIT_DESKTOP=15
RATE_LIMIT_BOT=2

# ─── SECURITY ─────────────────────────────────────────────────────────────
BCRYPT_ROUNDS=12
SESSION_TTL=86400
CSP_ENABLED=true
HSTS_ENABLED=true
CORS_ENABLED=true

# ─── LOGGING ──────────────────────────────────────────────────────────────
LOG_LEVEL=info
LOG_FORMAT=combined
LOG_TO_FILE=true
LOG_TO_CONSOLE=true
DEBUG=false
METRICS_ENABLED=true

# ─── QUEUE CONFIGURATION ──────────────────────────────────────────────────
QUEUE_ENABLED=false
QUEUE_CONCURRENCY=5
QUEUE_REDIS_URL=redis://localhost:6379

# ─── WEBHOOKS ─────────────────────────────────────────────────────────────
WEBHOOK_URL=https://api.example.com/webhook
WEBHOOK_EVENTS=link.created,link.clicked,bot.detected

# ─── 2FA/MFA ──────────────────────────────────────────────────────────────
MFA_ENABLED=false
BACKUP_CODES=xxxx-xxxx-xxxx-xxxx,xxxx-xxxx-xxxx-xxxx

# ─── GENERATE SECURE VALUES ───────────────────────────────────────────────
# Run: node generate-secrets.js --write --all
# This will generate all required secure values
`;

  fs.writeFileSync(ENV_EXAMPLE_FILE, example);
  log('green', `✅ Created ${ENV_EXAMPLE_FILE}`);
  
  const examples = {
    [ENV_DEV_FILE]: '# Development environment\nNODE_ENV=development\nDEBUG=true',
    [ENV_PROD_FILE]: '# Production environment\nNODE_ENV=production\nDEBUG=false',
    [ENV_LOCAL_FILE]: '# Local overrides\n# Add local-only configuration here'
  };
  
  Object.entries(examples).forEach(([file, content]) => {
    if (!fs.existsSync(file)) {
      fs.writeFileSync(file, content + '\n');
      log('green', `✅ Created ${file}`);
    }
  });
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
  
  const usePassword = await promptForVar('Set Redis password?', 'yes');
  if (usePassword.toLowerCase().startsWith('y')) {
    env.REDIS_PASSWORD = generateRedisPassword();
    log('green', `✅ Generated Redis password: ${env.REDIS_PASSWORD}`);
    
    // FIXED: Properly encode password for Redis URL
    const encodedPassword = encodeURIComponent(env.REDIS_PASSWORD);
    env.REDIS_URL = `redis://:${encodedPassword}@${env.REDIS_HOST}:${env.REDIS_PORT}/${env.REDIS_DB}`;
    log('green', `✅ Redis URL generated: ${env.REDIS_URL.replace(/:([^@]+)@/, ':****@')}`);
  } else {
    env.REDIS_URL = `redis://${env.REDIS_HOST}:${env.REDIS_PORT}/${env.REDIS_DB}`;
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
  
  const password = generatePostgresPassword();
  env.DB_PASSWORD = await promptForVar('DB_PASSWORD', password);
  
  env.DB_POOL_MIN = await promptForVar('DB_POOL_MIN', '2');
  env.DB_POOL_MAX = await promptForVar('DB_POOL_MAX', '10');
  env.DB_IDLE_TIMEOUT = await promptForVar('DB_IDLE_TIMEOUT', '30000');
  
  // FIXED: Properly encode password for PostgreSQL URL
  const encodedPassword = encodeURIComponent(env.DB_PASSWORD);
  env.DATABASE_URL = `postgresql://${env.DB_USER}:${encodedPassword}@${env.DB_HOST}:${env.DB_PORT}/${env.DB_NAME}`;
  log('green', `✅ PostgreSQL URL generated: ${env.DATABASE_URL.replace(/:([^@]+)@/, ':****@')}`);
  
  return env;
}

function exportSecrets(filePath) {
  const env = readEnvFile();
  const secrets = {
    generated: new Date().toISOString(),
    hostname: os.hostname(),
    user: os.userInfo().username,
    environment: env.NODE_ENV || 'production',
    secrets: {}
  };
  
  Object.entries(env).forEach(([key, value]) => {
    if (key.includes('PASSWORD') || key.includes('SECRET') || key.includes('KEY')) {
      secrets.secrets[key] = {
        value: value,
        masked: value.substring(0, 8) + '...',
        length: value.length
      };
    } else {
      secrets.secrets[key] = value;
    }
  });
  
  fs.writeFileSync(filePath, JSON.stringify(secrets, null, 2));
  log('green', `✅ Secrets exported to ${filePath}`);
}

function importSecrets(filePath) {
  if (!fs.existsSync(filePath)) {
    log('red', `❌ File not found: ${filePath}`);
    process.exit(1);
  }
  
  const content = fs.readFileSync(filePath, 'utf8');
  const data = JSON.parse(content);
  
  const env = readEnvFile();
  
  Object.entries(data.secrets).forEach(([key, value]) => {
    if (typeof value === 'object' && value.value) {
      env[key] = value.value;
    } else {
      env[key] = value;
    }
  });
  
  writeEnvFile(env, ENV_FILE, true);
  log('green', `✅ Secrets imported from ${filePath}`);
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
    
    if (errors.length > 0) {
      errors.forEach(err => log('red', `❌ ${err}`));
      process.exit(1);
    }
    
    if (warnings.length > 0) {
      warnings.forEach(warn => log('yellow', `⚠️ ${warn}`));
    } else {
      log('green', '✅ Environment file is valid');
    }
    process.exit(0);
  }
  
  const exportIndex = args.indexOf('--export');
  if (exportIndex !== -1 && args[exportIndex + 1]) {
    exportSecrets(args[exportIndex + 1]);
    process.exit(0);
  }
  
  const importIndex = args.indexOf('--import');
  if (importIndex !== -1 && args[importIndex + 1]) {
    importSecrets(args[importIndex + 1]);
    process.exit(0);
  }
  
  const writeToFile = args.includes('--write');
  const forceOverwrite = args.includes('--force');
  const configureRedis = args.includes('--redis') || args.includes('--all');
  const configurePostgres = args.includes('--postgres') || args.includes('--all');
  const generateJWT = args.includes('--jwt') || args.includes('--all');
  const generateDocker = args.includes('--docker') || args.includes('--all');
  const encryptSecrets = args.includes('--encrypt');
  const rotateSecrets = args.includes('--rotate');
  
  if (rotateSecrets && fs.existsSync(ENV_FILE)) {
    backupEnvFile();
  }
  
  let password = args.find(arg => !arg.startsWith('--') && arg !== password);
  
  console.log('\n' + '='.repeat(70));
  log('bright', '🔐 REDIRECTOR PRO - ENTERPRISE SECRETS GENERATOR v2.1');
  console.log('='.repeat(70) + '\n');

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
    otpSecret: generateOTPSecret()
  };
  
  if (!password) {
    password = await promptForPassword();
  } else {
    const validationError = validatePassword(password);
    if (validationError) {
      log('red', `❌ ${validationError}`);
      process.exit(1);
    }
  }
  
  const passwordHash = generatePasswordHash(password);
  secrets.passwordHash = passwordHash;
  
  log('green', '✅ Generated successfully!\n');
  
  console.log(colors.bright + 'SESSION_SECRET=' + colors.reset + secrets.sessionSecret);
  console.log(colors.bright + 'METRICS_API_KEY=' + colors.reset + secrets.metricsKey);
  console.log(colors.bright + 'JWT_SECRET=' + colors.reset + secrets.jwtSecret);
  console.log(colors.bright + 'ENCRYPTION_KEY=' + colors.reset + secrets.encryptionKey);
  console.log(colors.bright + 'API_KEY=' + colors.reset + secrets.apiKey);
  console.log(colors.bright + 'WEBHOOK_SECRET=' + colors.reset + secrets.webhookSecret);
  console.log(colors.bright + 'CSRF_SECRET=' + colors.reset + secrets.csrfSecret);
  console.log(colors.bright + 'ADMIN_PASSWORD_HASH=' + colors.reset + passwordHash);
  console.log(colors.dim + '(Password: ' + password + ')' + colors.reset);
  
  console.log('\n' + '='.repeat(70));
  
  const env = readEnvFile();
  
  env.SESSION_SECRET = secrets.sessionSecret;
  env.METRICS_API_KEY = secrets.metricsKey;
  env.ADMIN_PASSWORD_HASH = passwordHash;
  env.ADMIN_USERNAME = env.ADMIN_USERNAME || 'admin';
  
  if (generateJWT) {
    env.JWT_SECRET = secrets.jwtSecret;
  }
  
  env.ENCRYPTION_KEY = secrets.encryptionKey;
  env.API_KEY = secrets.apiKey;
  env.WEBHOOK_SECRET = secrets.webhookSecret;
  env.CSRF_SECRET = secrets.csrfSecret;
  env.OTP_SECRET = secrets.otpSecret;
  
  env.PORT = env.PORT || '10000';
  env.NODE_ENV = env.NODE_ENV || 'production';
  env.TARGET_URL = env.TARGET_URL || 'https://example.com';
  env.LINK_TTL = env.LINK_TTL || '30m';
  env.MAX_LINKS = env.MAX_LINKS || '1000000';
  env.BOT_URLS = env.BOT_URLS || 'https://www.google.com,https://www.microsoft.com';
  env.LOG_LEVEL = env.LOG_LEVEL || 'info';
  env.DEBUG = env.DEBUG || 'false';
  env.DISABLE_DESKTOP_CHALLENGE = env.DISABLE_DESKTOP_CHALLENGE || 'false';
  
  if (configureRedis) {
    const redisEnv = await promptForRedis();
    Object.assign(env, redisEnv);
  }
  
  if (configurePostgres) {
    const pgEnv = await promptForPostgres();
    Object.assign(env, pgEnv);
  }
  
  if (generateDocker) {
    const secretsDir = path.join(process.cwd(), 'secrets');
    if (!fs.existsSync(secretsDir)) {
      fs.mkdirSync(secretsDir, { recursive: true });
    }
    
    Object.entries({
      'session_secret': secrets.sessionSecret,
      'metrics_key': secrets.metricsKey,
      'jwt_secret': secrets.jwtSecret,
      'encryption_key': secrets.encryptionKey,
      'api_key': secrets.apiKey,
      'webhook_secret': secrets.webhookSecret,
      'csrf_secret': secrets.csrfSecret,
      'redis_password': env.REDIS_PASSWORD || '',
      'db_password': env.DB_PASSWORD || ''
    }).forEach(([name, value]) => {
      if (value) {
        const filePath = path.join(secretsDir, name);
        fs.writeFileSync(filePath, value);
        fs.chmodSync(filePath, 0o600);
        log('green', `✅ Docker secret created: ${filePath}`);
      }
    });
  }
  
  if (encryptSecrets && env.ENCRYPTION_KEY) {
    const sensitiveKeys = ['DB_PASSWORD', 'REDIS_PASSWORD', 'SMTP_PASS', 'WEBHOOK_SECRET'];
    
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
    }
    
    writeEnvFile(env, targetFile, forceOverwrite);
    
    if (targetFile !== ENV_FILE && !fs.existsSync(ENV_FILE)) {
      try {
        fs.symlinkSync(path.basename(targetFile), ENV_FILE);
        log('green', `✅ Created symlink: .env -> ${path.basename(targetFile)}`);
      } catch (err) {
        // Ignore symlink errors on Windows
      }
    }
  } else {
    log('yellow', '\n📋 Copy the values above to your .env file');
    
    console.log('\n' + colors.bright + 'Complete configuration:' + colors.reset);
    console.log('-'.repeat(50));
    Object.entries(env).forEach(([key, value]) => {
      if (key.includes('PASSWORD') || key.includes('SECRET') || key.includes('KEY') || key.includes('TOKEN')) {
        console.log(`${key}=${value.substring(0, 8)}...`);
      } else {
        console.log(`${key}=${value}`);
      }
    });
    console.log('-'.repeat(50));
    
    console.log('\n' + colors.bright + 'Run with --write to save to file' + colors.reset);
  }
  
  console.log('\n' + '='.repeat(70));
  log('yellow', '⚠️  IMPORTANT SECURITY NOTES:');
  console.log('   • Store these values in a secure password manager');
  console.log('   • Never commit .env files to version control');
  console.log('   • Use different passwords in production vs development');
  console.log('   • Enable 2FA for admin accounts');
  console.log('   • Regularly rotate secrets (every 90 days)');
  console.log('   • Monitor audit logs for suspicious activity');
  console.log('   • Set up database backups');
  console.log('   • Configure Redis with password and TLS in production');
  console.log('='.repeat(70) + '\n');
  
  log('cyan', '📋 Next steps:');
  console.log('   1. Review the generated configuration');
  console.log('   2. Test with: npm run dev');
  console.log('   3. Deploy with: npm run prod');
  console.log('   4. Monitor with: npm run pm2');
  console.log('   5. Backup with: npm run backup\n');
  
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