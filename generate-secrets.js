// Run this script to generate secure values: node generate-secrets.js
const crypto = require('crypto');
const bcrypt = require('bcryptjs');

console.log('\n🔐 GENERATE SECURE VALUES FOR .ENV\n');
console.log('=' .repeat(50));

// Generate session secret
const sessionSecret = crypto.randomBytes(32).toString('hex');
console.log('SESSION_SECRET=' + sessionSecret);

// Generate metrics API key
const metricsKey = crypto.randomBytes(32).toString('hex');
console.log('METRICS_API_KEY=' + metricsKey);

// Generate password hash (default: admin123)
const password = process.argv[2] || 'admin123';
const hash = bcrypt.hashSync(password, 10);
console.log('ADMIN_PASSWORD_HASH=' + hash);
console.log('(Password: ' + password + ')');

console.log('=' .repeat(50));
console.log('\nCopy these values to your .env file\n');
