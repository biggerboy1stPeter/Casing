// diagnose.js
const http = require('http');
const os = require('os');

console.log('\n🔍 SYSTEM DIAGNOSTIC');
console.log('='.repeat(50));

// Node.js info
console.log('\n📦 Node.js:');
console.log(`  Version: ${process.version}`);
console.log(`  Platform: ${process.platform}`);
console.log(`  Architecture: ${process.arch}`);
console.log(`  PID: ${process.pid}`);

// Environment
console.log('\n🌍 Environment:');
console.log(`  NODE_ENV: ${process.env.NODE_ENV || 'not set'}`);
console.log(`  PORT: ${process.env.PORT || 'not set!'}`);
console.log(`  HOST: ${process.env.HOST || 'not set'}`);

// System info
console.log('\n💻 System:');
console.log(`  Hostname: ${os.hostname()}`);
console.log(`  Platform: ${os.platform()}`);
console.log(`  CPUs: ${os.cpus().length}`);
console.log(`  Memory: ${Math.round(os.totalmem() / 1024 / 1024)} MB`);
console.log(`  Free Memory: ${Math.round(os.freemem() / 1024 / 1024)} MB`);
console.log(`  Uptime: ${Math.round(os.uptime() / 60)} minutes`);

// Network interfaces
console.log('\n🌐 Network Interfaces:');
const nets = os.networkInterfaces();
for (const name of Object.keys(nets)) {
    for (const net of nets[name]) {
        if (net.family === 'IPv4' && !net.internal) {
            console.log(`  ${name}: ${net.address}`);
        }
    }
}

// Test port binding
console.log('\n🔌 Testing port binding...');
const testPort = process.env.PORT || 10000;
const testServer = http.createServer((req, res) => {
    res.writeHead(200);
    res.end('OK');
});

testServer.listen(testPort, '0.0.0.0')
    .once('listening', () => {
        console.log(`  ✅ Successfully bound to port ${testPort}`);
        testServer.close();
        console.log('\n✅ Diagnostic complete - port binding works!\n');
    })
    .once('error', (err) => {
        console.error(`  ❌ Failed to bind to port ${testPort}:`, err.message);
        console.error('\n❌ Diagnostic failed - port binding issue detected!\n');
        process.exit(1);
    });
