# 🔗 Redirector Pro

<div align="center">

Advanced URL redirection service with strong bot protection, real-time analytics, QR code generation, and a clean admin dashboard.

[![Version](https://img.shields.io/badge/version-3.0.0-blue?style=for-the-badge&logo=semver)](https://github.com/yourusername/redirector-pro)
[![Node](https://img.shields.io/badge/node-%3E%3D16.0.0-brightgreen?style=for-the-badge&logo=node.js)](https://nodejs.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](https://opensource.org/licenses/MIT)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen?style=for-the-badge&logo=github)](http://makeapullrequest.com)
[![Docker Ready](https://img.shields.io/badge/docker-ready-blue?style=for-the-badge&logo=docker)](https://hub.docker.com/r/yourusername/redirector-pro)

**Sophisticated. Secure. Performant.**

[Features](#-features) • [Installation](#-installation) • [Configuration](#-configuration) • [API](#-api) • [Security](#-security-best-practices) • [Screenshots](#-screenshots)

</div>

---

## ✨ Features

### 🛡️ Advanced Bot & Threat Protection
- Multi-factor bot scoring (UA + headers + behavior)
- Headless browser & automation detection
- Device-type aware thresholds (very lenient for real mobiles)
- Custom bot fallback URLs (Microsoft, Apple, Google, …)
- Real-time block statistics

### 📱 Mobile-First Design
- Ultra-permissive mobile verification
- Mobile-specific rate limits (30 req/min default)
- Fully responsive admin interface
- Touch-optimized controls

### 🎯 QR Code Engine
- Instant QR generation for any destination
- Downloadable PNGs
- Cached for speed
- Optional QR landing page before final redirect

### 📊 Real-time Analytics & Monitoring
- Live traffic via Socket.IO
- Device breakdown (mobile/desktop/tablet/bot)
- Country-level geo stats (IPinfo)
- Block vs success ratio
- Request rate heatmaps

### 🔐 Security Hardening
- Helmet + strict CSP with nonces
- Per-device rate limiting
- Session-based admin auth (bcrypt)
- Double URL encoding layer option
- Secure headers & anti-clickjacking

### 🎨 Elegant Admin Dashboard
- Modern dark/light theme support
- Live charts (Chart.js)
- Real-time request log tail
- Quick link + QR generator
- Cache & config management UI

### ⚡ Optimized Performance
- Multi-level caching (geo, device, QR, links)
- gzip/brotli compression
- Memory-friendly design
- Configurable link expiration

---

## 🚀 Installation

### Prerequisites
- **Node.js** ≥ 16
- npm / yarn / pnpm
- (Recommended) IPinfo.io token for geo data

### Quick Start (Local)

```bash
git clone https://github.com/yourusername/redirector-pro.git
cd redirector-pro

npm install

cp .env.example .env

# Generate bcrypt hash for admin password
node -e "console.log(require('bcryptjs').hashSync('strong-password-here', 10))"

# Edit .env (especially credentials and secrets!)
code .env   # or nano/vim

npm start
# or with auto-reload (dev):
npm run dev