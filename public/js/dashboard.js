// ============================================
// Redirector Pro v4.1.0 - Enterprise Dashboard
// ============================================

// Global variables injected from server
/* global METRICS_API_KEY, TARGET_URL, CSRF_TOKEN, LINK_LENGTH_MODE, 
   ALLOW_LINK_MODE_SWITCH, LONG_LINK_SEGMENTS, LONG_LINK_PARAMS, 
   LINK_ENCODING_LAYERS, MAX_ENCODING_ITERATIONS, ENABLE_COMPRESSION,
   ENABLE_ENCRYPTION, BULL_BOARD_PATH, NODE_ENV, RATE_LIMIT_MAX, 
   ENCODING_RATE_LIMIT, MFA_ENABLED, WEBAUTHN_ENABLED, SESSION_TTL,
   AUDIT_LOG_ENABLED, BACKUP_ENCRYPTION_ENABLED */

// ============================================
// Configuration and Constants
// ============================================
const APP_CONFIG = {
    version: '4.1.0',
    maxLogEntries: 1000,
    maxAuditEntries: 500,
    chartUpdateThrottle: 100,
    socketRetryAttempts: 10,
    socketRetryDelay: 1000,
    maxSocketQueueSize: 100,
    refreshInterval: 5000,
    validation: {
        linkIdPattern: /^[a-f0-9]{32,64}$/i,
        ipPattern: /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/,
        urlPattern: /^https?:\/\//i
    }
};

// ============================================
// State Management with Improved Organization
// ============================================
class AppState {
    constructor() {
        this.socket = null;
        this.socketQueue = new SocketQueue();
        this.requestsChart = null;
        this.deviceChart = null;
        this.countryChart = null;
        this.analyticsDeviceChart = null;
        this.performanceChart = null;
        this.allLinks = [];
        this.filteredLinks = [];
        this.autoScroll = true;
        this.showTimestamps = true;
        this.currentTimeRange = '5m';
        this.logCount = 0;
        this.selectedLinkMode = typeof LINK_LENGTH_MODE !== 'undefined' ? LINK_LENGTH_MODE : 'short';
        this.currentPage = 1;
        this.pageSize = 20;
        this.securityData = { blockedIPs: [], activeAttacks: [], totalAttempts: 0, activeSessions: [] };
        this.logFilter = 'all';
        this.logRate = 0;
        this.logRateCounter = 0;
        this.encryptionKeys = [];
        this.auditLogs = [];
        this.backupStatus = {};
        this.mfaSetupRequired = false;
        this.activeAlerts = [];
        this.notificationSound = false;
        this.darkMode = true;
        this.refreshInterval = APP_CONFIG.refreshInterval;
        this.autoRefreshEnabled = true;
        this.chartUpdateTimeout = null;
        this.cleanupFunctions = [];
        this.startTime = Date.now();
        this.updateIntervals = [];
    }

    registerCleanup(fn) {
        this.cleanupFunctions.push(fn);
    }

    registerInterval(interval) {
        this.updateIntervals.push(interval);
    }

    destroy() {
        this.cleanupFunctions.forEach(fn => fn());
        this.updateIntervals.forEach(clearInterval);
        
        // Destroy charts
        [this.requestsChart, this.deviceChart, this.countryChart, 
         this.analyticsDeviceChart, this.performanceChart].forEach(chart => {
            if (chart) {
                chart.destroy();
            }
        });
        
        if (this.socket) {
            this.socket.disconnect();
        }
        
        if (this.chartUpdateTimeout) {
            clearTimeout(this.chartUpdateTimeout);
        }
    }
}

const appState = new AppState();

// ============================================
// Socket Queue for Managing Events
// ============================================
class SocketQueue {
    constructor(maxSize = APP_CONFIG.maxSocketQueueSize) {
        this.queue = [];
        this.processing = false;
        this.maxSize = maxSize;
    }

    add(action, data) {
        if (this.queue.length >= this.maxSize) {
            console.warn('Socket queue full, dropping oldest item');
            this.queue.shift();
        }
        this.queue.push({ action, data, timestamp: Date.now() });
        this.process().catch(err => console.error('Queue processing error:', err));
    }

    async process() {
        if (this.processing || this.queue.length === 0 || !appState.socket?.connected) {
            return;
        }

        this.processing = true;

        while (this.queue.length > 0) {
            const item = this.queue.shift();
            
            // Drop items older than 30 seconds
            if (Date.now() - item.timestamp > 30000) {
                console.warn('Dropping stale socket item:', item);
                continue;
            }

            try {
                await new Promise((resolve, reject) => {
                    const timeout = setTimeout(() => {
                        reject(new Error('Socket emit timeout'));
                    }, 5000);

                    appState.socket.emit('command', item, (response) => {
                        clearTimeout(timeout);
                        if (response?.error) {
                            reject(new Error(response.error));
                        } else {
                            resolve(response);
                        }
                    });
                });
            } catch (err) {
                console.error('Socket emit failed:', err);
            }

            // Small delay between emits
            await new Promise(resolve => setTimeout(resolve, 50));
        }

        this.processing = false;
    }

    clear() {
        this.queue = [];
        this.processing = false;
    }
}

// ============================================
// Data Validators
// ============================================
const Validators = {
    linkId(id) {
        return id && APP_CONFIG.validation.linkIdPattern.test(id);
    },

    url(url) {
        if (!url) return false;
        try {
            const parsed = new URL(url);
            return ['http:', 'https:'].includes(parsed.protocol);
        } catch {
            return false;
        }
    },

    ip(ip) {
        return ip && APP_CONFIG.validation.ipPattern.test(ip);
    },

    sanitizeHTML(str) {
        if (!str) return '';
        return String(str)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
    },

    sanitizeJSON(obj) {
        return JSON.stringify(obj).replace(/</g, '\\u003c').replace(/>/g, '\\u003e');
    },

    escapeForHTML(str) {
        return Validators.sanitizeHTML(str);
    },

    validateAndSanitizeUrl(url) {
        if (!Validators.url(url)) {
            return '#invalid-url';
        }
        return Validators.sanitizeHTML(url);
    },

    validateIp(ip) {
        return Validators.ip(ip) ? ip : null;
    }
};

// ============================================
// Debounce Utility
// ============================================
function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

// ============================================
// Retryable Operation Utility
// ============================================
class RetryableOperation {
    constructor(operation, maxRetries = 3, baseDelay = 1000) {
        this.operation = operation;
        this.maxRetries = maxRetries;
        this.baseDelay = baseDelay;
    }

    async execute() {
        let lastError;
        for (let i = 0; i < this.maxRetries; i++) {
            try {
                return await this.operation();
            } catch (err) {
                lastError = err;
                if (i === this.maxRetries - 1) break;
                
                const delay = this.baseDelay * Math.pow(2, i);
                console.warn(`Retry ${i + 1}/${this.maxRetries} after ${delay}ms`);
                await new Promise(resolve => setTimeout(resolve, delay));
            }
        }
        throw lastError;
    }
}

// ============================================
// Socket.IO Initialization with Improved Error Handling
// ============================================
function initSocket() {
    console.log('🔌 Initializing Socket.IO connection...');
    
    if (appState.socket) {
        appState.socket.disconnect();
    }
    
    appState.socket = io({
        auth: { token: METRICS_API_KEY },
        transports: ['websocket', 'polling'],
        reconnection: true,
        reconnectionAttempts: APP_CONFIG.socketRetryAttempts,
        reconnectionDelay: APP_CONFIG.socketRetryDelay,
        reconnectionDelayMax: 5000,
        timeout: 20000
    });
    
    // Register all socket handlers first
    registerSocketHandlers();
    
    appState.registerCleanup(() => {
        if (appState.socket) {
            appState.socket.disconnect();
            appState.socket = null;
        }
        appState.socketQueue.clear();
    });
}

function registerSocketHandlers() {
    if (!appState.socket) return;
    
    appState.socket.on('connect', handleSocketConnect);
    appState.socket.on('disconnect', handleSocketDisconnect);
    appState.socket.on('connect_error', handleSocketError);
    appState.socket.on('stats', handleStatsUpdate);
    appState.socket.on('config', handleConfigUpdate);
    appState.socket.on('cacheStats', handleCacheStats);
    appState.socket.on('log', handleLogEntry);
    appState.socket.on('link-generated', handleLinkGenerated);
    appState.socket.on('link-deleted', () => refreshLinks());
    appState.socket.on('link-updated', () => refreshLinks());
    appState.socket.on('links', handleLinksUpdate);
    appState.socket.on('notification', handleNotification);
    appState.socket.on('commandResult', handleCommandResult);
    appState.socket.on('systemMetrics', handleSystemMetrics);
    appState.socket.on('keys', handleKeysUpdate);
    appState.socket.on('audit', handleAuditEntry);
    appState.socket.on('backup', handleBackupStatus);
    appState.socket.on('alert', handleAlert);
}

function handleSocketConnect() {
    console.log('✅ Socket connected successfully');
    showAlert('Real-time monitoring connected', 'success');
    updateSocketStatus('connected');
    
    // Queue initial data requests
    const initialRequests = [
        { action: 'getStats' },
        { action: 'getLinks' },
        { action: 'getConfig' },
        { action: 'getCacheStats' },
        { action: 'getSystemMetrics' }
    ];
    
    initialRequests.forEach(req => appState.socketQueue.add(req.action, req.data));
    
    // Request additional data based on active tab
    const activeTab = document.querySelector('.tab-content.active')?.id;
    handleTabSpecificRequests(activeTab);
}

function handleTabSpecificRequests(tabId) {
    if (!tabId) return;
    
    switch(tabId) {
        case 'encryption-keys':
            fetchEncryptionKeys();
            break;
        case 'audit-log':
            fetchAuditLogs();
            break;
        case 'security':
            refreshSecurityData();
            break;
        case 'backup':
            fetchBackupStatus();
            break;
    }
}

function handleSocketDisconnect(reason) {
    console.log('❌ Socket disconnected:', reason);
    showAlert('Real-time monitoring disconnected', 'error');
    updateSocketStatus('disconnected');
}

function handleSocketError(error) {
    console.error('Socket connection error:', error);
    showAlert('Socket connection error', 'error');
}

function handleStatsUpdate(data) {
    throttledChartUpdate(data);
    updateStats(data);
    updateCountryStats(data.byCountry);
    updateCacheStats(data.caches);
    updateLinkModeStats(data.linkModes);
    updatePerformanceMetrics(data);
    updateEncodingStats(data.encodingStats);
    updateSecurityMetrics(data);
    updateRealtimeMetrics(data);
}

function handleConfigUpdate(data) {
    console.log('⚙️ Config received:', data);
    updateConfig(data);
}

function handleCacheStats(data) {
    updateDetailedCacheStats(data);
}

function handleLogEntry(log) {
    addLogEntry(log);
    appState.logRateCounter++;
    checkForAlerts(log);
}

function handleLinkGenerated(data) {
    console.log('🔗 Link generated:', data);
    showAlert('New link generated', 'info');
    refreshLinks();
    playNotification('generated');
}

function handleLinksUpdate(links) {
    console.log('📋 Links received:', links.length);
    appState.allLinks = links;
    filterAndRenderLinks();
}

function handleNotification(notification) {
    console.log('🔔 Notification:', notification);
    showAlert(notification.message, notification.type);
    playNotification(notification.type);
}

function handleCommandResult(result) {
    console.log('📨 Command result:', result);
}

function handleSystemMetrics(metrics) {
    updateSystemMetrics(metrics);
}

function handleKeysUpdate(keys) {
    console.log('🔑 Encryption keys received:', keys);
    appState.encryptionKeys = keys;
    renderEncryptionKeys();
}

function handleAuditEntry(entry) {
    console.log('📝 Audit log entry:', entry);
    addAuditEntry(entry);
}

function handleBackupStatus(status) {
    console.log('💾 Backup status:', status);
    appState.backupStatus = status;
    updateBackupStatus();
}

function handleAlert(alert) {
    console.log('⚠️ Alert:', alert);
    appState.activeAlerts.push(alert);
    showAlert(alert.message, alert.severity);
    updateAlertBadge();
    playNotification('alert');
}

// Throttled chart updates
function throttledChartUpdate(data) {
    if (appState.chartUpdateTimeout) {
        clearTimeout(appState.chartUpdateTimeout);
    }
    appState.chartUpdateTimeout = setTimeout(() => {
        updateCharts(data);
        appState.chartUpdateTimeout = null;
    }, APP_CONFIG.chartUpdateThrottle);
}

// Calculate log rate every second
appState.registerInterval(setInterval(() => {
    appState.logRate = appState.logRateCounter;
    const logRateElement = document.getElementById('logRate');
    if (logRateElement) {
        logRateElement.textContent = appState.logRate + ' logs/sec';
    }
    appState.logRateCounter = 0;
}, 1000));

// Auto-refresh if enabled
appState.registerInterval(setInterval(() => {
    if (appState.autoRefreshEnabled && appState.socket?.connected) {
        const activeTab = document.querySelector('.tab-content.active')?.id;
        handleTabSpecificRequests(activeTab);
    }
}, appState.refreshInterval));

// ============================================
// Event Listeners Setup with Cleanup
// ============================================
function setupEventListeners() {
    console.log('🔧 Setting up event listeners...');
    
    const listeners = [];
    
    // Helper to add listeners with cleanup
    function addListener(element, event, handler) {
        if (!element) return;
        element.addEventListener(event, handler);
        listeners.push(() => element.removeEventListener(event, handler));
    }
    
    // Logout button
    addListener(document.getElementById('logoutBtn'), 'click', logout);
    
    // Menu toggle
    addListener(document.getElementById('menuToggle'), 'click', toggleSidebar);
    
    // Modal closes
    addListener(document.getElementById('modalClose'), 'click', closeModal);
    addListener(document.getElementById('testModalClose'), 'click', closeTestModal);
    addListener(document.getElementById('healthModalClose'), 'click', closeHealthModal);
    addListener(document.getElementById('qrModalClose'), 'click', closeQRModal);
    addListener(document.getElementById('keyModalClose'), 'click', closeKeyModal);
    addListener(document.getElementById('auditModalClose'), 'click', closeAuditModal);
    
    // Navigation items
    document.querySelectorAll('.nav-item[data-tab]').forEach(item => {
        addListener(item, 'click', (e) => {
            const tabId = e.currentTarget.dataset.tab;
            showTab(tabId);
            if (window.innerWidth <= 768) {
                toggleSidebar();
            }
        });
    });
    
    // API Docs nav item
    addListener(document.getElementById('apiDocsNavItem'), 'click', () => {
        window.open('/api-docs', '_blank');
    });
    
    // Queues nav item
    addListener(document.getElementById('queuesNavItem'), 'click', () => {
        const path = typeof BULL_BOARD_PATH !== 'undefined' ? BULL_BOARD_PATH : '/admin/queues';
        window.location.href = path;
    });
    
    // Time range buttons
    document.querySelectorAll('.time-range-btn').forEach(btn => {
        addListener(btn, 'click', (e) => {
            document.querySelectorAll('.time-range-btn').forEach(b => b.classList.remove('active'));
            e.currentTarget.classList.add('active');
            appState.currentTimeRange = e.currentTarget.dataset.range;
            appState.socketQueue.add('getStats', null);
        });
    });
    
    // Link mode selection
    document.querySelectorAll('.link-mode-btn').forEach(btn => {
        addListener(btn, 'click', (e) => {
            const mode = e.currentTarget.dataset.mode;
            selectLinkMode(mode);
        });
    });
    
    // Long link preset selection
    addListener(document.getElementById('longLinkPreset'), 'change', (e) => {
        const preset = e.currentTarget.value;
        const customOptions = document.getElementById('customLongOptions');
        
        if (customOptions) {
            customOptions.style.display = preset === 'custom' ? 'block' : 'none';
        }
        
        if (preset !== 'custom') {
            applyLongLinkPreset(preset);
        }
    });
    
    // Generate link button
    addListener(document.getElementById('generateBtn'), 'click', generateLink);
    
    // Clear form button
    addListener(document.getElementById('clearFormBtn'), 'click', clearForm);
    
    // Test mode button
    addListener(document.getElementById('testModeBtn'), 'click', testLinkModes);
    
    // Copy URL button
    addListener(document.getElementById('copyUrlBtn'), 'click', copyToClipboard);
    
    // Show QR button
    addListener(document.getElementById('showQRBtn'), 'click', showQRFromResult);
    
    // Visit URL button
    addListener(document.getElementById('visitUrlBtn'), 'click', () => {
        const url = document.getElementById('generatedUrl')?.value;
        if (Validators.url(url)) {
            window.open(url, '_blank');
        } else {
            showAlert('Invalid URL', 'error');
        }
    });
    
    // QR code checkbox
    addListener(document.getElementById('generateQR'), 'change', function() {
        const qrSize = document.getElementById('qrSize');
        if (qrSize) {
            qrSize.disabled = !this.checked;
        }
    });
    
    // Get stats button
    addListener(document.getElementById('getStatsBtn'), 'click', getLinkStats);
    
    // Clear stats button
    addListener(document.getElementById('clearStatsBtn'), 'click', clearStats);
    
    // Export buttons
    addListener(document.getElementById('exportCSVBtn'), 'click', () => exportData('csv'));
    addListener(document.getElementById('exportJSONBtn'), 'click', () => exportData('json'));
    addListener(document.getElementById('exportPDFBtn'), 'click', () => exportData('pdf'));
    addListener(document.getElementById('exportLinksBtn'), 'click', exportAllLinks);
    
    // Refresh links button
    addListener(document.getElementById('refreshLinksBtn'), 'click', refreshLinks);
    
    // Search and filter with debouncing
    const debouncedFilter = debounce(filterAndRenderLinks, 300);
    addListener(document.getElementById('linkSearch'), 'input', debouncedFilter);
    addListener(document.getElementById('linkFilter'), 'change', filterAndRenderLinks);
    addListener(document.getElementById('linkModeFilter'), 'change', filterAndRenderLinks);
    
    // Pagination
    addListener(document.getElementById('prevPageBtn'), 'click', () => {
        if (appState.currentPage > 1) {
            appState.currentPage--;
            renderLinksTable();
        }
    });
    
    addListener(document.getElementById('nextPageBtn'), 'click', () => {
        if (appState.currentPage < Math.ceil(appState.filteredLinks.length / appState.pageSize)) {
            appState.currentPage++;
            renderLinksTable();
        }
    });
    
    // Log controls
    addListener(document.getElementById('clearLogsBtn'), 'click', clearLogs);
    addListener(document.getElementById('exportLogsBtn'), 'click', exportLogs);
    
    const autoScrollCheckbox = document.getElementById('autoScroll');
    if (autoScrollCheckbox) {
        addListener(autoScrollCheckbox, 'change', (e) => {
            appState.autoScroll = e.target.checked;
        });
    }
    
    const showTimestampsCheckbox = document.getElementById('showTimestamps');
    if (showTimestampsCheckbox) {
        addListener(showTimestampsCheckbox, 'change', (e) => {
            appState.showTimestamps = e.target.checked;
        });
    }
    
    const logFilterSelect = document.getElementById('logFilter');
    if (logFilterSelect) {
        addListener(logFilterSelect, 'change', (e) => {
            appState.logFilter = e.target.value;
        });
    }
    
    // Cache management
    addListener(document.getElementById('clearAllCache'), 'click', () => clearCache('all'));
    addListener(document.getElementById('clearGeoCache'), 'click', () => clearCache('geo'));
    addListener(document.getElementById('clearQRCache'), 'click', () => clearCache('qr'));
    addListener(document.getElementById('clearEncodingCache'), 'click', () => clearCache('encoding'));
    addListener(document.getElementById('clearDeviceCache'), 'click', () => clearCache('device'));
    
    // Security
    addListener(document.getElementById('refreshSecurityBtn'), 'click', refreshSecurityData);
    addListener(document.getElementById('clearAttemptsBtn'), 'click', clearLoginAttempts);
    addListener(document.getElementById('unblockIPBtn'), 'click', showUnblockIPModal);
    addListener(document.getElementById('revokeSessionBtn'), 'click', showRevokeSessionModal);
    
    const botThresholdSlider = document.getElementById('botThresholdSlider');
    if (botThresholdSlider) {
        addListener(botThresholdSlider, 'input', (e) => {
            const botThreshold = document.getElementById('botThreshold');
            const botThresholdBar = document.getElementById('botThresholdBar');
            if (botThreshold) botThreshold.textContent = e.target.value;
            if (botThresholdBar) botThresholdBar.style.width = e.target.value + '%';
        });
        addListener(botThresholdSlider, 'change', (e) => {
            updateBotThreshold(parseInt(e.target.value));
        });
    }
    
    // Encryption keys
    addListener(document.getElementById('rotateKeysBtn'), 'click', rotateEncryptionKeys);
    addListener(document.getElementById('backupKeysBtn'), 'click', backupEncryptionKeys);
    addListener(document.getElementById('viewKeyBtn'), 'click', () => showKeyDetails());
    
    // Audit logs
    addListener(document.getElementById('refreshAuditBtn'), 'click', fetchAuditLogs);
    addListener(document.getElementById('exportAuditBtn'), 'click', exportAuditLogs);
    addListener(document.getElementById('auditFilter'), 'change', filterAuditLogs);
    addListener(document.getElementById('auditDateRange'), 'change', filterAuditLogs);
    
    // Backup
    addListener(document.getElementById('runBackupBtn'), 'click', runBackup);
    addListener(document.getElementById('restoreBackupBtn'), 'click', showRestoreModal);
    addListener(document.getElementById('configureBackupBtn'), 'click', showBackupConfig);
    
    // Settings
    addListener(document.getElementById('saveLinkModeSettings'), 'click', saveLinkModeSettings);
    addListener(document.getElementById('saveSystemSettings'), 'click', saveSystemSettings);
    addListener(document.getElementById('saveSecuritySettings'), 'click', saveSecuritySettings);
    addListener(document.getElementById('saveNotificationSettings'), 'click', saveNotificationSettings);
    addListener(document.getElementById('reloadConfigBtn'), 'click', reloadConfig);
    addListener(document.getElementById('viewHealthBtn'), 'click', viewHealthCheck);
    
    // Refresh interval
    addListener(document.getElementById('refreshInterval'), 'change', (e) => {
        appState.refreshInterval = parseInt(e.target.value) * 1000;
    });
    
    addListener(document.getElementById('autoRefresh'), 'change', (e) => {
        appState.autoRefreshEnabled = e.target.checked;
    });
    
    // Notification sound
    addListener(document.getElementById('notificationSound'), 'change', (e) => {
        appState.notificationSound = e.target.checked;
    });
    
    // Dark mode toggle
    addListener(document.getElementById('darkModeToggle'), 'change', (e) => {
        appState.darkMode = e.target.checked;
        document.body.classList.toggle('light-mode', !appState.darkMode);
    });
    
    // Register cleanup for all listeners
    appState.registerCleanup(() => {
        listeners.forEach(remove => remove());
    });
    
    // Initialize link mode
    selectLinkMode(appState.selectedLinkMode);
    
    // Initialize dark mode
    document.body.classList.toggle('light-mode', !appState.darkMode);
    
    // Check for MFA setup
    if (typeof MFA_ENABLED !== 'undefined' && MFA_ENABLED === 'true' && !localStorage.getItem('mfa_setup_completed')) {
        appState.mfaSetupRequired = true;
        showMFASetupPrompt();
    }
}

// ============================================
// UI Functions with Improved Security
// ============================================
function toggleSidebar() {
    document.getElementById('sidebar')?.classList.toggle('open');
}

function showTab(tabId) {
    if (!tabId) return;
    
    // Update navigation
    document.querySelectorAll('.nav-item').forEach(item => {
        item.classList.remove('active');
    });
    
    // Find and activate the clicked nav item
    document.querySelectorAll('.nav-item').forEach(item => {
        if (item.dataset.tab === tabId) {
            item.classList.add('active');
        }
    });
    
    // Update tab content
    document.querySelectorAll('.tab-content').forEach(content => {
        content.classList.remove('active');
    });
    const tabElement = document.getElementById(tabId);
    if (tabElement) {
        tabElement.classList.add('active');
    }
    
    // Close sidebar on mobile
    if (window.innerWidth <= 768) {
        document.getElementById('sidebar')?.classList.remove('open');
    }
    
    // Load data for specific tabs
    handleTabSpecificRequests(tabId);
}

function selectLinkMode(mode) {
    if (!mode) return;
    
    appState.selectedLinkMode = mode;
    
    // Update button styles
    document.querySelectorAll('.link-mode-btn').forEach(btn => {
        btn.classList.remove('btn-success');
        btn.classList.add('btn-secondary');
        if (btn.dataset.mode === mode) {
            btn.classList.remove('btn-secondary');
            btn.classList.add('btn-success');
        }
    });
    
    // Update help text
    const helpText = document.getElementById('linkModeHelp');
    const longOptions = document.getElementById('longLinkOptions');
    
    if (helpText) {
        const helpMessages = {
            short: 'Short: Clean, simple URLs (/v/id)',
            long: 'Long: Obfuscated URLs with many segments and parameters',
            auto: 'Auto: Automatically choose based on URL length'
        };
        helpText.textContent = helpMessages[mode] || 'Select link mode';
    }
    
    if (longOptions) {
        const showLongOptions = mode === 'long' || (mode === 'auto' && typeof ALLOW_LINK_MODE_SWITCH !== 'undefined' && ALLOW_LINK_MODE_SWITCH);
        longOptions.style.display = showLongOptions ? 'block' : 'none';
        
        if (mode === 'auto' && helpText && !ALLOW_LINK_MODE_SWITCH) {
            helpText.textContent = 'Auto mode disabled. Using ' + (typeof LINK_LENGTH_MODE !== 'undefined' ? LINK_LENGTH_MODE : 'short') + ' mode.';
        }
    }
    
    const modeIndicator = document.getElementById('modeIndicator');
    if (modeIndicator) {
        modeIndicator.textContent = 'Mode: ' + mode;
    }
}

function applyLongLinkPreset(preset) {
    let segments, params, layers, iterations;
    
    const presets = {
        standard: { segments: 6, params: 13, layers: 4, iterations: 2 },
        aggressive: { segments: 12, params: 20, layers: 6, iterations: 3 },
        stealth: { segments: 18, params: 28, layers: 8, iterations: 4 },
        maximum: { segments: 20, params: 30, layers: 12, iterations: 5 }
    };
    
    const config = presets[preset];
    if (!config) return;
    
    const elements = {
        segments: document.getElementById('longLinkSegments'),
        params: document.getElementById('longLinkParams'),
        layers: document.getElementById('linkEncodingLayers'),
        iterations: document.getElementById('maxEncodingIterations')
    };
    
    if (elements.segments) elements.segments.value = config.segments;
    if (elements.params) elements.params.value = config.params;
    if (elements.layers) elements.layers.value = config.layers;
    if (elements.iterations) elements.iterations.value = config.iterations;
}

function showAlert(message, type = 'info') {
    if (!message) return;
    
    const alert = document.getElementById('alert');
    if (!alert) return;
    
    const icons = {
        success: 'check-circle',
        error: 'exclamation-circle',
        warning: 'exclamation-triangle',
        info: 'info-circle'
    };
    
    alert.className = `alert alert-${type}`;
    alert.innerHTML = `
        <div class="alert-icon">
            <i class="fas fa-${icons[type] || 'info-circle'}"></i>
        </div>
        <div class="alert-content">
            <div class="alert-title">${type.charAt(0).toUpperCase() + type.slice(1)}</div>
            <div class="alert-message">${Validators.escapeForHTML(message)}</div>
        </div>
        <button class="alert-close" onclick="this.parentElement.style.display='none'">
            <i class="fas fa-times"></i>
        </button>
    `;
    alert.style.display = 'flex';
    
    // Auto-hide after 5 seconds for non-error messages
    if (type !== 'error') {
        setTimeout(() => {
            if (alert.style.display === 'flex') {
                alert.style.display = 'none';
            }
        }, 5000);
    }
}

function playNotification(type) {
    if (!appState.notificationSound) return;
    
    // Check if browser supports Audio
    if (typeof Audio === 'undefined') return;
    
    const audio = new Audio();
    // Use silent audio for browsers that require user interaction
    audio.volume = 0.3;
    
    // Only attempt to play if user has interacted with the page
    if (document.hasFocus?.() && navigator.userActivation?.hasBeenActive) {
        audio.play().catch(() => {});
    }
}

function updateAlertBadge() {
    const alertBadge = document.getElementById('alertBadge');
    if (alertBadge) {
        alertBadge.textContent = appState.activeAlerts.length;
        alertBadge.style.display = appState.activeAlerts.length > 0 ? 'flex' : 'none';
    }
}

function checkForAlerts(log) {
    if (!log) return;
    
    const now = Date.now();
    const alertTypes = {
        'rate-limit': { threshold: 10, severity: 'warning', message: 'High rate limiting' },
        'bot-block': { threshold: 1, severity: 'info', message: 'Bot detected' },
        'error': { threshold: 1, severity: 'error', message: 'Error occurred' }
    };
    
    const alertConfig = alertTypes[log.type];
    if (alertConfig && log.count >= alertConfig.threshold) {
        appState.activeAlerts.push({
            id: now,
            type: log.type,
            severity: alertConfig.severity,
            message: `${alertConfig.message}: ${Validators.escapeForHTML(log.ip || 'unknown')}`,
            timestamp: new Date().toISOString()
        });
        
        // Keep only last 50 alerts
        if (appState.activeAlerts.length > 50) {
            appState.activeAlerts = appState.activeAlerts.slice(-50);
        }
        
        updateAlertBadge();
    }
}

function showMFASetupPrompt() {
    const prompt = document.createElement('div');
    prompt.className = 'alert alert-warning mfa-prompt';
    prompt.innerHTML = `
        <i class="fas fa-shield-alt"></i>
        <div class="mfa-prompt-content">
            <strong>Two-Factor Authentication Available</strong>
            <p>Enhance your account security by enabling 2FA</p>
        </div>
        <button class="btn btn-sm btn-primary" onclick="setupMFA()">Setup Now</button>
        <button class="btn btn-sm btn-secondary" onclick="this.parentElement.remove()">Dismiss</button>
    `;
    document.body.appendChild(prompt);
    
    setTimeout(() => {
        if (prompt.parentElement) {
            prompt.remove();
        }
    }, 30000);
}

function setupMFA() {
    window.location.href = '/admin/setup-mfa';
}

function updateSocketStatus(status) {
    const socketStatus = document.getElementById('socketStatus');
    if (socketStatus) {
        socketStatus.className = `status-dot ${Validators.escapeForHTML(status)}`;
        socketStatus.title = `Socket ${status}`;
    }
}

function updateStats(data) {
    if (!data) return;
    
    const elements = {
        totalRequests: document.getElementById('totalRequests'),
        activeLinks: document.getElementById('activeLinks'),
        botBlocks: document.getElementById('botBlocks'),
        requestTrend: document.getElementById('requestTrend'),
        blockRate: document.getElementById('blockRate'),
        peakLinks: document.getElementById('peakLinks'),
        totalDevices: document.getElementById('totalDevices')
    };
    
    if (elements.totalRequests) {
        elements.totalRequests.textContent = formatNumber(data.totalRequests || 0);
    }
    if (elements.activeLinks) {
        elements.activeLinks.textContent = formatNumber(data.realtime?.activeLinks || 0);
    }
    if (elements.botBlocks) {
        elements.botBlocks.textContent = formatNumber(data.botBlocks || 0);
    }
    
    // Calculate trends
    const lastMinute = data.realtime?.lastMinute || [];
    if (lastMinute.length > 1 && elements.requestTrend) {
        const current = lastMinute[lastMinute.length - 1]?.requests || 0;
        const previous = lastMinute[lastMinute.length - 2]?.requests || 0;
        const trend = previous ? ((current - previous) / previous * 100).toFixed(1) : 0;
        elements.requestTrend.textContent = (trend > 0 ? '+' : '') + trend + '%';
        elements.requestTrend.className = trend >= 0 ? 'trend-up' : 'trend-down';
    }
    
    // Block rate
    if (elements.blockRate) {
        const blockRate = data.totalRequests ? ((data.botBlocks / data.totalRequests) * 100).toFixed(1) : 0;
        elements.blockRate.textContent = blockRate + '%';
    }
    
    // Peak links
    if (elements.peakLinks) {
        elements.peakLinks.textContent = formatNumber(data.realtime?.peakLinks || 0);
    }
    
    // Total devices
    if (elements.totalDevices) {
        const totalDevices = Object.values(data.byDevice || {}).reduce((a, b) => a + b, 0);
        elements.totalDevices.textContent = formatNumber(totalDevices) + ' total';
    }
}

function updateLinkModeStats(modes) {
    const linkModesEl = document.getElementById('linkModes');
    if (modes && linkModesEl) {
        linkModesEl.textContent = `S:${modes.short || 0} L:${modes.long || 0} A:${modes.auto || 0}`;
    }
}

function updateCacheStats(caches) {
    if (!caches) return;
    
    const elements = {
        linkReq: document.getElementById('cacheLinks'),
        geo: document.getElementById('cacheGeo'),
        qr: document.getElementById('cacheQR'),
        encoding: document.getElementById('cacheEncoding'),
        device: document.getElementById('cacheDevice'),
        nonce: document.getElementById('cacheNonce')
    };
    
    if (elements.linkReq) elements.linkReq.textContent = formatNumber(caches.linkReq || 0);
    if (elements.geo) elements.geo.textContent = formatNumber(caches.geo || 0);
    if (elements.qr) elements.qr.textContent = formatNumber(caches.qr || 0);
    if (elements.encoding) elements.encoding.textContent = formatNumber(caches.encoding || 0);
    if (elements.device) elements.device.textContent = formatNumber(caches.device || 0);
    if (elements.nonce) elements.nonce.textContent = formatNumber(caches.nonce || 0);
}

function updateDetailedCacheStats(stats) {
    if (!stats) return;
    
    const elements = {
        cacheHits: document.getElementById('cacheHits'),
        cacheMisses: document.getElementById('cacheMisses'),
        detailedHitRate: document.getElementById('detailedHitRate'),
        cacheHitRate: document.getElementById('cacheHitRate')
    };
    
    const totalHits = Object.values(stats).reduce((sum, s) => sum + (s.hits || 0), 0);
    const totalMisses = Object.values(stats).reduce((sum, s) => sum + (s.misses || 0), 0);
    const total = totalHits + totalMisses;
    const hitRate = total ? ((totalHits / total) * 100).toFixed(1) : 0;
    
    if (elements.cacheHits) elements.cacheHits.textContent = formatNumber(totalHits);
    if (elements.cacheMisses) elements.cacheMisses.textContent = formatNumber(totalMisses);
    if (elements.detailedHitRate) elements.detailedHitRate.textContent = hitRate + '%';
    if (elements.cacheHitRate) elements.cacheHitRate.textContent = hitRate + '%';
}

function updatePerformanceMetrics(data) {
    if (!data?.performance) return;
    
    const elements = {
        avgResponseTime: document.getElementById('avgResponseTime'),
        p95Time: document.getElementById('p95Time'),
        p99Time: document.getElementById('p99Time'),
        currentRPS: document.getElementById('currentRPS'),
        peakRPS: document.getElementById('peakRPS'),
        totalResponseTime: document.getElementById('totalResponseTime')
    };
    
    if (elements.avgResponseTime) {
        elements.avgResponseTime.textContent = (data.performance.avgResponseTime?.toFixed(0) || '0') + 'ms';
    }
    if (elements.p95Time) {
        elements.p95Time.textContent = (data.performance.p95ResponseTime?.toFixed(0) || '0') + 'ms';
    }
    if (elements.p99Time) {
        elements.p99Time.textContent = (data.performance.p99ResponseTime?.toFixed(0) || '0') + 'ms';
    }
    if (elements.totalResponseTime) {
        elements.totalResponseTime.textContent = formatDuration(data.performance.totalResponseTime || 0);
    }
    
    if (data.realtime) {
        if (elements.currentRPS) elements.currentRPS.textContent = data.realtime.requestsPerSecond || 0;
        if (elements.peakRPS) elements.peakRPS.textContent = data.realtime.peakRPS || 0;
    }
}

function updateEncodingStats(encodingStats) {
    if (!encodingStats) return;
    
    const elements = {
        encodingStats: document.getElementById('encodingStats'),
        avgLayers: document.getElementById('avgLayers'),
        cacheHitRate: document.getElementById('cacheHitRate'),
        cacheSize: document.getElementById('cacheSize'),
        avgComplexity: document.getElementById('avgComplexity'),
        avgDecodeTime: document.getElementById('avgDecodeTime')
    };
    
    if (elements.encodingStats) {
        elements.encodingStats.textContent = formatNumber(encodingStats.totalEncoded || 0);
    }
    if (elements.avgLayers) {
        elements.avgLayers.textContent = (encodingStats.avgLayers || 0).toFixed(1);
    }
    if (elements.avgComplexity) {
        elements.avgComplexity.textContent = (encodingStats.avgComplexity || 0).toFixed(1);
    }
    if (elements.avgDecodeTime) {
        elements.avgDecodeTime.textContent = (encodingStats.avgDecodeTime || 0).toFixed(0) + 'ms';
    }
    
    // Cache hit rate
    const totalRequests = (encodingStats.cacheHits || 0) + (encodingStats.cacheMisses || 0);
    const hitRate = totalRequests ? ((encodingStats.cacheHits / totalRequests) * 100).toFixed(1) : 0;
    if (elements.cacheHitRate) elements.cacheHitRate.textContent = hitRate + '%';
    if (elements.cacheSize) elements.cacheSize.textContent = formatNumber(encodingStats.totalEncoded || 0);
}

function updateSecurityMetrics(data) {
    if (!data) return;
    
    const botReasonsEl = document.getElementById('botReasons');
    if (botReasonsEl && data.byBotReason) {
        const reasons = Object.entries(data.byBotReason)
            .sort((a, b) => b[1] - a[1])
            .slice(0, 5)
            .map(([reason, count]) => 
                `<div><span>${Validators.escapeForHTML(reason)}:</span> <span>${formatNumber(count)}</span></div>`
            )
            .join('');
        botReasonsEl.innerHTML = reasons || '<div>No data</div>';
    }
    
    const signaturesValidEl = document.getElementById('signaturesValid');
    const signaturesInvalidEl = document.getElementById('signaturesInvalid');
    
    if (data.signatures) {
        if (signaturesValidEl) signaturesValidEl.textContent = formatNumber(data.signatures.valid || 0);
        if (signaturesInvalidEl) signaturesInvalidEl.textContent = formatNumber(data.signatures.invalid || 0);
    }
}

function updateRealtimeMetrics(data) {
    if (!data?.system) return;
    
    const elements = {
        memoryUsage: document.getElementById('memoryUsage'),
        cpuUsage: document.getElementById('cpuUsage'),
        uptimeValue: document.getElementById('uptimeValue'),
        systemUptime: document.getElementById('systemUptime')
    };
    
    if (elements.memoryUsage) {
        elements.memoryUsage.textContent = formatBytes(data.system.memory || 0);
    }
    if (elements.cpuUsage) {
        elements.cpuUsage.textContent = (data.system.cpu || 0).toFixed(1) + '%';
    }
    if (elements.uptimeValue) {
        elements.uptimeValue.textContent = formatDuration(data.system.uptime || 0);
    }
    if (elements.systemUptime) {
        elements.systemUptime.textContent = formatDuration(data.system.uptime || 0);
    }
}

function updateSystemMetrics(metrics) {
    if (!metrics) return;
    
    const elements = {
        memoryUsage: document.getElementById('memoryUsage'),
        cpuUsage: document.getElementById('cpuUsage'),
        uptimeValue: document.getElementById('uptimeValue'),
        systemUptime: document.getElementById('systemUptime'),
        activeConnections: document.getElementById('activeConnections')
    };
    
    if (elements.memoryUsage) {
        elements.memoryUsage.textContent = formatBytes(metrics.memory?.heapUsed || 0);
    }
    if (elements.cpuUsage) {
        elements.cpuUsage.textContent = (metrics.cpu || 0).toFixed(1) + '%';
    }
    if (elements.uptimeValue) {
        elements.uptimeValue.textContent = formatDuration(metrics.uptime || 0);
    }
    if (elements.systemUptime) {
        elements.systemUptime.textContent = formatDuration(metrics.uptime || 0);
    }
    if (elements.activeConnections) {
        elements.activeConnections.textContent = metrics.connections || 0;
    }
}

function updateConfig(data) {
    if (!data) return;
    
    const elements = {
        settingLinkLengthMode: document.getElementById('settingLinkLengthMode'),
        settingAllowLinkModeSwitch: document.getElementById('settingAllowLinkModeSwitch'),
        settingLongLinkSegments: document.getElementById('settingLongLinkSegments'),
        settingLongLinkParams: document.getElementById('settingLongLinkParams'),
        settingLinkEncodingLayers: document.getElementById('settingLinkEncodingLayers'),
        settingMaxEncodingIterations: document.getElementById('settingMaxEncodingIterations'),
        settingEnableCompression: document.getElementById('settingEnableCompression'),
        settingEnableEncryption: document.getElementById('settingEnableEncryption'),
        longLinkSegments: document.getElementById('longLinkSegments'),
        longLinkParams: document.getElementById('longLinkParams'),
        linkEncodingLayers: document.getElementById('linkEncodingLayers'),
        maxEncodingIterations: document.getElementById('maxEncodingIterations'),
        enableCompression: document.getElementById('enableCompression'),
        enableEncryption: document.getElementById('enableEncryption'),
        nodeEnv: document.getElementById('nodeEnv'),
        dbStatus: document.getElementById('dbStatus'),
        redisStatus: document.getElementById('redisStatus'),
        queueStatus: document.getElementById('queueStatus'),
        versionInfo: document.getElementById('versionInfo')
    };
    
    if (data.linkLengthMode && elements.settingLinkLengthMode) {
        elements.settingLinkLengthMode.value = data.linkLengthMode;
    }
    if (data.allowLinkModeSwitch !== undefined && elements.settingAllowLinkModeSwitch) {
        elements.settingAllowLinkModeSwitch.checked = data.allowLinkModeSwitch;
    }
    if (data.longLinkSegments) {
        if (elements.settingLongLinkSegments) elements.settingLongLinkSegments.value = data.longLinkSegments;
        if (elements.longLinkSegments) elements.longLinkSegments.value = data.longLinkSegments;
    }
    if (data.longLinkParams) {
        if (elements.settingLongLinkParams) elements.settingLongLinkParams.value = data.longLinkParams;
        if (elements.longLinkParams) elements.longLinkParams.value = data.longLinkParams;
    }
    if (data.linkEncodingLayers) {
        if (elements.settingLinkEncodingLayers) elements.settingLinkEncodingLayers.value = data.linkEncodingLayers;
        if (elements.linkEncodingLayers) elements.linkEncodingLayers.value = data.linkEncodingLayers;
    }
    if (data.maxEncodingIterations && elements.settingMaxEncodingIterations) {
        elements.settingMaxEncodingIterations.value = data.maxEncodingIterations;
        if (elements.maxEncodingIterations) elements.maxEncodingIterations.value = data.maxEncodingIterations;
    }
    if (data.enableCompression !== undefined) {
        if (elements.settingEnableCompression) elements.settingEnableCompression.checked = data.enableCompression;
        if (elements.enableCompression) elements.enableCompression.checked = data.enableCompression;
    }
    if (data.enableEncryption !== undefined) {
        if (elements.settingEnableEncryption) elements.settingEnableEncryption.checked = data.enableEncryption;
        if (elements.enableEncryption) elements.enableEncryption.checked = data.enableEncryption;
    }
    if (data.nodeEnv && elements.nodeEnv) {
        elements.nodeEnv.textContent = data.nodeEnv;
    }
    if (elements.dbStatus) {
        elements.dbStatus.className = data.databaseEnabled ? 'status-dot connected' : 'status-dot disconnected';
    }
    if (elements.redisStatus) {
        elements.redisStatus.className = data.redisEnabled ? 'status-dot connected' : 'status-dot disconnected';
    }
    if (elements.queueStatus) {
        elements.queueStatus.className = data.queuesEnabled ? 'status-dot connected' : 'status-dot disconnected';
    }
    if (data.version && elements.versionInfo) {
        elements.versionInfo.textContent = data.version;
    }
}

function updateCharts(data) {
    if (!data) return;
    
    const ctx1 = document.getElementById('requestsChart')?.getContext('2d');
    const ctx2 = document.getElementById('deviceChart')?.getContext('2d');
    const ctx3 = document.getElementById('performanceChart')?.getContext('2d');
    
    if (!ctx1 || !ctx2) return;
    
    // Destroy existing charts properly
    if (appState.requestsChart) {
        appState.requestsChart.destroy();
        appState.requestsChart = null;
    }
    if (appState.deviceChart) {
        appState.deviceChart.destroy();
        appState.deviceChart = null;
    }
    if (appState.performanceChart) {
        appState.performanceChart.destroy();
        appState.performanceChart = null;
    }
    
    // Prepare data based on time range
    const lastMinute = data.realtime?.lastMinute || [];
    const points = {
        '5m': 300,
        '15m': 900,
        '1h': 3600,
        '6h': 21600,
        '24h': 86400
    }[appState.currentTimeRange] || 60;
    
    const recentData = lastMinute.slice(-Math.min(points, lastMinute.length));
    
    const timestamps = recentData.map(d => {
        const date = new Date(d.time);
        return date.getHours() + ':' + date.getMinutes().toString().padStart(2, '0') + ':' + date.getSeconds().toString().padStart(2, '0');
    });
    
    const requests = recentData.map(d => d.requests || 0);
    const blocks = recentData.map(d => d.blocks || 0);
    const successes = recentData.map(d => d.successes || 0);
    
    // Requests Chart
    appState.requestsChart = new Chart(ctx1, {
        type: 'line',
        data: {
            labels: timestamps,
            datasets: [
                {
                    label: 'Requests',
                    data: requests,
                    borderColor: '#8a8a8a',
                    backgroundColor: 'rgba(138, 138, 138, 0.1)',
                    tension: 0.4,
                    fill: true,
                    pointRadius: 2,
                    pointHoverRadius: 5
                },
                {
                    label: 'Successful',
                    data: successes,
                    borderColor: '#4ade80',
                    backgroundColor: 'rgba(74, 222, 128, 0.1)',
                    tension: 0.4,
                    fill: true,
                    pointRadius: 2,
                    pointHoverRadius: 5
                },
                {
                    label: 'Blocks',
                    data: blocks,
                    borderColor: '#ef4444',
                    backgroundColor: 'rgba(239, 68, 68, 0.1)',
                    tension: 0.4,
                    fill: true,
                    pointRadius: 2,
                    pointHoverRadius: 5
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            interaction: {
                mode: 'index',
                intersect: false
            },
            plugins: {
                legend: {
                    position: 'top',
                    labels: {
                        usePointStyle: true,
                        boxWidth: 6,
                        color: '#aaa'
                    }
                },
                tooltip: {
                    backgroundColor: '#1a1a1a',
                    titleColor: '#fff',
                    bodyColor: '#fff',
                    borderColor: '#333',
                    borderWidth: 1
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    grid: {
                        color: 'rgba(255, 255, 255, 0.05)'
                    },
                    ticks: {
                        color: '#666'
                    }
                },
                x: {
                    grid: {
                        display: false
                    },
                    ticks: {
                        color: '#666',
                        maxRotation: 45,
                        minRotation: 45,
                        maxTicksLimit: 10
                    }
                }
            }
        }
    });
    
    // Device Chart
    appState.deviceChart = new Chart(ctx2, {
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
                backgroundColor: ['#4ade80', '#3b82f6', '#f59e0b', '#ef4444'],
                borderWidth: 0,
                hoverOffset: 4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: '70%',
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        usePointStyle: true,
                        boxWidth: 8,
                        padding: 20,
                        color: '#aaa'
                    }
                },
                tooltip: {
                    callbacks: {
                        label: (context) => {
                            const label = context.label || '';
                            const value = context.raw || 0;
                            const total = context.dataset.data.reduce((a, b) => a + b, 0);
                            const percentage = total > 0 ? ((value / total) * 100).toFixed(1) : 0;
                            return `${Validators.escapeForHTML(label)}: ${formatNumber(value)} (${percentage}%)`;
                        }
                    }
                }
            }
        }
    });
    
    // Performance Chart (if available)
    if (ctx3 && data.performance?.responseTimes) {
        const responseTimes = data.performance.responseTimes.slice(-100);
        const responseLabels = responseTimes.map((_, i) => i);
        
        appState.performanceChart = new Chart(ctx3, {
            type: 'line',
            data: {
                labels: responseLabels,
                datasets: [{
                    label: 'Response Time (ms)',
                    data: responseTimes,
                    borderColor: '#7aa2f7',
                    backgroundColor: 'rgba(122, 162, 247, 0.1)',
                    tension: 0.4,
                    fill: true,
                    pointRadius: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        display: false
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        grid: { color: 'rgba(255,255,255,0.05)' },
                        ticks: { color: '#666' }
                    },
                    x: {
                        display: false
                    }
                }
            }
        });
    }
}

function updateCountryStats(countries) {
    if (!countries) return;
    
    const container = document.getElementById('countryStats');
    const totalCountries = document.getElementById('totalCountries');
    
    if (Object.keys(countries).length === 0) {
        if (container) container.innerHTML = '<div class="text-center p-4">No data yet</div>';
        if (totalCountries) totalCountries.textContent = '0 countries';
        return;
    }
    
    const sorted = Object.entries(countries)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 8);
    
    if (totalCountries) totalCountries.textContent = Object.keys(countries).length + ' countries';
    
    if (container) {
        container.innerHTML = sorted.map(([country, count]) => `
            <div class="stat-card">
                <div class="stat-header">
                    <span class="stat-title">${Validators.escapeForHTML(country)}</span>
                    <span class="stat-icon"><i class="fas fa-flag"></i></span>
                </div>
                <div class="stat-value">${formatNumber(count)}</div>
                <div class="stat-trend">requests</div>
            </div>
        `).join('');
    }
}

function addLogEntry(log) {
    if (!log) return;
    
    const logs = document.getElementById('logs');
    if (!logs) return;
    
    // Apply filter
    if (appState.logFilter !== 'all' && log.type !== appState.logFilter) {
        return;
    }
    
    // Remove placeholder if it exists
    if (logs.children.length === 1 && logs.children[0].textContent.includes('Connecting')) {
        logs.innerHTML = '';
    }
    
    const entry = document.createElement('div');
    entry.className = 'log-entry';
    
    const time = new Date(log.t).toLocaleTimeString();
    const device = Validators.escapeForHTML(log.device || 'unknown');
    const method = Validators.escapeForHTML(log.method || 'GET');
    const path = Validators.escapeForHTML(log.path || '/');
    const ip = Validators.escapeForHTML(log.ip || '0.0.0.0');
    const duration = log.duration || 0;
    const type = log.type || 'request';
    
    // Determine log type class
    let typeClass = '';
    let typeIcon = '🌐';
    
    const typeConfig = {
        redirect: { class: 'type-redirect', icon: '🔄' },
        generate: { class: 'type-generate', icon: '🔗' },
        'bot-block': { class: 'type-bot-block', icon: '🤖' },
        bot: { class: 'type-bot-block', icon: '🤖' },
        'rate-limit': { class: 'type-rate-limit', icon: '⏱️' },
        error: { class: 'type-error', icon: '❌' },
        '404': { class: 'type-404', icon: '404' },
        'long-link-decode': { class: 'type-generate', icon: '🔓' },
        signature: { class: 'type-success', icon: '✅' }
    };
    
    const config = typeConfig[type];
    if (config) {
        typeClass = config.class;
        typeIcon = config.icon;
    }
    
    // Device icon
    let deviceIcon = '💻';
    if (device === 'mobile') deviceIcon = '📱';
    else if (device === 'tablet') deviceIcon = '📟';
    else if (device === 'bot') deviceIcon = '🤖';
    
    // Build log entry HTML with proper escaping
    let logHtml = '';
    
    if (appState.showTimestamps) {
        logHtml += `<span class="timestamp">[${Validators.escapeForHTML(time)}]</span> `;
    }
    
    logHtml += `<span class="type-badge ${typeClass}">${typeIcon} ${Validators.escapeForHTML(type)}</span> `;
    logHtml += `<span class="ip">${ip}</span> `;
    logHtml += `<span class="method">${method}</span> `;
    logHtml += `<span class="path">${path}</span> `;
    logHtml += `<span class="device">${deviceIcon} ${device}</span> `;
    
    if (duration > 0) {
        logHtml += `<span class="duration">${duration}ms</span>`;
    }
    
    if (log.target) {
        const sanitizedTarget = Validators.validateAndSanitizeUrl(log.target);
        logHtml += ` <span style="color: #9ece6a;">→ ${sanitizedTarget.substring(0, 50)}${log.target.length > 50 ? '...' : ''}</span>`;
    }
    
    if (log.reason) {
        logHtml += ` <span style="color: #f7768e;">[${Validators.escapeForHTML(log.reason)}]</span>`;
    }
    
    if (log.layers) {
        logHtml += ` <span style="color: #bb9af7;">[${log.layers} layers]</span>`;
    }
    
    if (log.complexity) {
        logHtml += ` <span style="color: #7aa2f7;">[complexity: ${log.complexity}]</span>`;
    }
    
    if (log.version) {
        logHtml += ` <span style="color: #9ece6a;">[v${Validators.escapeForHTML(log.version)}]</span>`;
    }
    
    entry.innerHTML = logHtml;
    
    // Add to logs
    logs.insertBefore(entry, logs.firstChild);
    
    // Limit number of log entries
    while (logs.children.length > APP_CONFIG.maxLogEntries) {
        logs.removeChild(logs.lastChild);
    }
    
    // Auto-scroll if enabled
    if (appState.autoScroll) {
        logs.scrollTop = 0;
    }
    
    // Update log count
    appState.logCount++;
    const logCounter = document.getElementById('logCounter');
    if (logCounter) logCounter.textContent = appState.logCount;
}

function filterAndRenderLinks() {
    const search = document.getElementById('linkSearch')?.value?.toLowerCase() || '';
    const filter = document.getElementById('linkFilter')?.value || 'all';
    const modeFilter = document.getElementById('linkModeFilter')?.value || 'all';
    
    appState.filteredLinks = appState.allLinks.filter(link => {
        if (filter !== 'all' && link.status !== filter) return false;
        if (modeFilter !== 'all' && link.link_mode !== modeFilter) return false;
        if (search) {
            const searchTerm = Validators.escapeForHTML(search);
            return (link.id && link.id.toLowerCase().includes(searchTerm)) || 
                   (link.target_url && link.target_url.toLowerCase().includes(searchTerm)) ||
                   (link.notes && link.notes.toLowerCase().includes(searchTerm));
        }
        return true;
    });
    
    const totalCount = document.getElementById('totalCount');
    if (totalCount) totalCount.textContent = appState.filteredLinks.length;
    appState.currentPage = 1;
    renderLinksTable();
}

function renderLinksTable() {
    const tbody = document.getElementById('linksTableBody');
    const displayedCount = document.getElementById('displayedCount');
    const totalLinksCount = document.getElementById('totalLinksCount');
    const totalCount = document.getElementById('totalCount');
    const prevPageBtn = document.getElementById('prevPageBtn');
    const nextPageBtn = document.getElementById('nextPageBtn');
    const pageInfo = document.getElementById('pageInfo');
    
    if (!appState.filteredLinks || appState.filteredLinks.length === 0) {
        if (tbody) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="9" style="text-align: center; padding: 2rem;">
                        <i class="fas fa-link"></i> No links found
                    </td>
                </tr>
            `;
        }
        if (displayedCount) displayedCount.textContent = '0';
        if (totalLinksCount) totalLinksCount.textContent = '0';
        if (totalCount) totalCount.textContent = '0';
        if (prevPageBtn) prevPageBtn.disabled = true;
        if (nextPageBtn) nextPageBtn.disabled = true;
        if (pageInfo) pageInfo.textContent = 'Page 1';
        return;
    }
    
    const start = (appState.currentPage - 1) * appState.pageSize;
    const end = Math.min(start + appState.pageSize, appState.filteredLinks.length);
    const pageLinks = appState.filteredLinks.slice(start, end);
    
    if (displayedCount) displayedCount.textContent = pageLinks.length;
    if (totalLinksCount) totalLinksCount.textContent = appState.filteredLinks.length;
    if (totalCount) totalCount.textContent = appState.filteredLinks.length;
    
    // Update pagination
    const totalPages = Math.ceil(appState.filteredLinks.length / appState.pageSize);
    if (prevPageBtn) prevPageBtn.disabled = appState.currentPage <= 1;
    if (nextPageBtn) nextPageBtn.disabled = appState.currentPage >= totalPages;
    if (pageInfo) pageInfo.textContent = `Page ${appState.currentPage} of ${totalPages}`;
    
    if (tbody) {
        tbody.innerHTML = pageLinks.map(link => {
            const sanitizedId = Validators.escapeForHTML(link.id);
            const sanitizedTargetUrl = Validators.validateAndSanitizeUrl(link.target_url);
            const sanitizedNotes = Validators.escapeForHTML(link.notes || '');
            
            return `
                <tr>
                    <td><code>${sanitizedId.substring(0, 8)}...</code></td>
                    <td>
                        <span class="badge badge-${link.link_mode === 'long' ? 'warning' : 'info'}">
                            ${link.link_mode || 'short'}
                        </span>
                        ${link.link_length ? `<small style="color:#666;">${link.link_length}c</small>` : ''}
                        ${link.encoding_layers ? `<small style="color:#666;"> (${link.encoding_layers} layers)</small>` : ''}
                    </td>
                    <td>
                        <a href="${sanitizedTargetUrl}" target="_blank" rel="noopener" style="color: #8a8a8a; text-decoration: none;">
                            ${sanitizedTargetUrl.substring(0, 40)}${link.target_url.length > 40 ? '...' : ''}
                        </a>
                    </td>
                    <td>${new Date(link.created_at).toLocaleString()}</td>
                    <td>${new Date(link.expires_at).toLocaleString()}</td>
                    <td>
                        <span style="font-weight: 600;">${formatNumber(link.current_clicks || 0)}</span>
                        ${link.max_clicks ? '/' + formatNumber(link.max_clicks) : ''}
                    </td>
                    <td>
                        <span class="badge badge-${link.status === 'active' ? 'success' : link.status === 'expired' ? 'error' : 'warning'}">
                            ${link.status}
                        </span>
                    </td>
                    <td>
                        <span class="badge badge-info">v${link.api_version || '1'}</span>
                    </td>
                    <td>
                        <div class="btn-group" style="gap: 0.25rem;">
                            <button class="btn btn-sm btn-secondary view-link" data-link-id="${sanitizedId}" title="View Details">
                                <i class="fas fa-eye"></i>
                            </button>
                            <button class="btn btn-sm btn-secondary copy-link" data-link-id="${sanitizedId}" title="Copy Link">
                                <i class="fas fa-copy"></i>
                            </button>
                            <button class="btn btn-sm btn-secondary qr-link" data-link-id="${sanitizedId}" title="Generate QR">
                                <i class="fas fa-qrcode"></i>
                            </button>
                            <button class="btn btn-sm btn-danger delete-link" data-link-id="${sanitizedId}" title="Delete">
                                <i class="fas fa-trash"></i>
                            </button>
                        </div>
                    </td>
                </tr>
            `;
        }).join('');
        
        // Add event listeners to dynamically created buttons
        document.querySelectorAll('.view-link').forEach(btn => {
            btn.addEventListener('click', () => viewLink(btn.dataset.linkId));
        });
        
        document.querySelectorAll('.copy-link').forEach(btn => {
            btn.addEventListener('click', () => copyLink(btn.dataset.linkId));
        });
        
        document.querySelectorAll('.qr-link').forEach(btn => {
            btn.addEventListener('click', () => {
                const url = window.location.origin + '/v/' + btn.dataset.linkId;
                showQRModal(url, 300);
            });
        });
        
        document.querySelectorAll('.delete-link').forEach(btn => {
            btn.addEventListener('click', () => deleteLink(btn.dataset.linkId));
        });
    }
}

// ============================================
// Link Management with Improved Error Handling
// ============================================
async function generateLink() {
    const urlInput = document.getElementById('targetUrl');
    const url = urlInput?.value;
    
    if (!url) {
        showAlert('Please enter a URL', 'error');
        return;
    }
    
    // Validate URL
    if (!Validators.url(url)) {
        showAlert('Please enter a valid URL', 'error');
        return;
    }
    
    const password = document.getElementById('linkPassword')?.value;
    const maxClicks = document.getElementById('maxClicks')?.value;
    const expiresIn = document.getElementById('expiresIn')?.value;
    const notes = document.getElementById('linkNotes')?.value;
    
    // Build request body
    const body = { 
        url, 
        password: password || undefined,
        maxClicks: maxClicks ? parseInt(maxClicks) : undefined,
        expiresIn,
        notes,
        linkMode: appState.selectedLinkMode,
        _csrf: typeof CSRF_TOKEN !== 'undefined' ? CSRF_TOKEN : ''
    };
    
    // Add long link options if applicable
    if (appState.selectedLinkMode === 'long' || 
        (appState.selectedLinkMode === 'auto' && typeof ALLOW_LINK_MODE_SWITCH !== 'undefined' && ALLOW_LINK_MODE_SWITCH)) {
        const longLinkSegments = document.getElementById('longLinkSegments')?.value;
        const longLinkParams = document.getElementById('longLinkParams')?.value;
        const linkEncodingLayers = document.getElementById('linkEncodingLayers')?.value;
        const maxEncodingIterations = document.getElementById('maxEncodingIterations')?.value;
        const enableCompression = document.getElementById('enableCompression');
        const enableEncryption = document.getElementById('enableEncryption');
        
        body.longLinkOptions = {
            segments: parseInt(longLinkSegments || (typeof LONG_LINK_SEGMENTS !== 'undefined' ? LONG_LINK_SEGMENTS : 6)),
            params: parseInt(longLinkParams || (typeof LONG_LINK_PARAMS !== 'undefined' ? LONG_LINK_PARAMS : 13)),
            maxLayers: parseInt(linkEncodingLayers || (typeof LINK_ENCODING_LAYERS !== 'undefined' ? LINK_ENCODING_LAYERS : 4)),
            iterations: parseInt(maxEncodingIterations || (typeof MAX_ENCODING_ITERATIONS !== 'undefined' ? MAX_ENCODING_ITERATIONS : 3)),
            includeFingerprint: true
        };
        
        if (enableCompression) {
            body.longLinkOptions.enableCompression = enableCompression.checked;
        }
        if (enableEncryption) {
            body.longLinkOptions.enableEncryption = enableEncryption.checked;
        }
    }
    
    try {
        const operation = new RetryableOperation(async () => {
            const res = await fetch('/api/generate', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-Token': typeof CSRF_TOKEN !== 'undefined' ? CSRF_TOKEN : ''
                },
                body: JSON.stringify(body),
                credentials: 'include'
            });
            
            if (!res.ok) {
                const errorData = await res.json().catch(() => ({}));
                throw new Error(errorData.error || `HTTP ${res.status}`);
            }
            
            return res.json();
        }, 2, 500);
        
        const data = await operation.execute();
        
        // Update UI with generated link
        const elements = {
            generatedUrl: document.getElementById('generatedUrl'),
            generatedId: document.getElementById('generatedId'),
            generatedExpires: document.getElementById('generatedExpires'),
            generatedPassword: document.getElementById('generatedPassword'),
            generatedLength: document.getElementById('generatedLength'),
            generatedMode: document.getElementById('generatedMode'),
            result: document.getElementById('result'),
            encodingDetails: document.getElementById('encodingDetails'),
            encodingLayers: document.getElementById('encodingLayers'),
            encodingComplexity: document.getElementById('encodingComplexity'),
            encodingIterations: document.getElementById('encodingIterations'),
            encodingTime: document.getElementById('encodingTime'),
            apiVersion: document.getElementById('apiVersion')
        };
        
        if (elements.generatedUrl) elements.generatedUrl.value = Validators.validateAndSanitizeUrl(data.url);
        if (elements.generatedId) elements.generatedId.textContent = Validators.escapeForHTML(data.id);
        if (elements.generatedExpires) elements.generatedExpires.textContent = Validators.escapeForHTML(data.expires_human);
        if (elements.generatedPassword) elements.generatedPassword.textContent = data.passwordProtected ? 'Yes' : 'No';
        if (elements.generatedLength) elements.generatedLength.textContent = (data.linkLength || 0) + ' chars';
        if (elements.generatedMode) elements.generatedMode.textContent = (data.mode || 'short').toUpperCase() + ' Link';
        if (elements.apiVersion) elements.apiVersion.textContent = data.metadata?.apiVersion || 'v1';
        if (elements.result) elements.result.style.display = 'block';
        
        // Show encoding details for long links
        if (data.encodingDetails && elements.encodingDetails) {
            if (elements.encodingLayers) elements.encodingLayers.textContent = data.encodingDetails.layers || 0;
            if (elements.encodingComplexity) elements.encodingComplexity.textContent = data.encodingDetails.complexity || 0;
            if (elements.encodingIterations) elements.encodingIterations.textContent = data.encodingDetails.iterations || 1;
            if (elements.encodingTime) elements.encodingTime.textContent = (data.encodingDetails.encodingTime || 0).toFixed(0) + 'ms';
            elements.encodingDetails.style.display = 'block';
        } else if (elements.encodingDetails) {
            elements.encodingDetails.style.display = 'none';
        }
        
        const generateQR = document.getElementById('generateQR');
        if (generateQR && generateQR.checked) {
            const size = document.getElementById('qrSize')?.value || 300;
            await showQRForUrl(data.url, size);
        }
        
        showAlert('Link generated successfully!', 'success');
        refreshLinks();
    } catch (err) {
        console.error('Link generation failed:', err);
        showAlert('Failed to generate link: ' + err.message, 'error');
    }
}

async function showQRForUrl(url, size = 300) {
    if (!Validators.url(url)) {
        showAlert('Invalid URL for QR code', 'error');
        return;
    }
    
    try {
        const res = await fetch('/qr?url=' + encodeURIComponent(url) + '&size=' + size);
        if (!res.ok) {
            throw new Error(`HTTP ${res.status}`);
        }
        
        const data = await res.json();
        const qrResult = document.getElementById('qrResult');
        if (!qrResult) return;
        
        qrResult.innerHTML = `
            <img src="${Validators.escapeForHTML(data.qr)}" alt="QR Code" style="max-width: 200px; border-radius: 8px; box-shadow: var(--shadow-md);">
            <div style="margin-top: 1rem;" class="btn-group">
                <button class="btn btn-sm btn-secondary download-qr" data-url="${Validators.escapeForHTML(url)}" data-size="${size}">
                    <i class="fas fa-download"></i> Download PNG
                </button>
                <button class="btn btn-sm btn-secondary view-qr-modal" data-url="${Validators.escapeForHTML(url)}" data-size="${size}">
                    <i class="fas fa-expand"></i> Expand
                </button>
            </div>
        `;
        
        // Add event listeners
        document.querySelector('.download-qr')?.addEventListener('click', (e) => {
            const btn = e.currentTarget;
            downloadQR(btn.dataset.url, btn.dataset.size);
        });
        
        document.querySelector('.view-qr-modal')?.addEventListener('click', (e) => {
            const btn = e.currentTarget;
            showQRModal(btn.dataset.url, btn.dataset.size);
        });
    } catch (err) {
        console.error('QR generation failed:', err);
        showAlert('Failed to generate QR code', 'error');
    }
}

function showQRModal(url, size) {
    if (!Validators.url(url)) {
        showAlert('Invalid URL', 'error');
        return;
    }
    
    fetch('/qr?url=' + encodeURIComponent(url) + '&size=' + (size * 2))
        .then(res => {
            if (!res.ok) throw new Error(`HTTP ${res.status}`);
            return res.json();
        })
        .then(data => {
            const qrModalContent = document.getElementById('qrModalContent');
            if (!qrModalContent) return;
            
            qrModalContent.innerHTML = `
                <img src="${Validators.escapeForHTML(data.qr)}" alt="QR Code" style="max-width: 100%; border-radius: 12px;">
                <div style="margin-top: 1rem;" class="btn-group">
                    <button class="btn btn-sm btn-secondary download-qr-modal" data-url="${Validators.escapeForHTML(url)}" data-size="${size}">
                        <i class="fas fa-download"></i> Download
                    </button>
                </div>
            `;
            document.getElementById('qrModal')?.classList.add('active');
            
            document.querySelector('.download-qr-modal')?.addEventListener('click', () => {
                downloadQR(url, size);
            });
        })
        .catch(err => {
            console.error('QR modal failed:', err);
            showAlert('Failed to load QR code', 'error');
        });
}

async function getLinkStats() {
    const linkIdInput = document.getElementById('analyticsLinkId');
    const linkId = linkIdInput?.value;
    
    if (!linkId) {
        showAlert('Please enter a link ID', 'error');
        return;
    }
    
    if (!Validators.linkId(linkId)) {
        showAlert('Invalid link ID format', 'error');
        return;
    }
    
    try {
        const res = await fetch('/api/stats/' + encodeURIComponent(linkId));
        if (!res.ok) {
            throw new Error(`HTTP ${res.status}`);
        }
        
        const stats = await res.json();
        const linkStats = document.getElementById('linkStats');
        const totalClicksCount = document.getElementById('totalClicksCount');
        const statsContent = document.getElementById('statsContent');
        const recentClicksTable = document.getElementById('recentClicksTable');
        
        if (linkStats) linkStats.style.display = 'block';
        if (totalClicksCount) totalClicksCount.textContent = (stats.clicks || 0) + ' clicks';
        
        let statsHtml = '';
        if (stats.exists) {
            statsHtml = `
                <div class="stat-card">
                    <div class="stat-header">
                        <span class="stat-title">Total Clicks</span>
                        <span class="stat-icon"><i class="fas fa-mouse-pointer"></i></span>
                    </div>
                    <div class="stat-value">${formatNumber(stats.clicks || 0)}</div>
                </div>
                <div class="stat-card">
                    <div class="stat-header">
                        <span class="stat-title">Unique Visitors</span>
                        <span class="stat-icon"><i class="fas fa-users"></i></span>
                    </div>
                    <div class="stat-value">${formatNumber(stats.uniqueVisitors || 0)}</div>
                </div>
                <div class="stat-card">
                    <div class="stat-header">
                        <span class="stat-title">Link Mode</span>
                        <span class="stat-icon"><i class="fas fa-link"></i></span>
                    </div>
                    <div class="stat-value" style="font-size: 1.25rem;">${Validators.escapeForHTML(stats.linkMode || 'short')}</div>
                </div>
                <div class="stat-card">
                    <div class="stat-header">
                        <span class="stat-title">Length</span>
                        <span class="stat-icon"><i class="fas fa-ruler"></i></span>
                    </div>
                    <div class="stat-value" style="font-size: 1.25rem;">${stats.linkLength || 0} chars</div>
                </div>
                <div class="stat-card">
                    <div class="stat-header">
                        <span class="stat-title">Avg Decode Time</span>
                        <span class="stat-icon"><i class="fas fa-clock"></i></span>
                    </div>
                    <div class="stat-value">${(stats.avg_decoding_time || 0).toFixed(0)}ms</div>
                </div>
            `;
            
            const recentHtml = stats.recentClicks?.map(click => {
                const sanitizedIp = Validators.escapeForHTML(click.ip || '');
                const sanitizedCountry = Validators.escapeForHTML(click.country || 'XX');
                const sanitizedDevice = Validators.escapeForHTML(click.device_type || 'unknown');
                
                return `
                    <tr>
                        <td>${new Date(click.created_at).toLocaleString()}</td>
                        <td>${sanitizedIp}</td>
                        <td>${sanitizedCountry}</td>
                        <td>${sanitizedDevice}</td>
                        <td><span class="badge badge-info">${Validators.escapeForHTML(click.link_mode || 'short')}</span></td>
                        <td>${click.encoding_layers || 0}</td>
                        <td>${click.decoding_time_ms ? click.decoding_time_ms + 'ms' : '-'}</td>
                    </tr>
                `;
            }).join('') || '<tr><td colspan="7" style="text-align: center;">No clicks yet</td></tr>';
            
            if (recentClicksTable) recentClicksTable.innerHTML = recentHtml;
            
            // Update charts
            updateAnalyticsCharts(stats);
        } else {
            statsHtml = '<div class="stat-card">Link not found or expired</div>';
            if (recentClicksTable) recentClicksTable.innerHTML = '';
        }
        
        if (statsContent) statsContent.innerHTML = statsHtml;
    } catch (err) {
        console.error('Failed to get stats:', err);
        showAlert('Failed to get statistics', 'error');
    }
}

function updateAnalyticsCharts(stats) {
    if (!stats) return;
    
    // Destroy existing charts
    if (appState.countryChart) {
        appState.countryChart.destroy();
        appState.countryChart = null;
    }
    if (appState.analyticsDeviceChart) {
        appState.analyticsDeviceChart.destroy();
        appState.analyticsDeviceChart = null;
    }
    
    const ctxCountry = document.getElementById('countryChart')?.getContext('2d');
    const ctxDevice = document.getElementById('analyticsDeviceChart')?.getContext('2d');
    
    if (ctxCountry && stats.countries) {
        const countries = Object.entries(stats.countries).slice(0, 10);
        appState.countryChart = new Chart(ctxCountry, {
            type: 'bar',
            data: {
                labels: countries.map(([c]) => Validators.escapeForHTML(c)),
                datasets: [{
                    label: 'Clicks by Country',
                    data: countries.map(([, v]) => v),
                    backgroundColor: '#3b82f6',
                    borderRadius: 4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        grid: { color: 'rgba(255,255,255,0.05)' },
                        ticks: { color: '#666' }
                    },
                    x: {
                        ticks: { color: '#666' }
                    }
                }
            }
        });
    }
    
    if (ctxDevice && stats.devices) {
        appState.analyticsDeviceChart = new Chart(ctxDevice, {
            type: 'pie',
            data: {
                labels: Object.keys(stats.devices).map(k => Validators.escapeForHTML(k)),
                datasets: [{
                    data: Object.values(stats.devices),
                    backgroundColor: ['#4ade80', '#3b82f6', '#f59e0b', '#ef4444']
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: { color: '#aaa' }
                    }
                }
            }
        });
    }
}

function clearStats() {
    const linkStats = document.getElementById('linkStats');
    const analyticsLinkId = document.getElementById('analyticsLinkId');
    
    if (linkStats) linkStats.style.display = 'none';
    if (analyticsLinkId) analyticsLinkId.value = '';
    showAlert('Statistics cleared', 'info');
}

async function viewLink(linkId) {
    if (!Validators.linkId(linkId)) {
        showAlert('Invalid link ID', 'error');
        return;
    }
    
    try {
        const res = await fetch('/api/stats/' + encodeURIComponent(linkId));
        if (!res.ok) {
            throw new Error(`HTTP ${res.status}`);
        }
        
        const stats = await res.json();
        
        const sanitizedTargetUrl = Validators.validateAndSanitizeUrl(stats.target_url);
        const sanitizedNotes = Validators.escapeForHTML(stats.notes || '');
        
        const modalContent = `
            <div style="margin-bottom: 1.5rem;">
                <p><strong>ID:</strong> <code>${Validators.escapeForHTML(linkId)}</code></p>
                <p><strong>Mode:</strong> <span class="badge badge-${stats.linkMode === 'long' ? 'warning' : 'info'}">${Validators.escapeForHTML(stats.linkMode || 'short')}</span></p>
                <p><strong>Target URL:</strong> <a href="${sanitizedTargetUrl}" target="_blank" style="color: #8a8a8a;">${sanitizedTargetUrl}</a></p>
                <p><strong>Created:</strong> ${stats.created ? new Date(stats.created).toLocaleString() : 'N/A'}</p>
                <p><strong>Expires:</strong> ${stats.expiresAt ? new Date(stats.expiresAt).toLocaleString() : 'N/A'}</p>
                <p><strong>Clicks:</strong> ${formatNumber(stats.clicks || 0)}${stats.maxClicks ? '/' + formatNumber(stats.maxClicks) : ''}</p>
                <p><strong>Unique Visitors:</strong> ${formatNumber(stats.uniqueVisitors || 0)}</p>
                <p><strong>Password Protected:</strong> ${stats.passwordProtected ? 'Yes' : 'No'}</p>
                <p><strong>API Version:</strong> v${stats.apiVersion || '1'}</p>
                ${stats.notes ? `<p><strong>Notes:</strong> ${sanitizedNotes}</p>` : ''}
                ${stats.linkLength ? `<p><strong>URL Length:</strong> ${stats.linkLength} characters</p>` : ''}
                ${stats.encodingLayers ? `<p><strong>Encoding Layers:</strong> ${stats.encodingLayers}</p>` : ''}
                ${stats.encodingComplexity ? `<p><strong>Encoding Complexity:</strong> ${stats.encodingComplexity}</p>` : ''}
            </div>
            
            <h4 style="margin-bottom: 1rem;">Country Distribution</h4>
            <div style="max-height: 200px; overflow-y: auto; margin-bottom: 1.5rem;">
                ${Object.entries(stats.countries || {}).map(([country, count]) => `
                    <div style="display: flex; justify-content: space-between; padding: 0.5rem 0; border-bottom: 1px solid #1a1a1a;">
                        <span>${Validators.escapeForHTML(country)}</span>
                        <span style="font-weight: 600;">${formatNumber(count)}</span>
                    </div>
                `).join('')}
            </div>
            
            <div class="btn-group">
                <button class="btn btn-sm copy-link-modal" data-link-id="${Validators.escapeForHTML(linkId)}">
                    <i class="fas fa-copy"></i> Copy Link
                </button>
                <button class="btn btn-sm btn-secondary qr-link-modal" data-link-id="${Validators.escapeForHTML(linkId)}">
                    <i class="fas fa-qrcode"></i> Generate QR
                </button>
                <button class="btn btn-sm btn-danger delete-link-modal" data-link-id="${Validators.escapeForHTML(linkId)}">
                    <i class="fas fa-trash"></i> Delete
                </button>
            </div>
        `;
        
        const linkModalContent = document.getElementById('linkModalContent');
        if (linkModalContent) {
            linkModalContent.innerHTML = modalContent;
        }
        document.getElementById('linkModal')?.classList.add('active');
        
        // Add event listeners for modal buttons
        document.querySelector('.copy-link-modal')?.addEventListener('click', () => copyLink(linkId));
        document.querySelector('.qr-link-modal')?.addEventListener('click', () => {
            const url = window.location.origin + '/v/' + linkId;
            showQRModal(url, 300);
        });
        document.querySelector('.delete-link-modal')?.addEventListener('click', () => deleteLink(linkId));
    } catch (err) {
        console.error('Failed to load link details:', err);
        showAlert('Failed to load link details', 'error');
    }
}

function copyLink(linkId) {
    if (!linkId) {
        showAlert('Invalid link ID', 'error');
        return;
    }
    
    const url = window.location.origin + '/v/' + encodeURIComponent(linkId);
    navigator.clipboard.writeText(url)
        .then(() => showAlert('Link copied to clipboard!', 'success'))
        .catch(err => {
            console.error('Copy failed:', err);
            showAlert('Failed to copy to clipboard', 'error');
        });
}

async function deleteLink(linkId) {
    if (!Validators.linkId(linkId)) {
        showAlert('Invalid link ID', 'error');
        return;
    }
    
    if (!confirm('Are you sure you want to delete this link?')) {
        return;
    }
    
    try {
        const res = await fetch('/api/links/' + encodeURIComponent(linkId), {
            method: 'DELETE',
            headers: {
                'X-CSRF-Token': typeof CSRF_TOKEN !== 'undefined' ? CSRF_TOKEN : ''
            },
            credentials: 'include'
        });
        
        if (res.ok) {
            showAlert('Link deleted successfully', 'success');
            refreshLinks();
            closeModal();
        } else {
            const errorData = await res.json().catch(() => ({}));
            showAlert(errorData.error || 'Failed to delete link', 'error');
        }
    } catch (err) {
        console.error('Delete failed:', err);
        showAlert('Network error', 'error');
    }
}

// ============================================
// Test Link Modes
// ============================================
async function testLinkModes() {
    const testUrl = prompt('Enter a URL to test (or use default):', 'https://example.com/very/long/path/with/many/segments?param1=value1&param2=value2');
    if (!testUrl) return;
    
    if (!Validators.url(testUrl)) {
        showAlert('Invalid test URL', 'error');
        return;
    }
    
    try {
        const res = await fetch('/api/test/link-modes?url=' + encodeURIComponent(testUrl));
        if (!res.ok) {
            throw new Error(`HTTP ${res.status}`);
        }
        
        const data = await res.json();
        
        let html = `
            <div style="margin-bottom: 1.5rem;">
                <p><strong>Original URL:</strong> ${Validators.escapeForHTML(data.originalUrl?.substring(0, 50))}...</p>
                <p><strong>Original Length:</strong> ${data.originalLength} characters</p>
            </div>
            
            <h4 style="margin-bottom: 1rem;">Short Link</h4>
            <div style="background: #1a1a1a; padding: 1rem; border-radius: 8px; margin-bottom: 1.5rem;">
                <p><strong>Length:</strong> ${data.shortLink.length} chars (${data.shortLink.ratio}x)</p>
                <p><strong>Time:</strong> ${data.shortLink.encodingTime.toFixed(0)}ms</p>
                <p><code style="word-break: break-all;">${Validators.escapeForHTML(data.shortLink.url)}</code></p>
            </div>
            
            <h4 style="margin-bottom: 1rem;">Long Link Configurations</h4>
            <table class="table" style="min-width: 600px;">
                <thead>
                    <tr>
                        <th>Segments</th>
                        <th>Params</th>
                        <th>Layers</th>
                        <th>Length</th>
                        <th>Ratio</th>
                        <th>Time</th>
                        <th>Complexity</th>
                    </tr>
                </thead>
                <tbody>
        `;
        
        data.longLinks.forEach(link => {
            html += `
                <tr>
                    <td>${link.config.segments}</td>
                    <td>${link.config.params}</td>
                    <td>${link.layers}</td>
                    <td>${link.length} chars</td>
                    <td>${(link.length / data.originalLength).toFixed(2)}x</td>
                    <td>${link.encodingTime.toFixed(0)}ms</td>
                    <td>${link.complexity || 'N/A'}</td>
                </tr>
            `;
        });
        
        html += `
                </tbody>
            </table>
            
            <div style="margin-top: 1rem; background: #1a1a1a; padding: 1rem; border-radius: 8px;">
                <p><strong>Summary:</strong> Shortest long: ${data.summary.shortest} chars, Longest long: ${data.summary.longest} chars</p>
                <p><strong>Average Encoding Time:</strong> ${data.summary.avgEncodingTime.toFixed(0)}ms</p>
                <p><strong>Average Complexity:</strong> ${data.summary.avgComplexity.toFixed(1)}</p>
            </div>
        `;
        
        const testModalContent = document.getElementById('testModalContent');
        if (testModalContent) {
            testModalContent.innerHTML = html;
        }
        document.getElementById('testModal')?.classList.add('active');
    } catch (err) {
        console.error('Test failed:', err);
        showAlert('Failed to run test', 'error');
    }
}

// ============================================
// Security Functions with Improved Error Handling
// ============================================
async function refreshSecurityData() {
    try {
        const res = await fetch('/admin/security/monitor');
        if (!res.ok) {
            throw new Error(`HTTP ${res.status}`);
        }
        
        appState.securityData = await res.json();
        updateSecurityTables();
    } catch (err) {
        console.error('Failed to load security data:', err);
        showAlert('Failed to load security data', 'error');
    }
}

function updateSecurityTables() {
    // Login attempts
    const attemptsTable = document.getElementById('loginAttemptsTable');
    if (attemptsTable) {
        if (appState.securityData.activeAttacks?.length > 0) {
            attemptsTable.innerHTML = appState.securityData.activeAttacks.map(attack => `
                <tr>
                    <td>${Validators.escapeForHTML(attack.ip)}</td>
                    <td>${attack.attempts}</td>
                    <td>${new Date(attack.lastAttempt).toLocaleString()}</td>
                </tr>
            `).join('');
        } else {
            attemptsTable.innerHTML = '<tr><td colspan="3">No recent attempts</td></tr>';
        }
    }
    
    // Blocked IPs
    const blockedTable = document.getElementById('blockedIPsTable');
    const blockedCount = document.getElementById('blockedCount');
    
    if (blockedTable) {
        if (appState.securityData.blockedIPs?.length > 0) {
            blockedTable.innerHTML = appState.securityData.blockedIPs.map(ip => `
                <tr>
                    <td>${Validators.escapeForHTML(ip.ip)}</td>
                    <td>${Validators.escapeForHTML(ip.reason || 'Unknown')}</td>
                    <td>${new Date(ip.expires_at).toLocaleString()}</td>
                    <td>
                        <button class="btn btn-sm btn-danger unblock-ip" data-ip="${Validators.escapeForHTML(ip.ip)}">
                            <i class="fas fa-ban"></i> Unblock
                        </button>
                    </td>
                </tr>
            `).join('');
            if (blockedCount) blockedCount.textContent = appState.securityData.blockedIPs.length;
            
            document.querySelectorAll('.unblock-ip').forEach(btn => {
                btn.addEventListener('click', () => unblockIP(btn.dataset.ip));
            });
        } else {
            blockedTable.innerHTML = '<tr><td colspan="4">No blocked IPs</td></tr>';
            if (blockedCount) blockedCount.textContent = '0';
        }
    }
    
    // Active sessions
    const sessionsTable = document.getElementById('activeSessionsTable');
    if (sessionsTable) {
        if (appState.securityData.activeSessions?.length > 0) {
            sessionsTable.innerHTML = appState.securityData.activeSessions.map(session => `
                <tr>
                    <td>${Validators.escapeForHTML(session.user_id || 'anonymous')}</td>
                    <td>${Validators.escapeForHTML(session.ip)}</td>
                    <td>${new Date(session.created_at).toLocaleString()}</td>
                    <td>
                        <button class="btn btn-sm btn-danger revoke-session" data-session="${Validators.escapeForHTML(session.session_id)}">
                            <i class="fas fa-ban"></i> Revoke
                        </button>
                    </td>
                </tr>
            `).join('');
            
            document.querySelectorAll('.revoke-session').forEach(btn => {
                btn.addEventListener('click', () => revokeSession(btn.dataset.session));
            });
        } else {
            sessionsTable.innerHTML = '<tr><td colspan="4">No active sessions</td></tr>';
        }
    }
    
    const totalAttempts = document.getElementById('totalAttempts');
    if (totalAttempts) totalAttempts.textContent = appState.securityData.totalAttempts || 0;
}

function clearLoginAttempts() {
    showAlert('Login attempts cleared', 'success');
}

function showUnblockIPModal() {
    const ip = prompt('Enter IP address to unblock:');
    if (ip && Validators.ip(ip)) {
        unblockIP(ip);
    } else if (ip) {
        showAlert('Invalid IP address format', 'error');
    }
}

async function unblockIP(ip) {
    if (!Validators.ip(ip)) {
        showAlert('Invalid IP address', 'error');
        return;
    }
    
    try {
        const res = await fetch('/admin/unblock-ip', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-Token': typeof CSRF_TOKEN !== 'undefined' ? CSRF_TOKEN : ''
            },
            body: JSON.stringify({ ip }),
            credentials: 'include'
        });
        
        if (res.ok) {
            showAlert(`IP ${ip} unblocked`, 'success');
            refreshSecurityData();
        } else {
            const error = await res.json().catch(() => ({}));
            showAlert(error.error || 'Failed to unblock IP', 'error');
        }
    } catch (err) {
        console.error('Unblock failed:', err);
        showAlert('Network error', 'error');
    }
}

function showRevokeSessionModal() {
    const sessionId = prompt('Enter session ID to revoke:');
    if (sessionId) revokeSession(sessionId);
}

async function revokeSession(sessionId) {
    if (!sessionId) {
        showAlert('Invalid session ID', 'error');
        return;
    }
    
    try {
        const res = await fetch('/admin/revoke-session', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-Token': typeof CSRF_TOKEN !== 'undefined' ? CSRF_TOKEN : ''
            },
            body: JSON.stringify({ sessionId }),
            credentials: 'include'
        });
        
        if (res.ok) {
            showAlert('Session revoked', 'success');
            refreshSecurityData();
        } else {
            const error = await res.json().catch(() => ({}));
            showAlert(error.error || 'Failed to revoke session', 'error');
        }
    } catch (err) {
        console.error('Revoke failed:', err);
        showAlert('Network error', 'error');
    }
}

async function updateBotThreshold(threshold) {
    try {
        const res = await fetch('/api/settings', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-Token': typeof CSRF_TOKEN !== 'undefined' ? CSRF_TOKEN : ''
            },
            body: JSON.stringify({
                key: 'botThresholds',
                value: { desktop: threshold }
            }),
            credentials: 'include'
        });
        
        if (res.ok) {
            showAlert('Bot threshold updated', 'success');
        } else {
            const error = await res.json().catch(() => ({}));
            showAlert(error.error || 'Failed to update threshold', 'error');
        }
    } catch (err) {
        console.error('Update failed:', err);
        showAlert('Network error', 'error');
    }
}

// ============================================
// Encryption Key Functions
// ============================================
async function fetchEncryptionKeys() {
    try {
        const res = await fetch('/admin/keys');
        if (!res.ok) {
            throw new Error(`HTTP ${res.status}`);
        }
        
        const data = await res.json();
        appState.encryptionKeys = data.keys || [];
        renderEncryptionKeys();
        
        const currentKeyEl = document.getElementById('currentKeyId');
        if (currentKeyEl && data.currentKey) {
            currentKeyEl.textContent = `${data.currentKey.id.substring(0, 8)}... (v${data.currentKey.version})`;
        }
    } catch (err) {
        console.error('Failed to load encryption keys:', err);
        showAlert('Failed to load encryption keys', 'error');
    }
}

function renderEncryptionKeys() {
    const keysTable = document.getElementById('keysTableBody');
    if (!keysTable) return;
    
    if (appState.encryptionKeys.length === 0) {
        keysTable.innerHTML = '<tr><td colspan="6">No encryption keys found</td></tr>';
        return;
    }
    
    keysTable.innerHTML = appState.encryptionKeys.map(key => `
        <tr>
            <td><code>${Validators.escapeForHTML(key.id.substring(0, 8))}...</code></td>
            <td>${key.version}</td>
            <td>${new Date(key.createdAt).toLocaleString()}</td>
            <td>${new Date(key.expiresAt).toLocaleString()}</td>
            <td>
                ${key.isCurrent ? '<span class="badge badge-success">Current</span>' : ''}
            </td>
            <td>
                <button class="btn btn-sm btn-secondary view-key" data-key-id="${Validators.escapeForHTML(key.id)}">
                    <i class="fas fa-eye"></i>
                </button>
            </td>
        </tr>
    `).join('');
    
    document.querySelectorAll('.view-key').forEach(btn => {
        btn.addEventListener('click', () => showKeyDetails(btn.dataset.keyId));
    });
}

async function rotateEncryptionKeys() {
    if (!confirm('Are you sure you want to rotate encryption keys? This will generate a new key.')) {
        return;
    }
    
    try {
        const res = await fetch('/admin/keys/rotate', {
            method: 'POST',
            headers: {
                'X-CSRF-Token': typeof CSRF_TOKEN !== 'undefined' ? CSRF_TOKEN : ''
            },
            credentials: 'include'
        });
        
        if (res.ok) {
            const data = await res.json();
            showAlert(`New key generated: ${data.keyId.substring(0, 8)}...`, 'success');
            fetchEncryptionKeys();
        } else {
            const error = await res.json().catch(() => ({}));
            showAlert(error.error || 'Failed to rotate keys', 'error');
        }
    } catch (err) {
        console.error('Rotate failed:', err);
        showAlert('Network error', 'error');
    }
}

async function backupEncryptionKeys() {
    try {
        const res = await fetch('/admin/keys/backup', {
            method: 'POST',
            headers: {
                'X-CSRF-Token': typeof CSRF_TOKEN !== 'undefined' ? CSRF_TOKEN : ''
            },
            credentials: 'include'
        });
        
        if (res.ok) {
            const blob = await res.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `keys-backup-${new Date().toISOString()}.enc`;
            a.click();
            window.URL.revokeObjectURL(url);
            showAlert('Keys backup downloaded', 'success');
        } else {
            const error = await res.json().catch(() => ({}));
            showAlert(error.error || 'Failed to backup keys', 'error');
        }
    } catch (err) {
        console.error('Backup failed:', err);
        showAlert('Network error', 'error');
    }
}

function showKeyDetails(keyId) {
    const key = appState.encryptionKeys.find(k => k.id === keyId);
    if (!key) {
        showAlert('Key not found', 'error');
        return;
    }
    
    const modalContent = `
        <div style="margin-bottom: 1.5rem;">
            <p><strong>Key ID:</strong> <code>${Validators.escapeForHTML(key.id)}</code></p>
            <p><strong>Version:</strong> ${key.version}</p>
            <p><strong>Created:</strong> ${new Date(key.createdAt).toLocaleString()}</p>
            <p><strong>Expires:</strong> ${new Date(key.expiresAt).toLocaleString()}</p>
            <p><strong>Status:</strong> ${key.isCurrent ? '<span class="badge badge-success">Current</span>' : '<span class="badge badge-info">Archived</span>'}</p>
            <p><strong>Age:</strong> ${formatDuration((Date.now() - new Date(key.createdAt)) / 1000)}</p>
        </div>
    `;
    
    const keyModalContent = document.getElementById('keyModalContent');
    if (keyModalContent) {
        keyModalContent.innerHTML = modalContent;
    }
    document.getElementById('keyModal')?.classList.add('active');
}

// ============================================
// Audit Log Functions
// ============================================
async function fetchAuditLogs() {
    try {
        const res = await fetch('/admin/audit/logs');
        if (!res.ok) {
            throw new Error(`HTTP ${res.status}`);
        }
        
        const data = await res.json();
        appState.auditLogs = data.logs || [];
        renderAuditLogs();
    } catch (err) {
        console.error('Failed to load audit logs:', err);
        showAlert('Failed to load audit logs', 'error');
    }
}

function renderAuditLogs() {
    const logsTable = document.getElementById('auditLogsBody');
    if (!logsTable) return;
    
    if (appState.auditLogs.length === 0) {
        logsTable.innerHTML = '<tr><td colspan="5">No audit logs found</td></tr>';
        return;
    }
    
    logsTable.innerHTML = appState.auditLogs.map(log => `
        <tr>
            <td>${new Date(log.timestamp).toLocaleString()}</td>
            <td><span class="badge badge-info">${Validators.escapeForHTML(log.action)}</span></td>
            <td>${Validators.escapeForHTML(log.user || 'system')}</td>
            <td>${Validators.escapeForHTML(log.ip || 'N/A')}</td>
            <td>${Validators.sanitizeJSON(log.details || {})}</td>
        </tr>
    `).join('');
}

function filterAuditLogs() {
    // Implement filtering logic
    console.log('Filtering audit logs...');
}

function exportAuditLogs() {
    const dataStr = Validators.sanitizeJSON(appState.auditLogs);
    const blob = new Blob([dataStr], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `audit-logs-${new Date().toISOString()}.json`;
    a.click();
    URL.revokeObjectURL(url);
    showAlert('Audit logs exported', 'success');
}

function addAuditEntry(entry) {
    appState.auditLogs.unshift(entry);
    if (appState.auditLogs.length > APP_CONFIG.maxAuditEntries) {
        appState.auditLogs.pop();
    }
    
    const activeTab = document.querySelector('.tab-content.active')?.id;
    if (activeTab === 'audit-log') {
        renderAuditLogs();
    }
}

// ============================================
// Backup Functions
// ============================================
async function fetchBackupStatus() {
    try {
        const res = await fetch('/admin/backup/status');
        if (!res.ok) {
            throw new Error(`HTTP ${res.status}`);
        }
        
        appState.backupStatus = await res.json();
        updateBackupStatus();
    } catch (err) {
        console.error('Failed to load backup status:', err);
        showAlert('Failed to load backup status', 'error');
    }
}

function updateBackupStatus() {
    const lastBackupEl = document.getElementById('lastBackup');
    const backupCountEl = document.getElementById('backupCount');
    const backupSizeEl = document.getElementById('backupSize');
    
    if (lastBackupEl && appState.backupStatus.lastBackup) {
        lastBackupEl.textContent = new Date(appState.backupStatus.lastBackup).toLocaleString();
    }
    if (backupCountEl) {
        backupCountEl.textContent = appState.backupStatus.count || 0;
    }
    if (backupSizeEl) {
        backupSizeEl.textContent = formatBytes(appState.backupStatus.totalSize || 0);
    }
}

async function runBackup() {
    try {
        const res = await fetch('/admin/backup/run', {
            method: 'POST',
            headers: {
                'X-CSRF-Token': typeof CSRF_TOKEN !== 'undefined' ? CSRF_TOKEN : ''
            },
            credentials: 'include'
        });
        
        if (res.ok) {
            showAlert('Backup started', 'success');
            fetchBackupStatus();
        } else {
            const error = await res.json().catch(() => ({}));
            showAlert(error.error || 'Failed to start backup', 'error');
        }
    } catch (err) {
        console.error('Backup failed:', err);
        showAlert('Network error', 'error');
    }
}

function showRestoreModal() {
    const backupId = prompt('Enter backup ID to restore:');
    if (backupId) restoreBackup(backupId);
}

async function restoreBackup(backupId) {
    if (!backupId) {
        showAlert('Invalid backup ID', 'error');
        return;
    }
    
    if (!confirm('Are you sure you want to restore this backup? This will overwrite current data.')) {
        return;
    }
    
    try {
        const res = await fetch('/admin/backup/restore', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-Token': typeof CSRF_TOKEN !== 'undefined' ? CSRF_TOKEN : ''
            },
            body: JSON.stringify({ backupId }),
            credentials: 'include'
        });
        
        if (res.ok) {
            showAlert('Backup restored', 'success');
        } else {
            const error = await res.json().catch(() => ({}));
            showAlert(error.error || 'Failed to restore backup', 'error');
        }
    } catch (err) {
        console.error('Restore failed:', err);
        showAlert('Network error', 'error');
    }
}

function showBackupConfig() {
    window.location.href = '/admin/backup/config';
}

// ============================================
// Settings Functions
// ============================================
async function saveLinkModeSettings() {
    const elements = {
        settingLinkLengthMode: document.getElementById('settingLinkLengthMode'),
        settingAllowLinkModeSwitch: document.getElementById('settingAllowLinkModeSwitch'),
        settingLongLinkSegments: document.getElementById('settingLongLinkSegments'),
        settingLongLinkParams: document.getElementById('settingLongLinkParams'),
        settingLinkEncodingLayers: document.getElementById('settingLinkEncodingLayers'),
        settingMaxEncodingIterations: document.getElementById('settingMaxEncodingIterations'),
        settingEnableCompression: document.getElementById('settingEnableCompression'),
        settingEnableEncryption: document.getElementById('settingEnableEncryption'),
        settingEncodingComplexityThreshold: document.getElementById('settingEncodingComplexityThreshold')
    };
    
    const settings = {
        linkLengthMode: elements.settingLinkLengthMode?.value || 'short',
        allowLinkModeSwitch: elements.settingAllowLinkModeSwitch?.checked ?? true,
        longLinkSegments: parseInt(elements.settingLongLinkSegments?.value || 6),
        longLinkParams: parseInt(elements.settingLongLinkParams?.value || 13),
        linkEncodingLayers: parseInt(elements.settingLinkEncodingLayers?.value || 4),
        maxEncodingIterations: parseInt(elements.settingMaxEncodingIterations?.value || 3),
        enableCompression: elements.settingEnableCompression?.checked ?? true,
        enableEncryption: elements.settingEnableEncryption?.checked ?? false,
        encodingComplexityThreshold: parseInt(elements.settingEncodingComplexityThreshold?.value || 50)
    };
    
    try {
        const res = await fetch('/api/settings/link-mode', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-Token': typeof CSRF_TOKEN !== 'undefined' ? CSRF_TOKEN : ''
            },
            body: JSON.stringify(settings),
            credentials: 'include'
        });
        
        if (res.ok) {
            showAlert('Link mode settings saved', 'success');
            
            // Update local variables
            if (settings.linkLengthMode) window.LINK_LENGTH_MODE = settings.linkLengthMode;
            if (settings.longLinkSegments) window.LONG_LINK_SEGMENTS = settings.longLinkSegments;
            if (settings.longLinkParams) window.LONG_LINK_PARAMS = settings.longLinkParams;
            if (settings.linkEncodingLayers) window.LINK_ENCODING_LAYERS = settings.linkEncodingLayers;
            
            selectLinkMode(window.LINK_LENGTH_MODE);
        } else {
            const error = await res.json().catch(() => ({}));
            showAlert(error.error || 'Failed to save settings', 'error');
        }
    } catch (err) {
        console.error('Save settings failed:', err);
        showAlert('Network error', 'error');
    }
}

async function saveSystemSettings() {
    const elements = {
        settingLinkTTL: document.getElementById('settingLinkTTL'),
        settingDesktopChallenge: document.getElementById('settingDesktopChallenge'),
        settingBotDetection: document.getElementById('settingBotDetection'),
        settingAnalytics: document.getElementById('settingAnalytics'),
        settingLogLevel: document.getElementById('settingLogLevel'),
        settingLogFormat: document.getElementById('settingLogFormat'),
        settingLogRetention: document.getElementById('settingLogRetention')
    };
    
    const settings = {
        linkTTL: parseInt(elements.settingLinkTTL?.value || 1800),
        desktopChallenge: elements.settingDesktopChallenge?.checked ?? true,
        botDetection: elements.settingBotDetection?.checked ?? true,
        analytics: elements.settingAnalytics?.checked ?? true,
        logLevel: elements.settingLogLevel?.value || 'info',
        logFormat: elements.settingLogFormat?.value || 'json',
        logRetentionDays: parseInt(elements.settingLogRetention?.value || 30)
    };
    
    let success = true;
    
    for (const [key, value] of Object.entries(settings)) {
        try {
            const res = await fetch('/api/settings', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-Token': typeof CSRF_TOKEN !== 'undefined' ? CSRF_TOKEN : ''
                },
                body: JSON.stringify({ key, value }),
                credentials: 'include'
            });
            
            if (!res.ok) {
                success = false;
                console.error('Failed to save setting:', key);
            }
        } catch (err) {
            success = false;
            console.error('Failed to save setting:', key, err);
        }
    }
    
    if (success) {
        showAlert('System settings saved', 'success');
    } else {
        showAlert('Some settings failed to save', 'warning');
    }
}

async function saveSecuritySettings() {
    const elements = {
        settingBCryptRounds: document.getElementById('settingBCryptRounds'),
        settingSessionTTL: document.getElementById('settingSessionTTL'),
        settingLoginAttempts: document.getElementById('settingLoginAttempts'),
        settingCSRFEnabled: document.getElementById('settingCSRFEnabled'),
        settingCSPEnabled: document.getElementById('settingCSPEnabled'),
        settingHSTSEnabled: document.getElementById('settingHSTSEnabled')
    };
    
    const settings = {
        bcryptRounds: parseInt(elements.settingBCryptRounds?.value || 12),
        sessionTTL: parseInt(elements.settingSessionTTL?.value || 86400),
        loginAttempts: parseInt(elements.settingLoginAttempts?.value || 10),
        csrfEnabled: elements.settingCSRFEnabled?.checked ?? true,
        cspEnabled: elements.settingCSPEnabled?.checked ?? true,
        hstsEnabled: elements.settingHSTSEnabled?.checked ?? true
    };
    
    let success = true;
    
    for (const [key, value] of Object.entries(settings)) {
        try {
            const res = await fetch('/api/settings', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-Token': typeof CSRF_TOKEN !== 'undefined' ? CSRF_TOKEN : ''
                },
                body: JSON.stringify({ key, value }),
                credentials: 'include'
            });
            
            if (!res.ok) {
                success = false;
                console.error('Failed to save setting:', key);
            }
        } catch (err) {
            success = false;
            console.error('Failed to save setting:', key, err);
        }
    }
    
    if (success) {
        showAlert('Security settings saved', 'success');
    } else {
        showAlert('Some settings failed to save', 'warning');
    }
}

async function saveNotificationSettings() {
    const elements = {
        settingNotificationSound: document.getElementById('settingNotificationSound'),
        settingAlertEmail: document.getElementById('settingAlertEmail'),
        settingSlackWebhook: document.getElementById('settingSlackWebhook')
    };
    
    const settings = {
        notificationSound: elements.settingNotificationSound?.checked ?? false,
        alertEmail: elements.settingAlertEmail?.value || '',
        slackWebhook: elements.settingSlackWebhook?.value || ''
    };
    
    let success = true;
    
    for (const [key, value] of Object.entries(settings)) {
        try {
            const res = await fetch('/api/settings', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-Token': typeof CSRF_TOKEN !== 'undefined' ? CSRF_TOKEN : ''
                },
                body: JSON.stringify({ key, value }),
                credentials: 'include'
            });
            
            if (!res.ok) {
                success = false;
                console.error('Failed to save setting:', key);
            }
        } catch (err) {
            success = false;
            console.error('Failed to save setting:', key, err);
        }
    }
    
    if (success) {
        showAlert('Notification settings saved', 'success');
    } else {
        showAlert('Some settings failed to save', 'warning');
    }
}

async function reloadConfig() {
    try {
        const res = await fetch('/admin/reload-config', {
            method: 'POST',
            headers: {
                'X-CSRF-Token': typeof CSRF_TOKEN !== 'undefined' ? CSRF_TOKEN : ''
            },
            credentials: 'include'
        });
        
        if (res.ok) {
            showAlert('Configuration reloaded', 'success');
            setTimeout(() => location.reload(), 1000);
        } else {
            const error = await res.json().catch(() => ({}));
            showAlert(error.error || 'Failed to reload config', 'error');
        }
    } catch (err) {
        console.error('Reload failed:', err);
        showAlert('Network error', 'error');
    }
}

async function viewHealthCheck() {
    try {
        const res = await fetch('/health/full');
        if (!res.ok) {
            throw new Error(`HTTP ${res.status}`);
        }
        
        const health = await res.json();
        
        let html = '<div style="margin-bottom: 1rem;">';
        for (const [service, status] of Object.entries(health.checks)) {
            const statusClass = status === true ? 'success' : status === 'disabled' ? 'info' : 'error';
            html += `
                <div style="display: flex; justify-content: space-between; padding: 0.5rem 0; border-bottom: 1px solid #1a1a1a;">
                    <span>${Validators.escapeForHTML(service)}</span>
                    <span class="badge badge-${statusClass}">${status === true ? 'Healthy' : status === 'disabled' ? 'Disabled' : 'Unhealthy'}</span>
                </div>
            `;
        }
        html += '</div>';
        
        html += `
            <div style="background: #1a1a1a; padding: 1rem; border-radius: 8px;">
                <p><strong>Status:</strong> <span class="badge badge-${health.status === 'healthy' ? 'success' : 'error'}">${Validators.escapeForHTML(health.status)}</span></p>
                <p><strong>Uptime:</strong> ${formatDuration(health.uptime)}</p>
                <p><strong>Timestamp:</strong> ${new Date(health.timestamp).toLocaleString()}</p>
            </div>
        `;
        
        const healthModalContent = document.getElementById('healthModalContent');
        if (healthModalContent) {
            healthModalContent.innerHTML = html;
        }
        document.getElementById('healthModal')?.classList.add('active');
    } catch (err) {
        console.error('Health check failed:', err);
        showAlert('Failed to load health check', 'error');
    }
}

// ============================================
// Export Functions
// ============================================
function exportData(format) {
    const linkIdInput = document.getElementById('analyticsLinkId');
    const linkId = linkIdInput?.value;
    
    if (!linkId) {
        showAlert('Please enter a link ID', 'error');
        return;
    }
    
    if (!Validators.linkId(linkId)) {
        showAlert('Invalid link ID format', 'error');
        return;
    }
    
    window.location.href = `/api/export/${encodeURIComponent(linkId)}?format=${encodeURIComponent(format)}`;
}

function exportAllLinks() {
    const dataStr = Validators.sanitizeJSON(appState.allLinks);
    const blob = new Blob([dataStr], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `links-${new Date().toISOString()}.json`;
    a.click();
    URL.revokeObjectURL(url);
    showAlert('Links exported', 'success');
}

// ============================================
// Utility Functions
// ============================================
function formatNumber(num) {
    if (num === undefined || num === null) return '0';
    if (num >= 1000000) return (num / 1000000).toFixed(1) + 'M';
    if (num >= 1000) return (num / 1000).toFixed(1) + 'K';
    return num.toString();
}

function formatBytes(bytes) {
    if (bytes === 0 || !bytes) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

function formatDuration(seconds) {
    if (!seconds || seconds < 0) return '0s';
    if (seconds < 60) return Math.floor(seconds) + 's';
    if (seconds < 3600) {
        const mins = Math.floor(seconds / 60);
        const secs = Math.floor(seconds % 60);
        return mins + 'm ' + (secs > 0 ? secs + 's' : '');
    }
    if (seconds < 86400) {
        const hours = Math.floor(seconds / 3600);
        const mins = Math.floor((seconds % 3600) / 60);
        return hours + 'h ' + (mins > 0 ? mins + 'm' : '');
    }
    const days = Math.floor(seconds / 86400);
    const hours = Math.floor((seconds % 86400) / 3600);
    return days + 'd ' + (hours > 0 ? hours + 'h' : '');
}

function refreshLinks() {
    if (appState.socket?.connected) {
        appState.socketQueue.add('getLinks', null);
    }
}

function clearForm() {
    const elements = {
        targetUrl: document.getElementById('targetUrl'),
        linkPassword: document.getElementById('linkPassword'),
        maxClicks: document.getElementById('maxClicks'),
        linkNotes: document.getElementById('linkNotes'),
        expiresIn: document.getElementById('expiresIn'),
        generateQR: document.getElementById('generateQR'),
        qrSize: document.getElementById('qrSize'),
        result: document.getElementById('result'),
        qrResult: document.getElementById('qrResult'),
        encodingDetails: document.getElementById('encodingDetails')
    };
    
    if (elements.targetUrl) elements.targetUrl.value = typeof TARGET_URL !== 'undefined' ? TARGET_URL : '';
    if (elements.linkPassword) elements.linkPassword.value = '';
    if (elements.maxClicks) elements.maxClicks.value = '';
    if (elements.linkNotes) elements.linkNotes.value = '';
    if (elements.expiresIn) elements.expiresIn.value = '30m';
    if (elements.generateQR) elements.generateQR.checked = false;
    if (elements.qrSize) elements.qrSize.disabled = true;
    if (elements.result) elements.result.style.display = 'none';
    if (elements.qrResult) elements.qrResult.innerHTML = '';
    if (elements.encodingDetails) elements.encodingDetails.style.display = 'none';
}

function copyToClipboard() {
    const url = document.getElementById('generatedUrl');
    if (!url?.value) {
        showAlert('No URL to copy', 'error');
        return;
    }
    
    url.select();
    navigator.clipboard.writeText(url.value)
        .then(() => showAlert('Copied to clipboard!', 'success'))
        .catch(() => {
            // Fallback for older browsers
            document.execCommand('copy');
            showAlert('Copied to clipboard!', 'success');
        });
}

function showQRFromResult() {
    const url = document.getElementById('generatedUrl')?.value;
    const size = document.getElementById('qrSize')?.value || 300;
    
    if (url && Validators.url(url)) {
        showQRModal(url, size);
    } else {
        showAlert('Invalid URL', 'error');
    }
}

function downloadQR(url, size) {
    if (!Validators.url(url)) {
        showAlert('Invalid URL', 'error');
        return;
    }
    window.location.href = '/qr/download?url=' + encodeURIComponent(url) + '&size=' + encodeURIComponent(size);
}

function clearLogs() {
    const logs = document.getElementById('logs');
    if (!logs) return;
    
    logs.innerHTML = '<div class="log-entry" style="color: #7aa2f7; text-align: center;"><i class="fas fa-check-circle"></i> Logs cleared</div>';
    appState.logCount = 0;
    
    const logCounter = document.getElementById('logCounter');
    const logRateEl = document.getElementById('logRate');
    
    if (logCounter) logCounter.textContent = '0';
    if (logRateEl) logRateEl.textContent = '0 logs/sec';
    showAlert('Logs cleared', 'success');
}

function exportLogs() {
    const logs = document.getElementById('logs');
    if (!logs) return;
    
    const logEntries = [];
    for (const entry of logs.children) {
        logEntries.push(entry.textContent);
    }
    
    const blob = new Blob([logEntries.join('\n')], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `logs-${new Date().toISOString()}.txt`;
    a.click();
    URL.revokeObjectURL(url);
    
    showAlert('Logs exported', 'success');
}

function logout() {
    fetch('/admin/logout', {
        method: 'POST',
        credentials: 'include'
    })
        .then(() => {
            window.location.href = '/admin/login';
        })
        .catch(err => {
            console.error('Logout failed:', err);
            window.location.href = '/admin/login';
        });
}

// ============================================
// Cache Management
// ============================================
async function clearCache(type) {
    let action = 'clearCache';
    let message = 'all caches';
    
    const typeMap = {
        geo: { action: 'clearGeoCache', message: 'geo cache' },
        qr: { action: 'clearQRCache', message: 'QR cache' },
        encoding: { action: 'clearEncodingCache', message: 'encoding cache' },
        device: { action: 'clearDeviceCache', message: 'device cache' }
    };
    
    if (type !== 'all' && typeMap[type]) {
        action = typeMap[type].action;
        message = typeMap[type].message;
    }
    
    if (!confirm(`Are you sure you want to clear ${message}?`)) return;
    
    if (type === 'all') {
        try {
            const res = await fetch('/admin/clear-cache', {
                method: 'POST',
                headers: { 
                    'Content-Type': 'application/json',
                    'X-CSRF-Token': typeof CSRF_TOKEN !== 'undefined' ? CSRF_TOKEN : ''
                },
                body: JSON.stringify({ _csrf: typeof CSRF_TOKEN !== 'undefined' ? CSRF_TOKEN : '' }),
                credentials: 'include'
            });
            
            if (res.ok) {
                showAlert('All caches cleared', 'success');
            } else {
                const error = await res.json().catch(() => ({}));
                showAlert(error.error || 'Failed to clear cache', 'error');
            }
        } catch (err) {
            console.error('Cache clear failed:', err);
            showAlert('Network error', 'error');
        }
    } else if (appState.socket?.connected) {
        appState.socketQueue.add(action, null);
        showAlert(`${message} cleared`, 'success');
    }
}

// ============================================
// Modal functions
// ============================================
function closeModal() {
    document.getElementById('linkModal')?.classList.remove('active');
}

function closeTestModal() {
    document.getElementById('testModal')?.classList.remove('active');
}

function closeHealthModal() {
    document.getElementById('healthModal')?.classList.remove('active');
}

function closeQRModal() {
    document.getElementById('qrModal')?.classList.remove('active');
}

function closeKeyModal() {
    document.getElementById('keyModal')?.classList.remove('active');
}

function closeAuditModal() {
    document.getElementById('auditModal')?.classList.remove('active');
}

// ============================================
// Click outside to close modal
// ============================================
window.onclick = function(event) {
    const modals = [
        { element: document.getElementById('linkModal'), close: closeModal },
        { element: document.getElementById('testModal'), close: closeTestModal },
        { element: document.getElementById('healthModal'), close: closeHealthModal },
        { element: document.getElementById('qrModal'), close: closeQRModal },
        { element: document.getElementById('keyModal'), close: closeKeyModal },
        { element: document.getElementById('auditModal'), close: closeAuditModal }
    ];
    
    for (const modal of modals) {
        if (event.target === modal.element) {
            modal.close();
            break;
        }
    }
};

// Handle escape key
document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
        closeModal();
        closeTestModal();
        closeHealthModal();
        closeQRModal();
        closeKeyModal();
        closeAuditModal();
    }
});

// Handle window resize
window.addEventListener('resize', () => {
    if (window.innerWidth > 768) {
        document.getElementById('sidebar')?.classList.remove('open');
    }
});

// ============================================
// Uptime counter
// ============================================
appState.registerInterval(setInterval(() => {
    const uptime = Math.floor((Date.now() - appState.startTime) / 1000);
    const uptimeElement = document.getElementById('uptimeValue');
    const systemUptimeElement = document.getElementById('systemUptime');
    
    if (uptimeElement) {
        uptimeElement.textContent = formatDuration(uptime);
    }
    if (systemUptimeElement) {
        systemUptimeElement.textContent = formatDuration(uptime);
    }
}, 1000));

// ============================================
// Check for queues
// ============================================
fetch('/health')
    .then(res => {
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        return res.json();
    })
    .then(data => {
        const elements = {
            queuesNavItem: document.getElementById('queuesNavItem'),
            dbStatus: document.getElementById('dbStatus'),
            redisStatus: document.getElementById('redisStatus'),
            queueStatus: document.getElementById('queueStatus')
        };
        
        if (elements.queuesNavItem && data.queues?.redirect === 'ready') {
            elements.queuesNavItem.style.display = 'flex';
        }
        if (elements.dbStatus) {
            elements.dbStatus.className = data.database ? 'status-dot connected' : 'status-dot disconnected';
        }
        if (elements.redisStatus) {
            elements.redisStatus.className = data.redis === 'connected' ? 'status-dot connected' : 'status-dot disconnected';
        }
        if (elements.queueStatus) {
            elements.queueStatus.className = data.queues?.redirect === 'ready' ? 'status-dot connected' : 'status-dot disconnected';
        }
    })
    .catch(err => console.error('Health check failed:', err));

// ============================================
// Initialize everything with proper cleanup
// ============================================
function init() {
    console.log('🚀 Initializing admin dashboard v4.1.0...');
    console.log('Environment:', typeof NODE_ENV !== 'undefined' ? NODE_ENV : 'unknown');
    console.log('Link Mode:', typeof LINK_LENGTH_MODE !== 'undefined' ? LINK_LENGTH_MODE : 'short');
    console.log('MFA Enabled:', typeof MFA_ENABLED !== 'undefined' ? MFA_ENABLED : 'false');
    console.log('WebAuthn Enabled:', typeof WEBAUTHN_ENABLED !== 'undefined' ? WEBAUTHN_ENABLED : 'false');
    
    initSocket();
    setupEventListeners();
    
    // Initialize the first tab
    showTab('dashboard');
    
    // Load security data in background
    setTimeout(() => {
        refreshSecurityData();
        fetchEncryptionKeys();
        fetchBackupStatus();
    }, 1000);
}

// Start the application when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
} else {
    // DOM is already loaded
    init();
}