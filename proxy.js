const http = require('http');
const https = require('https');
const url = require('url');
const fs = require('fs');
const path = require('path');

// Configuration
const CONFIG = {
    PORT: process.env.PORT || 3000,
    TARGET_SERVER: process.env.TARGET_SERVER || 'https://gps-server-zq8o.onrender.com',
    LOG_REQUESTS: process.env.LOG_REQUESTS === 'true',
    ALLOWED_IPS: process.env.ALLOWED_IPS ? process.env.ALLOWED_IPS.split(',') : [],
    BLOCKED_IPS: process.env.BLOCKED_IPS ? process.env.BLOCKED_IPS.split(',') : [],
    REQUEST_TIMEOUT: parseInt(process.env.REQUEST_TIMEOUT) || 30000, // 30 seconds
    MAX_BODY_SIZE: parseInt(process.env.MAX_BODY_SIZE) || 10485760, // 10MB
    ENABLE_CACHE: process.env.ENABLE_CACHE === 'true',
    CACHE_DURATION: parseInt(process.env.CACHE_DURATION) || 60000, // 1 minute
};

// Request cache (simple in-memory)
const requestCache = new Map();

// Counters
let requestCount = 0;
let gpsRequestCount = 0;
let cacheHits = 0;
let cacheMisses = 0;

// Logging function
function log(message, type = 'INFO') {
    const timestamp = new Date().toISOString();
    console.log(`[${timestamp}] [${type}] ${message}`);
    
    // Also write to file in production
    if (process.env.NODE_ENV === 'production') {
        fs.appendFileSync('proxy.log', `[${timestamp}] [${type}] ${message}\n`);
    }
}

// IP validation
function isIPAllowed(clientIP) {
    // Allow all if no restrictions
    if (CONFIG.ALLOWED_IPS.length === 0 && CONFIG.BLOCKED_IPS.length === 0) {
        return true;
    }
    
    // Check blocked list
    if (CONFIG.BLOCKED_IPS.includes(clientIP)) {
        log(`Blocked IP: ${clientIP}`, 'SECURITY');
        return false;
    }
    
    // Check allowed list (if specified)
    if (CONFIG.ALLOWED_IPS.length > 0 && !CONFIG.ALLOWED_IPS.includes(clientIP)) {
        log(`Unauthorized IP: ${clientIP}`, 'SECURITY');
        return false;
    }
    
    return true;
}

// Parse GPS data from request
function parseGPSRequest(req) {
    const clientIP = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    const userAgent = req.headers['user-agent'] || 'Unknown';
    const contentType = req.headers['content-type'] || 'unknown';
    
    return {
        ip: clientIP,
        userAgent: userAgent,
        method: req.method,
        url: req.url,
        contentType: contentType,
        timestamp: new Date().toISOString(),
        isGPSDevice: userAgent.includes('GPS') || 
                     contentType.includes('application/octet-stream') ||
                     req.url.includes('/gps') ||
                     req.headers['x-gps-protocol']
    };
}

// Generate cache key
function generateCacheKey(req) {
    return `${req.method}:${req.url}:${req.headers['content-type'] || ''}`;
}

// Detect GPS protocol from data
function detectGPSProtocol(buffer) {
    if (!buffer || buffer.length === 0) return 'UNKNOWN';
    
    // Check hex patterns
    const hexStart = buffer.toString('hex', 0, Math.min(10, buffer.length));
    
    // GT06 protocol starts with 7878 or 7979
    if (hexStart.startsWith('7878') || hexStart.startsWith('7979')) {
        return 'GT06';
    }
    
    // Check ASCII for other protocols
    const asciiStart = buffer.toString('ascii', 0, Math.min(50, buffer.length));
    
    // TK103 often contains "imei" or "##"
    if (asciiStart.includes('imei') || asciiStart.includes('##') || asciiStart.includes('IMSI')) {
        return 'TK103';
    }
    
    // NMEA sentences
    if (asciiStart.includes('GPRMC') || asciiStart.includes('GPGGA')) {
        return 'NMEA';
    }
    
    // GSM AT commands
    if (asciiStart.includes('AT+') || asciiStart.includes('AT')) {
        return 'GSM_AT';
    }
    
    return 'UNKNOWN';
}

// Forward request to target server
async function forwardRequest(req, res, targetUrl, bodyBuffer = null) {
    const startTime = Date.now();
    const requestInfo = parseGPSRequest(req);
    
    // Log incoming request
    if (CONFIG.LOG_REQUESTS) {
        log(`← INCOMING: ${requestInfo.method} ${requestInfo.url} from ${requestInfo.ip} (${requestInfo.userAgent})`);
    }
    
    // Check IP restrictions
    if (!isIPAllowed(requestInfo.ip)) {
        res.writeHead(403, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Access denied' }));
        return;
    }
    
    // Check cache for GET requests
    if (req.method === 'GET' && CONFIG.ENABLE_CACHE) {
        const cacheKey = generateCacheKey(req);
        const cached = requestCache.get(cacheKey);
        
        if (cached && (Date.now() - cached.timestamp) < CONFIG.CACHE_DURATION) {
            if (CONFIG.LOG_REQUESTS) {
                log(`✓ CACHE HIT: ${req.url}`, 'CACHE');
            }
            cacheHits++;
            res.writeHead(cached.status, cached.headers);
            res.end(cached.body);
            return;
        }
        cacheMisses++;
    }
    
    // Collect request body if not provided
    let buffer = bodyBuffer;
    if (!buffer) {
        let requestBody = [];
        let bodySize = 0;
        
        req.on('data', (chunk) => {
            bodySize += chunk.length;
            
            // Prevent oversized requests
            if (bodySize > CONFIG.MAX_BODY_SIZE) {
                log(`Request too large: ${bodySize} bytes from ${requestInfo.ip}`, 'ERROR');
                res.writeHead(413, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ error: 'Request too large' }));
                req.destroy();
                return;
            }
            
            requestBody.push(chunk);
        });
        
        req.on('end', () => {
            buffer = Buffer.concat(requestBody);
            continueForwarding();
        });
    } else {
        continueForwarding();
    }
    
    function continueForwarding() {
        // Prepare forward request options
        const parsedTarget = new URL(targetUrl);
        const isHttps = parsedTarget.protocol === 'https:';
        const protocolModule = isHttps ? https : http;
        
        const options = {
            hostname: parsedTarget.hostname,
            port: parsedTarget.port || (isHttps ? 443 : 80),
            path: parsedTarget.pathname + (parsedTarget.search || ''),
            method: req.method,
            headers: {
                ...req.headers,
                'host': parsedTarget.hostname,
                'x-forwarded-for': requestInfo.ip,
                'x-forwarded-proto': isHttps ? 'https' : 'http',
                'x-proxy-timestamp': new Date().toISOString(),
                'x-gps-protocol': detectGPSProtocol(buffer)
            },
            timeout: CONFIG.REQUEST_TIMEOUT
        };
        
        // Detect and log GPS data
        const contentType = req.headers['content-type'] || '';
        const isGPSDevice = contentType.includes('application/octet-stream') ||
                           contentType.includes('text/plain') ||
                           req.method === 'POST' ||
                           req.url === '/' ||
                           req.headers['user-agent']?.includes('GPS') ||
                           detectGPSProtocol(buffer) !== 'UNKNOWN';
        
        if (isGPSDevice) {
            gpsRequestCount++;
            const protocol = detectGPSProtocol(buffer);
            log(`📡 GPS DEVICE: ${requestInfo.ip} → ${buffer?.length || 0} bytes (Protocol: ${protocol})`, 'GPS');
            
            // Log first 100 chars of GPS data (for debugging)
            if (buffer && buffer.length > 0) {
                const preview = buffer.toString('hex', 0, Math.min(100, buffer.length));
                log(`GPS Data (hex preview): ${preview}...`, 'GPS-DATA');
            }
        }
        
        // Make the forward request
        const forwardReq = protocolModule.request(options, (forwardRes) => {
            const responseTime = Date.now() - startTime;
            const responseInfo = {
                status: forwardRes.statusCode,
                headers: forwardRes.headers,
                body: []
            };
            
            // Log response
            if (CONFIG.LOG_REQUESTS) {
                log(`→ RESPONSE: ${req.url} → ${forwardRes.statusCode} (${responseTime}ms)`, 'INFO');
            }
            
            // Set response headers
            const responseHeaders = {
                ...forwardRes.headers,
                'x-proxy-server': 'GPS-Proxy/1.0',
                'x-response-time': `${responseTime}ms`,
                'x-cache-status': 'MISS',
                'x-gps-detected': isGPSDevice ? 'true' : 'false'
            };
            
            res.writeHead(forwardRes.statusCode, responseHeaders);
            
            // Handle response data
            forwardRes.on('data', (chunk) => {
                responseInfo.body.push(chunk);
                res.write(chunk);
            });
            
            forwardRes.on('end', () => {
                responseInfo.body = Buffer.concat(responseInfo.body);
                res.end();
                
                // Cache successful GET responses
                if (req.method === 'GET' && 
                    CONFIG.ENABLE_CACHE && 
                    forwardRes.statusCode === 200) {
                    const cacheKey = generateCacheKey(req);
                    requestCache.set(cacheKey, {
                        status: forwardRes.statusCode,
                        headers: forwardRes.headers,
                        body: responseInfo.body,
                        timestamp: Date.now()
                    });
                    
                    // Clean old cache entries periodically
                    if (requestCache.size > 1000) {
                        const oldestKey = requestCache.keys().next().value;
                        requestCache.delete(oldestKey);
                    }
                }
                
                // Log completion
                log(`✓ COMPLETED: ${req.method} ${req.url} → ${forwardRes.statusCode} (${responseTime}ms)`, 'SUCCESS');
            });
        });
        
        // Handle forward request errors
        forwardReq.on('error', (error) => {
            const responseTime = Date.now() - startTime;
            log(`✗ FORWARD ERROR: ${error.message} for ${req.url} (${responseTime}ms)`, 'ERROR');
            
            res.writeHead(502, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ 
                error: 'Bad Gateway', 
                message: 'Cannot connect to target server',
                timestamp: new Date().toISOString()
            }));
        });
        
        forwardReq.on('timeout', () => {
            log(`⏰ TIMEOUT: Request to ${req.url} timed out`, 'ERROR');
            forwardReq.destroy();
            
            res.writeHead(504, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ 
                error: 'Gateway Timeout', 
                message: 'Target server did not respond in time'
            }));
        });
        
        // Send request body if present
        if (buffer && buffer.length > 0) {
            forwardReq.write(buffer);
        }
        
        forwardReq.end();
    }
    
    // Handle request errors
    req.on('error', (error) => {
        log(`✗ REQUEST ERROR: ${error.message} from ${requestInfo.ip}`, 'ERROR');
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Bad Request' }));
    });
}

// Health check endpoint
function handleHealthCheck(req, res) {
    const health = {
        status: 'healthy',
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        memory: process.memoryUsage(),
        config: {
            target: CONFIG.TARGET_SERVER,
            port: CONFIG.PORT,
            cacheEnabled: CONFIG.ENABLE_CACHE,
            cacheSize: requestCache.size
        },
        stats: {
            totalRequests: requestCount,
            gpsRequests: gpsRequestCount,
            cacheHits: cacheHits,
            cacheMisses: cacheMisses
        }
    };
    
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(health, null, 2));
}

// Stats endpoint
function handleStats(req, res) {
    const stats = {
        requests: {
            total: requestCount,
            gps: gpsRequestCount
        },
        cache: {
            size: requestCache.size,
            hits: cacheHits,
            misses: cacheMisses
        },
        uptime: process.uptime()
    };
    
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(stats, null, 2));
}

// Create HTTP server with GPS detection
const server = http.createServer((req, res) => {
    requestCount++;
    
    // Handle special endpoints FIRST
    if (req.url === '/health' && req.method === 'GET') {
        return handleHealthCheck(req, res);
    }
    
    if (req.url === '/stats' && req.method === 'GET') {
        return handleStats(req, res);
    }
    
    if (req.url === '/clear-cache' && req.method === 'POST') {
        requestCache.clear();
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ message: 'Cache cleared' }));
        return;
    }
    
    // Collect request body to detect GPS data
    let bodyChunks = [];
    let bodySize = 0;
    let isGPSRequest = false;
    let gpsProtocol = 'UNKNOWN';
    
    req.on('data', (chunk) => {
        bodySize += chunk.length;
        
        // Prevent oversized requests
        if (bodySize > CONFIG.MAX_BODY_SIZE) {
            log(`Request too large: ${bodySize} bytes`, 'ERROR');
            res.writeHead(413, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Request too large' }));
            req.destroy();
            return;
        }
        
        bodyChunks.push(chunk);
        
        // Check first chunk for GPS patterns
        if (bodyChunks.length === 1) {
            const buffer = Buffer.concat(bodyChunks);
            gpsProtocol = detectGPSProtocol(buffer);
            
            const contentType = req.headers['content-type'] || '';
            const userAgent = req.headers['user-agent'] || '';
            
            // Detect GPS request
            isGPSRequest = 
                gpsProtocol !== 'UNKNOWN' ||
                contentType.includes('application/octet-stream') ||
                contentType.includes('text/plain') ||
                req.method === 'POST' ||
                userAgent.includes('GPS') ||
                userAgent.includes('Tracker') ||
                userAgent.includes('GT') ||
                req.url === '/' ||
                req.url === '' ||
                req.headers['x-gps-protocol'];
            
            if (isGPSRequest) {
                log(`📡 GPS Device detected! Protocol: ${gpsProtocol}`, 'GPS');
            }
        }
    });
    
    req.on('end', () => {
        const bodyBuffer = bodyChunks.length > 0 ? Buffer.concat(bodyChunks) : Buffer.alloc(0);
        
        // Determine target URL
        let targetUrl = CONFIG.TARGET_SERVER + req.url;
        
        // If GPS request, redirect to /api/gps
        if (isGPSRequest) {
            targetUrl = CONFIG.TARGET_SERVER + '/api/gps';
            log(`🎯 Redirecting GPS data to: ${targetUrl}`, 'GPS');
            log(`   Data size: ${bodyBuffer.length} bytes, Protocol: ${gpsProtocol}`, 'GPS-DATA');
            
            // Log GPS data sample for debugging
            if (bodyBuffer.length > 0) {
                const sample = bodyBuffer.toString('hex', 0, Math.min(100, bodyBuffer.length));
                log(`   Data sample (hex): ${sample}${bodyBuffer.length > 100 ? '...' : ''}`, 'GPS-DATA');
            }
        }
        
        // Forward the request with collected body
        forwardRequest(req, res, targetUrl, bodyBuffer);
    });
    
    // Handle request errors
    req.on('error', (error) => {
        log(`✗ REQUEST ERROR: ${error.message}`, 'ERROR');
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Bad Request' }));
    });
});

// Graceful shutdown
function gracefulShutdown() {
    log('Shutting down gracefully...', 'INFO');
    
    server.close(() => {
        log('Server closed', 'INFO');
        process.exit(0);
    });
    
    // Force shutdown after 10 seconds
    setTimeout(() => {
        log('Forcing shutdown', 'WARN');
        process.exit(1);
    }, 10000);
}

// Start server
server.listen(CONFIG.PORT, '0.0.0.0', () => {
    log(`✅ GPS Proxy Server started on port ${CONFIG.PORT}`, 'STARTUP');
    log(`🎯 Forwarding to: ${CONFIG.TARGET_SERVER}`, 'STARTUP');
    log(`📡 Ready for GPS devices!`, 'STARTUP');
    
    // Display connection info
    console.log('\n=== GPS PROXY CONFIGURATION ===');
    console.log(`Local URL: http://localhost:${CONFIG.PORT}`);
    console.log(`External URL: https://gps-proxy-server.onrender.com`);
    console.log(`Target: ${CONFIG.TARGET_SERVER}`);
    console.log(`Health Check: https://gps-proxy-server.onrender.com/health`);
    console.log(`Stats: https://gps-proxy-server.onrender.com/stats`);
    console.log(`GPS Devices: Configure with IP: 216.24.57.251 Port: 443`);
    console.log('==============================\n');
});

// Handle shutdown signals
process.on('SIGTERM', gracefulShutdown);
process.on('SIGINT', gracefulShutdown);

// Handle uncaught errors
process.on('uncaughtException', (error) => {
    log(`🔥 UNCAUGHT EXCEPTION: ${error.message}`, 'CRITICAL');
    log(error.stack, 'CRITICAL');
});

process.on('unhandledRejection', (reason, promise) => {
    log(`🔥 UNHANDLED REJECTION: ${reason}`, 'CRITICAL');
});
