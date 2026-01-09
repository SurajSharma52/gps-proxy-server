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

// Forward request to target server
async function forwardRequest(req, res, targetUrl) {
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
            res.writeHead(cached.status, cached.headers);
            res.end(cached.body);
            return;
        }
    }
    
    // Collect request body for POST/PUT
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
        const buffer = Buffer.concat(requestBody);
        
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
                'x-proxy-timestamp': new Date().toISOString()
            },
            timeout: CONFIG.REQUEST_TIMEOUT
        };
        
        // Log GPS-specific requests
        if (requestInfo.isGPSDevice) {
            log(`📡 GPS DEVICE: ${requestInfo.ip} → ${buffer.length} bytes`, 'GPS');
            
            // Log first 100 chars of GPS data (for debugging)
            if (buffer.length > 0) {
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
                'x-cache-status': 'MISS'
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
        if (buffer.length > 0) {
            forwardReq.write(buffer);
        }
        
        forwardReq.end();
    });
    
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

// Counters
let requestCount = 0;
let gpsRequestCount = 0;
let cacheHits = 0;
let cacheMisses = 0;

// Create HTTP server
const server = http.createServer((req, res) => {
    requestCount++;
    
    // Handle special endpoints
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
    
    // Forward all other requests
    forwardRequest(req, res, CONFIG.TARGET_SERVER + req.url);
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
    console.log(`Target: ${CONFIG.TARGET_SERVER}`);
    console.log(`Health Check: http://localhost:${CONFIG.PORT}/health`);
    console.log(`Stats: http://localhost:${CONFIG.PORT}/stats`);
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
