#!/bin/bash

# GPS Proxy Server Startup Script
echo "Starting GPS Proxy Server..."

# Load environment variables
if [ -f .env ]; then
    export $(cat .env | grep -v '^#' | xargs)
    echo "✓ Loaded environment variables"
else
    echo "⚠️ No .env file found, using defaults"
fi

# Check if target server is reachable
echo "Checking target server: $TARGET_SERVER"
if curl -s --head "$TARGET_SERVER" | grep "200 OK" > /dev/null; then
    echo "✓ Target server is reachable"
else
    echo "⚠️ Warning: Cannot reach target server"
fi

# Create logs directory
mkdir -p logs

# Start the server
echo "Starting proxy on port ${PORT:-3000}..."
node proxy.js 2>&1 | tee -a logs/proxy-$(date +%Y%m%d).log
