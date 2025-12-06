#!/bin/bash

# Setup script for the vulnerable RSC test application
# This script installs dependencies and optionally starts the server

set -e

echo "========================================"
echo "Vulnerable RSC Test App Setup"
echo "========================================"
echo ""
echo "WARNING: This application contains intentionally vulnerable code."
echo "DO NOT deploy to production or expose to the internet."
echo ""

# Check Node.js version
NODE_VERSION=$(node -v 2>/dev/null || echo "not installed")
if [[ "$NODE_VERSION" == "not installed" ]]; then
    echo "Error: Node.js is not installed"
    echo "Please install Node.js 18.0.0 or higher"
    exit 1
fi

echo "Node.js version: $NODE_VERSION"

# Check if correct directory
if [ ! -f "package.json" ]; then
    echo "Error: package.json not found"
    echo "Please run this script from the test-vulnerable-app directory"
    exit 1
fi

# Install dependencies
echo ""
echo "Installing dependencies..."
npm install

echo ""
echo "========================================"
echo "Setup Complete!"
echo "========================================"
echo ""
echo "To start the vulnerable test app:"
echo "  npm run dev"
echo ""
echo "To test with the scanner:"
echo "  cd .."
echo "  python ore_rsc_vulnerability_scanner.py localhost:3000 --deep"
echo ""
echo "Or run the test suite:"
echo "  ./test-scanner.sh"
echo ""
echo "Available React versions for testing:"
echo "  npm run dev         # React 19.0.0 (default, vulnerable)"
echo "  npm run dev:19.0.0  # React 19.0.0 (vulnerable)"
echo "  npm run dev:19.1.0  # React 19.1.0 (vulnerable)"
echo "  npm run dev:19.1.1  # React 19.1.1 (vulnerable)"
echo "  npm run dev:19.2.0  # React 19.2.0 (vulnerable)"
echo ""
