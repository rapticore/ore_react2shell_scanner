#!/bin/bash

# Test script for ore_rsc_vulnerability_scanner.py against the vulnerable test app
# Usage: ./test-scanner.sh [port]

PORT=${1:-3000}
HOST="http://localhost:$PORT"

echo "========================================"
echo "RSC Vulnerability Scanner Test Suite"
echo "========================================"
echo "Target: $HOST"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if the test app is running
echo "Checking if test app is running..."
if ! curl -s "http://$HOST" > /dev/null 2>&1; then
    echo -e "${RED}Error: Test app is not running on $HOST${NC}"
    echo "Please start the app with: npm run dev"
    exit 1
fi
echo -e "${GREEN}Test app is running!${NC}"
echo ""

# Navigate to scanner directory
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SCANNER_DIR="$(dirname "$SCRIPT_DIR")"

cd "$SCANNER_DIR" || exit 1

echo "Running scanner tests..."
echo ""

# Test 1: Basic scan
echo "========================================"
echo "Test 1: Basic Scan"
echo "========================================"
python ore_rsc_vulnerability_scanner.py "$HOST"
echo ""

# Test 2: Deep scan
echo "========================================"
echo "Test 2: Deep Scan (--deep)"
echo "========================================"
python ore_rsc_vulnerability_scanner.py "$HOST" --deep --rsc-only
echo ""

# Test 3: JSON output
echo "========================================"
echo "Test 3: JSON Output"
echo "========================================"
python ore_rsc_vulnerability_scanner.py "$HOST" --format json -o test_results.json
echo "Results saved to test_results.json"
echo ""

# Test 4: CSV output
echo "========================================"
echo "Test 4: CSV Output"
echo "========================================"
python ore_rsc_vulnerability_scanner.py "$HOST" --format csv -o test_results.csv
echo "Results saved to test_results.csv"
echo ""

# Test 5: Specific paths
echo "========================================"
echo "Test 5: Specific Paths"
echo "========================================"
python ore_rsc_vulnerability_scanner.py "$HOST" --paths "/,/admin,/dashboard,/forms,/api/rsc,/action"
echo ""

# Test 6: All endpoints with high concurrency
echo "========================================"
echo "Test 6: High Concurrency Scan"
echo "========================================"
python ore_rsc_vulnerability_scanner.py "$HOST" --deep -c 50
echo ""

# Summary
echo "========================================"
echo "Test Complete!"
echo "========================================"
echo ""
echo "Check the following files for detailed results:"
echo "  - test_results.json"
echo "  - test_results.csv"
echo ""
echo "Expected detections:"
echo "  - CRITICAL: /api/rsc, /action"
echo "  - HIGH: /, /admin, /dashboard, /forms"
echo "  - MEDIUM: /stream, /api/products"
echo "  - LOW: /api/users"
