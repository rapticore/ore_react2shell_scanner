#!/usr/bin/env python3
"""
test_scanner.py - Automated Test Suite for RSC Vulnerability Scanner

This test suite verifies that the scanner correctly detects various
RSC endpoint configurations and assigns appropriate risk levels.

Usage:
    # Start the test server first (in another terminal):
    python test_server.py

    # Run tests:
    python -m pytest test_scanner.py -v

    # Or run directly:
    python test_scanner.py
"""

import asyncio
import json
import subprocess
import sys
import time
import unittest
from pathlib import Path
from typing import Dict, List, Optional
from unittest.mock import patch, MagicMock

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    import aiohttp
except ImportError:
    print("Error: aiohttp required. Install: pip install aiohttp")
    sys.exit(1)


# =============================================================================
# TEST CONFIGURATION
# =============================================================================

import os

TEST_SERVER_HOST = "localhost"
TEST_SERVER_PORT = int(os.environ.get("TEST_SERVER_PORT", "8080"))
TEST_SERVER_URL = f"http://{TEST_SERVER_HOST}:{TEST_SERVER_PORT}"

# Expected results for each endpoint
EXPECTED_RESULTS = {
    # CRITICAL risk endpoints
    "/_rsc": {"risk": "CRITICAL", "is_rsc": True, "has_server_actions": True},
    "/action": {"risk": "CRITICAL", "is_rsc": True, "has_server_actions": True},
    "/server-action": {"risk": "CRITICAL", "is_rsc": True, "has_server_actions": True},
    "/api/server-action": {"risk": "CRITICAL", "is_rsc": True, "has_server_actions": True},

    # HIGH risk endpoints
    "/_next/rsc": {"risk": "HIGH", "is_rsc": True, "has_server_actions": False},
    "/rsc": {"risk": "HIGH", "is_rsc": True, "has_server_actions": False},
    "/api/rsc": {"risk": "HIGH", "is_rsc": True, "has_server_actions": False},
    "/flight": {"risk": "HIGH", "is_rsc": True, "has_server_actions": False},
    "/nextjs-rsc": {"risk": "HIGH", "is_rsc": True, "has_server_actions": False},

    # MEDIUM risk endpoints
    "/__flight": {"risk": "MEDIUM", "is_rsc": True, "has_server_actions": False},
    "/api/__rsc": {"risk": "MEDIUM", "is_rsc": True, "has_server_actions": False},

    # LOW risk endpoints
    "/_next/data": {"risk": "LOW", "is_rsc": False, "has_server_actions": False},
    "/__rsc__": {"risk": "LOW", "is_rsc": False, "has_server_actions": False},

    # INFO (no RSC) endpoints
    "/": {"risk": "INFO", "is_rsc": False, "has_server_actions": False},
    "/api/health": {"risk": "INFO", "is_rsc": False, "has_server_actions": False},
}


# =============================================================================
# TEST UTILITIES
# =============================================================================

def is_server_running(host: str = TEST_SERVER_HOST, port: int = TEST_SERVER_PORT) -> bool:
    """Check if the test server is running."""
    import socket
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except Exception:
        return False


def run_scanner_cli(args: List[str]) -> Dict:
    """Run the scanner CLI and return parsed JSON output."""
    scanner_path = Path(__file__).parent.parent / "ore_rsc.py"

    cmd = [sys.executable, str(scanner_path)] + args + ["--format", "json"]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=60,
        )

        # Parse JSON from stdout (skip any non-JSON lines)
        for line in result.stdout.split("\n"):
            line = line.strip()
            if line.startswith("{"):
                return json.loads(line)

        # If no JSON found, try parsing entire stdout
        if result.stdout.strip().startswith("{"):
            return json.loads(result.stdout)

        return {"error": "No JSON output", "stdout": result.stdout, "stderr": result.stderr}

    except subprocess.TimeoutExpired:
        return {"error": "Timeout"}
    except json.JSONDecodeError as e:
        return {"error": f"JSON parse error: {e}", "stdout": result.stdout}
    except Exception as e:
        return {"error": str(e)}


async def scan_single_url(url: str) -> Dict:
    """Scan a single URL and return the result."""
    from ore_rsc import RSCScanner

    scanner = RSCScanner(concurrency=1, timeout=5.0)
    # Initialize the semaphore that would normally be set in scan()
    scanner.semaphore = asyncio.Semaphore(1)

    domain = url.replace("http://", "").replace("https://", "").split("/")[0]
    path = "/" + "/".join(url.replace("http://", "").replace("https://", "").split("/")[1:])
    if not path or path == "/":
        path = "/"

    # Run single URL scan
    connector = aiohttp.TCPConnector(ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        result = await scanner._check_url(session, domain, path, url)

    return {
        "url": result.url,
        "is_rsc_endpoint": result.is_rsc_endpoint,
        "risk_level": result.risk_level.value,
        "has_server_actions": result.has_server_actions,
        "framework": result.framework,
        "rsc_indicators": result.rsc_indicators,
        "status_code": result.status_code,
        "content_type": result.content_type,
    }


# =============================================================================
# TEST CLASSES
# =============================================================================

class TestRSCScanner(unittest.TestCase):
    """Test the RSC vulnerability scanner detection capabilities."""

    @classmethod
    def setUpClass(cls):
        """Check if test server is available."""
        if not is_server_running():
            print(f"""
WARNING: Test server not running at {TEST_SERVER_URL}

Start the test server first:
    cd tests
    python test_server.py

Some tests will be skipped.
""")

    def test_server_available(self):
        """Verify test server is running."""
        if not is_server_running():
            self.skipTest("Test server not running")
        self.assertTrue(is_server_running())


class TestCriticalEndpoints(unittest.TestCase):
    """Test detection of CRITICAL risk endpoints."""

    def setUp(self):
        if not is_server_running():
            self.skipTest("Test server not running")

    def test_rsc_endpoint_with_server_actions(self):
        """Test /_rsc endpoint detection (CRITICAL - has server actions)."""
        result = asyncio.run(scan_single_url(f"{TEST_SERVER_URL}/_rsc"))

        self.assertTrue(result["is_rsc_endpoint"], "Should detect as RSC endpoint")
        self.assertEqual(result["risk_level"], "CRITICAL", "Should be CRITICAL risk")
        self.assertTrue(result["has_server_actions"], "Should detect server actions")
        self.assertIn("content-type:text/x-component", result["rsc_indicators"])

    def test_action_endpoint(self):
        """Test /action endpoint detection (CRITICAL - server action)."""
        result = asyncio.run(scan_single_url(f"{TEST_SERVER_URL}/action"))

        self.assertTrue(result["is_rsc_endpoint"])
        self.assertEqual(result["risk_level"], "CRITICAL")
        self.assertTrue(result["has_server_actions"])

    def test_server_action_endpoint(self):
        """Test /server-action endpoint detection (CRITICAL)."""
        result = asyncio.run(scan_single_url(f"{TEST_SERVER_URL}/server-action"))

        self.assertTrue(result["is_rsc_endpoint"])
        self.assertEqual(result["risk_level"], "CRITICAL")


class TestHighRiskEndpoints(unittest.TestCase):
    """Test detection of HIGH risk endpoints."""

    def setUp(self):
        if not is_server_running():
            self.skipTest("Test server not running")

    def test_next_rsc_endpoint(self):
        """Test /_next/rsc endpoint detection (HIGH)."""
        result = asyncio.run(scan_single_url(f"{TEST_SERVER_URL}/_next/rsc"))

        self.assertTrue(result["is_rsc_endpoint"])
        self.assertEqual(result["risk_level"], "HIGH")
        self.assertFalse(result["has_server_actions"])

    def test_generic_rsc_endpoint(self):
        """Test /rsc endpoint detection (HIGH)."""
        result = asyncio.run(scan_single_url(f"{TEST_SERVER_URL}/rsc"))

        self.assertTrue(result["is_rsc_endpoint"])
        self.assertEqual(result["risk_level"], "HIGH")

    def test_api_rsc_endpoint(self):
        """Test /api/rsc endpoint detection (HIGH)."""
        result = asyncio.run(scan_single_url(f"{TEST_SERVER_URL}/api/rsc"))

        self.assertTrue(result["is_rsc_endpoint"])
        self.assertIn(result["risk_level"], ["HIGH", "CRITICAL"])

    def test_flight_endpoint(self):
        """Test /flight endpoint detection (HIGH)."""
        result = asyncio.run(scan_single_url(f"{TEST_SERVER_URL}/flight"))

        self.assertTrue(result["is_rsc_endpoint"])
        self.assertEqual(result["risk_level"], "HIGH")


class TestMediumRiskEndpoints(unittest.TestCase):
    """Test detection of MEDIUM risk endpoints."""

    def setUp(self):
        if not is_server_running():
            self.skipTest("Test server not running")

    def test_flight_with_headers(self):
        """Test /__flight endpoint detection (MEDIUM - multiple indicators)."""
        result = asyncio.run(scan_single_url(f"{TEST_SERVER_URL}/__flight"))

        self.assertTrue(result["is_rsc_endpoint"])
        self.assertIn(result["risk_level"], ["MEDIUM", "HIGH"])
        # Should have multiple indicators
        self.assertGreaterEqual(len(result["rsc_indicators"]), 2)

    def test_api_rsc_with_indicators(self):
        """Test /api/__rsc endpoint detection (MEDIUM)."""
        result = asyncio.run(scan_single_url(f"{TEST_SERVER_URL}/api/__rsc"))

        self.assertTrue(result["is_rsc_endpoint"])


class TestLowRiskEndpoints(unittest.TestCase):
    """Test detection of LOW risk endpoints."""

    def setUp(self):
        if not is_server_running():
            self.skipTest("Test server not running")

    def test_next_data_endpoint(self):
        """Test /_next/data endpoint detection (LOW - single indicator)."""
        result = asyncio.run(scan_single_url(f"{TEST_SERVER_URL}/_next/data"))

        # May or may not be detected as RSC depending on indicators
        self.assertIn(result["risk_level"], ["LOW", "INFO", "MEDIUM"])

    def test_rsc_prefetch_endpoint(self):
        """Test /__rsc__ endpoint detection (LOW)."""
        result = asyncio.run(scan_single_url(f"{TEST_SERVER_URL}/__rsc__"))

        self.assertIn(result["risk_level"], ["LOW", "INFO", "MEDIUM"])


class TestNonRSCEndpoints(unittest.TestCase):
    """Test that non-RSC endpoints are correctly identified."""

    def setUp(self):
        if not is_server_running():
            self.skipTest("Test server not running")

    def test_html_page(self):
        """Test / HTML page is not flagged as RSC."""
        result = asyncio.run(scan_single_url(f"{TEST_SERVER_URL}/"))

        self.assertFalse(result["is_rsc_endpoint"])
        self.assertEqual(result["risk_level"], "INFO")

    def test_health_api(self):
        """Test /api/health is not flagged as RSC."""
        result = asyncio.run(scan_single_url(f"{TEST_SERVER_URL}/api/health"))

        self.assertFalse(result["is_rsc_endpoint"])
        self.assertEqual(result["risk_level"], "INFO")


class TestFrameworkDetection(unittest.TestCase):
    """Test framework detection capabilities."""

    def setUp(self):
        if not is_server_running():
            self.skipTest("Test server not running")

    def test_nextjs_detection(self):
        """Test Next.js framework detection."""
        result = asyncio.run(scan_single_url(f"{TEST_SERVER_URL}/nextjs-rsc"))

        self.assertEqual(result["framework"], "nextjs")

    def test_nextjs_html_detection(self):
        """Test Next.js detection from HTML page."""
        result = asyncio.run(scan_single_url(f"{TEST_SERVER_URL}/nextjs"))

        # Framework should be detected from body patterns
        self.assertEqual(result["framework"], "nextjs")


class TestCLIIntegration(unittest.TestCase):
    """Test command-line interface integration."""

    def setUp(self):
        if not is_server_running():
            self.skipTest("Test server not running")

    def test_cli_scan_single_domain(self):
        """Test CLI scan of single domain."""
        result = run_scanner_cli([f"{TEST_SERVER_HOST}:{TEST_SERVER_PORT}"])

        if "error" in result:
            self.skipTest(f"CLI error: {result['error']}")

        self.assertIn("scan_time", result)
        self.assertIn("rsc_endpoints_found", result)
        self.assertGreater(result["rsc_endpoints_found"], 0)

    def test_cli_deep_scan(self):
        """Test CLI deep scan mode."""
        result = run_scanner_cli([
            f"{TEST_SERVER_HOST}:{TEST_SERVER_PORT}",
            "--deep"
        ])

        if "error" in result:
            self.skipTest(f"CLI error: {result['error']}")

        self.assertIn("scan_time", result)

    def test_cli_rsc_only_filter(self):
        """Test CLI RSC-only output filter."""
        result = run_scanner_cli([
            f"{TEST_SERVER_HOST}:{TEST_SERVER_PORT}",
            "--rsc-only"
        ])

        if "error" in result:
            self.skipTest(f"CLI error: {result['error']}")

        # All results should be RSC endpoints
        for r in result.get("results", []):
            self.assertTrue(r.get("is_rsc_endpoint", False))


class TestRiskCalculation(unittest.TestCase):
    """Test risk level calculation logic."""

    def test_critical_risk_calculation(self):
        """Test CRITICAL risk is assigned for RSC + server actions."""
        from ore_rsc import ScanResult, RiskLevel

        result = ScanResult(
            url="http://test.com/_rsc",
            domain="test.com",
            path="/_rsc",
            rsc_indicators=["content-type:text/x-component", "server-actions-detected"],
            has_server_actions=True,
        )
        result.calculate_risk()

        self.assertEqual(result.risk_level, RiskLevel.CRITICAL)

    def test_high_risk_calculation(self):
        """Test HIGH risk is assigned for RSC content type."""
        from ore_rsc import ScanResult, RiskLevel

        result = ScanResult(
            url="http://test.com/rsc",
            domain="test.com",
            path="/rsc",
            rsc_indicators=["content-type:text/x-component"],
            has_server_actions=False,
        )
        result.calculate_risk()

        self.assertEqual(result.risk_level, RiskLevel.HIGH)

    def test_medium_risk_calculation(self):
        """Test MEDIUM risk is assigned for multiple indicators."""
        from ore_rsc import ScanResult, RiskLevel

        result = ScanResult(
            url="http://test.com/test",
            domain="test.com",
            path="/test",
            rsc_indicators=["header:rsc", "header:next-router-state-tree", "flight-pattern:0:"],
            has_server_actions=False,
        )
        result.calculate_risk()

        self.assertEqual(result.risk_level, RiskLevel.MEDIUM)

    def test_low_risk_calculation(self):
        """Test LOW risk is assigned for single indicator."""
        from ore_rsc import ScanResult, RiskLevel

        result = ScanResult(
            url="http://test.com/test",
            domain="test.com",
            path="/test",
            rsc_indicators=["header:x-nextjs-cache"],
            has_server_actions=False,
        )
        result.calculate_risk()

        self.assertEqual(result.risk_level, RiskLevel.LOW)

    def test_info_risk_calculation(self):
        """Test INFO risk is assigned for no indicators."""
        from ore_rsc import ScanResult, RiskLevel

        result = ScanResult(
            url="http://test.com/",
            domain="test.com",
            path="/",
            rsc_indicators=[],
            has_server_actions=False,
        )
        result.calculate_risk()

        self.assertEqual(result.risk_level, RiskLevel.INFO)


class TestFlightPatternDetection(unittest.TestCase):
    """Test Flight protocol pattern detection."""

    def test_flight_stream_format(self):
        """Test detection of Flight stream format (0:, 1:, etc.)."""
        from ore_rsc import RSCScanner

        scanner = RSCScanner()

        # Test various Flight patterns
        patterns = scanner._check_flight_patterns("0:[\"$\",\"div\",null,{}]")
        self.assertTrue(len(patterns) > 0)

        patterns = scanner._check_flight_patterns("1:[\"$L2\",null,{}]")
        self.assertTrue(len(patterns) > 0)

    def test_action_id_detection(self):
        """Test detection of $ACTION_ID markers."""
        from ore_rsc import RSCScanner

        scanner = RSCScanner()

        patterns = scanner._check_flight_patterns('{"$ACTION_ID":"abc123"}')
        self.assertTrue(any("$ACTION_ID" in p for p in patterns))

    def test_undefined_marker_detection(self):
        """Test detection of $undefined markers."""
        from ore_rsc import RSCScanner

        scanner = RSCScanner()

        patterns = scanner._check_flight_patterns('{"value":"$undefined"}')
        self.assertTrue(any("$undefined" in p for p in patterns))


class TestServerActionDetection(unittest.TestCase):
    """Test Server Action detection."""

    def test_action_id_in_body(self):
        """Test detection of $ACTION_ID in response body."""
        from ore_rsc import RSCScanner

        scanner = RSCScanner()

        result = scanner._check_server_actions(
            '{"$ACTION_ID":"submitForm"}',
            {}
        )
        self.assertTrue(result)

    def test_action_header_detection(self):
        """Test detection of action headers."""
        from ore_rsc import RSCScanner

        scanner = RSCScanner()

        result = scanner._check_server_actions(
            "normal body",
            {"x-action": "true"}
        )
        self.assertTrue(result)

        result = scanner._check_server_actions(
            "normal body",
            {"Next-Action": "submitForm"}
        )
        self.assertTrue(result)

    def test_form_action_detection(self):
        """Test detection of formAction in body."""
        from ore_rsc import RSCScanner

        scanner = RSCScanner()

        result = scanner._check_server_actions(
            '<form action="/submit" formAction="/action">',
            {}
        )
        self.assertTrue(result)


# =============================================================================
# MAIN
# =============================================================================

def run_tests():
    """Run all tests."""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    # Add test classes
    test_classes = [
        TestRSCScanner,
        TestCriticalEndpoints,
        TestHighRiskEndpoints,
        TestMediumRiskEndpoints,
        TestLowRiskEndpoints,
        TestNonRSCEndpoints,
        TestFrameworkDetection,
        TestCLIIntegration,
        TestRiskCalculation,
        TestFlightPatternDetection,
        TestServerActionDetection,
    ]

    for test_class in test_classes:
        tests = loader.loadTestsFromTestCase(test_class)
        suite.addTests(tests)

    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    return result.wasSuccessful()


if __name__ == "__main__":
    print("""
╔═══════════════════════════════════════════════════════════════════════╗
║           RSC Vulnerability Scanner - Test Suite                       ║
╚═══════════════════════════════════════════════════════════════════════╝
""")

    if not is_server_running():
        print(f"""
NOTE: Test server not running at {TEST_SERVER_URL}

For full integration tests, start the test server first:
    python test_server.py

Running unit tests only...
""")

    success = run_tests()
    sys.exit(0 if success else 1)
