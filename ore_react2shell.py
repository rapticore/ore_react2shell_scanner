#!/usr/bin/env python3
"""
ore_react2shell.py - React2Shell Vulnerability Assessment Suite

Developed by: Rapticore Security Research Team

A comprehensive security assessment tool for CVE-2025-55182 (React2Shell):
  1. Enumerates subdomains using subfinder (or accepts pre-generated lists)
  2. Probes live hosts and identifies Next.js/RSC-powered applications
  3. Tests for React2Shell vulnerability indicators
  4. Optionally verifies exploitability with active checks
  5. Detects Server Actions and Flight protocol patterns
  6. Generates executive reports with prioritized remediation guidance

Uses ore_rsc.py as the core scanning engine.

Acknowledgments:
  - Assetnote: Original CVE-2025-55182 (React2Shell) vulnerability research
  - ProjectDiscovery: subfinder subdomain enumeration tool

IMPORTANT: Only use this tool on domains you own or have explicit
           written authorization to assess.

Requirements:
    pip install aiohttp jinja2

Optional:
    - subfinder (https://github.com/projectdiscovery/subfinder)
    - httpx (https://github.com/projectdiscovery/httpx)

Usage:
    # Full assessment with subdomain enumeration
    python ore_react2shell.py --domain example.com

    # Use existing subdomain list
    python ore_react2shell.py --domain example.com -f subdomains.txt

    # Multiple root domains
    python ore_react2shell.py --domain example.com --domain example.org

    # With active verification
    python ore_react2shell.py --domain example.com --verify

    # Safe side-channel check
    python ore_react2shell.py --domain example.com --safe-check

    # Output options
    python ore_react2shell.py --domain example.com -o results --format all
"""

import argparse
import asyncio
import csv
import json
import os
import re
import shutil
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Dict, Optional, Tuple
from urllib.parse import urljoin, urlparse

try:
    import aiohttp
except ImportError:
    print("Error: aiohttp required. Install: pip install aiohttp")
    sys.exit(1)

try:
    from jinja2 import Template
except ImportError:
    Template = None
    print("Warning: jinja2 not installed. HTML reports will use basic formatting.")
    print("Install with: pip install jinja2")

# Import scanner engine and shared types
try:
    from ore_rsc import (
        RSCScanner,
        ScanResult,
        RiskLevel,
        VulnerabilityStatus,
        DEFAULT_RSC_PATHS,
        DEEP_SCAN_PATHS,
    )
except ImportError:
    print("Error: ore_rsc.py must be in the same directory")
    print("This assessment tool uses ore_rsc.py as its core engine.")
    sys.exit(1)


# =============================================================================
# NEXT.JS DETECTION SIGNATURES (assessment-specific)
# =============================================================================

NEXTJS_SIGNATURES = {
    "headers": [
        ("x-powered-by", "next.js"),
        ("x-nextjs-cache", None),
        ("x-nextjs-matched-path", None),
        ("x-middleware-rewrite", None),
        ("x-middleware-redirect", None),
    ],
    "body_patterns": [
        r"/_next/static/",
        r"__NEXT_DATA__",
        r"_next/image",
        r"next/dist/",
        r'"buildId":\s*"[a-zA-Z0-9_-]+"',
        r'"appGip":\s*true',
    ],
    "meta_tags": [
        r'<meta[^>]*name="next-head-count"',
        r'<script[^>]*id="__NEXT_DATA__"',
    ],
}


# =============================================================================
# DATA STRUCTURES
# =============================================================================

@dataclass
class Subdomain:
    """Discovered subdomain."""
    hostname: str
    source: str = "unknown"
    is_live: bool = False
    http_url: Optional[str] = None
    https_url: Optional[str] = None
    # For direct URLs (like localhost:3000)
    direct_url: Optional[str] = None


def parse_target(target: str) -> Tuple[str, Optional[str], Optional[int]]:
    """Parse a target string into hostname, scheme, and port.
    
    Returns:
        (hostname, scheme, port) - scheme and port may be None
    """
    target = target.strip()
    
    # Check if it's already a full URL
    if target.startswith(("http://", "https://")):
        parsed = urlparse(target)
        hostname = parsed.hostname or parsed.netloc
        scheme = parsed.scheme
        port = parsed.port
        return hostname, scheme, port
    
    # Check for port in hostname (e.g., "localhost:3000")
    if ":" in target and not target.startswith("["):  # Not IPv6
        parts = target.rsplit(":", 1)
        if parts[1].isdigit():
            return parts[0], None, int(parts[1])
    
    return target, None, None


def is_local_target(hostname: str) -> bool:
    """Check if hostname is a local/development target."""
    local_patterns = [
        "localhost",
        "127.0.0.1",
        "0.0.0.0",
        "::1",
    ]
    hostname_lower = hostname.lower()
    return any(hostname_lower == p or hostname_lower.startswith(f"{p}:") for p in local_patterns)


@dataclass
class HostInfo:
    """Information about a live host."""
    url: str
    hostname: str
    status_code: int = 0
    server: Optional[str] = None
    powered_by: Optional[str] = None
    content_type: Optional[str] = None
    title: Optional[str] = None
    is_nextjs: bool = False
    nextjs_indicators: List[str] = field(default_factory=list)
    response_time_ms: float = 0
    error: Optional[str] = None


@dataclass
class AssessmentResult:
    """Complete assessment result for a target."""
    hostname: str
    url: str
    is_live: bool = False
    is_nextjs: bool = False
    nextjs_indicators: List[str] = field(default_factory=list)
    has_rsc_endpoints: bool = False
    rsc_endpoints: List[ScanResult] = field(default_factory=list)
    risk_level: RiskLevel = RiskLevel.INFO
    vulnerability_status: VulnerabilityStatus = VulnerabilityStatus.UNKNOWN
    risk_factors: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)


# =============================================================================
# SUBDOMAIN ENUMERATION
# =============================================================================

class SubdomainEnumerator:
    """Enumerate subdomains using various sources."""

    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.subfinder_path = shutil.which("subfinder")

    def _log(self, msg: str):
        if self.verbose:
            print(f"[ENUM] {msg}")

    async def enumerate(self, domain: str, timeout: int = 300) -> List[Subdomain]:
        """Enumerate subdomains for a domain."""
        subdomains: Dict[str, Subdomain] = {}

        # Always include the root domain
        subdomains[domain] = Subdomain(hostname=domain, source="root")

        # Try subfinder if available
        if self.subfinder_path:
            self._log(f"Running subfinder for {domain}...")
            sf_results = await self._run_subfinder(domain, timeout)
            for host in sf_results:
                if host not in subdomains:
                    subdomains[host] = Subdomain(hostname=host, source="subfinder")
            self._log(f"Subfinder found {len(sf_results)} subdomains")
        else:
            self._log("subfinder not found, skipping enumeration")
            print("[!] Note: Install subfinder for automatic subdomain enumeration:")
            print("    go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest")

        return list(subdomains.values())

    async def _run_subfinder(self, domain: str, timeout: int) -> List[str]:
        """Run subfinder and parse results."""
        results = []
        try:
            proc = await asyncio.create_subprocess_exec(
                self.subfinder_path,
                "-d", domain,
                "-silent",
                "-timeout", str(min(timeout // 60, 5)),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)

            for line in stdout.decode().strip().split("\n"):
                line = line.strip()
                if line and self._is_valid_hostname(line):
                    results.append(line.lower())

        except asyncio.TimeoutError:
            self._log("subfinder timed out")
        except Exception as e:
            self._log(f"subfinder error: {e}")

        return results

    def _is_valid_hostname(self, hostname: str) -> bool:
        """Basic hostname validation."""
        if not hostname or len(hostname) > 253:
            return False
        pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        return bool(re.match(pattern, hostname))

    def load_from_file(self, filepath: str, domain: str) -> List[Subdomain]:
        """Load subdomains from a file."""
        subdomains = []
        try:
            with open(filepath, 'r') as f:
                for line in f:
                    hostname = line.strip().lower()
                    if hostname and not hostname.startswith('#'):
                        if hostname == domain or hostname.endswith(f".{domain}"):
                            subdomains.append(Subdomain(hostname=hostname, source="file"))
        except Exception as e:
            print(f"[!] Error reading {filepath}: {e}")
        return subdomains


# =============================================================================
# HOST PROBING & NEXT.JS DETECTION
# =============================================================================

class HostProber:
    """Probe hosts for liveness and technology detection."""

    def __init__(
            self,
            concurrency: int = 30,
            timeout: float = 10.0,
            user_agent: str = "Mozilla/5.0 (Security Assessment)",
    ):
        self.concurrency = concurrency
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.user_agent = user_agent
        self.semaphore: Optional[asyncio.Semaphore] = None

    async def probe_hosts(self, subdomains: List[Subdomain]) -> List[HostInfo]:
        """Probe all subdomains for live HTTP/HTTPS services."""
        self.semaphore = asyncio.Semaphore(self.concurrency)

        probe_tasks = []
        for sd in subdomains:
            # If we have a direct URL (like http://localhost:3000), use it directly
            if sd.direct_url:
                probe_tasks.append(self._probe_url(sd.direct_url, sd.hostname))
            else:
                # Otherwise probe both HTTP and HTTPS
                probe_tasks.append(self._probe_host(sd.hostname, "https"))
                probe_tasks.append(self._probe_host(sd.hostname, "http"))

        print(f"[*] Probing {len(subdomains)} hosts ({len(probe_tasks)} URLs)...")
        results = await asyncio.gather(*probe_tasks)

        # Deduplicate - prefer HTTPS over HTTP
        host_map: Dict[str, HostInfo] = {}
        for info in results:
            if info and info.status_code and info.status_code < 500:
                existing = host_map.get(info.hostname)
                if not existing:
                    host_map[info.hostname] = info
                elif info.url.startswith("https://") and existing.url.startswith("http://"):
                    host_map[info.hostname] = info

        live_hosts = list(host_map.values())
        print(f"[+] Found {len(live_hosts)} live hosts")

        return live_hosts

    async def _probe_url(self, url: str, hostname: str) -> Optional[HostInfo]:
        """Probe a specific URL directly."""
        info = HostInfo(url=url, hostname=hostname)
        return await self._do_probe(info, url)

    async def _probe_host(self, hostname: str, scheme: str) -> Optional[HostInfo]:
        """Probe a single host by constructing URL."""
        url = f"{scheme}://{hostname}"
        info = HostInfo(url=url, hostname=hostname)
        return await self._do_probe(info, url)

    async def _do_probe(self, info: HostInfo, url: str) -> Optional[HostInfo]:
        """Perform the actual probe request."""
        # Determine if HTTP or HTTPS from URL
        is_http = url.startswith("http://")

        async with self.semaphore:
            start = time.monotonic()
            try:
                connector = aiohttp.TCPConnector(ssl=False if is_http else None)
                async with aiohttp.ClientSession(
                        timeout=self.timeout,
                        connector=connector,
                ) as session:
                    async with session.get(
                            url,
                            headers={"User-Agent": self.user_agent},
                            allow_redirects=True,
                            ssl=False,
                    ) as resp:
                        info.status_code = resp.status
                        info.server = resp.headers.get("Server", "")
                        info.powered_by = resp.headers.get("X-Powered-By", "")
                        info.content_type = resp.headers.get("Content-Type", "")
                        info.response_time_ms = (time.monotonic() - start) * 1000

                        # Check headers for Next.js
                        for header, expected_value in NEXTJS_SIGNATURES["headers"]:
                            header_val = resp.headers.get(header, "").lower()
                            if header_val:
                                if expected_value is None or expected_value in header_val:
                                    info.is_nextjs = True
                                    info.nextjs_indicators.append(f"header:{header}")

                        # Check body for Next.js patterns
                        try:
                            body = await resp.text()
                            body_lower = body[:50000].lower()

                            title_match = re.search(r'<title[^>]*>([^<]+)</title>', body, re.I)
                            if title_match:
                                info.title = title_match.group(1).strip()[:100]

                            for pattern in NEXTJS_SIGNATURES["body_patterns"]:
                                if re.search(pattern, body, re.I):
                                    info.is_nextjs = True
                                    info.nextjs_indicators.append(f"body:{pattern[:30]}")

                            for pattern in NEXTJS_SIGNATURES["meta_tags"]:
                                if re.search(pattern, body, re.I):
                                    info.is_nextjs = True
                                    info.nextjs_indicators.append(f"meta:{pattern[:30]}")

                        except Exception:
                            pass

            except Exception as e:
                info.error = str(e)[:100]

        return info if info.status_code else None


# =============================================================================
# ASSESSMENT ENGINE
# =============================================================================

class AssessmentEngine:
    """Orchestrate the complete security assessment."""

    def __init__(
            self,
            concurrency: int = 30,
            timeout: float = 10.0,
            verbose: bool = False,
            deep_scan: bool = False,
            verify_mode: bool = False,
            safe_check: bool = False,
            waf_bypass: bool = False,
            vercel_waf_bypass: bool = False,
            windows: bool = False,
    ):
        self.concurrency = concurrency
        self.timeout = timeout
        self.verbose = verbose
        self.deep_scan = deep_scan
        self.verify_mode = verify_mode
        self.safe_check = safe_check

        self.enumerator = SubdomainEnumerator(verbose=verbose)
        self.prober = HostProber(concurrency=concurrency, timeout=timeout)

        # Use the imported RSCScanner with all options
        self.scanner = RSCScanner(
            concurrency=concurrency,
            timeout=timeout,
            deep_scan=deep_scan,
            verify_mode=verify_mode,
            safe_check=safe_check,
            waf_bypass=waf_bypass,
            vercel_waf_bypass=vercel_waf_bypass,
            windows=windows,
        )

    async def run_assessment(
            self,
            domains: List[str],
            subdomain_file: Optional[str] = None,
            skip_enumeration: bool = False,
    ) -> Tuple[List[AssessmentResult], Dict]:
        """Run complete assessment."""

        all_subdomains: List[Subdomain] = []

        for domain in domains:
            original_input = domain.strip()
            
            # Parse the target to handle URLs like http://localhost:3000
            hostname, scheme, port = parse_target(original_input)
            is_local = is_local_target(hostname)
            
            print(f"\n{'=' * 60}")
            print(f"[*] Assessing: {original_input}")
            print('=' * 60)

            # If it's a full URL or local target, use directly without subdomain enumeration
            if scheme or is_local or port:
                # Build the direct URL
                if scheme:
                    if port:
                        direct_url = f"{scheme}://{hostname}:{port}"
                    else:
                        direct_url = f"{scheme}://{hostname}"
                elif port:
                    # Default to http for local development
                    direct_url = f"http://{hostname}:{port}"
                else:
                    direct_url = f"http://{hostname}"
                
                print(f"[*] Direct target mode: {direct_url}")
                subs = [Subdomain(hostname=hostname, source="direct", direct_url=direct_url)]
            elif subdomain_file:
                print(f"[*] Loading subdomains from {subdomain_file}")
                subs = self.enumerator.load_from_file(subdomain_file, hostname)
            elif skip_enumeration:
                subs = [Subdomain(hostname=hostname, source="root")]
            else:
                print("[*] Enumerating subdomains...")
                subs = await self.enumerator.enumerate(hostname)

            all_subdomains.extend(subs)
            print(f"[+] Total targets for {hostname}: {len(subs)}")

        if not all_subdomains:
            print("[!] No subdomains to assess")
            return [], {}

        # Step 2: Probe for live hosts
        print(f"\n[*] Phase 2: Probing {len(all_subdomains)} subdomains for live hosts...")
        live_hosts = await self.prober.probe_hosts(all_subdomains)

        # Step 3: Filter to Next.js hosts
        nextjs_hosts = [h for h in live_hosts if h.is_nextjs]
        print(f"[+] Identified {len(nextjs_hosts)} Next.js applications")

        if not nextjs_hosts:
            print("[*] No Next.js applications found - RSC vulnerability not applicable")
            results = []
            for host in live_hosts:
                results.append(AssessmentResult(
                    hostname=host.hostname,
                    url=host.url,
                    is_live=True,
                    is_nextjs=False,
                    risk_level=RiskLevel.INFO,
                ))
            return results, self._build_metadata(all_subdomains, live_hosts, nextjs_hosts, {})

        # Step 4: Scan Next.js hosts for RSC endpoints using imported scanner
        print(f"\n[*] Phase 3: Scanning {len(nextjs_hosts)} Next.js hosts for RSC endpoints...")
        if self.verify_mode:
            print("[*] Active verification mode enabled - sending PoC payloads")
        elif self.safe_check:
            print("[*] Safe side-channel check mode enabled")

        rsc_results = await self._scan_hosts_with_scanner(nextjs_hosts)

        # Step 5: Build assessment results
        print("\n[*] Phase 4: Analyzing results...")
        results = self._build_results(live_hosts, nextjs_hosts, rsc_results)
        metadata = self._build_metadata(all_subdomains, live_hosts, nextjs_hosts, rsc_results)

        return results, metadata

    async def _scan_hosts_with_scanner(
            self,
            hosts: List[HostInfo]
    ) -> Dict[str, List[ScanResult]]:
        """Scan hosts using the imported RSCScanner."""
        # Prepare domains for the scanner
        domains = [h.url for h in hosts]

        # Run the scanner
        results = await self.scanner.scan(domains, show_progress=True)

        # Group results by hostname
        by_host: Dict[str, List[ScanResult]] = {}
        for result in results:
            hostname = result.domain
            if hostname not in by_host:
                by_host[hostname] = []
            by_host[hostname].append(result)

        return by_host

    def _build_results(
            self,
            live_hosts: List[HostInfo],
            nextjs_hosts: List[HostInfo],
            rsc_results: Dict[str, List[ScanResult]],
    ) -> List[AssessmentResult]:
        """Build final assessment results with conservative risk classification."""
        results = []

        for host in live_hosts:
            result = AssessmentResult(
                hostname=host.hostname,
                url=host.url,
                is_live=True,
                is_nextjs=host.is_nextjs,
                nextjs_indicators=host.nextjs_indicators,
            )

            # Check for RSC results for this host
            host_key = host.url.rstrip('/')
            host_rsc = rsc_results.get(host_key, [])

            # Also try hostname variations
            if not host_rsc:
                for key in rsc_results:
                    if host.hostname in key:
                        host_rsc = rsc_results[key]
                        break

            if host_rsc:
                rsc_endpoints = [r for r in host_rsc if r.is_rsc_endpoint]

                if rsc_endpoints:
                    result.has_rsc_endpoints = True
                    result.rsc_endpoints = rsc_endpoints

                    # Determine overall risk based on verification status (conservative)
                    confirmed = any(r.vulnerability_status == VulnerabilityStatus.CONFIRMED for r in rsc_endpoints)
                    likely = any(r.vulnerability_status == VulnerabilityStatus.LIKELY for r in rsc_endpoints)
                    has_actions = any(r.has_server_actions for r in rsc_endpoints)

                    if confirmed:
                        result.risk_level = RiskLevel.CRITICAL
                        result.vulnerability_status = VulnerabilityStatus.CONFIRMED
                        result.risk_factors = [
                            "EXPLOITATION CONFIRMED - RCE payload succeeded",
                            "Next.js application with vulnerable RSC implementation",
                            f"{len(rsc_endpoints)} RSC endpoint(s) identified",
                        ]
                        result.recommendations = [
                            "IMMEDIATE: Patch all React Server Components packages",
                            "Upgrade react-server-dom-* to 19.0.1, 19.1.2, or 19.2.1+",
                            "Update Next.js to latest patched version",
                            "Implement emergency WAF rules",
                            "Review server access logs for exploitation attempts",
                        ]
                    elif likely:
                        result.risk_level = RiskLevel.HIGH
                        result.vulnerability_status = VulnerabilityStatus.LIKELY
                        result.risk_factors = [
                            "Side-channel detection indicates likely vulnerability",
                            "Next.js application detected",
                            f"{len(rsc_endpoints)} RSC endpoint(s) identified",
                        ]
                        result.recommendations = [
                            "HIGH PRIORITY: Verify React Server Components versions",
                            "Upgrade react-server-dom-* packages",
                            "Update Next.js to latest version",
                            "Implement WAF rules to filter malicious RSC payloads",
                        ]
                    elif has_actions:
                        result.risk_level = RiskLevel.MEDIUM
                        result.vulnerability_status = VulnerabilityStatus.UNKNOWN
                        result.risk_factors = [
                            "Server Actions detected - potential attack surface",
                            "Next.js application detected",
                            f"{len(rsc_endpoints)} RSC endpoint(s) identified",
                            "Verification not performed - run with --verify or --safe-check",
                        ]
                        result.recommendations = [
                            "Verify React Server Components package versions",
                            "Run assessment with --verify or --safe-check to confirm",
                            "Upgrade react-server-dom-* packages to patched versions",
                            "Review server action implementations for input validation",
                        ]
                    else:
                        result.risk_level = RiskLevel.LOW
                        result.vulnerability_status = VulnerabilityStatus.UNKNOWN
                        result.risk_factors = [
                            "RSC endpoints detected",
                            "Next.js application detected",
                            "No server actions detected in scan",
                        ]
                        result.recommendations = [
                            "Verify React Server Components are patched",
                            "Run with --verify or --safe-check for confirmation",
                        ]

            elif host.is_nextjs:
                result.risk_level = RiskLevel.LOW
                result.risk_factors = ["Next.js detected but no RSC endpoints confirmed"]
                result.recommendations = ["Verify React Server Components are not in use or are patched"]

            results.append(result)

        # Sort by risk level
        risk_order = {RiskLevel.CRITICAL: 0, RiskLevel.HIGH: 1, RiskLevel.MEDIUM: 2,
                      RiskLevel.LOW: 3, RiskLevel.INFO: 4}
        results.sort(key=lambda r: risk_order[r.risk_level])

        return results

    def _build_metadata(
            self,
            subdomains: List[Subdomain],
            live_hosts: List[HostInfo],
            nextjs_hosts: List[HostInfo],
            rsc_results: Dict[str, List[ScanResult]],
    ) -> Dict:
        """Build assessment metadata."""
        total_rsc = sum(
            1 for results in rsc_results.values()
            for r in results if r.is_rsc_endpoint
        )

        confirmed_count = sum(
            1 for results in rsc_results.values()
            for r in results if r.vulnerability_status == VulnerabilityStatus.CONFIRMED
        )

        likely_count = sum(
            1 for results in rsc_results.values()
            for r in results if r.vulnerability_status == VulnerabilityStatus.LIKELY
        )

        return {
            "assessment_time": datetime.now(timezone.utc).isoformat(),
            "total_subdomains": len(subdomains),
            "live_hosts": len(live_hosts),
            "nextjs_applications": len(nextjs_hosts),
            "rsc_endpoints_found": total_rsc,
            "hosts_with_rsc": len([h for h in rsc_results if any(r.is_rsc_endpoint for r in rsc_results[h])]),
            "confirmed_vulnerable": confirmed_count,
            "likely_vulnerable": likely_count,
        }


# =============================================================================
# REPORT GENERATOR
# =============================================================================

class ReportGenerator:
    """Generate assessment reports in various formats."""

    HTML_TEMPLATE = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>RSC Security Assessment Report - Rapticore Security Research</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            /* Professional Cybersecurity Color Palette */
            --neutral-0: #FFFFFF;
            --neutral-50: #F8FAFC;
            --neutral-100: #F2F4F7;
            --neutral-200: #EAECF0;
            --neutral-300: #D0D5DD;
            --neutral-500: #667085;
            --neutral-700: #344054;
            --neutral-900: #101828;
            
            --critical: #D92D20;
            --high: #F04438;
            --medium: #F79009;
            --low: #12B76A;
            --info: #2E90FA;
            --confirmed: #D92D20;
            --likely: #F04438;
            --mitigated: #12B76A;
            
            --accent-primary: #2E90FA;
            --border: #EAECF0;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            font-size: 14px;
            line-height: 1.5;
            color: var(--neutral-900);
            background: var(--neutral-0);
            -webkit-font-smoothing: antialiased;
        }
        .container { max-width: 1200px; margin: 0 auto; padding: 2rem; }
        h1, h2, h3 { color: var(--neutral-900); margin-bottom: 1rem; font-weight: 600; }
        h1 { font-size: 1.75rem; border-bottom: 2px solid var(--border); padding-bottom: 0.5rem; }
        h2 { font-size: 1.25rem; margin-top: 2rem; }
        .header { 
            background: var(--neutral-50);
            color: var(--neutral-900);
            padding: 2rem;
            margin: -2rem -2rem 2rem -2rem;
            border-bottom: 1px solid var(--border);
            display: flex;
            align-items: center;
            gap: 20px;
        }
        .header h1 { color: var(--neutral-900); border: none; margin: 0; padding: 0; }
        .header p { color: var(--neutral-500); margin: 4px 0 0 0; font-size: 14px; }
        .logo-container { flex-shrink: 0; }
        .summary-cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                         gap: 1rem; margin: 1.5rem 0; }
        .card { background: var(--neutral-0); border-radius: 8px; padding: 1.5rem;
                box-shadow: 0 1px 3px rgba(0,0,0,0.05); border: 1px solid var(--border); }
        .card-value { font-size: 2.5rem; font-weight: 700; color: var(--neutral-900); }
        .card-label { color: var(--neutral-500); font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.5px; }
        .risk-critical .card-value { color: var(--critical); }
        .risk-high .card-value { color: var(--high); }
        .risk-medium .card-value { color: var(--medium); }
        .badge { display: inline-block; padding: 0.25rem 0.75rem; border-radius: 4px;
                 font-size: 0.75rem; font-weight: 600; text-transform: uppercase; }
        .badge-critical { background: var(--critical); color: white; }
        .badge-high { background: var(--high); color: white; }
        .badge-medium { background: var(--medium); color: white; }
        .badge-low { background: var(--low); color: white; }
        .badge-info { background: var(--info); color: white; }
        .badge-confirmed { background: var(--critical); color: white; }
        .badge-likely { background: var(--high); color: white; }
        .badge-mitigated { background: var(--mitigated); color: white; }
        table { width: 100%; border-collapse: collapse; margin: 1rem 0; background: var(--neutral-0);
                border-radius: 8px; overflow: hidden; border: 1px solid var(--border); }
        th, td { padding: 0.75rem 1rem; text-align: left; border-bottom: 1px solid var(--border); }
        th { background: var(--neutral-100); font-weight: 600; color: var(--neutral-700); 
             font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.5px; }
        tr:hover { background: var(--neutral-50); }
        .finding { background: var(--neutral-0); border-radius: 8px; padding: 1.5rem; margin: 1rem 0;
                   box-shadow: 0 1px 3px rgba(0,0,0,0.05); border: 1px solid var(--border); border-left: 4px solid; }
        .finding-critical { border-left-color: var(--critical); }
        .finding-high { border-left-color: var(--high); }
        .finding-medium { border-left-color: var(--medium); }
        .finding-low { border-left-color: var(--low); }
        .finding h3 { display: flex; align-items: center; gap: 0.75rem; }
        .endpoint-list { background: var(--neutral-50); border-radius: 4px; padding: 1rem; margin: 1rem 0; border: 1px solid var(--border); }
        .endpoint-list code { display: block; padding: 0.25rem 0; font-size: 0.875rem; color: var(--neutral-900); }
        .recommendations { background: var(--neutral-50); border-radius: 8px; padding: 1.5rem; margin: 2rem 0; border-left: 4px solid var(--accent-primary); }
        .recommendations h3 { color: var(--neutral-900); }
        .recommendations ul { margin-left: 1.5rem; }
        .recommendations li { margin: 0.5rem 0; color: var(--neutral-700); }
        .footer { text-align: center; color: var(--neutral-500); margin-top: 3rem; padding-top: 2rem;
                  border-top: 1px solid var(--border); }
        .footer p { margin: 0.5rem 0; }
        .verified-banner { background: #FEF3F2; border: 1px solid var(--critical); border-radius: 8px;
                          padding: 1rem; margin: 1rem 0; border-left: 4px solid var(--critical); }
        .verified-banner h3 { color: var(--critical); margin: 0; }
        @media print { 
            .container { max-width: none; } 
            body { background: white; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="logo-container">
                <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1992.89 363.76" style="height: 45px; width: auto;">
                    <defs><style>.cls-1{fill:#14213c;}.cls-2{fill:#ffaa32;}</style></defs>
                    <g id="Layer_2" data-name="Layer 2"><g id="Layer_1-2" data-name="Layer 1">
                        <path class="cls-1" d="M595,261.87,557.3,206.11H526v55.76H500.85v-160h53.7c35.89,0,57.83,21.94,57.83,52.79,0,22.4-11.66,39.54-31.77,47.08L622,261.87Zm-69-77.71h27.42c20.34,0,33.83-9.59,33.83-29.48s-13.49-29.48-33.83-29.48H526Z"/>
                        <path class="cls-1" d="M787,228H708.35l-13.94,33.83H667.67l67.88-160h24.22l67.88,160H800.91Zm-8.69-20.79-30.62-73.82L717,207.25Z"/>
                        <path class="cls-1" d="M991.73,154.68c0,30.85-21.94,51.43-57.83,51.43H905.34v55.76H880.2v-160h53.7C969.79,101.89,991.73,123.83,991.73,154.68Zm-25.14,0c0-19.88-13.49-29.48-33.83-29.48H905.34v59h27.42C953.1,184.16,966.59,174.57,966.59,154.68Z"/>
                        <path class="cls-1" d="M1153.29,125.2h-42.5V261.87h-25.15V125.2h-42.51V101.89h110.16Z"/>
                        <path class="cls-1" d="M1235.56,261.87h-25.15v-160h25.15Z"/>
                        <path class="cls-1" d="M1376.33,264.15c-43,0-82.5-33.82-82.5-82.27s39.53-82.28,82.5-82.28c20.57,0,39.08,6.86,53.25,19l-15.31,17.37a60.32,60.32,0,0,0-36.34-12.57c-31.08,0-58,24.23-58,58.51s27,58.5,58,58.5a59.54,59.54,0,0,0,37-13.25l15.31,17.6C1415.87,257.3,1397.13,264.15,1376.33,264.15Z"/>
                        <path class="cls-1" d="M1649.19,181.88c0,49.14-37.93,82.27-83.18,82.27s-83.19-33.13-83.19-82.27S1520.76,99.6,1566,99.6,1649.19,132.74,1649.19,181.88Zm-38.16,0c0-28.11-19.2-47.76-45-47.76s-44.8,19.65-44.8,47.76,19,47.77,44.8,47.77S1611,210,1611,181.88Z"/>
                        <path class="cls-1" d="M1764.13,209.53h-19.65v52.34h-36.8v-160h56.91c35.88,0,59.65,21.71,59.65,55.08,0,21.25-10.06,37.25-27,45.48l38.4,59.42h-38.86Zm-19.65-31.31h17.83c14.85,0,25.13-5.26,25.13-21.25,0-15.77-10.28-21.26-25.13-21.26h-17.83Z"/>
                        <path class="cls-1" d="M1992.89,228v33.83H1890.5v-160h100.33v33.82H1927.3v29h47.54v33.14H1927.3V228Z"/>
                        <path class="cls-2" d="M181.88,0A181.88,181.88,0,1,0,363.76,181.88,181.88,181.88,0,0,0,181.88,0Zm0,303.62A121.74,121.74,0,1,1,303.62,181.88,121.74,121.74,0,0,1,181.88,303.62Z"/>
                    </g></g>
                </svg>
            </div>
            <div>
                <h1>RSC Security Assessment Report</h1>
                <p>CVE-2025-55182 (React2Shell) & CVE-2025-66478 Vulnerability Assessment</p>
                <p>Generated: {{ metadata.assessment_time }}</p>
            </div>
        </div>

        {% if metadata.confirmed_vulnerable > 0 %}
        <div class="verified-banner">
            <h3>🚨 CRITICAL: {{ metadata.confirmed_vulnerable }} Confirmed Vulnerable Host(s)</h3>
            <p>Active exploitation was successful. Immediate remediation required.</p>
        </div>
        {% endif %}

        {% if metadata.likely_vulnerable > 0 %}
        <div class="verified-banner" style="border-color: #ea580c; background: #fff7ed;">
            <h3 style="color: #ea580c;">⚠️ HIGH RISK: {{ metadata.likely_vulnerable }} Likely Vulnerable Host(s)</h3>
            <p>Side-channel detection indicates vulnerability. Prioritize remediation.</p>
        </div>
        {% endif %}

        <h2>Executive Summary</h2>
        <div class="summary-cards">
            <div class="card">
                <div class="card-value">{{ metadata.total_subdomains }}</div>
                <div class="card-label">Subdomains Scanned</div>
            </div>
            <div class="card">
                <div class="card-value">{{ metadata.live_hosts }}</div>
                <div class="card-label">Live Hosts</div>
            </div>
            <div class="card">
                <div class="card-value">{{ metadata.nextjs_applications }}</div>
                <div class="card-label">Next.js Apps</div>
            </div>
            <div class="card risk-{{ 'critical' if metadata.confirmed_vulnerable > 0 else 'high' if metadata.likely_vulnerable > 0 else 'medium' }}">
                <div class="card-value">{{ metadata.rsc_endpoints_found }}</div>
                <div class="card-label">RSC Endpoints</div>
            </div>
        </div>

        <h2>Risk Distribution</h2>
        <div class="summary-cards">
            <div class="card risk-critical">
                <div class="card-value">{{ critical_count }}</div>
                <div class="card-label">Critical (Confirmed)</div>
            </div>
            <div class="card risk-high">
                <div class="card-value">{{ high_count }}</div>
                <div class="card-label">High (Likely)</div>
            </div>
            <div class="card risk-medium">
                <div class="card-value">{{ medium_count }}</div>
                <div class="card-label">Medium (Potential)</div>
            </div>
        </div>

        {% if high_risk_findings %}
        <h2>🚨 Priority Findings (Immediate Action Required)</h2>
        {% for finding in high_risk_findings %}
        <div class="finding finding-{{ finding.risk_level.value|lower }}">
            <h3>
                <span class="badge badge-{{ finding.risk_level.value|lower }}">{{ finding.risk_level.value }}</span>
                {% if finding.vulnerability_status.value == 'CONFIRMED' %}
                <span class="badge badge-confirmed">VERIFIED</span>
                {% elif finding.vulnerability_status.value == 'LIKELY' %}
                <span class="badge badge-likely">LIKELY</span>
                {% endif %}
                {{ finding.hostname }}
            </h3>
            <p><strong>URL:</strong> {{ finding.url }}</p>

            {% if finding.risk_factors %}
            <p><strong>Risk Factors:</strong></p>
            <ul>
                {% for factor in finding.risk_factors %}
                <li>{{ factor }}</li>
                {% endfor %}
            </ul>
            {% endif %}

            {% if finding.rsc_endpoints %}
            <p><strong>RSC Endpoints Detected:</strong></p>
            <div class="endpoint-list">
                {% for ep in finding.rsc_endpoints[:10] %}
                <code>{{ ep.path }} → {{ ep.rsc_indicators|join(', ')|truncate(80) }}</code>
                {% endfor %}
                {% if finding.rsc_endpoints|length > 10 %}
                <code>... and {{ finding.rsc_endpoints|length - 10 }} more</code>
                {% endif %}
            </div>
            {% endif %}

            {% if finding.recommendations %}
            <p><strong>Recommendations:</strong></p>
            <ul>
                {% for rec in finding.recommendations %}
                <li>{{ rec }}</li>
                {% endfor %}
            </ul>
            {% endif %}
        </div>
        {% endfor %}
        {% endif %}

        <h2>All Assessed Hosts</h2>
        <table>
            <thead>
                <tr>
                    <th>Hostname</th>
                    <th>Risk Level</th>
                    <th>Verification</th>
                    <th>Next.js</th>
                    <th>RSC Endpoints</th>
                </tr>
            </thead>
            <tbody>
                {% for r in results %}
                <tr>
                    <td><a href="{{ r.url }}" target="_blank">{{ r.hostname }}</a></td>
                    <td><span class="badge badge-{{ r.risk_level.value|lower }}">{{ r.risk_level.value }}</span></td>
                    <td>
                        {% if r.vulnerability_status.value == 'CONFIRMED' %}
                        <span class="badge badge-confirmed">CONFIRMED</span>
                        {% elif r.vulnerability_status.value == 'LIKELY' %}
                        <span class="badge badge-likely">LIKELY</span>
                        {% elif r.vulnerability_status.value == 'MITIGATED' %}
                        <span class="badge badge-mitigated">MITIGATED</span>
                        {% else %}
                        <span class="badge badge-info">UNKNOWN</span>
                        {% endif %}
                    </td>
                    <td>{{ '✅' if r.is_nextjs else '—' }}</td>
                    <td>{{ r.rsc_endpoints|length if r.rsc_endpoints else '—' }}</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>

        <div class="recommendations">
            <h3>📋 General Remediation Guidance</h3>
            <ul>
                <li><strong>Immediate:</strong> Identify all applications using React Server Components packages</li>
                <li><strong>Patch:</strong> Upgrade to fixed versions: 19.0.1, 19.1.2, or 19.2.1+</li>
                <li><strong>Framework Updates:</strong> Update Next.js to latest patched version</li>
                <li><strong>WAF Rules:</strong> Implement web application firewall rules to detect malicious RSC payloads</li>
                <li><strong>Monitoring:</strong> Enable logging for RSC endpoints to detect exploitation attempts</li>
                <li><strong>Audit:</strong> Review all Server Actions for proper input validation</li>
            </ul>
        </div>

        <h2>Vulnerability Reference</h2>
        <table>
            <tr><th>CVE ID</th><td>CVE-2025-55182, CVE-2025-66478</td></tr>
            <tr><th>Name</th><td>React2Shell</td></tr>
            <tr><th>Severity</th><td>Critical (Remote Code Execution)</td></tr>
            <tr><th>Affected Packages</th><td>react-server-dom-webpack, react-server-dom-parcel, react-server-dom-turbopack</td></tr>
            <tr><th>Affected Versions</th><td>19.0.0, 19.1.0, 19.1.1, 19.2.0</td></tr>
            <tr><th>Fixed Versions</th><td>19.0.1, 19.1.2, 19.2.1+</td></tr>
        </table>

        <div class="footer">
            <p><strong>Rapticore Security Research Team</strong></p>
            <p>RSC Vulnerability Assessment Tool</p>
            <p>⚠️ This report is for authorized security assessments only</p>
        </div>
    </div>
</body>
</html>'''

    def __init__(self, output_dir: str = "."):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

    def generate(
            self,
            results: List[AssessmentResult],
            metadata: Dict,
            formats: List[str] = None,
            base_name: str = "rsc_assessment",
    ) -> List[str]:
        """Generate reports in specified formats."""
        formats = formats or ["html", "json", "csv"]
        generated = []

        for fmt in formats:
            if fmt == "html":
                path = self._generate_html(results, metadata, base_name)
            elif fmt == "json":
                path = self._generate_json(results, metadata, base_name)
            elif fmt == "csv":
                path = self._generate_csv(results, metadata, base_name)
            elif fmt == "txt":
                path = self._generate_text(results, metadata, base_name)
            else:
                continue
            generated.append(path)

        return generated

    def _generate_html(self, results: List[AssessmentResult], metadata: Dict, base_name: str) -> str:
        """Generate HTML report."""
        path = os.path.join(self.output_dir, f"{base_name}.html")

        critical = [r for r in results if r.risk_level == RiskLevel.CRITICAL]
        high = [r for r in results if r.risk_level == RiskLevel.HIGH]
        medium = [r for r in results if r.risk_level == RiskLevel.MEDIUM]
        high_risk = critical + high

        if Template:
            template = Template(self.HTML_TEMPLATE)
            html = template.render(
                results=results,
                metadata=metadata,
                critical_count=len(critical),
                high_count=len(high),
                medium_count=len(medium),
                high_risk_findings=high_risk,
            )
        else:
            html = self._generate_basic_html(results, metadata, critical, high, medium)

        with open(path, 'w', encoding='utf-8') as f:
            f.write(html)

        return path

    def _generate_basic_html(self, results, metadata, critical, high, medium):
        """Generate basic HTML without Jinja2."""
        findings_html = ""
        for r in critical + high:
            endpoints = ""
            for ep in r.rsc_endpoints[:5]:
                indicators = ', '.join(ep.rsc_indicators)[:80]
                endpoints += f"<li><code>{ep.path}</code> - {indicators}</li>"

            status_badge = ""
            if r.vulnerability_status == VulnerabilityStatus.CONFIRMED:
                status_badge = '<span style="color: red;">[CONFIRMED]</span>'
            elif r.vulnerability_status == VulnerabilityStatus.LIKELY:
                status_badge = '<span style="color: orange;">[LIKELY]</span>'

            findings_html += f'''
            <div style="border-left: 4px solid {'#dc2626' if r.risk_level == RiskLevel.CRITICAL else '#ea580c'};
                        padding: 1rem; margin: 1rem 0; background: #fff;">
                <h3>{r.risk_level.value} {status_badge}: {r.hostname}</h3>
                <p>URL: {r.url}</p>
                <p>RSC Endpoints:</p><ul>{endpoints}</ul>
            </div>
            '''

        return f'''<!DOCTYPE html>
<html><head><title>RSC Security Assessment - Rapticore Security Research</title>
<style>body{{font-family:'Inter',sans-serif;max-width:1000px;margin:0 auto;padding:2rem}}</style>
</head><body>
<h1>Rapticore RSC Security Assessment Report</h1>
<p>Generated: {metadata.get('assessment_time', 'N/A')}</p>
<h2>Summary</h2>
<ul>
<li>Subdomains: {metadata.get('total_subdomains', 0)}</li>
<li>Live Hosts: {metadata.get('live_hosts', 0)}</li>
<li>Next.js Apps: {metadata.get('nextjs_applications', 0)}</li>
<li>RSC Endpoints: {metadata.get('rsc_endpoints_found', 0)}</li>
<li>Confirmed Vulnerable: {metadata.get('confirmed_vulnerable', 0)}</li>
<li>Likely Vulnerable: {metadata.get('likely_vulnerable', 0)}</li>
</ul>
<h2>Risk: Critical={len(critical)}, High={len(high)}, Medium={len(medium)}</h2>
<h2>Findings</h2>
{findings_html}
</body></html>'''

    def _generate_json(self, results: List[AssessmentResult], metadata: Dict, base_name: str) -> str:
        """Generate JSON report."""
        path = os.path.join(self.output_dir, f"{base_name}.json")

        data = {
            "metadata": metadata,
            "summary": {
                "critical": len([r for r in results if r.risk_level == RiskLevel.CRITICAL]),
                "high": len([r for r in results if r.risk_level == RiskLevel.HIGH]),
                "medium": len([r for r in results if r.risk_level == RiskLevel.MEDIUM]),
                "low": len([r for r in results if r.risk_level == RiskLevel.LOW]),
            },
            "results": [],
        }

        for r in results:
            entry = {
                "hostname": r.hostname,
                "url": r.url,
                "is_live": r.is_live,
                "is_nextjs": r.is_nextjs,
                "risk_level": r.risk_level.value,
                "vulnerability_status": r.vulnerability_status.value,
                "has_rsc_endpoints": r.has_rsc_endpoints,
                "rsc_endpoint_count": len(r.rsc_endpoints),
                "risk_factors": r.risk_factors,
                "recommendations": r.recommendations,
                "rsc_endpoints": [
                    {
                        "url": ep.url,
                        "path": ep.path,
                        "indicators": ep.rsc_indicators,
                        "vulnerability_status": ep.vulnerability_status.value if hasattr(ep, 'vulnerability_status') else "UNKNOWN",
                    }
                    for ep in r.rsc_endpoints
                ],
            }
            data["results"].append(entry)

        with open(path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)

        return path

    def _generate_csv(self, results: List[AssessmentResult], metadata: Dict, base_name: str) -> str:
        """Generate CSV report."""
        path = os.path.join(self.output_dir, f"{base_name}.csv")

        with open(path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow([
                "Hostname", "URL", "Risk Level", "Verification Status",
                "Is Next.js", "RSC Endpoints", "RSC Endpoint Paths", "Risk Factors"
            ])

            for r in results:
                writer.writerow([
                    r.hostname,
                    r.url,
                    r.risk_level.value,
                    r.vulnerability_status.value,
                    r.is_nextjs,
                    len(r.rsc_endpoints),
                    "; ".join(ep.path for ep in r.rsc_endpoints[:10]),
                    "; ".join(r.risk_factors),
                ])

        return path

    def _generate_text(self, results: List[AssessmentResult], metadata: Dict, base_name: str) -> str:
        """Generate plain text executive summary."""
        path = os.path.join(self.output_dir, f"{base_name}_executive_summary.txt")

        critical = [r for r in results if r.risk_level == RiskLevel.CRITICAL]
        high = [r for r in results if r.risk_level == RiskLevel.HIGH]
        medium = [r for r in results if r.risk_level == RiskLevel.MEDIUM]

        lines = [
            "=" * 70,
            "RAPTICORE SECURITY RESEARCH - RSC SECURITY ASSESSMENT",
            "CVE-2025-55182 & CVE-2025-66478 (React2Shell) Vulnerability Assessment",
            "=" * 70,
            "",
            f"Assessment Date: {metadata.get('assessment_time', 'N/A')}",
            "",
            "SCOPE",
            "-" * 40,
            f"  Subdomains Enumerated: {metadata.get('total_subdomains', 0)}",
            f"  Live Hosts Discovered: {metadata.get('live_hosts', 0)}",
            f"  Next.js Applications:  {metadata.get('nextjs_applications', 0)}",
            f"  RSC Endpoints Found:   {metadata.get('rsc_endpoints_found', 0)}",
            "",
            "VERIFICATION RESULTS",
            "-" * 40,
            f"  Confirmed Vulnerable:  {metadata.get('confirmed_vulnerable', 0)}",
            f"  Likely Vulnerable:     {metadata.get('likely_vulnerable', 0)}",
            "",
            "RISK SUMMARY",
            "-" * 40,
            f"  CRITICAL: {len(critical)} hosts (Exploitation confirmed)",
            f"  HIGH:     {len(high)} hosts (Likely vulnerable)",
            f"  MEDIUM:   {len(medium)} hosts (Potential attack surface)",
            "",
        ]

        if critical or high:
            lines.extend([
                "IMMEDIATE ACTION REQUIRED",
                "-" * 40,
            ])

            for i, r in enumerate(critical + high, 1):
                status = "CONFIRMED" if r.vulnerability_status == VulnerabilityStatus.CONFIRMED else "LIKELY"
                lines.extend([
                    f"",
                    f"  [{r.risk_level.value}] [{status}] #{i}: {r.hostname}",
                    f"    URL: {r.url}",
                    f"    RSC Endpoints: {len(r.rsc_endpoints)}",
                ])
                if r.rsc_endpoints:
                    lines.append(f"    Paths: {', '.join(ep.path for ep in r.rsc_endpoints[:5])}")

            lines.append("")

        lines.extend([
            "REMEDIATION PRIORITY",
            "-" * 40,
            "  1. [IMMEDIATE] Patch all applications using React Server Components",
            "     - Upgrade to react-server-dom-* version 19.0.1, 19.1.2, or 19.2.1+",
            "     - Update Next.js to latest patched version",
            "",
            "  2. [SHORT-TERM] Implement compensating controls",
            "     - Deploy WAF rules to filter malicious RSC payloads",
            "     - Enable detailed logging on RSC endpoints",
            "",
            "  3. [ONGOING] Security hardening",
            "     - Audit Server Actions for input validation",
            "     - Implement security monitoring for exploitation attempts",
            "",
            "VULNERABILITY REFERENCE",
            "-" * 40,
            "  CVE:      CVE-2025-55182, CVE-2025-66478",
            "  Name:     React2Shell",
            "  Severity: Critical (Remote Code Execution)",
            "",
            "=" * 70,
            "END OF EXECUTIVE SUMMARY",
            "=" * 70,
        ])

        with open(path, 'w', encoding='utf-8') as f:
            f.write("\n".join(lines))

        return path


# =============================================================================
# MAIN
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Complete RSC vulnerability assessment with subdomain enumeration",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Full assessment with automatic subdomain enumeration
  # Results saved to: results/example_com_{timestamp}/
  %(prog)s --domain example.com

  # Use existing subdomain list
  %(prog)s --domain example.com -f subdomains.txt

  # Multiple domains with all output formats
  %(prog)s --domain example.com --domain example.org --format all

  # Quick scan of root domain only (skip enumeration)
  %(prog)s --domain example.com --skip-enum

  # With active verification (sends PoC payload - use with caution)
  %(prog)s --domain example.com --verify

  # Safe side-channel check (non-exploitative verification)
  %(prog)s --domain example.com --safe-check

  # Custom output directory
  %(prog)s --domain example.com -o ./custom_reports

Output:
  Reports are saved to: {output_dir}/{domain}_{timestamp}/
  Default: results/example_com_20250101_120000/

Requirements:
  - pip install aiohttp jinja2
  - subfinder (optional, for subdomain enumeration)
  - ore_rsc.py (in same directory)

⚠️  Only use on domains you own or have authorization to test.
        """
    )

    parser.add_argument(
        "-d", "--domain",
        action="append",
        dest="domains",
        required=True,
        help="Target domain(s) to assess (can specify multiple)",
    )
    parser.add_argument(
        "-f", "--file",
        help="File containing subdomains (one per line)",
    )
    parser.add_argument(
        "--skip-enum",
        action="store_true",
        help="Skip subdomain enumeration, only test provided domains",
    )
    parser.add_argument(
        "-c", "--concurrency",
        type=int,
        default=30,
        help="Concurrent requests (default: 30)",
    )
    parser.add_argument(
        "-t", "--timeout",
        type=float,
        default=10.0,
        help="Request timeout in seconds (default: 10)",
    )
    parser.add_argument(
        "-o", "--output",
        default="results",
        help="Base output directory for reports (default: results)",
    )
    parser.add_argument(
        "--format",
        choices=["html", "json", "csv", "txt", "all"],
        default="all",
        help="Output format (default: all)",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Verbose output",
    )
    parser.add_argument(
        "--deep",
        action="store_true",
        help="Enable deep scanning with additional RSC-related paths",
    )

    # Verification Options
    verify_group = parser.add_argument_group("Verification Options")
    verify_group.add_argument(
        "--verify",
        action="store_true",
        help="Active verification - sends RCE PoC payload (use with caution)",
    )
    verify_group.add_argument(
        "--safe-check",
        action="store_true",
        help="Safe side-channel verification (non-exploitative)",
    )
    verify_group.add_argument(
        "--windows",
        action="store_true",
        help="Use Windows PowerShell payload (with --verify)",
    )

    # WAF Bypass Options
    waf_group = parser.add_argument_group("WAF Bypass Options")
    waf_group.add_argument(
        "--waf-bypass",
        action="store_true",
        help="Add junk data to bypass WAF content inspection",
    )
    waf_group.add_argument(
        "--vercel-waf-bypass",
        action="store_true",
        help="Use Vercel-specific WAF bypass payload",
    )

    args = parser.parse_args()

    # Validate args
    if args.verify and args.safe_check:
        print("[!] Error: Cannot use both --verify and --safe-check")
        sys.exit(1)

    print("""
╔═══════════════════════════════════════════════════════════════════════════╗
║  RAPTICORE SECURITY RESEARCH - RSC Vulnerability Assessment               ║
║  CVE-2025-55182 & CVE-2025-66478 (React2Shell)                            ║
╠═══════════════════════════════════════════════════════════════════════════╣
║  ⚠️  FOR AUTHORIZED SECURITY ASSESSMENTS ONLY                             ║
║  Only use on domains you own or have explicit written authorization       ║
╚═══════════════════════════════════════════════════════════════════════════╝
""")

    # Create assessment engine with all options
    engine = AssessmentEngine(
        concurrency=args.concurrency,
        timeout=args.timeout,
        verbose=args.verbose,
        deep_scan=args.deep,
        verify_mode=args.verify,
        safe_check=args.safe_check,
        waf_bypass=args.waf_bypass,
        vercel_waf_bypass=args.vercel_waf_bypass,
        windows=args.windows,
    )

    if args.deep:
        print("[*] Deep scan mode enabled - scanning additional paths")
    if args.verify:
        print("[*] Active verification mode enabled - sending PoC payloads")
    elif args.safe_check:
        print("[*] Safe side-channel check mode enabled")
    if args.waf_bypass:
        print("[*] WAF bypass mode enabled")
    if args.vercel_waf_bypass:
        print("[*] Vercel WAF bypass mode enabled")

    # Run assessment
    try:
        results, metadata = asyncio.run(
            engine.run_assessment(
                domains=args.domains,
                subdomain_file=args.file,
                skip_enumeration=args.skip_enum,
            )
        )
    except KeyboardInterrupt:
        print("\n[!] Assessment interrupted")
        sys.exit(1)

    if not results:
        print("[!] No results to report")
        sys.exit(0)

    # Generate reports
    print(f"\n[*] Generating reports...")

    formats = ["html", "json", "csv", "txt"] if args.format == "all" else [args.format]
    
    # Create results folder structure: results/{domain}_{timestamp}/
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    # Create clean domain slug from the first target
    first_target = args.domains[0]
    hostname, scheme, port = parse_target(first_target)
    if port:
        domain_slug = f"{hostname}_{port}".replace('.', '_')
    else:
        domain_slug = hostname.replace('.', '_')
    output_folder = os.path.join(args.output, f"{domain_slug}_{timestamp}")
    os.makedirs(output_folder, exist_ok=True)
    
    reporter = ReportGenerator(output_dir=output_folder)

    base_name = f"rsc_assessment"

    generated = reporter.generate(results, metadata, formats=formats, base_name=base_name)

    print(f"\n[+] Assessment complete!")
    print(f"[+] Reports generated:")
    for path in generated:
        print(f"    → {path}")

    # Print summary
    critical = len([r for r in results if r.risk_level == RiskLevel.CRITICAL])
    high = len([r for r in results if r.risk_level == RiskLevel.HIGH])
    medium = len([r for r in results if r.risk_level == RiskLevel.MEDIUM])
    confirmed = metadata.get('confirmed_vulnerable', 0)
    likely = metadata.get('likely_vulnerable', 0)

    print(f"\n{'=' * 60}")
    print("RISK SUMMARY")
    print(f"{'=' * 60}")
    print(f"  CRITICAL (Confirmed): {critical}")
    print(f"  HIGH (Likely):        {high}")
    print(f"  MEDIUM (Potential):   {medium}")

    if confirmed:
        print(f"\n🚨 {confirmed} endpoint(s) CONFIRMED VULNERABLE - Immediate remediation required!")
    elif likely:
        print(f"\n⚠️  {likely} endpoint(s) LIKELY VULNERABLE - Prioritize remediation!")
    elif critical + high + medium > 0:
        print(f"\n[*] {critical + high + medium} host(s) detected as potential attack surface")
        print("    Run with --verify or --safe-check to confirm vulnerability")


if __name__ == "__main__":
    main()
