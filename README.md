# Rapticore Security Research - React2Shell Scanner

A security assessment toolkit developed by the **Rapticore Security Research Team** for detecting React Server Components (RSC) vulnerabilities including **CVE-2025-55182** (React2Shell) - a critical Remote Code Execution vulnerability.

## Overview

This toolkit provides two specialized tools:

| Tool | Description |
|------|-------------|
| **`ore_rsc.py`** | Fast RSC endpoint scanner for quick assessments |
| **`ore_react2shell.py`** | Full assessment suite with subdomain enumeration and reporting |

## Demo

https://github.com/user-attachments/assets/5be7661b-515c-46b4-ade4-8e88fdff6528

> Scanner detecting CVE-2025-55182 (React2Shell) vulnerabilities in a test Next.js application.

## Vulnerability Background

**CVE-2025-55182** (React2Shell) is a critical RCE vulnerability affecting React Server Components:

| Affected Packages | Vulnerable Versions | Fixed Versions |
|-------------------|---------------------|----------------|
| react-server-dom-webpack | 19.0.0, 19.1.0, 19.1.1, 19.2.0 | 19.0.1, 19.1.2, 19.2.1+ |
| react-server-dom-parcel | 19.0.0, 19.1.0, 19.1.1, 19.2.0 | 19.0.1, 19.1.2, 19.2.1+ |
| react-server-dom-turbopack | 19.0.0, 19.1.0, 19.1.1, 19.2.0 | 19.0.1, 19.1.2, 19.2.1+ |

**Reference:** [GHSA-fv66-9v8q-g76r](https://github.com/facebook/react/security/advisories/GHSA-fv66-9v8q-g76r)

## Features

### Fast Scanner (`ore_rsc.py`)

- Async concurrent scanning
- RSC endpoint path discovery
- Multiple output formats (console, CSV, JSON)
- Risk classification (CRITICAL, HIGH, MEDIUM, LOW)
- Framework detection (Next.js, Remix, Waku)
- Server Action detection
- Flight protocol pattern matching
- Deep scan mode
- WAF bypass techniques

### Full Assessment Suite (`ore_react2shell.py`)

- Subdomain enumeration (subfinder integration)
- Live host probing
- Next.js/RSC application identification
- Executive report generation (HTML, JSON, CSV, TXT)
- Risk stratification and remediation guidance
- Organized output by domain and timestamp

## Installation

```bash
# Clone the repository
git clone https://github.com/rapticore/ore_react2shell_scanner.git
cd ore_react2shell_scanner

# Create virtual environment
python3 -m venv env
source env/bin/activate  # On Windows: env\Scripts\activate

# Install dependencies
pip install aiohttp jinja2

# Optional: Install subfinder for subdomain enumeration
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
```

## Quick Start

### Fast Scan with `ore_rsc.py`

```bash
# Single domain scan
python ore_rsc.py example.com

# Multiple domains
python ore_rsc.py example.com api.example.com

# Scan from file
python ore_rsc.py -f subdomains.txt

# Deep scan with extended paths
python ore_rsc.py example.com --deep

# Active verification (sends PoC payload)
python ore_rsc.py example.com --verify

# Safe side-channel check (non-exploitative)
python ore_rsc.py example.com --safe-check

# JSON output
python ore_rsc.py example.com --format json -o results.json
```

### Full Assessment with `ore_react2shell.py`

```bash
# Full assessment with subdomain enumeration
# Results saved to: results/example_com_{timestamp}/
python ore_react2shell.py --domain example.com

# Use existing subdomain list
python ore_react2shell.py --domain example.com -f subdomains.txt

# Multiple root domains
python ore_react2shell.py --domain example.com --domain example.org

# With active verification
python ore_react2shell.py --domain example.com --verify

# Safe side-channel check
python ore_react2shell.py --domain example.com --safe-check

# Skip subdomain enumeration
python ore_react2shell.py --domain example.com --skip-enum

# Custom output directory
python ore_react2shell.py --domain example.com -o ./reports
```

### Output Structure

Reports are automatically organized by domain and timestamp:

```
results/
└── example_com_20250106_143052/
    ├── rsc_assessment.html              # Interactive HTML report
    ├── rsc_assessment.json              # Machine-readable JSON
    ├── rsc_assessment.csv               # Spreadsheet format
    └── rsc_assessment_executive_summary.txt  # Text summary
```

## Command Line Options

### ore_rsc.py

| Option | Description |
|--------|-------------|
| `domains` | Domain(s) to scan |
| `-f, --file` | File containing domains (one per line) |
| `-c, --concurrency` | Concurrent requests (default: 20) |
| `-t, --timeout` | Request timeout in seconds (default: 10) |
| `--deep` | Deep scanning with extended paths |
| `--verify` | Active verification - sends RCE PoC payload |
| `--safe-check` | Safe side-channel verification |
| `--waf-bypass` | WAF bypass mode with junk data |
| `-o, --output` | Output file path |
| `--format` | Output format: console, json, csv |

### ore_react2shell.py

| Option | Description |
|--------|-------------|
| `-d, --domain` | Target domain(s) to assess (required) |
| `-f, --file` | File containing subdomains |
| `--skip-enum` | Skip subdomain enumeration |
| `-c, --concurrency` | Concurrent requests (default: 30) |
| `--deep` | Deep scanning with extended paths |
| `--verify` | Active verification mode |
| `--safe-check` | Safe side-channel verification |
| `-o, --output` | Base output directory (default: results) |
| `--format` | Output format: html, json, csv, txt, all |

## Detection Methodology

### RSC Endpoint Detection

The scanners detect RSC endpoints through:

1. **Content-Type Headers**: `text/x-component`, `text/x-rsc`, `text/x-flight`
2. **Response Headers**: `x-nextjs-cache`, `rsc`, `next-action`, etc.
3. **Flight Protocol Patterns**: Stream chunks (`0:`, `1:`), React references (`$`)
4. **Server Action Markers**: `$ACTION_ID`, `formAction` attributes

### Risk Classification

| Risk Level | Criteria |
|------------|----------|
| CRITICAL | Exploitation confirmed via --verify |
| HIGH | Likely vulnerable via --safe-check |
| MEDIUM | RSC endpoint with server actions |
| LOW | RSC endpoint detected |
| INFO | RSC indicators present |

## Remediation Guidance

If vulnerable endpoints are detected:

1. **Immediate**: Upgrade `react-server-dom-*` to fixed versions (19.0.1, 19.1.2, 19.2.1+)
2. **Short-term**: Deploy WAF rules, enable logging
3. **Ongoing**: Review Server Actions, implement CSP

## Requirements

- Python 3.8+
- aiohttp
- jinja2 (for HTML reports)
- subfinder (optional, for subdomain enumeration)

## Security Notice

This tool is for **authorized security assessments only**. Only use on domains you own or have explicit written authorization to test.

The Rapticore Security Research Team assumes no liability for misuse.

## Acknowledgments

- **Rapticore Security Research Team** - Tool development and maintenance
- **Assetnote** - Original CVE-2025-55182 (React2Shell) vulnerability research
- **ProjectDiscovery** - [subfinder](https://github.com/projectdiscovery/subfinder) subdomain enumeration tool
- React Security Team for responsible disclosure coordination

---

**Developed by Rapticore Security Research Team**
