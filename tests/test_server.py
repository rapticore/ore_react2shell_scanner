#!/usr/bin/env python3
"""
test_server.py - Mock RSC Server for Scanner Testing

This server simulates various RSC endpoint configurations to test
the vulnerability scanner's detection capabilities.

Usage:
    python test_server.py [--port PORT]

Then test with:
    python ../ore_rsc_vulnerability_scanner.py localhost:PORT
"""

import argparse
import json
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import threading


# =============================================================================
# RSC RESPONSE TEMPLATES
# =============================================================================

# Standard RSC Flight response (vulnerable)
RSC_FLIGHT_RESPONSE = """0:["$","div",null,{"children":["$","h1",null,{"children":"Hello RSC"}]}]
1:["$","$L2",null,{}]
2:{"name":"App","env":"production"}"""

# RSC with Server Actions (CRITICAL vulnerability indicator)
RSC_SERVER_ACTIONS_RESPONSE = """0:["$","div",null,{"children":["$","form",null,{"action":"$ACTION_ID_1234"}]}]
1:["$","$L2",null,{"formState":["pending",null]}]
2:{"$ACTION_ID":"1234","actionId":"submitForm"}"""

# RSC Stream format
RSC_STREAM_RESPONSE = """0:{"type":"module","chunks":["chunk-abc123"]}
1:["$","div",null,{"className":"container"}]
2:$undefined
3:["$Sreact.transition",null]"""

# Next.js specific RSC response
NEXTJS_RSC_RESPONSE = """0:["$","$L1",null,{"buildId":"abc123xyz"}]
1:["$","main",null,{"children":"Content"}]
2:{"router":"app","segment":"(root)"}"""

# Remix RSC-like response
REMIX_RSC_RESPONSE = """{"type":"remix","data":{"__remixContext":true}}"""

# Standard HTML response (not RSC)
HTML_RESPONSE = """<!DOCTYPE html>
<html>
<head><title>Normal Page</title></head>
<body>
<h1>Not an RSC endpoint</h1>
<script src="/_next/static/chunks/main.js"></script>
</body>
</html>"""

# Next.js HTML with RSC indicators in body
NEXTJS_HTML_RESPONSE = """<!DOCTYPE html>
<html>
<head>
<meta name="next-head-count" content="2">
<title>Next.js App</title>
</head>
<body>
<div id="__next">
<script id="__NEXT_DATA__" type="application/json">
{"buildId":"abc123","assetPrefix":""}
</script>
</div>
<script src="/_next/static/chunks/main.js"></script>
</body>
</html>"""


# =============================================================================
# ENDPOINT CONFIGURATIONS
# =============================================================================

ENDPOINTS = {
    # =========================================================================
    # CRITICAL: RSC with Server Actions
    # =========================================================================
    "/_rsc": {
        "content_type": "text/x-component",
        "body": RSC_SERVER_ACTIONS_RESPONSE,
        "headers": {
            "X-NextJS-Cache": "HIT",
            "RSC": "1",
            "Next-Router-State-Tree": '["",{}]',
        },
        "description": "RSC endpoint with Server Actions (CRITICAL)",
    },

    "/action": {
        "content_type": "text/x-component",
        "body": RSC_SERVER_ACTIONS_RESPONSE,
        "headers": {
            "X-Action": "true",
            "Next-Action": "submitForm",
        },
        "description": "Server Action endpoint (CRITICAL)",
    },

    # =========================================================================
    # HIGH: RSC Content Type
    # =========================================================================
    "/_next/rsc": {
        "content_type": "text/x-component",
        "body": RSC_FLIGHT_RESPONSE,
        "headers": {
            "X-NextJS-Cache": "STALE",
        },
        "description": "Next.js RSC endpoint (HIGH)",
    },

    "/rsc": {
        "content_type": "application/x-component",
        "body": RSC_FLIGHT_RESPONSE,
        "headers": {},
        "description": "Generic RSC endpoint (HIGH)",
    },

    "/api/rsc": {
        "content_type": "text/x-rsc",
        "body": NEXTJS_RSC_RESPONSE,
        "headers": {
            "X-Matched-Path": "/api/rsc",
        },
        "description": "API RSC endpoint (HIGH)",
    },

    "/flight": {
        "content_type": "text/x-flight",
        "body": RSC_STREAM_RESPONSE,
        "headers": {},
        "description": "Flight protocol endpoint (HIGH)",
    },

    # =========================================================================
    # MEDIUM: Multiple RSC indicators
    # =========================================================================
    "/__flight": {
        "content_type": "application/json",
        "body": RSC_STREAM_RESPONSE,
        "headers": {
            "RSC": "1",
            "Next-Router-State-Tree": '["",{}]',
            "X-NextJS-Matched-Path": "/__flight",
        },
        "description": "Flight endpoint with headers (MEDIUM)",
    },

    "/api/__rsc": {
        "content_type": "application/json",
        "body": '{"$undefined":true,"data":{}}',
        "headers": {
            "RSC": "1",
            "X-NextJS-Cache": "HIT",
        },
        "description": "RSC API with indicators (MEDIUM)",
    },

    # =========================================================================
    # LOW: Some RSC indicators
    # =========================================================================
    "/_next/data": {
        "content_type": "application/json",
        "body": '{"pageProps":{},"__N_SSG":true}',
        "headers": {
            "X-NextJS-Cache": "HIT",
        },
        "description": "Next.js data endpoint (LOW)",
    },

    "/__rsc__": {
        "content_type": "application/json",
        "body": '{"type":"prefetch"}',
        "headers": {
            "Next-Router-Prefetch": "1",
        },
        "description": "RSC prefetch endpoint (LOW)",
    },

    # =========================================================================
    # INFO: No RSC indicators (control endpoints)
    # =========================================================================
    "/": {
        "content_type": "text/html",
        "body": HTML_RESPONSE,
        "headers": {},
        "description": "Normal HTML page (INFO)",
    },

    "/api/health": {
        "content_type": "application/json",
        "body": '{"status":"ok"}',
        "headers": {},
        "description": "Health check API (INFO)",
    },

    # =========================================================================
    # FRAMEWORK SPECIFIC
    # =========================================================================
    "/nextjs": {
        "content_type": "text/html",
        "body": NEXTJS_HTML_RESPONSE,
        "headers": {
            "X-Powered-By": "Next.js",
        },
        "description": "Next.js HTML page with framework markers",
    },

    "/nextjs-rsc": {
        "content_type": "text/x-component",
        "body": NEXTJS_RSC_RESPONSE,
        "headers": {
            "X-Powered-By": "Next.js",
            "X-NextJS-Cache": "HIT",
        },
        "description": "Next.js RSC with framework detection",
    },

    "/remix": {
        "content_type": "application/json",
        "body": REMIX_RSC_RESPONSE,
        "headers": {
            "X-Remix-Response": "yes",
        },
        "description": "Remix framework endpoint",
    },

    # =========================================================================
    # DEEP SCAN PATHS
    # =========================================================================
    "/_next/static/chunks": {
        "content_type": "application/javascript",
        "body": "// chunk content",
        "headers": {},
        "description": "Static chunk (for deep scan)",
    },

    "/server-action": {
        "content_type": "text/x-component",
        "body": RSC_SERVER_ACTIONS_RESPONSE,
        "headers": {
            "Next-Action": "true",
        },
        "description": "Explicit server action endpoint",
    },

    "/api/server-action": {
        "content_type": "text/x-component",
        "body": '{"$ACTION_ID":"abc123","formState":["idle",null]}',
        "headers": {},
        "description": "API server action endpoint",
    },

    # =========================================================================
    # EDGE CASES
    # =========================================================================
    "/partial-indicators": {
        "content_type": "text/html",
        "body": HTML_RESPONSE,
        "headers": {
            "RSC": "1",
        },
        "description": "HTML with RSC header (edge case)",
    },

    "/json-flight": {
        "content_type": "application/json",
        "body": '{"0:":["$","div",null,{}]}',
        "headers": {},
        "description": "JSON with flight-like content",
    },

    "/undefined-marker": {
        "content_type": "application/json",
        "body": '{"value":"$undefined","nested":{"$ACTION_":"test"}}',
        "headers": {},
        "description": "JSON with RSC markers in body",
    },
}


# =============================================================================
# HTTP REQUEST HANDLER
# =============================================================================

class RSCTestHandler(BaseHTTPRequestHandler):
    """HTTP handler that simulates RSC endpoints."""

    def log_message(self, format, *args):
        """Customize log format."""
        print(f"[{self.log_date_time_string()}] {args[0]}")

    def send_response_headers(self, status_code, content_type, extra_headers=None):
        """Send response with headers."""
        self.send_response(status_code)
        self.send_header("Content-Type", content_type)
        self.send_header("Access-Control-Allow-Origin", "*")

        if extra_headers:
            for key, value in extra_headers.items():
                self.send_header(key, value)

        self.end_headers()

    def do_GET(self):
        """Handle GET requests."""
        parsed = urlparse(self.path)
        path = parsed.path

        # Check if RSC header is present (affects some responses)
        rsc_header = self.headers.get("RSC", "0")
        accept_header = self.headers.get("Accept", "")

        # Find matching endpoint
        if path in ENDPOINTS:
            endpoint = ENDPOINTS[path]

            # If RSC header is set and endpoint can respond with RSC
            if rsc_header == "1" and "text/x-component" in accept_header:
                # Check if we should upgrade response
                if endpoint["content_type"] == "text/html":
                    # Some endpoints might upgrade to RSC on RSC request
                    pass

            self.send_response_headers(
                200,
                endpoint["content_type"],
                endpoint.get("headers", {})
            )
            self.wfile.write(endpoint["body"].encode())

        elif path == "/endpoints":
            # List all available endpoints
            self.send_response_headers(200, "application/json")
            endpoint_list = {
                path: {
                    "content_type": cfg["content_type"],
                    "description": cfg.get("description", ""),
                }
                for path, cfg in ENDPOINTS.items()
            }
            self.wfile.write(json.dumps(endpoint_list, indent=2).encode())

        else:
            # 404 for unknown paths
            self.send_response_headers(404, "text/plain")
            self.wfile.write(b"Not Found")

    def do_POST(self):
        """Handle POST requests (for server actions)."""
        parsed = urlparse(self.path)
        path = parsed.path

        # Server actions typically respond to POST
        if path in ["/action", "/server-action", "/api/server-action"]:
            endpoint = ENDPOINTS.get(path, ENDPOINTS["/action"])
            self.send_response_headers(
                200,
                endpoint["content_type"],
                endpoint.get("headers", {})
            )
            self.wfile.write(endpoint["body"].encode())
        else:
            self.send_response_headers(405, "text/plain")
            self.wfile.write(b"Method Not Allowed")


# =============================================================================
# SERVER STARTUP
# =============================================================================

def run_server(port=8080):
    """Run the test server."""
    server = HTTPServer(("0.0.0.0", port), RSCTestHandler)

    print(f"""
╔═══════════════════════════════════════════════════════════════════════╗
║           RSC Vulnerability Scanner - Test Server                      ║
╠═══════════════════════════════════════════════════════════════════════╣
║  Listening on: http://localhost:{port:<5}                               ║
║  Endpoints:    {len(ENDPOINTS):<3} configured                                       ║
╚═══════════════════════════════════════════════════════════════════════╝

Available endpoints:
""")

    for path, cfg in ENDPOINTS.items():
        desc = cfg.get("description", "")
        ct = cfg["content_type"]
        print(f"  {path:<25} [{ct:<25}] {desc}")

    print(f"""
To test the scanner:
  python ore_rsc_vulnerability_scanner.py localhost:{port}
  python ore_rsc_vulnerability_scanner.py localhost:{port} --deep

To list endpoints as JSON:
  curl http://localhost:{port}/endpoints

Press Ctrl+C to stop the server.
""")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down server...")
        server.shutdown()


def main():
    parser = argparse.ArgumentParser(
        description="Mock RSC server for testing the vulnerability scanner"
    )
    parser.add_argument(
        "-p", "--port",
        type=int,
        default=8080,
        help="Port to listen on (default: 8080)"
    )
    args = parser.parse_args()

    run_server(args.port)


if __name__ == "__main__":
    main()
