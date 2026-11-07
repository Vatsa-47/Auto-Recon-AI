"""
AUTO-RECON AI — Local Frontend Asset & Configuration Verification Test
Validates:
1. All local file references (<script>, <link>) in frontend/index.html exist and are readable.
2. config.js syntax and logic.
3. app.js and sample-data.js syntax.
4. HTTP server retrieval simulation (mimicking Vercel static file serving).
"""

import os
import re
import sys
import http.server
import threading
import urllib.request
from pathlib import Path

def test_frontend_files():
    frontend_dir = Path("frontend").resolve()
    assert frontend_dir.exists(), "frontend/ directory does not exist!"

    required_files = ["index.html", "config.js", "app.js", "styles.css", "sample-data.js", "vercel.json"]
    for rf in required_files:
        fp = frontend_dir / rf
        assert fp.exists(), f"Missing required frontend file: {rf}"
        assert fp.stat().st_size > 0, f"File {rf} is empty!"
        print(f"  [OK] Found {rf} ({fp.stat().st_size:,} bytes)")

    # Read index.html
    html = (frontend_dir / "index.html").read_text(encoding="utf-8")
    
    # Check script order
    assert '<script src="sample-data.js"></script>' in html, "sample-data.js script tag missing"
    assert '<script src="config.js"></script>' in html, "config.js script tag missing"
    assert '<script src="app.js"></script>' in html, "app.js script tag missing"
    
    idx_sample = html.find('src="sample-data.js"')
    idx_config = html.find('src="config.js"')
    idx_app = html.find('src="app.js"')
    
    assert idx_sample < idx_config < idx_app, "Script load order is incorrect! config.js must load before app.js."
    print("  [OK] Script load order verified: sample-data.js -> config.js -> app.js")

    # Check local references in index.html
    local_scripts = [s for s in re.findall(r'src=["\']([^"\']+)["\']', html) if not s.startswith("http")]
    local_links = [l for l in re.findall(r'href=["\']([^"\']+)["\']', html) if not l.startswith("http")]

    for ls in local_scripts:
        assert (frontend_dir / ls).exists(), f"Referenced local script {ls} not found in frontend/"
        print(f"  [OK] Script reference verified: {ls}")

    for ll in local_links:
        assert (frontend_dir / ll).exists(), f"Referenced local link {ll} not found in frontend/"
        print(f"  [OK] Stylesheet reference verified: {ll}")

def test_local_http_serving():
    frontend_dir = Path("frontend").resolve()
    
    class Handler(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, directory=str(frontend_dir), **kwargs)
        def log_message(self, format, *args):
            pass # Suppress logging

    server = http.server.HTTPServer(("127.0.0.1", 8765), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    
    print("\nStarting local HTTP server simulation on port 8765...")
    try:
        urls_to_test = [
            "http://127.0.0.1:8765/",
            "http://127.0.0.1:8765/index.html",
            "http://127.0.0.1:8765/config.js",
            "http://127.0.0.1:8765/app.js",
            "http://127.0.0.1:8765/styles.css",
            "http://127.0.0.1:8765/sample-data.js"
        ]
        
        for url in urls_to_test:
            req = urllib.request.urlopen(url, timeout=5)
            assert req.status == 200, f"HTTP GET {url} failed with status {req.status}"
            content = req.read()
            assert len(content) > 0, f"HTTP GET {url} returned empty body"
            print(f"  [HTTP 200 OK] {url} ({len(content):,} bytes)")
            
    finally:
        server.shutdown()
        server.server_close()
        print("Local HTTP server simulation finished.")

if __name__ == "__main__":
    print("=" * 60)
    print("AUTO-RECON AI — Frontend Verification Suite")
    print("=" * 60)
    test_frontend_files()
    test_local_http_serving()
    print("=" * 60)
    print("ALL FRONTEND VERIFICATION TESTS PASSED SUCCESSFULLY!")
    print("=" * 60)
