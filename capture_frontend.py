import subprocess
import time
import urllib.request
import json
import http.server
import socketserver
import threading
import sys
import os
import socket
import base64
import struct
from urllib.parse import urlparse

PORT = 5500
CDP_PORT = 9224

class QuietHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

# Check if port 5500 is in use
def start_server():
    try:
        with socketserver.TCPServer(("", PORT), QuietHandler) as httpd:
            httpd.serve_forever()
    except Exception as e:
        print(f"Server on {PORT} notice: {e}")

t = threading.Thread(target=start_server, daemon=True)
t.start()
time.sleep(0.5)

edge_path = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
proc = subprocess.Popen([
    edge_path,
    "--headless",
    "--disable-gpu",
    "--window-size=1920,1080",
    f"--remote-debugging-port={CDP_PORT}",
    f"http://127.0.0.1:{PORT}/index.html"
], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

time.sleep(2)
with urllib.request.urlopen(f"http://127.0.0.1:{CDP_PORT}/json") as resp:
    targets = json.loads(resp.read().decode())
page_target = next(t for t in targets if t.get('type') == 'page')
ws_url = page_target['webSocketDebuggerUrl']

parsed = urlparse(ws_url)
s = socket.create_connection((parsed.hostname, parsed.port))
key = base64.b64encode(os.urandom(16)).decode('ascii')
handshake = (
    f"GET {parsed.path} HTTP/1.1\r\n"
    f"Host: localhost:{parsed.port}\r\n"
    f"Upgrade: websocket\r\n"
    f"Connection: Upgrade\r\n"
    f"Sec-WebSocket-Key: {key}\r\n"
    f"Sec-WebSocket-Version: 13\r\n\r\n"
)
s.sendall(handshake.encode())
resp = s.recv(4096)
assert b"101" in resp

def send_cdp(method, params=None, req_id=1):
    msg = json.dumps({"id": req_id, "method": method, "params": params or {}}).encode('utf-8')
    length = len(msg)
    mask = os.urandom(4)
    masked = bytes(b ^ mask[i % 4] for i, b in enumerate(msg))
    if length < 126:
        header = bytes([0x81, 0x80 | length]) + mask
    elif length < 65536:
        header = bytes([0x81, 0x80 | 126]) + struct.pack('>H', length) + mask
    else:
        header = bytes([0x81, 0x80 | 127]) + struct.pack('>Q', length) + mask
    s.sendall(header + masked)

def recv_frame():
    header = s.recv(2)
    if not header:
        return None
    b1, b2 = header[0], header[1]
    masked = bool(b2 & 0x80)
    length = b2 & 0x7f
    if length == 126:
        length = struct.unpack('>H', s.recv(2))[0]
    elif length == 127:
        length = struct.unpack('>Q', s.recv(8))[0]
    if masked:
        mask = s.recv(4)
    data = b""
    while len(data) < length:
        data += s.recv(length - len(data))
    if masked:
        data = bytes(b ^ mask[i % 4] for i, b in enumerate(data))
    return json.loads(data.decode('utf-8'))

def eval_js(expr, req_id=100):
    send_cdp("Runtime.evaluate", {"expression": expr, "returnByValue": True}, req_id=req_id)
    while True:
        res = recv_frame()
        if res and res.get('id') == req_id:
            return res.get('result', {}).get('result', {})

def capture_screenshot(filename, req_id=200):
    send_cdp("Page.captureScreenshot", {"format": "png"}, req_id=req_id)
    while True:
        msg = recv_frame()
        if msg and msg.get('id') == req_id:
            png_b64 = msg['result']['data']
            png_bytes = base64.b64decode(png_b64)
            with open(f"review_ii_screenshots/{filename}", "wb") as f:
                f.write(png_bytes)
            print(f"Captured {filename}: {len(png_bytes)} bytes")
            break

# Ensure viewport is 1920x1080
send_cdp("Emulation.setDeviceMetricsOverride", {
    "width": 1920,
    "height": 1080,
    "deviceScaleFactor": 1,
    "mobile": False
}, req_id=10)
recv_frame()
time.sleep(1.5)

# --- 1. 01_dashboard.png ---
eval_js("window.scrollTo(0, 0)", 101)
time.sleep(0.5)
capture_screenshot("01_dashboard.png", 201)

# --- 3. 03_evidence_verification.png ---
eval_js("document.querySelector(`.nav-pill-btn[data-view='evidence']`).click()", 102)
time.sleep(1.0)
eval_js("window.scrollTo(0, 0)", 103)
time.sleep(0.5)
capture_screenshot("03_evidence_verification.png", 202)

# --- 5. 05_reconstruction.png ---
# Switch back to studio, choose Dashcam perspective
eval_js("document.querySelector(`.nav-pill-btn[data-view='studio']`).click()", 104)
time.sleep(0.5)
eval_js("document.querySelector(`.camera-pill[data-camera='dashcam']`).click()", 105)
time.sleep(0.5)
eval_js("window.scrollTo(0, 100)", 106)
time.sleep(0.5)
capture_screenshot("05_reconstruction.png", 203)

# --- 6. 06_what_if_simulation.png ---
# Scroll to what-if simulation
eval_js("""(() => {
    const el = document.getElementById('whatif-sim-detail') || document.getElementById('whatif-reaction-slider');
    if (el) el.scrollIntoView({ behavior: 'instant', block: 'center' });
})()""", 107)
time.sleep(0.5)
capture_screenshot("06_what_if_simulation.png", 204)

# --- 7. 07_anomalies_timeline.png ---
# Scroll to timeline & anomalies
eval_js("""(() => {
    const el = document.getElementById('rec-anomalies-list') || document.getElementById('incident-timeline-track');
    if (el) el.scrollIntoView({ behavior: 'instant', block: 'center' });
})()""", 108)
time.sleep(0.5)
capture_screenshot("07_anomalies_timeline.png", 205)

# --- 8. 08_forensic_report.png ---
eval_js("document.querySelector(`.nav-pill-btn[data-view='reports']`).click()", 109)
time.sleep(1.0)
eval_js("window.scrollTo(0, 0)", 110)
time.sleep(0.5)
capture_screenshot("08_forensic_report.png", 206)

s.close()
proc.terminate()
print("Frontend screenshots completed successfully!")
