import os
import shutil
from pathlib import Path

# 1. Update app.js
with open('app.js', 'r', encoding='utf-8') as f:
    content = f.read()

target1 = "document.addEventListener('DOMContentLoaded', () => {\n  // Application State"
repl1 = "document.addEventListener('DOMContentLoaded', () => {\n  // Configurable Backend API Base URL (loaded from config.js / window.AUTORECON_CONFIG)\n  const API_BASE = (window.AUTORECON_CONFIG && window.AUTORECON_CONFIG.API_BASE_URL) || window.API_BASE || 'http://127.0.0.1:8000/api';\n\n  // Application State"

if target1 not in content:
    target1 = target1.replace('\n', '\r\n')
    repl1 = repl1.replace('\n', '\r\n')

if target1 in content:
    content = content.replace(target1, repl1, 1)
    print("Found and replaced target1 in app.js")
else:
    print("Warning: target1 not found in app.js")

target2 = '  const API_BASE = window.API_BASE || "http://127.0.0.1:8000/api";'
repl2 = '  // API_BASE is configured globally via window.AUTORECON_CONFIG.API_BASE_URL'
if target2 not in content:
    target2 = target2.replace('\n', '\r\n')
    repl2 = repl2.replace('\n', '\r\n')

if target2 in content:
    content = content.replace(target2, repl2, 1)
    print("Found and replaced target2 in app.js")
else:
    print("Warning: target2 not found in app.js")

with open('app.js', 'w', encoding='utf-8') as f:
    f.write(content)

# Copy updated app.js to frontend/app.js
shutil.copy2('app.js', 'frontend/app.js')
print("Updated frontend/app.js")

# 2. Update index.html
with open('index.html', 'r', encoding='utf-8') as f:
    html_content = f.read()

script_target = '<script src="sample-data.js"></script>\n  <script src="app.js"></script>'
script_repl = '<script src="sample-data.js"></script>\n  <script src="config.js"></script>\n  <script src="app.js"></script>'

if script_target not in html_content:
    script_target = script_target.replace('\n', '\r\n')
    script_repl = script_repl.replace('\n', '\r\n')

if script_target in html_content:
    html_content = html_content.replace(script_target, script_repl, 1)
    print("Found and inserted config.js before app.js in index.html")
else:
    print("Warning: script_target not found in index.html")

with open('index.html', 'w', encoding='utf-8') as f:
    f.write(html_content)

# Copy updated index.html to frontend/index.html
shutil.copy2('index.html', 'frontend/index.html')
print("Updated frontend/index.html")

print("All frontend files synchronized!")
