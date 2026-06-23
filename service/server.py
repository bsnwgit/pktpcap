#!/usr/bin/env python3
"""
Packet Capture Analyzer — standalone web service
Run: python server.py
"""

import json, os, sys, webbrowser, threading, time
from pathlib import Path
from flask import Flask, request, jsonify, send_from_directory, render_template

BASE = Path(__file__).parent
CONFIG_FILE = BASE / "config.json"

DEFAULT_CONFIG = {
    "port": 8765,
    "provider": "anthropic",
    "anthropic_key": "",
    "anthropic_model": "claude-opus-4-8",
    "openai_key": "",
    "openai_model": "gpt-4o",
    "ssl_enabled": False,
    "ssl_cert": "",
    "ssl_key": ""
}

# ── Config helpers ────────────────────────────────────────────────────────────

def load_config():
    if CONFIG_FILE.exists():
        try:
            data = json.loads(CONFIG_FILE.read_text())
            cfg = {**DEFAULT_CONFIG, **data}
            return cfg
        except Exception:
            pass
    return dict(DEFAULT_CONFIG)

def save_config(cfg):
    CONFIG_FILE.write_text(json.dumps(cfg, indent=2))

# ── Flask app ─────────────────────────────────────────────────────────────────

app = Flask(__name__, static_folder="static", template_folder="templates")

@app.route("/")
def index():
    return send_from_directory(BASE / "static", "index.html")

@app.route("/settings")
def settings_page():
    return render_template("settings.html")

# ── API: settings ─────────────────────────────────────────────────────────────

@app.route("/api/settings", methods=["GET"])
def get_settings():
    cfg = load_config()
    # Mask keys before sending to client
    masked = dict(cfg)
    for k in ("anthropic_key", "openai_key"):
        if masked.get(k):
            v = masked[k]
            masked[k] = v[:8] + "•" * max(0, len(v) - 8)
    return jsonify(masked)

@app.route("/api/settings", methods=["POST"])
def post_settings():
    body = request.get_json(force=True)
    cfg = load_config()
    # Only update known fields; keep existing masked keys if not changed
    cfg["port"]             = int(body.get("port", cfg["port"]))
    cfg["provider"]         = body.get("provider", cfg["provider"])
    cfg["anthropic_model"]  = body.get("anthropic_model", cfg["anthropic_model"])
    cfg["openai_model"]     = body.get("openai_model", cfg["openai_model"])
    # Only overwrite keys if the value doesn't look like a masked string
    for k in ("anthropic_key", "openai_key"):
        v = body.get(k, "")
        if v and "•" not in v:
            cfg[k] = v
    # SSL settings
    if "ssl_enabled" in body:
        cfg["ssl_enabled"] = bool(body["ssl_enabled"])
    if "ssl_cert" in body:
        cfg["ssl_cert"] = body["ssl_cert"].strip()
    if "ssl_key" in body:
        cfg["ssl_key"] = body["ssl_key"].strip()
    save_config(cfg)
    return jsonify({"ok": True, "port": cfg["port"]})

# ── API: AI proxy ─────────────────────────────────────────────────────────────

@app.route("/api/ai", methods=["POST"])
def ai_call():
    cfg = load_config()
    body = request.get_json(force=True)
    prompt = body.get("prompt", "")
    data   = body.get("data", [])   # list of strings (capture context JSON)

    provider = cfg.get("provider", "anthropic")

    # Build a single user message combining all data strings
    user_content = "\n\n".join(data) if data else ""
    full_message  = (prompt + "\n\n" + user_content).strip() if user_content else prompt

    try:
        if provider == "anthropic":
            key   = cfg.get("anthropic_key", "")
            model = cfg.get("anthropic_model", "claude-opus-4-8")
            if not key:
                return jsonify({"error": "Anthropic API key not configured. Go to /settings to add it."}), 400
            import anthropic as _ant
            client = _ant.Anthropic(api_key=key)
            resp = client.messages.create(
                model=model,
                max_tokens=2048,
                messages=[{"role": "user", "content": full_message}]
            )
            text = resp.content[0].text if resp.content else ""

        elif provider == "openai":
            key   = cfg.get("openai_key", "")
            model = cfg.get("openai_model", "gpt-4o")
            if not key:
                return jsonify({"error": "OpenAI API key not configured. Go to /settings to add it."}), 400
            import openai as _oai
            client = _oai.OpenAI(api_key=key)
            resp = client.chat.completions.create(
                model=model,
                max_tokens=2048,
                messages=[{"role": "user", "content": full_message}]
            )
            text = resp.choices[0].message.content or ""

        else:
            return jsonify({"error": f"Unknown provider: {provider}"}), 400

        return jsonify({"content": text})

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/ai/test", methods=["POST"])
def ai_test():
    cfg = load_config()
    body = request.get_json(force=True)
    provider = body.get("provider", cfg.get("provider", "anthropic"))
    # Use submitted key if it's not masked, else fall back to saved
    def pick_key(field):
        v = body.get(field, "")
        return v if (v and "•" not in v) else cfg.get(field, "")

    try:
        if provider == "anthropic":
            key   = pick_key("anthropic_key")
            model = body.get("anthropic_model") or cfg.get("anthropic_model", "claude-opus-4-8")
            if not key:
                return jsonify({"ok": False, "error": "No Anthropic key provided"}), 400
            import anthropic as _ant
            client = _ant.Anthropic(api_key=key)
            resp = client.messages.create(
                model=model, max_tokens=20,
                messages=[{"role": "user", "content": "Say PONG"}]
            )
            return jsonify({"ok": True, "reply": resp.content[0].text})

        elif provider == "openai":
            key   = pick_key("openai_key")
            model = body.get("openai_model") or cfg.get("openai_model", "gpt-4o")
            if not key:
                return jsonify({"ok": False, "error": "No OpenAI key provided"}), 400
            import openai as _oai
            client = _oai.OpenAI(api_key=key)
            resp = client.chat.completions.create(
                model=model, max_tokens=20,
                messages=[{"role": "user", "content": "Say PONG"}]
            )
            return jsonify({"ok": True, "reply": resp.choices[0].message.content})

        else:
            return jsonify({"ok": False, "error": f"Unknown provider: {provider}"}), 400

    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/api/restart", methods=["POST"])
def restart_server():
    def do_restart():
        time.sleep(0.8)
        import subprocess
        subprocess.Popen([sys.executable] + sys.argv)
        os._exit(0)
    threading.Thread(target=do_restart, daemon=True).start()
    return jsonify({"ok": True})


# ── API: save screenshot ──────────────────────────────────────────────────────

@app.route("/api/save-image", methods=["POST"])
def save_image():
    import base64, re
    body = request.get_json(force=True)
    filename = body.get("filename", "screenshot.png")
    data_url = body.get("dataUrl", "")
    filename = re.sub(r'[^a-zA-Z0-9_\-.]', '_', filename)
    match = re.match(r'data:image/\w+;base64,(.*)', data_url, re.DOTALL)
    if not match:
        return jsonify({"ok": False, "error": "Invalid data URL"}), 400
    img_bytes = base64.b64decode(match.group(1))
    out_dir = BASE / "screenshots"
    out_dir.mkdir(exist_ok=True)
    out_path = out_dir / filename
    out_path.write_bytes(img_bytes)
    return jsonify({"ok": True, "path": str(out_path)})

@app.route("/api/screenshot", methods=["POST"])
def take_screenshot():
    import re, subprocess
    body = request.get_json(force=True)
    filename = re.sub(r'[^a-zA-Z0-9_\-.]', '_', body.get("filename", "screenshot.png"))
    out_dir = BASE / "screenshots"
    out_dir.mkdir(exist_ok=True)
    out_path = str(out_dir / filename).replace("\\", "/")
    ps = r"""
Add-Type -AssemblyName System.Drawing
Add-Type @"
using System;
using System.Drawing;
using System.Runtime.InteropServices;
public class Win32 {
    [DllImport("user32.dll")] public static extern bool PrintWindow(IntPtr hwnd, IntPtr hdc, uint nFlags);
    [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr hwnd, out RECT rect);
    [StructLayout(LayoutKind.Sequential)]
    public struct RECT { public int Left, Top, Right, Bottom; }
}
"@
$chrome = Get-Process | Where-Object { $_.Name -eq 'chrome' -and $_.MainWindowHandle -ne [IntPtr]::Zero } | Sort-Object CPU -Descending | Select-Object -First 1
if (-not $chrome) { Write-Error "Chrome not found"; exit 1 }
$hwnd = $chrome.MainWindowHandle
$rect = New-Object Win32+RECT
[Win32]::GetWindowRect($hwnd, [ref]$rect) | Out-Null
$w = $rect.Right - $rect.Left
$h = $rect.Bottom - $rect.Top
$bmp = New-Object System.Drawing.Bitmap($w, $h)
$g = [System.Drawing.Graphics]::FromImage($bmp)
$hdc = $g.GetHdc()
[Win32]::PrintWindow($hwnd, $hdc, 2) | Out-Null
$g.ReleaseHdc($hdc)
$bmp.Save('""" + out_path + r"""')
$bmp.Dispose(); $g.Dispose()
"""
    result = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
        capture_output=True, text=True, timeout=20
    )
    if result.returncode != 0:
        return jsonify({"ok": False, "error": result.stderr[:300]}), 500
    return jsonify({"ok": True, "path": out_path})


# ── Entry point ───────────────────────────────────────────────────────────────

def open_browser(port, scheme="http"):
    time.sleep(1.2)
    webbrowser.open(f"{scheme}://localhost:{port}")

if __name__ == "__main__":
    cfg = load_config()
    port = int(sys.argv[1]) if len(sys.argv) > 1 else cfg.get("port", 8765)

    # First-run: create empty config if needed
    if not CONFIG_FILE.exists():
        save_config(cfg)

    ssl_enabled = cfg.get("ssl_enabled", False)
    ssl_cert    = cfg.get("ssl_cert", "")
    ssl_key     = cfg.get("ssl_key", "")
    ssl_context = None
    scheme = "http"

    if ssl_enabled and ssl_cert and ssl_key:
        if not os.path.isfile(ssl_cert):
            print(f"  WARNING: SSL cert not found: {ssl_cert}")
        elif not os.path.isfile(ssl_key):
            print(f"  WARNING: SSL key not found: {ssl_key}")
        else:
            ssl_context = (ssl_cert, ssl_key)
            scheme = "https"

    print(f"\n  Packet Capture Analyzer")
    print(f"  ─────────────────────────────────────")
    print(f"  App      →  {scheme}://localhost:{port}/")
    print(f"  Settings →  {scheme}://localhost:{port}/settings")
    if ssl_context:
        print(f"  SSL      →  enabled ({ssl_cert})")
    print(f"  Press Ctrl+C to stop\n")

    if sys.platform == "win32":
        threading.Thread(target=open_browser, args=(port, scheme), daemon=True).start()
    app.run(host="0.0.0.0", port=port, debug=False, ssl_context=ssl_context)
