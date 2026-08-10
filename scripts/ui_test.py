#!/usr/bin/env python3
"""Automated build + startup smoke check for the Nyx operator GUI.

Current architecture: crates/client-ui-web — Tauri 2 shell + React/Vite
frontend (the legacy Makepad `nyx-client-ui` binary was archived together
with nyx-cli). This script exercises:

  1. Frontend build:      npm run build   (tsc -b && vite build)
  2. Rust shell check:    cargo check -p nyx-client-ui-web
  3. Dev-server startup:  npm run dev, poll http://127.0.0.1:1420 until the
                          Vite server answers, then shut it down.

For a full interactive run (real webview window) use:
  ./scripts/dev_test.sh gui      # npm run tauri dev
"""
import os
import sys
import time
import signal
import urllib.request
import subprocess
from datetime import datetime

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GUI_DIR = os.path.join(_REPO_ROOT, "crates", "client-ui-web")
DEV_URL = "http://127.0.0.1:1420"  # vite.config.ts: strictPort 1420, host 127.0.0.1
LOG_DIR = os.path.join(_REPO_ROOT, "tmp", "ui_test")
LOG_FILE = os.path.join(LOG_DIR, "ui_test_results.log")


def log(msg):
    timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    line = f"[{timestamp}] {msg}"
    print(line)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")


def run_command(args, cwd=None):
    log(f"Running command: {' '.join(args)}")
    res = subprocess.run(args, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return res


def ensure_node_modules():
    if os.path.isdir(os.path.join(GUI_DIR, "node_modules")):
        return True
    log("node_modules missing, running npm install (first-time setup)...")
    res = run_command(["npm", "install"], cwd=GUI_DIR)
    if res.returncode != 0:
        log("ERROR: npm install failed!")
        log(f"stderr:\n{res.stderr}")
        return False
    return True


def main():
    os.makedirs(LOG_DIR, exist_ok=True)
    with open(LOG_FILE, "w") as f:
        f.write("=== Nyx Operator GUI (client-ui-web / Tauri 2 + React) Automated UI Test Run ===\n")

    log("Starting automated UI testing suite (crates/client-ui-web).")
    success = True

    if not os.path.isdir(GUI_DIR):
        log(f"ERROR: GUI directory not found: {GUI_DIR}")
        sys.exit(1)

    # 1. Frontend build (tsc type-check + vite production build)
    if ensure_node_modules():
        log("Step 1: Building frontend (npm run build)...")
        build_res = run_command(["npm", "run", "build"], cwd=GUI_DIR)
        if build_res.returncode != 0:
            log("ERROR: Frontend build failed!")
            log(f"stdout:\n{build_res.stdout}")
            log(f"stderr:\n{build_res.stderr}")
            success = False
        else:
            log("SUCCESS: frontend built successfully (dist/).")
    else:
        success = False

    # 2. Rust shell compile check (Tauri side; src-tauri has no unit tests)
    if success:
        log("Step 2: Checking Tauri Rust shell (cargo check -p nyx-client-ui-web)...")
        check_res = run_command(["cargo", "check", "-p", "nyx-client-ui-web"], cwd=_REPO_ROOT)
        if check_res.returncode != 0:
            log("ERROR: cargo check failed for nyx-client-ui-web!")
            log(f"stderr:\n{check_res.stderr}")
            success = False
        else:
            log("SUCCESS: nyx-client-ui-web Rust shell compiles.")

    # 3. Dev-server startup smoke check (Vite serves the app without crash)
    if success:
        log(f"Step 3: Verifying dev-server startup (npm run dev, polling {DEV_URL})...")
        proc = None
        try:
            proc = subprocess.Popen(
                ["npm", "run", "dev"],
                cwd=GUI_DIR,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                start_new_session=True,  # own process group so we can kill npm + vite
            )
            deadline = time.time() + 60
            up = False
            while time.time() < deadline:
                if proc.poll() is not None:
                    break  # exited prematurely
                try:
                    with urllib.request.urlopen(DEV_URL, timeout=2) as resp:
                        body = resp.read().decode("utf-8", errors="ignore")
                    if resp.status == 200 and "<div id=\"root\">" in body:
                        up = True
                        break
                except Exception:
                    time.sleep(1)
            if up:
                log("SUCCESS: Vite dev server is up and serving the React app.")
            else:
                code = proc.poll()
                out = proc.stdout.read().decode("utf-8", errors="ignore") if proc.stdout else ""
                log(f"ERROR: dev server did not come up (process exit: {code})!")
                log(f"output:\n{out}")
                success = False
        except Exception as e:
            log(f"ERROR: Failed to run dev-server startup test: {e}")
            success = False
        finally:
            if proc and proc.poll() is None:
                try:
                    os.killpg(proc.pid, signal.SIGTERM)
                    proc.wait(timeout=10)
                except Exception:
                    try:
                        os.killpg(proc.pid, signal.SIGKILL)
                    except Exception:
                        pass

    if success:
        log("=== ALL UI BUILD AND STARTUP CHECKS PASSED SUCCESSFULLY ===")
        sys.exit(0)
    else:
        log("=== UI TESTING SUITE DETECTED FAILURES ===")
        sys.exit(1)


if __name__ == "__main__":
    main()
