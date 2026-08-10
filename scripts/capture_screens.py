#!/usr/bin/env python3
"""Capture a screenshot of the Nyx operator GUI (crates/client-ui-web).

Current architecture: Tauri 2 shell + React/Vite frontend. The legacy
Makepad `nyx-client-ui` binary (and its NYX_AUTO_CONNECT / NYX_START_DARK
env vars) was archived; the new frontend has no such env hooks, so this
script captures the startup connect page and prints manual guidance for
further shots (dark mode, connected session, ...).

How it works:
  1. `npm run tauri dev` (starts Vite via beforeDevCommand, builds the
     Rust shell, opens the "Nyx Operator" webview window).
  2. Poll AppleScript System Events for the window geometry of the
     `nyx-client-ui-web` process, raise the window, then `screencapture -R`.
  3. If geometry lookup fails (e.g. missing Accessibility permission),
     fall back to a full-screen capture.

Requires macOS permissions for the invoking terminal: Accessibility
(System Events) and Screen Recording (screencapture). Output goes to
tmp/ui_test/screenshot_ui_1.png.
"""
import os
import signal
import subprocess
import sys
import time

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GUI_DIR = os.path.join(_REPO_ROOT, "crates", "client-ui-web")
PROCESS_NAME = "nyx-client-ui-web"  # dev binary name (src-tauri package)
OUT_DIR = os.path.join(_REPO_ROOT, "tmp", "ui_test")
OUT_PATH = os.path.join(OUT_DIR, "screenshot_ui_1.png")
WINDOW_TIMEOUT = 300  # cold Rust build of the Tauri shell can take minutes


def get_window_geometry():
    script = (
        f'tell application "System Events" to tell process "{PROCESS_NAME}" '
        "to get {position, size} of window 1"
    )
    res = subprocess.run(["osascript", "-e", script], capture_output=True, text=True)
    if res.returncode == 0:
        parts = [p.strip() for p in res.stdout.strip().split(",")]
        if len(parts) == 4:
            try:
                return [int(x) for x in parts]
            except ValueError:
                pass
    return None


def raise_window():
    subprocess.run(
        ["osascript", "-e",
         f'tell application "System Events" to tell process "{PROCESS_NAME}" to set frontmost to true'],
        capture_output=True,
    )
    subprocess.run(
        ["osascript", "-e",
         f'tell application "System Events" to tell process "{PROCESS_NAME}" '
         'to perform action "AXRaise" of window 1'],
        capture_output=True,
    )


def ensure_node_modules():
    if os.path.isdir(os.path.join(GUI_DIR, "node_modules")):
        return True
    print("node_modules missing, running npm install (first-time setup)...")
    return subprocess.run(["npm", "install"], cwd=GUI_DIR).returncode == 0


def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    if not os.path.isdir(GUI_DIR):
        print(f"ERROR: GUI directory not found: {GUI_DIR}", file=sys.stderr)
        sys.exit(1)
    if not ensure_node_modules():
        print("ERROR: npm install failed.", file=sys.stderr)
        sys.exit(1)

    print("Launching GUI via `npm run tauri dev` (this builds the Rust shell;")
    print("first run may take a few minutes)...")
    proc = subprocess.Popen(
        ["npm", "run", "tauri", "dev"],
        cwd=GUI_DIR,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.STDOUT,
        start_new_session=True,  # own process group: kill npm + cargo + app together
    )

    try:
        # Wait for the webview window to appear.
        geom = None
        deadline = time.time() + WINDOW_TIMEOUT
        while time.time() < deadline:
            if proc.poll() is not None:
                print(f"ERROR: `npm run tauri dev` exited prematurely (code {proc.returncode}).",
                      file=sys.stderr)
                sys.exit(1)
            geom = get_window_geometry()
            if geom:
                break
            time.sleep(2)
        if not geom:
            print("ERROR: GUI window did not appear within "
                  f"{WINDOW_TIMEOUT}s — cannot capture.", file=sys.stderr)
            sys.exit(1)

        raise_window()
        time.sleep(2)  # wait for render after raising

        x, y, w, h = geom
        rect = f"{x},{y},{w},{h}"
        print(f"Capturing window at rect: {rect} -> {OUT_PATH}")
        res = subprocess.run(["screencapture", f"-R{rect}", OUT_PATH])
        if res.returncode != 0 or not os.path.isfile(OUT_PATH):
            print("WARNING: window capture failed (Screen Recording permission "
                  "missing?), trying full-screen fallback...")
            res = subprocess.run(["screencapture", "-x", OUT_PATH])
            if res.returncode != 0 or not os.path.isfile(OUT_PATH):
                print("ERROR: screencapture failed. Grant the terminal Screen "
                      "Recording permission in System Settings and retry.",
                      file=sys.stderr)
                sys.exit(1)

        print(f"Screenshot saved: {OUT_PATH}")
        print()
        print("Further shots are manual (no env hooks in the new frontend):")
        print("  - connect page is what you just captured;")
        print("  - for a connected session: start server+agent via")
        print("    ./scripts/dev_test.sh server / agent, connect in the GUI")
        print("    (Server http://127.0.0.1:8443, Bearer dev:dev), re-run this")
        print("    script with the GUI already arranged, or capture manually")
        print("    with: screencapture -R<x,y,w,h> out.png")
    finally:
        if proc.poll() is None:
            try:
                os.killpg(proc.pid, signal.SIGTERM)
                proc.wait(timeout=15)
            except Exception:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except Exception:
                    pass


if __name__ == "__main__":
    main()
