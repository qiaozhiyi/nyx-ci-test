#!/usr/bin/env python3
import subprocess
import time
import sys

def get_window_geometry():
    script = 'tell application "System Events" to tell process "nyx-client-ui" to get {position, size} of window 1'
    res = subprocess.run(["osascript", "-e", script], capture_output=True, text=True)
    if res.returncode == 0:
        out = res.stdout.strip()
        parts = [p.strip() for p in out.split(",")]
        if len(parts) == 4:
            return [int(x) for x in parts]
    return None

def raise_window():
    subprocess.run(["osascript", "-e", 'tell application "System Events" to tell process "nyx-client-ui" to set frontmost to true'])
    subprocess.run(["osascript", "-e", 'tell application "System Events" to tell process "nyx-client-ui" to perform action "AXRaise" of window 1'])

def capture_screenshot(output_path, env=None):
    proc = subprocess.Popen(["./target/gui/nyx-client-ui"], env=env)
    time.sleep(3) # wait for startup
    
    try:
        raise_window()
        time.sleep(1) # wait for render after raising
        
        geom = get_window_geometry()
        if geom:
            x, y, w, h = geom
            rect = f"{x},{y},{w},{h}"
            print(f"Capturing window at rect: {rect} -> {output_path}")
            subprocess.run(["screencapture", f"-R{rect}", output_path])
            return True
        else:
            print("Failed to get window geometry, capturing full screen as fallback")
            subprocess.run(["screencapture", "-x", output_path])
            return False
    finally:
        proc.terminate()
        proc.wait()

def main():
    import os
    _repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    # 1. Screenshot 1: default startup, disconnected (no env vars)
    print("Capturing Screenshot 1...")
    capture_screenshot(os.path.join(_repo_root, "screenshot_ui_1.png"))

    # 2. Screenshot 2: connected and dark mode (using our new env vars)
    print("Capturing Screenshot 2...")
    custom_env = os.environ.copy()
    custom_env["NYX_AUTO_CONNECT"] = "1"
    custom_env["NYX_START_DARK"] = "1"
    capture_screenshot(os.path.join(_repo_root, "screenshot_ui_2.png"), env=custom_env)

    print("Done capturing screenshots.")

if __name__ == "__main__":
    main()
