#!/usr/bin/env python3
"""Automated build + test + startup smoke check for the Nyx operator GUI.

The egui client (`crates/client`) was removed — Makepad (`crates/client-ui`)
is the sole native GUI now, so this script only exercises that one binary.
"""
import os
import sys
import subprocess
import time
from datetime import datetime

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_FILE = os.path.join(_REPO_ROOT, ".agents", "worker_m2", "ui_test_results.log")


def log(msg):
    timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    line = f"[{timestamp}] {msg}"
    print(line)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")


def run_command(args, shell=False):
    log(f"Running command: {' '.join(args) if isinstance(args, list) else args}")
    res = subprocess.run(args, shell=shell, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return res


def main():
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    with open(LOG_FILE, "w") as f:
        f.write("=== Nyx GUI Client (Makepad) Automated UI Test Run ===\n")

    log("Starting automated UI testing suite (nyx-client-ui / Makepad).")
    success = True

    # 1. Compile Check
    log("Step 1: Compiling/Checking nyx-client-ui (Makepad)...")
    build_res = run_command(["cargo", "build", "-p", "nyx-client-ui"])
    if build_res.returncode != 0:
        log("ERROR: Compilation failed!")
        log(f"stdout:\n{build_res.stdout}")
        log(f"stderr:\n{build_res.stderr}")
        success = False
    else:
        log("SUCCESS: nyx-client-ui compiled successfully.")

    # 2. Run Cargo Tests
    if success:
        log("Step 2: Running cargo tests for nyx-client-ui...")
        test_res = run_command(["cargo", "test", "-p", "nyx-client-ui"])
        if test_res.returncode != 0:
            log("ERROR: nyx-client-ui tests failed!")
            log(f"stderr:\n{test_res.stderr}")
            success = False
        else:
            log("SUCCESS: nyx-client-ui tests passed.")
        log("Test output summary:")
        for line in test_res.stdout.splitlines():
            if "test result: ok" in line or "running" in line or "tests passed" in line:
                log(f"  [nyx-client-ui] {line}")

    # 3. Dry-run startup check (event loop initialises without crash)
    if success:
        log("Step 3: Verifying dry-run startup check for nyx-client-ui...")
        proc = None
        try:
            proc = subprocess.Popen(
                ["./target/debug/nyx-client-ui"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            time.sleep(2)
            poll = proc.poll()
            if poll is None:
                log("SUCCESS: nyx-client-ui started up and is running event loop.")
                proc.terminate()
                proc.wait(timeout=5)
            else:
                stdout, stderr = proc.communicate()
                log(f"ERROR: nyx-client-ui exited prematurely with code {poll}!")
                log(f"stdout:\n{stdout.decode('utf-8', errors='ignore')}")
                log(f"stderr:\n{stderr.decode('utf-8', errors='ignore')}")
                success = False
        except Exception as e:
            log(f"ERROR: Failed to run nyx-client-ui startup test: {e}")
            if proc:
                try:
                    proc.kill()
                except Exception:
                    pass
            success = False

    if success:
        log("=== ALL UI TESTS AND STARTUP CHECKS PASSED SUCCESSFULLY ===")
        sys.exit(0)
    else:
        log("=== UI TESTING SUITE DETECTED FAILURES ===")
        sys.exit(1)


if __name__ == "__main__":
    main()
