#!/usr/bin/env python3
import os
import sys
import subprocess
import re

# Expected exit codes for the self-test exports
EXPECTED_CODES = {
    "nyx_selftest_calib42": 42,
    "nyx_selftest_config": 3,
    "nyx_selftest_hostinfo": 15,
    "nyx_selftest_antidebug": 7,
    "nyx_selftest_recon": 7,
    "nyx_selftest_shell": 1,
    "nyx_selftest_fs": 127,
    "nyx_selftest_bof": 1
}

# Bitmask interpretations for each export
BITMASK_DOC = {
    "nyx_selftest_calib42": {
        # calibration: just checks exit code 42
    },
    "nyx_selftest_config": {
        0: "Decode succeeds",
        1: "Fields match expected serialized values"
    },
    "nyx_selftest_hostinfo": {
        0: "Hostname is non-empty and non-placeholder",
        1: "Username is non-empty and non-placeholder",
        2: "PID is non-zero",
        3: "Beacon ID is non-default (not 0x1337)"
    },
    "nyx_selftest_antidebug": {
        0: "BeingDebugged PEB flag is false",
        1: "Uptime is greater than 0",
        2: "Syscall query completed without panic"
    },
    "nyx_selftest_recon": {
        0: "DriveInfo is non-empty",
        1: "Environment PATH variable is non-empty and contains '='",
        2: "Network interfaces are non-empty"
    },
    "nyx_selftest_shell": {
        0: "Captured stdout of 'echo' matches expected marker"
    },
    "nyx_selftest_fs": {
        0: "Upload writes file successfully via NT syscall",
        1: "Download reads file back and contents match",
        2: "Mv command successfully renames file",
        3: "Cp command successfully copies file",
        4: "Mkdir creates directory, and Cd succeeds into it",
        5: "Rm command is gated and returns expected error",
        6: "Indirect-syscall runtime is successfully initialized"
    },
    "nyx_selftest_bof": {
        0: "BOF output contains 'BOF-PRINT-OK' (parsed, mapped, relocated, and run correctly)"
    }
}

def parse_ssh_config(config_path):
    if not os.path.exists(config_path):
        return []
    hosts = []
    current_host = None
    try:
        with open(config_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                stripped = line.strip()
                if not stripped or stripped.startswith('#'):
                    continue
                parts = re.split(r'\s+|=', stripped, 1)
                if len(parts) < 2:
                    continue
                key = parts[0].strip().lower()
                val = parts[1].strip()
                if key == 'host':
                    aliases = [a.strip() for a in re.split(r'\s+', val) if a.strip()]
                    current_host = {
                        'hosts': aliases,
                        'hostname': None
                    }
                    hosts.append(current_host)
                elif key == 'hostname' and current_host is not None:
                    current_host['hostname'] = val
    except Exception as e:
        print(f"Error parsing SSH config: {e}", file=sys.stderr)
    return hosts

def find_alias(hosts):
    for entry in hosts:
        if 'win' in entry['hosts']:
            return 'win'
    for entry in hosts:
        if entry['hostname'] == '154.201.73.67':
            if entry['hosts']:
                return entry['hosts'][0]
    for entry in hosts:
        for h in entry['hosts']:
            if 'win' in h.lower():
                return h
    return 'win'

def main():
    log_messages = []
    def log(msg):
        print(msg)
        log_messages.append(msg)

    log("Starting remote test execution script.")
    
    # 1. Resolve SSH alias
    config_path = os.path.expanduser("~/.ssh/config")
    hosts = parse_ssh_config(config_path)
    ssh_alias = find_alias(hosts)
    log(f"Resolved Windows server SSH alias: {ssh_alias}")

    # Paths
    local_dll = "/Users/qiaozhiyi/Desktop/pentest/crates/implant-win/target/x86_64-pc-windows-gnu/release/nyx_implant_win.dll"
    remote_dir = "C:\\nyx"
    remote_dll = f"{remote_dir}\\nyx_implant_win.dll"

    # 2. Copy DLL via SCP
    log(f"Creating remote directory {remote_dir} if it does not exist...")
    mkdir_cmd = ["ssh", ssh_alias, f"mkdir {remote_dir} 2>nul || echo directory already exists"]
    try:
        subprocess.run(mkdir_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
    except Exception as e:
        log(f"Warning: directory creation output or error: {e}")

    remote_dll_unix = remote_dll.replace('\\', '/')
    scp_cmd = ["scp", local_dll, f"{ssh_alias}:{remote_dll_unix}"]
    try:
        subprocess.run(scp_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
        log("SCP copy completed successfully.")
    except subprocess.CalledProcessError as e:
        log(f"Error: SCP failed: {e.stderr}")
        sys.exit(1)

    # 3. Run each export and verify
    test_results = {}
    
    for export, expected in EXPECTED_CODES.items():
        log(f"Running test: {export} (expected exit code: {expected})")
        # To get the real exit code of the rundll32 process, we run start-process in PowerShell and query the ExitCode.
        # This resolves issues where cmd errorlevel returns 0, or rundll32 executes asynchronously.
        ps_command = f"$p = Start-Process rundll32.exe -ArgumentList '{remote_dll},{export}' -PassThru -Wait; $p.ExitCode"
        ssh_cmd = ["ssh", ssh_alias, f"powershell.exe -Command \"{ps_command}\""]
        
        try:
            res = subprocess.run(ssh_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=30)
            stdout_str = res.stdout.strip()
            stderr_str = res.stderr.strip()
            
            # Attempt to parse integer exit code from stdout
            if stdout_str:
                # Find the last line that might contain the exit code (in case there's warning output)
                lines = [l.strip() for l in stdout_str.splitlines() if l.strip()]
                exit_code = None
                for line in reversed(lines):
                    try:
                        exit_code = int(line)
                        break
                    except ValueError:
                        continue
                if exit_code is None:
                    log(f"Warning: Could not parse exit code from stdout: '{stdout_str}'")
                    exit_code = -999
            else:
                exit_code = -999
                
            log(f"Result for {export}: exit code = {exit_code} (stdout: '{stdout_str}', stderr: '{stderr_str}')")
            test_results[export] = {
                "exit_code": exit_code,
                "expected": expected,
                "stdout": stdout_str,
                "stderr": stderr_str,
                "passed": exit_code == expected
            }
        except subprocess.TimeoutExpired:
            log(f"Error: Test {export} timed out.")
            test_results[export] = {
                "exit_code": -1,
                "expected": expected,
                "stdout": "",
                "stderr": "Timeout expired",
                "passed": False
            }
        except Exception as e:
            log(f"Error executing test {export}: {e}")
            test_results[export] = {
                "exit_code": -1,
                "expected": expected,
                "stdout": "",
                "stderr": str(e),
                "passed": False
            }

    # 4. Generate Markdown Report
    report_lines = []
    report_lines.append("# Nyx Implant Win Functional Test Report")
    report_lines.append("")
    report_lines.append("## Overview")
    report_lines.append("This report details the execution and results of the built-in self-tests of the Windows position-independent implant DLL (`nyx_implant_win.dll`). The tests were executed on the remote Windows server via SSH, using `rundll32.exe` to trigger each exported self-test method.")
    report_lines.append("")
    
    total_tests = len(EXPECTED_CODES)
    passed_tests = sum(1 for r in test_results.values() if r["passed"])
    report_lines.append(f"- **Total Tests Executed:** {total_tests}")
    report_lines.append(f"- **Passed Tests:** {passed_tests}")
    report_lines.append(f"- **Failed Tests:** {total_tests - passed_tests}")
    report_lines.append("")
    
    report_lines.append("## Summary Table")
    report_lines.append("| Test Export Name | Expected Exit Code | Actual Exit Code | Result |")
    report_lines.append("| --- | --- | --- | --- |")
    for export, res in test_results.items():
        status = "✅ PASS" if res["passed"] else "❌ FAIL"
        report_lines.append(f"| `{export}` | `{res['expected']}` | `{res['exit_code']}` | {status} |")
    report_lines.append("")
    
    report_lines.append("## Detailed Test Breakdown")
    for export, res in test_results.items():
        report_lines.append(f"### `{export}`")
        status = "Passed" if res["passed"] else "Failed"
        report_lines.append(f"- **Status:** {status}")
        report_lines.append(f"- **Expected Exit Code:** `{res['expected']}`")
        report_lines.append(f"- **Actual Exit Code:** `{res['exit_code']}`")
        if res["stderr"]:
            report_lines.append(f"- **Stderr Output:** `{res['stderr']}`")
            
        # Parse the bitmask
        if export in BITMASK_DOC and BITMASK_DOC[export]:
            report_lines.append("- **Sub-check details (Bitmask parsing):**")
            bit_checks = BITMASK_DOC[export]
            actual_code = res["exit_code"]
            
            if actual_code == 0xFFFF_FFFE:
                report_lines.append("  - ❌ Indirect Syscall Runtime Bootstrap failed")
            elif actual_code == -999 or actual_code < 0:
                report_lines.append("  - ❌ Execution / Parse error")
            else:
                for bit, desc in bit_checks.items():
                    passed_sub = bool(actual_code & (1 << bit))
                    status_sub = "✅ PASS" if passed_sub else "❌ FAIL"
                    report_lines.append(f"  - [{status_sub}] Bit {bit}: {desc}")
        elif export == "nyx_selftest_calib42":
            report_lines.append("- **Description:** Calibrates ExitProcess exit code propagation via rundll32. (42 implies exact propagation works).")
            
        report_lines.append("")

    report_content = "\n".join(report_lines)
    
    # Write report to orchestrator folder
    report_path = "/Users/qiaozhiyi/Desktop/pentest/.agents/orchestrator/remote_tests_report.md"
    os.makedirs(os.path.dirname(report_path), exist_ok=True)
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(report_content)
    log(f"Functional test report written to: {report_path}")

    # Write log to worker_m4 folder
    log_path = "/Users/qiaozhiyi/Desktop/pentest/.agents/worker_m4/remote_tests.log"
    os.makedirs(os.path.dirname(log_path), exist_ok=True)
    with open(log_path, "w", encoding="utf-8") as f:
        f.write("\n".join(log_messages))
    log(f"Execution log written to: {log_path}")

if __name__ == "__main__":
    main()
