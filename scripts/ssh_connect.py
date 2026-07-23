#!/usr/bin/env python3
import os
import sys
import subprocess
import re

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
                
                # Split key and value (space or equal separated)
                parts = re.split(r'\s+|=', stripped, 1)
                if len(parts) < 2:
                    continue
                key = parts[0].strip().lower()
                val = parts[1].strip()
                
                if key == 'host':
                    # split by spaces to handle multiple hosts on one Host line
                    aliases = [a.strip() for a in re.split(r'\s+', val) if a.strip()]
                    current_host = {
                        'hosts': aliases,
                        'hostname': None
                    }
                    hosts.append(current_host)
                elif key == 'hostname' and current_host is not None:
                    current_host['hostname'] = val
    except Exception as e:
        print(f"Error reading/parsing ssh config: {e}", file=sys.stderr)
    return hosts

def find_alias(hosts):
    # 1. Explicit env override (no assumption about the alias name).
    # Honor both NYX_WIN_HOST and WIN_HOST (the latter matches win_deploy.sh).
    if os.environ.get('NYX_WIN_HOST'):
        return os.environ['NYX_WIN_HOST']
    if os.environ.get('WIN_HOST'):
        return os.environ['WIN_HOST']

    # 2. Search for entry with Host "win"
    for entry in hosts:
        if 'win' in entry['hosts']:
            return 'win'

    # 3. Fallback: if 'win' exists in hosts list at all (case-insensitive)
    for entry in hosts:
        for h in entry['hosts']:
            if 'win' in h.lower():
                return h

    return None

def main():
    config_path = os.path.expanduser("~/.ssh/config")
    print(f"Parsing SSH config at: {config_path}")
    hosts = parse_ssh_config(config_path)
    
    alias = find_alias(hosts)
    if not alias:
        print("Warning: Could not find alias in SSH config. Defaulting to 'win'.")
        alias = 'win'
    else:
        print(f"Found Windows server alias: {alias}")
        
    # Execute SSH command
    cmd = ["ssh", alias, "hostname"]
    print(f"Executing command: {' '.join(cmd)}")
    
    # Log under the repo's .agents/ tree (path relative to this script, no
    # hardcoded absolute path).
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    log_dir = os.path.join(repo_root, ".agents", "worker_m3")
    log_file = os.path.join(log_dir, "ssh_test_results.log")
    
    # Run the SSH command
    try:
        # Use subprocess.run to execute the command, capture output
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=30)
        stdout = result.stdout
        stderr = result.stderr
        exit_code = result.returncode
    except subprocess.TimeoutExpired as e:
        stdout = e.stdout.decode() if e.stdout else ""
        stderr = (e.stderr.decode() if e.stderr else "") + "\nCommand timed out."
        exit_code = -1
    except Exception as e:
        stdout = ""
        stderr = str(e)
        exit_code = -1
        
    output_log = []
    output_log.append("=== SSH Test Results ===")
    output_log.append(f"Alias: {alias}")
    output_log.append(f"Command: {' '.join(cmd)}")
    output_log.append(f"Exit Code: {exit_code}")
    output_log.append("--- Standard Output ---")
    output_log.append(stdout)
    output_log.append("--- Standard Error ---")
    output_log.append(stderr)
    output_log.append("========================")
    
    log_content = "\n".join(output_log)
    
    # Print to stdout
    print(log_content)
    
    # Write to log file
    os.makedirs(log_dir, exist_ok=True)
    try:
        with open(log_file, "w", encoding="utf-8") as f:
            f.write(log_content)
        print(f"Logs successfully written to: {log_file}")
    except Exception as e:
        print(f"Error writing log file: {e}", file=sys.stderr)
        
    sys.exit(exit_code)

if __name__ == "__main__":
    main()
