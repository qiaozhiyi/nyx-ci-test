# Nyx Framework Post-Exploitation Capabilities Security Audit Report

**Audit Target:** Nyx PIC Windows Implant Capabilities  
**Assigned Files:** `postex.rs`, `pivot.rs`, `fs.rs`, `shell.rs`, `screenshot.rs`, `keylog.rs`, `recon.rs`, `hashdump.rs`, `hostinfo.rs`, `transport.rs`  
**Date:** July 5, 2026  
**Auditor:** Security Reviewer Specialist  

---

## Executive Summary

A comprehensive code audit of the post-exploitation capability subsystem within the Windows PIC implant was performed. The audit revealed multiple security vulnerabilities, logic flaws, and operational risks (OPSEC/robustness issues). 

The most critical findings are:
1. A **File System Refusal Validation Bypass** in `fs.rs` that allows operators/users to circumvent blocklists and extract sensitive registry hives (e.g. SAM, SYSTEM) via path manipulation.
2. A **Pivoting Channel Collision & Routing Logic Bug** in `pivot.rs` that breaks the SOCKS5 BIND/reverse-pivoting relay, causing immediate connection drop upon any user data transfer.
3. A **Window Station Handle Leak and Potential Crash** in `screenshot.rs` that invalidates the host process's GUI session handle.
4. An **Incorrect CapsLock State Polling** in `keylog.rs` which degrades keylogging capture accuracy.

The detailed findings, impact, threat scenarios, and code-level remediations are documented below.

---

## Summary of Findings

| ID | Title | Severity | Affected File | Vulnerability Type |
| :--- | :--- | :--- | :--- | :--- |
| **NYX-CAP-01** | File System Refusal Check Bypass via Path Manipulation | **High** | `fs.rs` | Path Traversal / Validation Bypass |
| **NYX-CAP-02** | SOCKS BIND Socket Channel Collision & Routing Fail | **High** | `pivot.rs` | Logic Flaw / Denial of Service |
| **NYX-CAP-03** | Window Station Handle Closed Prematurely After Assignment | **Medium** | `screenshot.rs` | Resource Management / Potential Crash |
| **NYX-CAP-04** | CapsLock Toggle State Incorrectly Polled via `GetAsyncKeyState` | **Medium** | `keylog.rs` | Logic Flaw / Functional Issue |
| **NYX-CAP-05** | Fallback Registry Dump Failures Due to Existing Temp File | **Medium** | `hashdump.rs` | Robustness / Denial of Service |
| **NYX-CAP-06** | Hardcoded User Account in Cross-Session Task Creation | **Medium** | `screenshot.rs` | OPSEC / Localization Failure |
| **NYX-CAP-07** | Blocking Sequential Port Scan Causes Long Blackouts | **Low** | `recon.rs` | Performance / OPSEC Hazard |
| **NYX-CAP-08** | Truncated HTTP Response Data Returned on Limit Overflow | **Low** | `transport.rs` | Error Handling / Logic Flaw |

---

## Detailed Findings

### NYX-CAP-01: File System Refusal Check Bypass via Path Manipulation
* **Severity:** **High**
* **Affected Code:** `crates/implant-win/src/fs.rs`, `allowed` function (lines 162–179)
* **Vulnerability Description:**  
  The implant implements an `allowed` path check to refuse read/write/delete operations on sensitive registry hive files (`SAM`, `SYSTEM`, `SECURITY`, `SOFTWARE`, `DEFAULT`) to enforce engagement safety or security boundaries. However, this check is implemented by splitting the path string on standard delimiters (`/` and `\`) and comparing adjacent components in pairs using `.windows(2)` looking for `"config"` followed by a hive name.
  
  This check is easily bypassed in two ways:
  1. **Double Slashes (`\\` or `//`):** If an operator passes a path with double backslashes, such as `C:\Windows\System32\config\\SAM`, the split yields empty string components: `["C:", "Windows", "System32", "config", "", "SAM"]`. The window check fails to catch the `"config"` and `"SAM"` adjacency, allowing the path.
  2. **Relative Current Directory Dot (`.`):** If the path contains `C:\Windows\System32\config\.\SAM`, the components are split into `["C:", "Windows", "System32", "config", ".", "SAM"]`. The window checks are `("config", ".")` and `(".", "SAM")`, both of which bypass the filter.
  
  When these bypassed paths are sent to the NT Object Manager via `NtCreateFile`, it resolves double slashes and directory dots, opening the sensitive files successfully.
* **Threat Scenario:**  
  An operator or compromised agent can bypass safety guardrails to retrieve critical credential databases (`SAM`/`SYSTEM` hives) or corrupt security hives, violating operational bounds or constraints.
* **Remediation Fix:**  
  Prior to performing split checks, normalize the path by collapsing redundant delimiters (e.g. `\\` to `\`) and resolving relative components (`.` and `..`). Alternatively, search the fully normalized lowercase path string directly for sub-patterns (e.g. `\config\sam`, `\config\system`) rather than relying on structural split iterators.

  ```rust
  // Safe normalization and direct substring check
  fn allowed(path: &str) -> bool {
      // Normalize delimiters and convert to lowercase
      let mut normalized = String::with_capacity(path.len());
      let mut last_was_slash = false;
      for c in path.chars() {
          if c == '/' || c == '\\' {
              if !last_was_slash {
                  normalized.push('\\');
                  last_was_slash = true;
              }
          } else {
              normalized.push(c.to_ascii_lowercase());
              last_was_slash = false;
          }
      }
      
      // Simple substring search for blocked sequences
      let blocked = [
          "\\config\\sam",
          "\\config\\system",
          "\\config\\security",
          "\\config\\software",
          "\\config\\default",
      ];
      for &b in &blocked {
          if normalized.contains(b) {
              return false;
          }
      }
      true
  }
  ```

---

### NYX-CAP-02: SOCKS BIND Socket Channel Collision & Routing Fail
* **Severity:** **High**
* **Affected Code:** `crates/implant-win/src/pivot.rs`, `slot_of` and `channel_data` / `pump_channels`
* **Vulnerability Description:**  
  In the reverse-pivoting SOCKS5 BIND implementation (`op 2`), a listening socket is registered in the fixed-size `CHANNELS` array under a specific channel ID (e.g. `chan = 123`). When a client connects to this listener, `pump_channels` accepts it and calls `add_channel_kind(c.chan, peer, false)` to add the accepted client socket using the *same* channel ID.
  
  This creates a table collision where two different sockets have the exact same channel ID: one listening (passive) socket, and one active connection socket. When the operator sends data down the channel via `Command::ChannelData`, the routing function calls `slot_of(chan)` to get the slot index. `slot_of` iterates over `CHANNELS` and returns the first match it finds, which is always the listening socket.
* **Threat Scenario:**  
  When data is sent from the operator to the destination through the reverse SOCKS bridge, the implant attempts to write the payload to the listening socket. This results in a Winsock send error (since sending on a listening socket is invalid), which immediately triggers a socket shutdown, closing the channel and rendering the entire SOCKS BIND relay feature non-functional.
* **Remediation Fix:**  
  Modify the channel routing lookup so that it explicitly skips listening sockets when routing incoming operator data.

  ```rust
  // Fix slot_of to skip listening sockets when looking for data routing destinations
  unsafe fn slot_of_active(chan: u32) -> Option<usize> {
      for i in 0..MAX_CHANNELS {
          if let Some(c) = unsafe { CHANNELS[i] } {
              if c.chan == chan && !c.listening {
                  return Some(i);
              }
          }
      }
      None
  }
  ```

---

### NYX-CAP-03: Window Station Handle Closed Prematurely After Assignment
* **Severity:** **Medium**
* **Affected Code:** `crates/implant-win/src/screenshot.rs`, `attach_interactive` function (line 280)
* **Vulnerability Description:**  
  To capture screenshots from Session 0 (SYSTEM context), the implant opens the interactive window station `WinSta0` via `OpenWindowStationW`, assigns it to the process via `SetProcessWindowStation(hwinsta)`, and then immediately calls `CloseWindowStation(hwinsta)`.
  
  According to MSDN, developers must not close the handle to a window station currently assigned to a process. Doing so invalidates the process's active session resources, making it impossible for the process to open subsequent GUI/GDI objects, and potentially leading to GDI leaks, undefined behavior, or process crashes.
* **Threat Scenario:**  
  If the implant executes a direct screenshot capture in Path 1, it permanently damages the beacon's access to the window station, causing any subsequent screenshots or graphical operations to fail or crash the beacon process entirely.
* **Remediation Fix:**  
  Do not close the window station handle while it is assigned. Ideally, the implant should query and save the original window station first, apply the new one, perform the capture, restore the original, and only then close the temporary handles.

  ```rust
  // Safe window station swapping structure
  let mut original_winsta: *mut c_void = core::ptr::null_mut();
  type GetProcessWindowStation = unsafe extern "system" fn() -> *mut c_void;
  if let Some(addr) = unsafe { crate::resolve::export_addr(b"user32.dll", b"GetProcessWindowStation") } {
      let gpws: GetProcessWindowStation = core::mem::transmute(addr);
      original_winsta = gpws();
  }
  // ... swap to WinSta0 ...
  // [Perform capture operation]
  // ... restore original ...
  if !original_winsta.is_null() {
      spws(original_winsta);
  }
  cws(hwinsta); // Safe to close now that it is no longer active
  ```

---

### NYX-CAP-04: CapsLock Toggle State Incorrectly Polled via `GetAsyncKeyState`
* **Severity:** **Medium**
* **Affected Code:** `crates/implant-win/src/keylog.rs`, `poll_once` function (line 217)
* **Vulnerability Description:**  
  The keylogger attempts to detect whether CapsLock is active by checking the low-order bit (0x0001) of `GetAsyncKeyState(VK_CAPITAL)`: `caps = (unsafe { gaks(VK_CAPITAL) } & 1) != 0;`.
  
  This is a logical misconception. In `GetAsyncKeyState`, the least significant bit indicates whether the key was pressed since the last call to `GetAsyncKeyState` (and is often unreliable or always zero on modern Windows). It does *not* represent the persistent toggle status of the lock.
* **Threat Scenario:**  
  The keylogger will record characters with incorrect capitalization, swapping cases arbitrarily based on whether CapsLock happened to be pressed in the polling window rather than whether the light is on, corrupting captured credentials or logs.
* **Remediation Fix:**  
  Resolve and use `GetKeyState` instead of `GetAsyncKeyState` to query the CapsLock toggle status. The low-order bit of `GetKeyState` correctly maps to the toggle state.

  ```rust
  type GetKeyState = unsafe extern "system" fn(i32) -> i16;
  let gks: GetKeyState = match unsafe { export_addr(b"user32.dll", b"GetKeyState") } {
      Some(a) => core::mem::transmute(a),
      None => return,
  };
  let caps = (unsafe { gks(VK_CAPITAL) } & 1) != 0; // Correctly queries toggle state
  ```

---

### NYX-CAP-05: Fallback Registry Dump Failures Due to Existing Temp File
* **Severity:** **Medium**
* **Affected Code:** `crates/implant-win/src/hashdump.rs`, `save_hive_fallback` function (line 522)
* **Vulnerability Description:**  
  When raw file reading fails due to exclusive system locks (oplocks), `do_hashdump` falls back to using the Configuration Manager to write the hive to `C:\Windows\Temp\<chunk_name>.hive` via `RegSaveKeyW`. 
  
  If that file already exists—either because a prior deletion attempt failed (e.g. handle lock, path permissions) or because the implant was interrupted before the cleanup routine ran—`RegSaveKeyW` fails with `ERROR_ALREADY_EXISTS` (183) because it refuses to overwrite existing files.
* **Threat Scenario:**  
  A single interrupted or failed hashdump operation leaves a stale `.hive` file in `C:\Windows\Temp\`, permanently blocking all future hashdump commands from succeeding.
* **Remediation Fix:**  
  Explicitly call `DeleteFileW` on the destination file path immediately prior to invoking `RegSaveKeyW` inside `save_hive_fallback`.

  ```rust
  // Attempt to delete existing temp file before saving key
  type DeleteFileW = unsafe extern "system" fn(*const u16) -> i32;
  if let Some(addr) = unsafe { export_addr(b"kernel32.dll", b"DeleteFileW") } {
      let df: DeleteFileW = core::mem::transmute(addr);
      unsafe { df(file_wide.as_ptr()) };
  }
  let rc = unsafe { save(hkey, file_wide.as_ptr(), core::ptr::null()) };
  ```

---

### NYX-CAP-06: Hardcoded User Account in Cross-Session Task Creation
* **Severity:** **Medium**
* **Affected Code:** `crates/implant-win/src/screenshot.rs`, `cross_session_capture` function (line 759)
* **Vulnerability Description:**  
  The cross-session screenshot capture creates a scheduled task to launch the GDI capture helper in the user's interactive session. The command line is hardcoded to run as `/ru administrator`.
* **Threat Scenario:**  
  On non-English localized installations (where the account name is "Administrateur", "Administrador", etc.), or in hardened environments where the default administrator account is renamed or disabled, task registration fails with an account lookup error. This prevents cross-session screenshots from executing.
* **Remediation Fix:**  
  Query the active username dynamically, or omit the `/ru` parameter (defaulting to the current execution context) if the implant is already running under the desired target account token.

---

### NYX-CAP-07: Blocking Sequential Port Scan Causes Long Blackouts
* **Severity:** **Low**
* **Affected Code:** `crates/implant-win/src/recon.rs`, `do_portscan` and `probe_one` (lines 509, 617)
* **Vulnerability Description:**  
  The `do_portscan` function iterates through target ports sequentially on the main beacon thread. Each closed or filtered port triggers a blocking `select` call with a 2-second timeout.
* **Threat Scenario:**  
  If an operator requests a scan of 100 ports, and the ports are filtered or closed, the single-threaded beacon loop blocks sequentially for up to 200 seconds. During this period, the implant cannot check-in or execute other urgent commands. This long blackout period is highly anomalous and can trigger EDR communication warnings.
* **Remediation Fix:**  
  Perform asynchronous multi-socket polling using an array of sockets inside a single `select` loop, or reduce the port scan timeout to a lower value (e.g. 250ms).

---

### NYX-CAP-08: Truncated HTTP Response Data Returned on Limit Overflow
* **Severity:** **Low**
* **Affected Code:** `crates/implant-win/src/transport.rs`, `post_frame` function (lines 342–345)
* **Vulnerability Description:**  
  In `post_frame`, if the response from the C2 server exceeds `MAX_RESPONSE_BYTES` (16 MiB), the loop breaks, but the function still returns the partially read bytes.
* **Threat Scenario:**  
  Returning truncated, incomplete ciphertext causes decryption and frame parsing failures in the outer loop, which can lead to anomalous crashes or protocol errors rather than a clean transport failure report.
* **Remediation Fix:**  
  If the response length exceeds the limit, discard the buffer and return `None` to indicate a clean transport error.
