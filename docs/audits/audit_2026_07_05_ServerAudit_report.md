# Nyx Team Server Security Audit Report

## 1. Executive Summary
This document presents the security audit findings for the **Nyx Team Server** and the associated **Credential Store** modules. The scope of this audit covers:
* Control API routing and authorization validation (`NYX_TOKEN`).
* Operator authentication, credential parsing, and role boundaries.
* Database storage queries (rusqlite/SQL injection checks).
* Credential masking logic.
* Action audit log hash-chain verification and retrieval logic.
* Request payload sizes and connection limits/DoS vectors.

Multiple critical and high-severity issues were identified:
1. **Silent config parsing failures failing open**, allowing unauthenticated administrative control access.
2. **Missing role enforcement on control API routes**, enabling read-only `Viewer` operators to run commands on implants, add/delete credentials, and view plain secrets.
3. **Absence of TCP/TLS timeouts in connection sniffing**, creating a classic socket exhaustion (Slowloris) vulnerability.
4. **Audit log hash-chain field-shifting vulnerability**, making the integrity chain bypassable by moving characters between concatenated log fields.
5. **Constant-time comparison length leak**, revealing the token length.
6. **Denial of Service/OOM vulnerability in audit queries** due to loading whole files into memory.

Below is a detailed breakdown of each finding, threat scenarios, and the exact code fixes.

---

## 2. Summary of Findings

| ID | Severity | Finding Title | Affected File(s) | Component |
|---|---|---|---|---|
| **NYX-SRV-01** | **Critical** | Silent Parsing Errors on Operator Registry Fail Open | `crates/server/src/operators.rs` | Auth / Config |
| **NYX-SRV-02** | **High** | Privilege Escalation / Missing Role Check (Viewer Bypass) | `crates/server/src/lib.rs` | Control API |
| **NYX-SRV-03** | **High** | Connection / TLS Handshake Slowloris Denial of Service | `crates/server/src/main.rs` | Networking |
| **NYX-SRV-04** | **Medium** | Cryptographic Hash Collision / Byte Shifting in Audit Chain | `crates/server/src/audit.rs` | Audit Logging |
| **NYX-SRV-05** | **Medium** | Insecure Constant-Time Token Comparison Leaks Length | `crates/server/src/lib.rs` | Auth |
| **NYX-SRV-06** | **Medium** | DoS / OOM Risk in Audit Log Query Loading Entire File | `crates/server/src/audit.rs` | Audit Logging |
| **NYX-SRV-07** | **Low** | Cryptographic Leak of Password Trends in Masking Logic | `crates/store/src/model.rs` | Cred Vault |

---

## 3. Detailed Findings

### NYX-SRV-01: Silent Parsing Errors on Operator Registry Fail Open
* **Severity**: **Critical**
* **Affected Code**: `crates/server/src/operators.rs`, `OperatorRegistry::load_or_bootstrap` (Lines 125-131).
* **Description**:
  When the team server starts up, it attempts to load the multi-operator registry JSON file from disk. If the file exists but is corrupted, empty, or has syntax errors, `serde_json::from_str::<Vec<OperatorRecord>>(&txt)` fails. Instead of propagating the error and stopping the server, the code handles it with `.unwrap_or_default()`, silently ignoring the corruption and yielding an empty registry. 
  
  If the operator map is empty, `is_open()` returns `true`. If `NYX_TOKEN` is unset in the environment, the server automatically transitions into "open mode", permitting any anonymous connection to log in with `_anonymous` identity and administrative privileges (`Role::Admin`).
* **Threat Scenario**:
  A server restarts (e.g., following a crash or an OS upgrade) and reads an `operators.json` file that was corrupted during a dirty shutdown. The registry fails to load, returning an empty map. Because `NYX_TOKEN` was unset (as the project moved to multi-op mode), the server starts in open mode. An attacker scanning the internet discovers the open ports and assumes full administrative control over the team server and all active implants.
* **Exact Fix**:
  Do not ignore parsing errors. Propagate the error using `?` so that the team server fails to start, forcing the operator to restore or fix the corrupted registry file.
  
  *Modification in `crates/server/src/operators.rs`:*
  ```rust
  // Change this:
  let parsed: Vec<OperatorRecord> = serde_json::from_str(&txt).unwrap_or_default();
  
  // To this:
  let parsed: Vec<OperatorRecord> = serde_json::from_str(&txt)
      .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("operators file parse error: {e}")))?;
  ```

---

### NYX-SRV-02: Privilege Escalation / Missing Role Check (Viewer Bypass)
* **Severity**: **High**
* **Affected Code**: `crates/server/src/lib.rs`, functions `post_task`, `list_creds`, `post_creds`, `delete_cred`, `verify_audit`.
* **Description**:
  The system defines three roles: `Admin`, `Operator`, and `Viewer`. However, these roles are only checked in the `get_audit` handler (to restrict non-admin operator views). 
  Control API routes such as `POST /api/task` (which executes tasks on implants), `POST /api/creds` (add/update credentials), `POST /api/creds/delete` (delete credentials), and `GET /api/creds?reveal=1` (reveal plain passwords) only verify that the user is *authenticated* (via `require_auth` or `authenticate`), without enforcing their specific role capabilities. As a result, a `Viewer` can execute tasks, extract cleartext credentials, or delete records.
* **Threat Scenario**:
  A red team operator registers a new guest or external auditor with the `Viewer` role to watch active beacons. The auditor, using the assigned credentials, intercepts or directly sends requests to `POST /api/task` or `GET /api/creds?reveal=1`. The server performs no role validation and executes the commands or dumps domain admin credentials in cleartext.
* **Exact Fix**:
  Enforce roles in sensitive routes. Deny actions for `Role::Viewer` in write or credential-revealing paths.
  
  *Modification in `crates/server/src/lib.rs` (example in `post_task`):*
  ```rust
  async fn post_task(
      State(st): State<Arc<AppState>>,
      headers: HeaderMap,
      Json(req): Json<TaskReq>,
  ) -> Response {
      let op = match authenticate(&st, &headers) {
          AuthOutcome::Allowed(o) => o,
          AuthOutcome::Denied(r) => return r,
      };
      if op.role == operators::Role::Viewer {
          return (StatusCode::FORBIDDEN, "forbidden: viewer role cannot task beacons").into_response();
      }
      // ...
  }
  ```
  Apply similar checks to `post_creds`, `delete_cred`, and `list_creds` (when `reveal == 1`).

---

### NYX-SRV-03: Connection / TLS Handshake Slowloris Denial of Service
* **Severity**: **High**
* **Affected Code**: `crates/server/src/main.rs`, `sniff_and_store` function and the TLS connection spawning block (Lines 176-204).
* **Description**:
  When TLS is enabled, the server peeks the TLS ClientHello using `sniff_and_store` before delegating to `rustls` to complete the handshake. However, `sniff_and_store` uses `read_exact` to read the header (5 bytes) and payload (up to 16 KiB) directly from the socket without a timeout. Furthermore, `acceptor.accept(stream)` also executes without a timeout wrapper.
  Since each connection runs inside a spawned tokio task, an attacker can open thousands of TCP connections, send a single byte, and hold the sockets open. This keeps the tasks pending indefinitely, leading to socket and descriptor exhaustion.
* **Threat Scenario**:
  An attacker opens thousands of connections to the team server and sends nothing. The server spawns thousands of tokio tasks that block forever on `read_exact`. When legitimate operators attempt to log in or implants check in, the server has exhausted its file descriptor limit and refuses new connections.
* **Exact Fix**:
  Wrap socket peeking and TLS handshakes in `tokio::time::timeout` blocks.
  
  *Modification in `crates/server/src/main.rs`:*
  ```rust
  tokio::spawn(async move {
      let timeout_dur = std::time::Duration::from_secs(5);
      
      // Wrap ClientHello sniffing in a timeout
      let stream = match tokio::time::timeout(timeout_dur, sniff_and_store(stream, peer, fps)).await {
          Ok(Ok(s)) => s,
          _ => {
              tracing::debug!(%peer, "ClientHello sniff timed out or failed");
              return;
          }
      };
      
      // Wrap TLS handshake in a timeout
      match tokio::time::timeout(timeout_dur, acc.accept(stream)).await {
          Ok(Ok(tls)) => {
              // ... proceed with serving ...
          }
          _ => tracing::debug!(%peer, "TLS handshake timed out or failed"),
      }
  });
  ```

---

### NYX-SRV-04: Cryptographic Hash Collision / Byte Shifting in Audit Chain
* **Severity**: **Medium**
* **Affected Code**: `crates/server/src/audit.rs`, `hash_record` function (Lines 201-219).
* **Description**:
  The `hash_record` function calculates a SHA-256 hash across multiple variables to construct the hash-chain link:
  `hash = H(seq || ts || operator || action || target || detail_json || prev_hash)`.
  However, these fields are concatenated directly without delimiters or length-prefixes:
  ```rust
  h.update(operator.as_bytes());
  h.update(action.as_bytes());
  h.update(target.as_bytes());
  h.update(detail_json.as_bytes());
  ```
  Since `operator`, `action`, `target`, and `detail_json` are variable-length string fields, characters can be shifted between adjacent fields without changing the overall byte stream. Consequently, the recomputed hash remains identical, rendering the integrity check blind to byte-shifting modifications.
* **Threat Scenario**:
  An operator named `alice` performs a malicious action `delete` on target `session_1`. The resulting concatenation contains `alicedeletesession_1`. An attacker alters the log line to `operator = "al"`, `action = "icedelete"`, `target = "session_1"`. The recomputed hash remains valid, and the audit verification passes with no integrity errors, enabling attribution evasion.
* **Exact Fix**:
  Inject length-prefixes (as `u64` le bytes) for each variable-length string field before feeding their content to `Sha256::update`. This establishes clear field boundaries and guarantees domain separation.
  
  *Modification in `crates/server/src/audit.rs`:*
  ```rust
  fn hash_record(
      seq: u64,
      ts: u64,
      operator: &str,
      action: &str,
      target: &str,
      detail_json: &str,
      prev_hash: &str,
  ) -> String {
      let mut h = Sha256::new();
      h.update(seq.to_le_bytes());
      h.update(ts.to_le_bytes());
      
      // Wrap variable-length fields with length prefixes
      let fields = [operator, action, target, detail_json, prev_hash];
      for f in fields {
          h.update((f.len() as u64).to_le_bytes());
          h.update(f.as_bytes());
      }
      hex::encode(h.finalize())
  }
  ```

---

### NYX-SRV-05: Insecure Constant-Time Token Comparison Leaks Length
* **Severity**: **Medium**
* **Affected Code**: `crates/server/src/lib.rs`, `constant_time_eq` function (Lines 441-454).
* **Description**:
  The `constant_time_eq` function compares byte slices and incorporates a length-mismatch check to prevent timing leaks. However, the loop iterates using `.zip()`:
  ```rust
  for (x, y) in a.iter().zip(b.iter()) {
      diff |= x ^ y;
  }
  ```
  The `.zip()` iterator halts when the shorter input is exhausted. Thus, the total loop iterations are bounded by `min(a.len(), b.len())`. An attacker can measure the processing duration of requests with varying token lengths. The point where the timing response flattens indicates when the attacker's inputs exceed the target token's length, leaking the exact length of the secret token.
* **Threat Scenario**:
  An attacker aims to brute-force the control API. First, they measure the request round-trip time across different token lengths. They identify a timing inflection point at 32 characters, indicating the token length is exactly 32. This drastically narrows the keyspace required for a brute-force attack.
* **Exact Fix**:
  Hash both inputs using SHA-256 before doing the comparison. This normalizes both inputs to exactly 32 bytes and ensures that the comparison loop always runs exactly 32 times, completely neutralizing length-based timing leaks.
  
  *Modification in `crates/server/src/lib.rs`:*
  ```rust
  pub(crate) fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
      use sha2::{Digest, Sha256};
      
      let mut ha = Sha256::new();
      ha.update(a);
      let digest_a = ha.finalize();
      
      let mut hb = Sha256::new();
      hb.update(b);
      let digest_b = hb.finalize();
      
      let mut diff = 0;
      for (x, y) in digest_a.iter().zip(digest_b.iter()) {
          diff |= x ^ y;
      }
      diff == 0
  }
  ```

---

### NYX-SRV-06: DoS / OOM Risk in Audit Log Query Loading Entire File
* **Severity**: **Medium**
* **Affected Code**: `crates/server/src/audit.rs`, `query` function (Lines 141-160).
* **Description**:
  The `query` handler reads the entire `audit.jsonl` log file into memory using `BufReader::lines().collect()` and parses every single line into an `AuditRecord` struct, before applying filtering and pagination. Over a long-running engagement with extensive log entries, querying the audit endpoint consumes a massive amount of CPU and RAM, potentially triggering OOM crashes.
* **Threat Scenario**:
  During a 30-day engagement, the team server accumulates 1,000,000 action audit records (due to high implant tasking rates). An operator queries the log via `GET /api/audit`. The team server attempts to load and parse the 1,000,000 JSON lines at once, causing a severe memory allocation spike that triggers the Linux OOM killer, crashing the C2 server.
* **Exact Fix**:
  Stream and filter the file line-by-line, applying offsets and limits *during* the file-read pass rather than collecting all entries first.
  
  *Modification in `crates/server/src/audit.rs` (streaming implementation):*
  ```rust
  pub fn query(&self, q: &AuditQuery) -> std::io::Result<Vec<AuditRecord>> {
      let f = File::open(&self.path)?;
      let reader = BufReader::new(f);
      let mut recs = Vec::new();
      let limit = q.limit.unwrap_or(500).min(5000);
      let offset = q.offset.unwrap_or(0);
      let mut match_count = 0;
      
      // Since logs are written chronologically:
      // if dir == "asc", read forward and paginate early.
      // if dir != "asc" (descending), we must read from end or read forward with a buffer.
      // A simple streaming reader keeping only matching lines:
      for line in reader.lines().map_while(Result::ok) {
          if let Ok(r) = serde_json::from_str::<AuditRecord>(&line) {
              // Apply filters
              if q.operator.as_deref().is_none_or(|o| r.operator == o)
                  && q.action.as_deref().is_none_or(|a| r.action == a)
                  && q.since.is_none_or(|s| r.ts >= s)
                  && q.until.is_none_or(|u| r.ts <= u)
              {
                  match_count += 1;
                  if q.dir.as_deref() == Some("asc") {
                      if match_count > offset {
                          recs.push(r);
                          if recs.len() >= limit {
                              break;
                          }
                      }
                  } else {
                      // Descending order: keep matching records in a list and extract page at the end
                      recs.push(r);
                  }
              }
          }
      }
      
      if q.dir.as_deref() != Some("asc") {
          recs.reverse();
          let page_offset = offset.min(recs.len());
          recs = recs.into_iter().skip(page_offset).take(limit).collect();
      }
      Ok(recs)
  }
  ```

---

### NYX-SRV-07: Cryptographic Leak of Password Trends in Masking Logic
* **Severity**: **Low**
* **Affected Code**: `crates/store/src/model.rs`, `mask_secret` function (Lines 72-80).
* **Description**:
  The `mask_secret` function masks passwords/keys for general listing. If the secret is longer than 4 characters, it retains the first 2 characters and the last 2 characters (e.g. `pa....rd`). While this lets operators verify credentials, it leaks significant entropy (e.g. prefixes/suffixes and character positions) and hash prefixes.
* **Threat Scenario**:
  A standard read-only viewer leaks the masked credentials list. By inspecting the leaks, they identify common password root-words (e.g., `Pa....!1` -> `P@ssw0rd!1`) or recognize key patterns. Additionally, if the credentials contain NTLM or SHA-256 hashes, revealing the first 2 and last 2 hex chars reduces the search space for offline brute-forcing.
* **Exact Fix**:
  Mask secrets completely using a static placeholder string (e.g. `********`), unless `?reveal=1` is authenticated and explicitly authorized.
  
  *Modification in `crates/store/src/model.rs`:*
  ```rust
  pub fn mask_secret(_s: &str) -> String {
      "********".to_string()
  }
  ```

---

## 4. Conclusion & Recommended Next Steps
1. **Implement Fail-Closed Auth Loading**: Fix `NYX-SRV-01` immediately to ensure syntax issues in `operators.json` crash the server at boot rather than opening the framework to unauthorized connections.
2. **Apply Role-Based Action Validation**: Add checks for `Role::Viewer` across all modification endpoints and cleartext retrieval paths to safeguard credentials and implant state.
3. **Incorporate Handshake & Connection Timeouts**: Add `tokio::time::timeout` bounds to TLS sniffing and handshake routines to prevent Denial of Service via socket exhaustion.
4. **Length-Prefix Log Chain Fields**: Adopt length-prefixing in `hash_record` to ensure domain separation and avoid audit logs from being modified without detection.
