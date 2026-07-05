# Nyx Framework Transport & Authentication Audit Report

This report documents the security vulnerabilities, cryptographic defects, standard compliance issues, and design flaws identified during the audit of the following files:
- `crates/transport/src/lib.rs`
- `crates/transport/src/h2.rs`
- `crates/transport/src/emitter.rs`
- `crates/transport/src/tls.rs`
- `crates/rest/src/lib.rs`

---

## Executive Summary

The audit revealed **seven (7) primary findings** ranging from Medium to Critical severity. The most notable issues are:
1. **A mathematically incorrect GREASE detection algorithm** that corrupts JA4 fingerprints.
2. **Multiple format and hashing deviations from the official JA4 specification**, rendering the computed JA4 fingerprints non-standard and incompatible with external threat feeds.
3. **Fingerprint flapping (instability)** due to lack of GREASE filtering in extension order checking.
4. **Active server fingerprinting / desynchronization attack vector** in TLS record peeking.
5. **Local credential disclosure** due to a TOCTOU race condition in operator database persistence.

---

## Detailed Findings

### 1. Cryptographic/Logical Defect in GREASE Detection (High Severity)

* **Affected Code**: `crates/transport/src/tls.rs:37-39` (`fn is_grease(v: u16) -> bool`)
* **Description**: 
  RFC 8701 defines GREASE values as double-byte values where both bytes are equal and end in `0x0a` (e.g. `0x0a0a`, `0x1a1a`, ..., `0xfafa`). 
  The current implementation:
  ```rust
  fn is_grease(v: u16) -> bool {
      (v & 0x0f0f) == 0x0a0a
  }
  ```
  is mathematically incorrect. It only verifies that the low nibble of both the high and low bytes is `0xa`. It fails to verify that the high byte equals the low byte. As a result, it classifies 240 non-GREASE values (e.g. `0x1a2a`, `0x0a1a`) as GREASE.
* **Threat Scenario**: If a client handshake contains legitimate cipher suites or extension types that match this incorrect bitmask (e.g., custom or enterprise extensions of the form `0xXaZa` where `X != Z`), they will be silently omitted from the JA4 calculation. This produces incorrect JA4 fingerprints, breaking allowlists and causing connection denials.
* **Exact Fix**:
  Change the function to verify both bytes are equal and end in `0x0a`:
  ```rust
  fn is_grease(v: u16) -> bool {
      let bytes = v.to_be_bytes();
      bytes[0] == bytes[1] && (bytes[0] & 0x0f) == 0x0a
  }
  ```

---

### 2. JA4 Fingerprint Compliance Deviations (Medium Severity)

* **Affected Code**: `crates/transport/src/tls.rs:237-317` (`pub fn ja4`)
* **Description**: 
  The JA4 implementation deviates from the official FoxIO specification in three major ways:
  1. **Hexadecimal Counts**: The cipher and extension counts in `ja4_a` are formatted in hexadecimal (`ncs:02x`, `nex:02x`) instead of decimal (`%02`).
  2. **No Value Capping**: The JA4 specification dictates that counts greater than 99 must be capped at 99. The current code lacks this cap. A count exceeding 99 can produce a 3-character representation, corrupting the length of `ja4_a`.
  3. **Hash Input Delimiter Mismatch**: The JA4 spec requires sorting and joining the cipher suites and extensions with **commas (`,`)** before hashing. The current code joins them with **dashes (`-`)**.
* **Threat Scenario**: The computed JA4 string will not match standard JA4 signatures computed by security appliances (e.g. Cloudflare, Akamai, Zeek). Operators cannot cross-reference signatures against threat intelligence feeds, rendering JA4 allowlisting useless.
* **Exact Fix**:
  Update `ja4` to use decimal formatting, cap counts at 99, and join lists with commas:
  ```rust
  pub fn ja4(ch: &ClientHello) -> String {
      // ja4_a
      let ver_val = ch.supported_versions.iter().copied().filter(|v| !is_grease(*v)).max().unwrap_or(ch.legacy_version);
      let ver = match ver_val {
          0x0304 => "13",
          0x0303 => "12",
          0x0302 => "11",
          0x0301 => "10",
          _ => "00",
      };
      let sni = if ch.sni.is_some() { 'd' } else { 'i' };
      let ncs = ch.cipher_suites.iter().filter(|c| !is_grease(**c)).count().min(99);
      let nex = ch.extensions.iter().filter(|(t, _)| !is_grease(*t)).count().min(99);
      let alpn = ch.alpn.as_deref().map(|a| a.chars().take(2).collect::<String>()).filter(|s| !s.is_empty()).unwrap_or_else(|| "00".to_string());
      let ja4_a = format!("t{ver}{sni}{ncs:02}{nex:02}{alpn}");

      // ja4_b
      let mut cs: Vec<u16> = ch.cipher_suites.iter().copied().filter(|c| !is_grease(*c)).collect();
      cs.sort_unstable();
      let ja4_b = if cs.is_empty() {
          "000000000000".to_string()
      } else {
          sha256_12hex(cs.iter().copied().map(hex4).collect::<Vec<_>>().join(",").as_bytes())
      };

      // ja4_c
      let mut exts: Vec<u16> = ch.extensions.iter().map(|(t, _)| *t).filter(|t| !is_grease(*t) && *t != 0 && *t != 16).collect();
      exts.sort_unstable();
      let ja4_c = if exts.is_empty() && ch.signature_algorithms.is_empty() {
          "000000000000".to_string()
      } else {
          let ext_str = exts.iter().copied().map(hex4).collect::<Vec<_>>().join(",");
          let sig_str = ch.signature_algorithms.iter().copied().map(hex4).collect::<Vec<_>>().join(",");
          format!("{}{}", prefix, sha256_12hex(format!("{ext_str}_{sig_str}").as_bytes()))
      };

      format!("{ja4_a}_{ja4_b}_{ja4_c}")
  }
  ```

---

### 3. JA4 Fingerprint Flapping (Instability) via Unfiltered GREASE Extensions (Medium Severity)

* **Affected Code**: `crates/transport/src/tls.rs:291-295` (`pub fn ja4`)
* **Description**:
  The prefix character (`'a'` or `'i'`) in `ja4_c` indicates whether SNI (extension 0) is the first extension. However, the current code checks `ch.extensions.first()` *before* filtering out GREASE extensions:
  ```rust
  let prefix = if ch.extensions.first().map(|(t, _)| *t) == Some(0) {
      'a'
  } else {
      'i'
  };
  ```
* **Threat Scenario**: Modern browsers (especially Google Chrome) randomize the position of GREASE extensions in the ClientHello. If Chrome places a GREASE extension first, the prefix flips to `'i'` instead of `'a'`. This makes the fingerprint unstable and bypassable.
* **Exact Fix**:
  Filter out GREASE extensions before checking the first element:
  ```rust
  let prefix = if ch
      .extensions
      .iter()
      .map(|(t, _)| *t)
      .filter(|t| !is_grease(*t))
      .next() == Some(0)
  {
      'a'
  } else {
      'i'
  };
  ```

---

### 4. Active Server Fingerprinting via TLS Record Truncation (High Severity)

* **Affected Code**: `crates/transport/src/tls.rs:335-345` (`sniff_client_hello`) and `crates/server/src/main.rs:242-248` (`sniff_and_store`)
* **Description**:
  During the initial TLS handshake peeking, the server reads the ClientHello record and caps the payload length at 16 KiB using `.min(16 * 1024)`. If the ClientHello payload size exceeds 16 KiB, the server truncates it and leaves the remainder in the TCP buffer. When the TLS stack (rustls) subsequently reads from the stream, it reads the leftover body bytes as a new record header, leading to immediate protocol corruption and connection termination.
* **Threat Scenario**: Active scanners can identify the Nyx team server by sending a ClientHello that intentionally exceeds 16 KiB. A standard TLS server will reject the ClientHello gracefully (or process it if fragmentation is supported), whereas the Nyx server will experience protocol desynchronization and drop the connection abruptly mid-handshake.
* **Exact Fix**:
  Reject ClientHello payloads that exceed 16 KiB instead of truncating them:
  ```rust
  let rec_len = ((header[3] as usize) << 8) | header[4] as usize;
  if rec_len > 16384 {
      return Err(std::io::Error::new(
          std::io::ErrorKind::InvalidData,
          "ClientHello record size exceeds TLS maximum",
      ));
  }
  ```

---

### 5. Absence of TLS Handshake Message Type Verification (Medium Severity)

* **Affected Code**: `crates/transport/src/tls.rs:47-51` (`parse_client_hello`)
* **Description**:
  The parser extracts the handshake payload without checking the handshake type byte (`hs[0]`), assuming it is always a ClientHello (`1`).
* **Threat Scenario**: If a client or proxy sends other handshake message types (e.g. ServerHello or HelloVerifyRequest) to the server port, the server will attempt to parse it as a ClientHello, resulting in corrupted fingerprint calculations and cache pollution.
* **Exact Fix**:
  Verify the handshake message type byte:
  ```rust
  let hs = &rec[5..];
  if hs.len() < 4 {
      return Err("handshake header too short");
  }
  if hs[0] != 1 {
      return Err("handshake message is not a ClientHello");
  }
  ```

---

### 6. Local Information Disclosure via Insecure File Creation (Low Severity)

* **Affected Code**: `crates/server/src/operators.rs:215-224` (`persist`)
* **Description**:
  The operator database is written using `std::fs::write` on a temporary path (`.json.tmp`) using default permissions (often `0o644` depending on umask) before modifying it to `0o600` via `set_permissions`.
* **Threat Scenario**: A local unprivileged user on the team server can exploit this Time-of-Check to Time-of-Use (TOCTOU) window to read the temporary file and extract operator names and Argon2 password hashes.
* **Exact Fix**:
  Use `OpenOptions` to create the file with `0o600` permissions atomically at the time of creation:
  ```rust
  use std::fs::OpenOptions;
  #[cfg(unix)]
  use std::os::unix::fs::OpenOptionsExt;

  let tmp = path.with_extension("json.tmp");
  let mut opts = OpenOptions::new();
  opts.write(true).create(true).truncate(true);
  #[cfg(unix)]
  opts.mode(0o600);

  let mut file = opts.open(&tmp)?;
  file.write_all(&json)?;
  std::fs::rename(&tmp, path)?;
  ```

---

### 7. Missing Certificate Validation Override in Operator Clients (Design Flaw)

* **Affected Code**: `crates/client-cli/src/rest.rs:365-369`, `crates/client-ui/src/bridge.rs:382-385`
* **Description**:
  The CLI and UI clients construct their `reqwest::Client` without options for adding root certificates or bypassing certificate validation.
* **Threat Scenario**: Operators are unable to connect to a team server running with the default self-signed developer certificate unless they globally install the certificate into their operating system's trust store (exposing their workstation to security risks). This forces operators to fallback to unencrypted plaintext HTTP for C2 control, exposing credentials and tasking to network eavesdroppers.
* **Exact Fix**:
  Introduce a configuration option (such as `--insecure` or `NYX_INSECURE=1`) to allow trusting self-signed certificates:
  ```rust
  let mut builder = reqwest::Client::builder().timeout(Duration::from_secs(8));
  if std::env::var("NYX_INSECURE").is_ok() {
      builder = builder.danger_accept_invalid_certs(true);
  }
  let client = builder.build().expect("reqwest client build");
  ```

---

### 8. Dead Code: HTTP/2 passive fingerprinting (Design Gap)

* **Affected Code**: `crates/transport/src/h2.rs`
* **Description**:
  The HTTP/2 passive fingerprinting code is implemented but never called by the server to validate or filter traffic.
* **Threat Scenario**: Legitimate clients can be distinguished from automated scanners that spoof TLS fingerprints but fail to replicate the exact HTTP/2 frame parameters of standard web browsers. By not using the HTTP/2 passive fingerprinting engine, the team server leaves a significant detection gap open.
* **Exact Fix**:
  Integrate the HTTP/2 frame parser (`from_frames`) into the server connection handler after TLS termination to validate that the frame parameters match the TLS fingerprint profile.
