//! HTTP/2 passive fingerprinting (the Akamai scheme).
//!
//! After TLS, edge networks fingerprint the HTTP/2 frame sequence: the SETTINGS
//! frame's id/value pairs, the stream-0 WINDOW_UPDATE increment, the number of
//! standalone PRIORITY frames, and the pseudo-header order. Chrome, Firefox,
//! and a Rust `h2`/`reqwest` client differ measurably here (e.g. Chrome's
//! WINDOW_UPDATE increment is `15663105`, Firefox's `12517377`; Chrome omits
//! PRIORITY frames post-RFC 9218).
//!
//! The canonical Akamai fingerprint string is:
//! `id:val;id:val|window_update|priority_count|p,p,p,p`
//!
//! We parse SETTINGS / WINDOW_UPDATE / PRIORITY from raw frames. Extracting the
//! pseudo-header order requires HPACK-decoding the HEADERS frame (future); set
//! [`H2Fingerprint::pseudo_order`] explicitly until then.

/// Parsed HTTP/2 connection fingerprint inputs.
#[derive(Debug, Clone, Default)]
pub struct H2Fingerprint {
    /// SETTINGS id/value pairs, in frame order.
    pub settings: Vec<(u32, u32)>,
    /// Stream-0 WINDOW_UPDATE increment.
    pub window_update: u32,
    /// Count of standalone PRIORITY frames.
    pub priorities: usize,
    /// Pseudo-header order (e.g. `['m','a','s','p']`). Not parsed from frames
    /// yet (needs HPACK); set it explicitly.
    pub pseudo_order: Vec<char>,
}

const H2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// Parse the HTTP/2 frames in `raw` (optionally preceded by the connection
/// preface) into fingerprint inputs.
pub fn from_frames(raw: &[u8]) -> Result<H2Fingerprint, &'static str> {
    let mut fp = H2Fingerprint::default();
    let mut p = if raw.starts_with(H2_PREFACE) {
        H2_PREFACE.len()
    } else {
        0
    };
    // Each frame: length(3 BE) type(1) flags(1) stream_id(4) payload.
    while p + 9 <= raw.len() {
        let len = ((raw[p] as usize) << 16) | ((raw[p + 1] as usize) << 8) | raw[p + 2] as usize;
        let ftype = raw[p + 3];
        let payload = raw
            .get(p + 9..p + 9 + len)
            .ok_or("frame payload out of bounds")?;
        match ftype {
            0x04 => {
                // SETTINGS: id(2 BE) value(4 BE) pairs.
                let mut k = 0;
                while k + 6 <= payload.len() {
                    let id = u16::from_be_bytes([payload[k], payload[k + 1]]) as u32;
                    let val = u32::from_be_bytes([
                        payload[k + 2],
                        payload[k + 3],
                        payload[k + 4],
                        payload[k + 5],
                    ]);
                    fp.settings.push((id, val));
                    k += 6;
                }
            }
            0x08 if payload.len() >= 4 => {
                fp.window_update =
                    u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
            }
            0x02 => fp.priorities += 1, // PRIORITY
            _ => {}
        }
        p += 9 + len;
    }
    Ok(fp)
}

/// Format the Akamai HTTP/2 fingerprint string: `id:val;…|window_update|prio|p,p,…`.
pub fn akamai_h2(fp: &H2Fingerprint) -> String {
    let settings = fp
        .settings
        .iter()
        .map(|(id, val)| format!("{id}:{val}"))
        .collect::<Vec<_>>()
        .join(";");
    let pseudo = fp
        .pseudo_order
        .iter()
        .map(|c| c.to_string())
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "{}|{}|{}|{}",
        settings, fp.window_update, fp.priorities, pseudo
    )
}
