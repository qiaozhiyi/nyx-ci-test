//! WP-G polymorphism smoke test against the REAL HTTP API
//! (`POST /api/generate-implant`), complementing the unit-level
//! `polymorphism_tests` in `crates/server/src/implant_gen.rs`.
//!
//! Spawns the actual axum server (same pattern as `end_to_end.rs`) with a
//! synthetic DLL template and an in-memory implant store, generates two
//! implants with an identical request, and asserts:
//!
//!   (a) the two artifacts are byte-different, and every differing byte falls
//!       inside the `.nyx_cfg` section or the appended PE overlay — the
//!       template body outside the section is untouched;
//!   (b) functional equivalence: the template body outside `.nyx_cfg` is
//!       byte-identical, and both `.nyx_cfg` sections carry the same
//!       structural fields (magic, keying levels, data_len) for the same
//!       request — per-implant key/nonce/ciphertext bytes legitimately
//!       differ (that is the pre-existing per-implant keying, not WP-G);
//!   (c) both artifacts pass PE header + `.nyx_cfg` layout validation
//!       (mirrors `validate_patched_pe`, which is crate-private);
//!   (d) overlay length is in [128, 4224) = [OVERLAY_MIN, OVERLAY_MIN + 4096).

use std::sync::Arc;
use std::time::Duration;

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use nyx_server::{router, AppState};

/// Synthetic DLL template, laid out exactly like the unit tests'
/// `synthetic_template()` in implant_gen.rs: MZ magic, PE\0\0 signature via
/// the 0x3C pointer, and the 1024-byte `.nyx_cfg` placeholder at offset 1024
/// (magic 0x41414141 + 0xAA fill), as `config_placeholder.rs` builds it.
const PLACEHOLDER_OFF: usize = 1024;
const SECTION_LEN: usize = 1024;
const OVERLAY_MIN: usize = 128;
const OVERLAY_MAX: usize = OVERLAY_MIN + 4096;

fn synthetic_template() -> Vec<u8> {
    let mut t = vec![0u8; 8192];
    t[0] = 0x4D; // 'M'
    t[1] = 0x5A; // 'Z'
    t[0x3C] = 0x80; // PE signature at offset 0x80
    t[0x80] = 0x50; // 'P'
    t[0x81] = 0x45; // 'E'
    t[0x82] = 0x00;
    t[0x83] = 0x00;
    t[PLACEHOLDER_OFF..PLACEHOLDER_OFF + 4].copy_from_slice(&[0x41; 4]);
    for b in &mut t[PLACEHOLDER_OFF + 4..PLACEHOLDER_OFF + SECTION_LEN] {
        *b = 0xAA;
    }
    t
}

/// Mirror of the crate-private `check_patched_pe_headers` +
/// `check_nyx_cfg_layout` in implant_gen.rs.
fn validate_patched(binary: &[u8], cfg_off: usize) {
    assert!(binary.len() >= 4096, "patched binary too small");
    assert_eq!(&binary[0..2], b"MZ", "missing MZ magic");
    let pe_sig_off =
        u32::from_le_bytes([binary[0x3C], binary[0x3D], binary[0x3E], binary[0x3F]]) as usize;
    assert!(pe_sig_off + 4 <= binary.len(), "PE sig offset out of bounds");
    assert_eq!(
        &binary[pe_sig_off..pe_sig_off + 4],
        b"PE\0\0",
        "missing PE\\0\\0 signature"
    );
    // .nyx_cfg layout: magic / keying_levels / data_len bounds.
    assert!(cfg_off + SECTION_LEN <= binary.len(), "section past EOF");
    assert_eq!(
        u32::from_le_bytes([
            binary[cfg_off],
            binary[cfg_off + 1],
            binary[cfg_off + 2],
            binary[cfg_off + 3],
        ]),
        0xDEADBEEF,
        "bad .nyx_cfg magic"
    );
    let data_len = u16::from_le_bytes([binary[cfg_off + 8], binary[cfg_off + 9]]) as usize;
    assert!(data_len <= 900, "data_len too large: {data_len}");
    assert!(
        cfg_off + 86 + data_len <= cfg_off + SECTION_LEN,
        "encrypted config overflows .nyx_cfg"
    );
}

/// Locate the patched `.nyx_cfg` section by its 0xDEADBEEF magic.
fn locate_nyx_cfg(binary: &[u8]) -> usize {
    binary
        .windows(4)
        .position(|w| w == [0xEF, 0xBE, 0xAD, 0xDE])
        .expect("patched binary must contain a .nyx_cfg section")
}

struct Generated {
    binary: Vec<u8>,
    sha256: String,
    size_bytes: usize,
}

fn generate_once(url: &str) -> Generated {
    let resp: serde_json::Value = ureq::post(format!("{url}/api/generate-implant").as_str())
        .set("Authorization", "Bearer test-admin-token")
        .send_json(serde_json::json!({
            "callback": "192.0.2.1",
            "port": 8443,
            "format": "dll",
            "uri": "/beacon",
            "sleep": 60,
            "jitter": 20,
            "tls": true,
            "deliver": "inline",
        }))
        .expect("generate-implant POST must succeed")
        .into_json()
        .expect("generate-implant response must be JSON");
    assert_eq!(resp["ok"], true, "generation failed: {resp}");
    let b64 = resp["binary"]
        .as_str()
        .expect("deliver=inline must return a base64 binary");
    Generated {
        binary: B64.decode(b64).expect("binary must be valid base64"),
        sha256: resp["sha256"].as_str().expect("sha256").to_string(),
        size_bytes: resp["size_bytes"].as_u64().expect("size_bytes") as usize,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_generations_differ_in_dead_zone_and_overlay_only() {
    let template = synthetic_template();
    let template_len = template.len();
    let store = nyx_store::ImplantStore::open_in_memory().expect("in-memory implant store");
    let state = Arc::new(AppState {
        api_token: Some("test-admin-token".to_string()),
        template: Some(Arc::new(template)),
        implants: Some(Arc::new(store)),
        ..AppState::default()
    });
    let app = router(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("http://{addr}");
    tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await;
    });
    tokio::time::sleep(Duration::from_millis(150)).await;

    let a = generate_once(&url);
    let b = generate_once(&url);

    // Response metadata sanity: size_bytes matches the delivered binary.
    assert_eq!(a.size_bytes, a.binary.len());
    assert_eq!(b.size_bytes, b.binary.len());

    // (a) Two generations from the same template + same request must differ.
    assert_ne!(a.binary, b.binary, "two generations must not be identical");
    assert_ne!(a.sha256, b.sha256, "sha256 must differ across generations");

    // (d) Overlay length in [128, 4224).
    for (name, g) in [("A", &a), ("B", &b)] {
        let overlay_len = g.binary.len() - template_len;
        assert!(
            (OVERLAY_MIN..OVERLAY_MAX).contains(&overlay_len),
            "overlay length {overlay_len} out of [{OVERLAY_MIN}, {OVERLAY_MAX}) for {name}"
        );
    }

    // Locate .nyx_cfg in both patched binaries; the patch must not move it.
    let cfg_a = locate_nyx_cfg(&a.binary);
    let cfg_b = locate_nyx_cfg(&b.binary);
    assert_eq!(cfg_a, PLACEHOLDER_OFF);
    assert_eq!(cfg_b, PLACEHOLDER_OFF);

    // (c) Both artifacts pass PE header + .nyx_cfg layout validation.
    validate_patched(&a.binary, cfg_a);
    validate_patched(&b.binary, cfg_b);

    // (b) Functional equivalence: the template body OUTSIDE the .nyx_cfg
    // section is byte-identical across generations (the overlay starts at
    // template_len and is excluded).
    assert_eq!(
        a.binary[..cfg_a],
        b.binary[..cfg_b],
        "bytes before .nyx_cfg must be identical"
    );
    assert_eq!(
        a.binary[cfg_a + SECTION_LEN..template_len],
        b.binary[cfg_b + SECTION_LEN..template_len],
        "template body after .nyx_cfg must be identical"
    );
    // Structural fields of the section match for the same request: keying
    // levels (u32 at +4) and data_len (u16 at +8). The key/nonce/ciphertext
    // bytes legitimately differ (per-implant keying predates WP-G).
    assert_eq!(
        a.binary[cfg_a + 4..cfg_a + 10],
        b.binary[cfg_b + 4..cfg_b + 10],
        "keying_levels + data_len must match for an identical request"
    );

    // (a, cont.) Every differing byte in the common prefix must fall inside
    // the .nyx_cfg section; the only other difference is the overlay region.
    let common = a.binary.len().min(b.binary.len());
    for i in 0..common {
        if a.binary[i] != b.binary[i] {
            let in_section = (cfg_a..cfg_a + SECTION_LEN).contains(&i);
            let in_overlay = i >= template_len;
            assert!(
                in_section || in_overlay,
                "unexpected difference at offset {i} (outside .nyx_cfg and overlay)"
            );
        }
    }

    // The .nyx_cfg dead-zone tail (past header + ciphertext) must actually be
    // randomized — not the old all-zero padding.
    let data_len_a =
        u16::from_le_bytes([a.binary[cfg_a + 8], a.binary[cfg_a + 9]]) as usize;
    let tail_a = &a.binary[cfg_a + 86 + data_len_a..cfg_a + SECTION_LEN];
    assert!(
        tail_a.iter().any(|&x| x != 0),
        "dead-zone tail must not be all-zero padding"
    );
}
