//! The proc-macro can't be exercised inside the crate that defines it, so this
//! integration test (a separate crate) drives `embed!` and checks the compile-
//! time encrypt → runtime decrypt round-trip against a real config fixture.

#[test]
#[allow(deprecated)]
// Tests intentionally bake the default key path; the deprecation warning is
// the production signal and must not fail the test build under -D warnings.
fn embed_roundtrips_a_file() {
    let decrypted: Vec<u8> = nyx_config_macros::embed!("tests/fixtures/sample.cfg");
    let raw = std::fs::read("tests/fixtures/sample.cfg").unwrap();
    assert_eq!(decrypted, raw, "embed! must round-trip the config file");
}

#[test]
#[allow(deprecated)]
fn two_embeds_of_same_content_both_decrypt_correctly() {
    // Each `embed!` invocation bakes a fresh random key/nonce/offset at compile
    // time (different ciphertext), but both must decrypt back to the same bytes.
    let a: Vec<u8> = nyx_config_macros::embed!("tests/fixtures/sample.cfg");
    let b: Vec<u8> = nyx_config_macros::embed!("tests/fixtures/sample.cfg");
    assert_eq!(a, b);
}
