//! Shipped `profiles/stealth.profile`: c2lint-clean and http-post envelopes invert.

use nyx_profile::{
    decode, lint, parse, post_client_envelope, post_server_envelope, Severity, TimingBaseline,
};

const STEALTH: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../profiles/stealth.profile"
));

#[test]
fn stealth_profile_has_no_lint_errors() {
    let p = parse(STEALTH).expect("stealth.profile must parse");
    let diags = lint(&p);
    let errors: Vec<_> = diags
        .iter()
        .filter(|d| d.severity == Severity::Error)
        .map(|d| d.message.as_str())
        .collect();
    assert!(
        errors.is_empty(),
        "c2lint Errors on stealth.profile: {errors:?}"
    );
    let warnings: Vec<_> = diags
        .iter()
        .filter(|d| d.severity == Severity::Warning)
        .map(|d| d.message.as_str())
        .collect();
    assert!(
        warnings.is_empty(),
        "c2lint Warnings on stealth.profile (prefer 0): {warnings:?}"
    );
    assert!(diags
        .iter()
        .any(|d| d.severity == Severity::Note && d.message.contains("OK")));
}

#[test]
fn stealth_profile_sets_padding_and_bursty_timing() {
    let p = parse(STEALTH).expect("parse");
    assert_eq!(p.option("sleeptime").unwrap().as_str(), "60000");
    assert_eq!(p.option("jitter").unwrap().as_str(), "25");
    let min: u64 = p.option("padding_min").unwrap().as_str().parse().unwrap();
    let max: u64 = p.option("padding_max").unwrap().as_str().parse().unwrap();
    assert!(min <= max, "padding_min {min} > padding_max {max}");
    assert!(max <= 4096, "padding_max {max} exceeds 4096");
    assert_eq!(p.option("timing_baseline").unwrap().as_str(), "bursty");
    assert_eq!(p.timing_baseline(), TimingBaseline::Bursty);
    let ua = p.option("useragent").unwrap().as_str();
    assert!(!ua.contains("Nyx"), "UA must not be the Nyx default: {ua}");
    assert!(ua.starts_with("Mozilla/5.0"));
}

#[test]
fn stealth_http_post_envelopes_invert() {
    let p = parse(STEALTH).expect("parse");
    let frame = b"encrypted-frame-bytes-here";
    for env_name in ["client", "server"] {
        let (steps, body) = if env_name == "client" {
            let env = post_client_envelope(&p);
            let (body, extra) = env.shape_body(frame);
            let wire = if extra.is_empty() { body } else { extra };
            let stripped = env.strip_padding(&wire).expect("client pad_strip").to_vec();
            (env.steps, stripped)
        } else {
            let env = post_server_envelope(&p);
            let (body, extra) = env.shape_body(frame);
            let wire = if extra.is_empty() { body } else { extra };
            let stripped = env.strip_padding(&wire).expect("server pad_strip").to_vec();
            (env.steps, stripped)
        };
        let back = decode(&steps, &body)
            .unwrap_or_else(|e| panic!("{env_name} envelope decode failed: {e}"));
        assert_eq!(back, frame, "{env_name} envelope must invert");
    }
    assert_eq!(
        p.http_post().unwrap().get("uri").unwrap().as_str(),
        "/fd/ls/LCIClient/7.0"
    );
}
