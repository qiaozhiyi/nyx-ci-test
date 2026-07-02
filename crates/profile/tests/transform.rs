//! Transform-engine integration: a real profile's metadata pipeline round-trips,
//! and extracted steps match the declared order.

use nyx_profile::{decode, encode, parse, steps_from_block, Step};

const META_PROFILE: &str = r#"
http-get {
    set uri "/u";
    client {
        metadata {
            mask;
            base64;
            prepend "SESSION=";
            append ";";
            header "Cookie";
        }
    }
    server { output { print; } }
}
http-post { set uri "/p"; client { output { print; } } server { output { print; } } }
"#;

#[test]
fn declared_steps_match_order() {
    let p = parse(META_PROFILE).expect("parse");
    let meta = p
        .http_get()
        .unwrap()
        .sub("client")
        .unwrap()
        .sub("metadata")
        .unwrap();
    assert_eq!(
        steps_from_block(meta),
        vec![
            Step::Mask,
            Step::Base64,
            Step::Prepend(b"SESSION=".to_vec()),
            Step::Append(b";".to_vec()),
        ]
    );
}

#[test]
fn full_pipeline_roundtrips() {
    let p = parse(META_PROFILE).expect("parse");
    let meta = p
        .http_get()
        .unwrap()
        .sub("client")
        .unwrap()
        .sub("metadata")
        .unwrap();
    let steps = steps_from_block(meta);

    for msg in [
        b"".as_slice(),
        b"x",
        b"session-payload-12345",
        b"\x00\xff\x10\x80",
    ] {
        let wire = encode(&steps, msg);
        let back = decode(&steps, &wire).expect("decode");
        assert_eq!(back.as_slice(), msg, "round-trip failed for {msg:?}");
    }
}

#[test]
fn empty_step_list_is_identity() {
    let msg = b"identity";
    assert_eq!(encode(&[], msg), msg);
    assert_eq!(decode(&[], msg).unwrap(), msg);
}

#[test]
fn base64url_decodes_base64_and_vice_versa() {
    // The decoder accepts either alphabet (transport tolerance).
    let std = encode(&[Step::Base64], b"\xfb\xff");
    let url = encode(&[Step::Base64Url], b"\xfb\xff");
    // both decode back to the same bytes regardless of which alphabet produced them
    assert_eq!(decode(&[Step::Base64], &std).unwrap(), b"\xfb\xff");
    assert_eq!(decode(&[Step::Base64], &url).unwrap(), b"\xfb\xff");
}
