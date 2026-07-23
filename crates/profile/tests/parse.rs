//! Parser tests: lexing (escapes, comments), structural extraction, errors.

use nyx_profile::transform::steps_from_block;
use nyx_profile::Step;
use nyx_profile::{parse, ParseError};

/// A faithful, trimmed Malleable C2 profile exercising every construct the
/// parser must handle: options, http-get/post, client/server, metadata/output/id
/// data blocks, mask/base64/base64url, prepend/append with `\xNN` escapes, and
/// the one-arg vs two-arg `header` ambiguity.
const GOOD: &str = r#"
# Nyx test profile
set sample_name "Nyx Test";
set sleeptime "60000";
set jitter "10";
set useragent "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36";

http-get {
    set uri "/api/v1/Updates";
    client {
        header "Accept-Encoding" "deflate, gzip";
        metadata {
            mask;
            base64;
            prepend "SESSION=";
            append ";";
            header "Cookie";
        }
    }
    server {
        header "Content-Type" "application/octet-stream";
        output {
            mask;
            base64;
            prepend "\x1F\x8B\x08\x00";
            append "\x00\x00";
            print;
        }
    }
}

http-post {
    set uri "/api/v1/Telemetry/Id/";
    set verb "POST";
    client {
        header "Content-Type" "application/json";
        output {
            mask;
            base64url;
            uri-append;
        }
        id {
            mask;
            base64url;
            prepend "{v=1, d=\"";
            append "\"}";
            print;
        }
    }
    server {
        output {
            mask;
            base64;
            print;
        }
    }
}
"#;

#[test]
fn parses_options_and_uris() {
    let p = parse(GOOD).expect("GOOD must parse");
    assert_eq!(p.option("sample_name").unwrap().as_str(), "Nyx Test");
    assert_eq!(p.option("sleeptime").unwrap().as_str(), "60000");
    assert_eq!(
        p.http_get().unwrap().get("uri").unwrap().as_str(),
        "/api/v1/Updates"
    );
    assert_eq!(
        p.http_post().unwrap().get("uri").unwrap().as_str(),
        "/api/v1/Telemetry/Id/"
    );
    assert_eq!(p.http_post().unwrap().get("verb").unwrap().as_str(), "POST");
}

#[test]
fn extracts_metadata_transform_steps() {
    let p = parse(GOOD).expect("parse");
    let get = p.http_get().unwrap();
    let client = get.sub("client").unwrap();
    let metadata = client.sub("metadata").unwrap();
    let steps = steps_from_block(metadata);
    assert_eq!(
        steps,
        vec![
            Step::Mask,
            Step::Base64,
            Step::Prepend(b"SESSION=".to_vec()),
            Step::Append(b";".to_vec()),
        ]
    );
}

#[test]
fn x_escape_bytes_are_decoded() {
    let p = parse(GOOD).expect("parse");
    let output = p
        .http_get()
        .unwrap()
        .sub("server")
        .unwrap()
        .sub("output")
        .unwrap();
    let steps = steps_from_block(output);
    assert!(steps.contains(&Step::Prepend(vec![0x1F, 0x8B, 0x08, 0x00])));
    assert!(steps.contains(&Step::Append(vec![0x00, 0x00])));
}

#[test]
fn one_arg_vs_two_arg_header_is_unambiguous() {
    // In a data block, `header "Cookie";` is a 1-arg terminator.
    // In a client block, `header "Server" "Apache";` is a 2-arg statement.
    let p = parse(GOOD).expect("parse");
    let meta = p
        .http_get()
        .unwrap()
        .sub("client")
        .unwrap()
        .sub("metadata")
        .unwrap();
    let header_stmts: Vec<_> = meta.stmts("header").collect();
    assert_eq!(header_stmts.len(), 1, "metadata has one header terminator");
    assert_eq!(header_stmts[0].len(), 1, "terminator form has a single arg");

    let client = p.http_get().unwrap().sub("client").unwrap();
    let accept: Vec<_> = client.stmts("header").collect();
    assert_eq!(accept.len(), 1);
    assert_eq!(accept[0].len(), 2, "client header has name + value");
}

#[test]
fn unterminated_string_is_an_error() {
    let src = "set uri \"no-closing-quote;";
    assert!(matches!(parse(src), Err(ParseError::Syntax { .. })));
}

#[test]
fn missing_close_brace_is_an_error() {
    let src = "http-get { set uri \"/x\";";
    assert!(matches!(parse(src), Err(ParseError::Syntax { .. })));
}

#[test]
fn comments_are_ignored() {
    let src = "# a comment\nset sleeptime \"1000\";\n// another\nhttp-get {\n set uri \"/g\";\n}\n";
    let p = parse(src).expect("comments must not break parsing");
    assert_eq!(p.option("sleeptime").unwrap().as_str(), "1000");
    assert!(p.http_get().is_some());
}

#[test]
fn roundtrip_to_string_preserves_key_fields() {
    // Re-parse the parsed profile's extracted values to ensure no data is lost
    // across the lex/parse boundary.
    let p = parse(GOOD).expect("parse");
    let again = parse(&format!(
        "set useragent \"{}\";\nhttp-get {{ set uri \"{}\"; }}\nhttp-post {{ set uri \"{}\"; }}\n",
        p.option("useragent").unwrap().as_str(),
        p.http_get().unwrap().get("uri").unwrap().as_str(),
        p.http_post().unwrap().get("uri").unwrap().as_str(),
    ))
    .expect("reparse");
    assert_eq!(again.option("useragent"), p.option("useragent"));
}

#[test]
fn deeply_nested_profile_is_rejected_not_stack_overflow() {
    // Regression for the unbounded `items()` recursion: each `{` recursed one
    // frame deeper with no cap, so a few-hundred-KB profile of nested blocks
    // blew the stack (SIGSEGV, uncatchable, kills the server/agent under
    // panic=abort). The parser must reject past a sane depth with a clean
    // ParseError instead of recursing until the stack dies.
    let depth = 10_000; // well past any legitimate profile (real ones nest ≤ 5)
    let mut src = String::new();
    for _ in 0..depth {
        src.push_str("a { ");
    }
    src.push_str("set uri \"/x\";");
    for _ in 0..depth {
        src.push_str(" }");
    }
    match parse(&src) {
        Err(ParseError::Syntax { message, .. }) => {
            assert!(
                message.to_lowercase().contains("depth") || message.to_lowercase().contains("nest"),
                "deeply-nested profile must be rejected with a depth error, got: {message}"
            );
        }
        other => panic!("expected depth-limit error, got {other:?}"),
    }
}

#[test]
fn reasonably_nested_profile_still_parses() {
    // The depth cap must not reject legitimate (if unusual) nesting. A profile
    // nesting a dozen deep is absurd for real use but must parse fine.
    let depth = 32;
    let mut src = String::new();
    for _ in 0..depth {
        src.push_str("a { ");
    }
    src.push_str("set uri \"/x\";");
    for _ in 0..depth {
        src.push_str(" }");
    }
    parse(&src).expect("moderate nesting must parse");
}
