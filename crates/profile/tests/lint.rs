//! c2lint validation tests: good profile, and each error/warning class.

use nyx_profile::{lint, parse, Severity};

const GOOD: &str = r#"
set sleeptime "60000";
set jitter "10";
set useragent "Mozilla/5.0 (Macintosh) CustomBrowser/1.0";
http-get {
    set uri "/api/v1/Updates";
    client { metadata { base64; header "Cookie"; } }
    server { output { base64; print; } }
}
http-post {
    set uri "/api/v1/Telemetry/Id/";
    client { output { base64; print; } }
    server { output { base64; print; } }
}
"#;

fn errors(p: &nyx_profile::Profile) -> Vec<String> {
    lint(p)
        .into_iter()
        .filter(|d| d.severity == Severity::Error)
        .map(|d| d.message)
        .collect()
}

#[test]
fn good_profile_has_no_errors() {
    let p = parse(GOOD).expect("parse");
    let diags = lint(&p);
    assert!(errors(&p).is_empty(), "unexpected errors: {:?}", errors(&p));
    assert!(diags
        .iter()
        .any(|d| d.severity == Severity::Note && d.message.contains("OK")));
}

#[test]
fn missing_http_get_is_an_error() {
    let src =
        "http-post { set uri \"/p\"; client { output { print; } } server { output { print; } } }";
    let p = parse(src).unwrap();
    let errs = errors(&p);
    assert!(errs.iter().any(|m| m.contains("http-get")), "{errs:?}");
}

#[test]
fn missing_http_post_is_an_error() {
    let src = "http-get { set uri \"/g\"; client { metadata { header \"Cookie\"; } } server { output { print; } } }";
    let p = parse(src).unwrap();
    let errs = errors(&p);
    assert!(errs.iter().any(|m| m.contains("http-post")), "{errs:?}");
}

#[test]
fn missing_uri_is_an_error() {
    let src = r#"
        http-get { client { metadata { header "Cookie"; } } server { output { print; } } }
        http-post { set uri "/p"; client { output { print; } } server { output { print; } } }
    "#;
    let p = parse(src).unwrap();
    assert!(
        errors(&p).iter().any(|m| m.contains("uri")),
        "{:?}",
        errors(&p)
    );
}

#[test]
fn data_block_without_terminator_is_an_error() {
    let src = r#"
        http-get {
            set uri "/g";
            client { metadata { base64; } }
            server { output { print; } }
        }
        http-post { set uri "/p"; client { output { print; } } server { output { print; } } }
    "#;
    let p = parse(src).unwrap();
    let errs = errors(&p);
    assert!(errs.iter().any(|m| m.contains("terminator")), "{errs:?}");
}

#[test]
fn unknown_data_statement_is_an_error() {
    let src = r#"
        http-get {
            set uri "/g";
            client { metadata { bogus_transform; header "Cookie"; } }
            server { output { print; } }
        }
        http-post { set uri "/p"; client { output { print; } } server { output { print; } } }
    "#;
    let p = parse(src).unwrap();
    assert!(
        errors(&p).iter().any(|m| m.contains("bogus_transform")),
        "{:?}",
        errors(&p)
    );
}

#[test]
fn uri_not_starting_with_slash_is_a_warning() {
    let src = r#"
        http-get {
            set uri "api/v1/x";
            client { metadata { header "Cookie"; } } server { output { print; } }
        }
        http-post { set uri "/p"; client { output { print; } } server { output { print; } } }
    "#;
    let p = parse(src).unwrap();
    let warns: Vec<_> = lint(&p)
        .into_iter()
        .filter(|d| d.severity == Severity::Warning)
        .collect();
    assert!(
        warns.iter().any(|w| w.message.contains("should start")),
        "{warns:?}"
    );
}

#[test]
fn jitter_over_100_is_an_error() {
    let src = r#"
        set jitter "150";
        http-get { set uri "/g"; client { metadata { header "Cookie"; } } server { output { print; } } }
        http-post { set uri "/p"; client { output { print; } } server { output { print; } } }
    "#;
    let p = parse(src).unwrap();
    assert!(
        errors(&p).iter().any(|m| m.contains("jitter")),
        "{:?}",
        errors(&p)
    );
}

#[test]
fn crlf_in_header_value_is_an_error() {
    // HTTP request/response splitting: a `header "N" "V"` whose value (or name)
    // contains CR/LF can inject extra headers or smuggle a second request when
    // the transport reflects it. Must be a hard error.
    let src = r#"
        http-get {
            set uri "/g";
            client { header "X-Safe" "evil\r\nInjected: yes"; metadata { header "Cookie"; } }
            server { output { print; } }
        }
        http-post { set uri "/p"; client { output { print; } } server { output { print; } } }
    "#;
    let p = parse(src).unwrap();
    assert!(
        errors(&p).iter().any(|m| {
            let ml = m.to_lowercase();
            ml.contains("cr")
                || ml.contains("lf")
                || ml.contains("newline")
                || ml.contains("split")
                || ml.contains("header")
        }),
        "CRLF in header value must be an error: {:?}",
        errors(&p)
    );
}

#[test]
fn crlf_in_uri_is_an_error() {
    // A `set uri` carrying CRLF enables request-line splitting when the
    // transport builds the request line from it.
    let src = r#"
        http-get {
            set uri "/g\r\nGET /admin HTTP/1.1\r\n";
            client { metadata { header "Cookie"; } } server { output { print; } }
        }
        http-post { set uri "/p"; client { output { print; } } server { output { print; } } }
    "#;
    let p = parse(src).unwrap();
    assert!(
        errors(&p).iter().any(|m| {
            let ml = m.to_lowercase();
            ml.contains("cr")
                || ml.contains("lf")
                || ml.contains("newline")
                || ml.contains("split")
                || ml.contains("uri")
        }),
        "CRLF in uri must be an error: {:?}",
        errors(&p)
    );
}

#[test]
fn crlf_in_header_name_is_an_error() {
    let src = r#"
        http-get {
            set uri "/g";
            client { header "X-Injec\r\nted" "value"; metadata { header "Cookie"; } } server { output { print; } }
        }
        http-post { set uri "/p"; client { output { print; } } server { output { print; } } }
    "#;
    let p = parse(src).unwrap();
    assert!(
        !errors(&p).is_empty(),
        "CRLF in header name must be an error: {:?}",
        errors(&p)
    );
}
