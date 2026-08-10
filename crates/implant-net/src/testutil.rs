//! Test-only helpers (compiled under `cfg(test)` on the Windows target): one-shot
//! 127.0.0.1 loopback servers that let the WinHTTP/Winsock channel code run a
//! real transaction under wine64 without touching the network.
//!
//! The HTTP helper captures the implant's request (request line, header block,
//! body) so tests can assert envelope shaping / fronting / per-channel URI
//! paths against what ACTUALLY went on the wire.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::mpsc::{channel, Receiver};
use std::time::Duration;

/// How long a test waits for the server thread to report its capture before
/// failing. Generous because wine64 startup/scheduler latency dominates.
pub(crate) const CAPTURE_TIMEOUT: Duration = Duration::from_secs(15);

/// What the one-shot HTTP server captured from the implant's request.
pub(crate) struct CapturedRequest {
    /// e.g. `POST /beacon HTTP/1.1` (absolute-form when going through a proxy).
    pub request_line: String,
    /// Raw request head, lowercased — case-insensitive substring asserts.
    pub headers: String,
    /// Request body (per Content-Length; empty for header-terminator profiles).
    pub body: Vec<u8>,
}

/// Find `needle` in `hay`, returning the start index.
fn find_subslice(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

/// Bind 127.0.0.1:0 and spawn a thread that accepts ONE connection, reads ONE
/// HTTP request (headers + Content-Length body), replies `200 OK` with
/// `response` as the body, then sends the captured request over the channel.
pub(crate) fn one_shot_http_server(response: Vec<u8>) -> (u16, Receiver<CapturedRequest>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let port = listener.local_addr().expect("local_addr").port();
    let (tx, rx) = channel();
    std::thread::spawn(move || {
        let (mut sock, _) = listener.accept().expect("accept");
        sock.set_read_timeout(Some(CAPTURE_TIMEOUT)).ok();
        let mut buf: Vec<u8> = Vec::new();
        let mut tmp = [0u8; 4096];
        // Read until the end of the header block.
        let header_end = loop {
            if let Some(pos) = find_subslice(&buf, b"\r\n\r\n") {
                break pos;
            }
            let n = sock.read(&mut tmp).expect("read request head");
            assert!(n > 0, "eof before end of request head");
            buf.extend_from_slice(&tmp[..n]);
        };
        let head = String::from_utf8_lossy(&buf[..header_end]).into_owned();
        let request_line = head.lines().next().unwrap_or("").to_string();
        let headers = head.to_lowercase();
        let content_length: usize = headers
            .lines()
            .find_map(|l| l.strip_prefix("content-length:"))
            .and_then(|v| v.trim().parse().ok())
            .unwrap_or(0);
        let mut body: Vec<u8> = buf[header_end + 4..].to_vec();
        while body.len() < content_length {
            let n = sock.read(&mut tmp).expect("read request body");
            if n == 0 {
                break;
            }
            body.extend_from_slice(&tmp[..n]);
        }
        body.truncate(content_length);
        let head_out = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            response.len()
        );
        sock.write_all(head_out.as_bytes()).expect("write response head");
        sock.write_all(&response).expect("write response body");
        sock.flush().ok();
        let _ = tx.send(CapturedRequest {
            request_line,
            headers,
            body,
        });
    });
    (port, rx)
}

/// Bind 127.0.0.1:0 and spawn a thread that accepts ONE connection, reads ONE
/// length-prefixed frame (`[4-byte LE len][payload]` — the SMB/TCP pivot wire
/// format), replies with `[len][response]`, and reports the received payload.
pub(crate) fn one_shot_tcp_frame_server(response: Vec<u8>) -> (u16, Receiver<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let port = listener.local_addr().expect("local_addr").port();
    let (tx, rx) = channel();
    std::thread::spawn(move || {
        let (mut sock, _) = listener.accept().expect("accept");
        sock.set_read_timeout(Some(CAPTURE_TIMEOUT)).ok();
        let mut prefix = [0u8; 4];
        sock.read_exact(&mut prefix).expect("read length prefix");
        let len = u32::from_le_bytes(prefix) as usize;
        let mut payload = vec![0u8; len];
        sock.read_exact(&mut payload).expect("read frame payload");
        let out_len = (response.len() as u32).to_le_bytes();
        sock.write_all(&out_len).expect("write response prefix");
        sock.write_all(&response).expect("write response body");
        sock.flush().ok();
        let _ = tx.send(payload);
    });
    (port, rx)
}

/// A `ChannelCtx` pointing at `host:port` with every optional channel knob
/// unset (no rotation/fronting/proxy/resolver/pipe/peer/extc2). Tests mutate
/// the fields they exercise.
pub(crate) fn ctx(host: &str, port: u16) -> crate::channels::ChannelCtx {
    use nyx_implant_core::heap::String;
    crate::channels::ChannelCtx {
        server_host: String::from(host),
        server_port: port,
        use_tls: false,
        doh_resolver: String::new(),
        smb_pipe_name: String::new(),
        tcp_peer_host: String::new(),
        tcp_peer_port: 0,
        extc2_api_host: String::new(),
        extc2_token: String::new(),
        rotation_hosts: String::new(),
        fronting_host: String::new(),
        proxy_server: String::new(),
    }
}

/// Encode `payload` the way the team server would put it on the wire for the
/// http-post SERVER envelope (identity when the build has no NYX_PROFILE).
/// Using the baked steps keeps the loopback tests profile-agnostic: they pass
/// both for raw-frame builds and for malleable-profile builds.
pub(crate) fn server_wire_response(payload: &[u8]) -> Vec<u8> {
    nyx_profile::encode(&crate::envelopes::post_server_steps(), payload)
}
