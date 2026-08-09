//! End-to-end runtime test for the SMB named-pipe pivot parent
//! (`nyx_server::smb_listener`, spec-2).
//!
//! Windows-only: named pipes don't exist on macOS/Linux, so this whole file
//! compiles out on non-Windows hosts and runs on the hosted windows-latest CI
//! job — the "real Windows" runtime verification of the smb-pipe channel.
//!
//! The test drives the listener exactly like the implant child
//! (`crates/implant-win/src/channels/smb.rs`) does: open `\\.\pipe\<name>`,
//! write ONE `[4B LE len][encrypted frame]`, read the `[4B LE len][reply]`,
//! then close. The reply must be a valid server→client frame sealed for the
//! session key, and the session must land in the registry.

#![cfg(windows)]

use std::io::{Read, Write};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use nyx_protocol::{
    encode_frame_dir, open_frame_dir, wire::Writer, Direction, ImplantKeypair, SessionInfo,
};
use nyx_server::AppState;

/// Unique pipe name per test process so parallel test binaries never collide
/// on the same `\\.\pipe\` namespace.
static PIPE_SEQ: AtomicU32 = AtomicU32::new(0);

fn test_pipe_name() -> String {
    let seq = PIPE_SEQ.fetch_add(1, Ordering::Relaxed);
    format!(r"\\.\pipe\nyx-e2e-{}-{seq}", std::process::id())
}

/// Read exactly `buf.len()` bytes, looping over short reads (byte-mode
/// named-pipe reads return whatever is currently buffered) with a hard
/// deadline so a wedged listener fails the test instead of hanging CI.
fn read_exact_bounded(
    file: &mut std::fs::File,
    buf: &mut [u8],
    deadline: Instant,
) -> std::io::Result<()> {
    let mut off = 0;
    while off < buf.len() {
        if Instant::now() >= deadline {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "pipe reply timeout",
            ));
        }
        let n = file.read(&mut buf[off..])?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "pipe closed by server",
            ));
        }
        off += n;
    }
    Ok(())
}

/// One child transaction, exactly like the implant's `smb::send_recv`:
/// open the pipe, write `[4B LE len][sealed check-in frame]`, read the
/// `[4B LE len][sealed reply]`, assert the reply opens with the session key
/// and the session lands in the registry. Returns the session pubkey.
fn child_transaction(state: &Arc<AppState>, pipe_name: &str, beacon_id: u32) -> [u8; 32] {
    let server_pub = state.keypair.public_bytes();

    // The listener thread creates the pipe instance asynchronously, so the
    // first open can hit ERROR_FILE_NOT_FOUND / ERROR_PIPE_BUSY. Retry with
    // the same bounded window the implant child has (5 s WaitNamedPipeW).
    let open_deadline = Instant::now() + Duration::from_secs(5);
    let mut pipe = loop {
        match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(pipe_name)
        {
            Ok(f) => break f,
            Err(e) => {
                assert!(
                    Instant::now() < open_deadline,
                    "named pipe {pipe_name} never became connectable: {e}"
                );
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    };

    // Seal a check-in frame exactly like the implant child would.
    let ikp = ImplantKeypair::generate().unwrap();
    let pubkey = ikp.public_bytes();
    let key = ikp.session_key(&server_pub).unwrap();
    let mut w = Writer::new();
    SessionInfo {
        beacon_id,
        hostname: "smb-pipe-host".into(),
        username: "tester".into(),
        os: "windows".into(),
        arch: 0,
        pid: 4242,
        is_admin: 1,
        auth_token: None,
    }
    .encode(&mut w)
    .unwrap();
    let frame =
        encode_frame_dir(&pubkey, Direction::ClientToServer, 0, &key, &w.into_bytes()).unwrap();

    // Child transaction: [4B LE len][frame] in, [4B LE len][reply] out.
    let mut out = Vec::with_capacity(4 + frame.len());
    out.extend_from_slice(&(frame.len() as u32).to_le_bytes());
    out.extend_from_slice(&frame);
    pipe.write_all(&out).unwrap();

    let reply_deadline = Instant::now() + Duration::from_secs(10);
    let mut len_buf = [0u8; 4];
    read_exact_bounded(&mut pipe, &mut len_buf, reply_deadline).expect("reply length prefix");
    let reply_len = u32::from_le_bytes(len_buf) as usize;
    let mut reply = vec![0u8; reply_len];
    read_exact_bounded(&mut pipe, &mut reply, reply_deadline).expect("reply body");

    // The reply must be a valid server→client frame for our session.
    let raw = nyx_protocol::parse_frame(&reply).expect("reply parses as a frame");
    assert_eq!(raw.pubkey, pubkey);
    open_frame_dir(&key, Direction::ServerToClient, &raw).expect("reply opens with session key");

    // The session registry must contain the new session (peer placeholder
    // 0.0.0.0:0 is the documented named-pipe behavior).
    assert!(state.sessions.contains_key(&pubkey));
    pubkey
}

#[test]
fn smb_pipe_listener_roundtrips() {
    // Surface the listener thread's own logs (nyx::pivot target) so a
    // failing round-trip shows which phase errored server-side.
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_test_writer()
        .try_init();

    let state = Arc::new(AppState::default());
    let pipe_name = test_pipe_name();

    // Boot the listener on its own thread — the exact entry the server uses
    // at startup with NYX_SMB_PIPE_NAME set.
    nyx_server::smb_listener::spawn(state.clone(), pipe_name.clone());

    // First child transaction: full check-in round-trip.
    child_transaction(&state, &pipe_name, 42);

    // Second child transaction (fresh session, different beacon_id) proves
    // the listener re-arms after DisconnectNamedPipe and keeps serving — the
    // spawn-loop re-arm path, not just a one-shot transaction. No sleep:
    // the listener only re-arms after the child has consumed the reply
    // (FlushFileBuffers drain in serve_transaction), so the next connect can
    // race the re-arm safely.
    child_transaction(&state, &pipe_name, 43);
}
