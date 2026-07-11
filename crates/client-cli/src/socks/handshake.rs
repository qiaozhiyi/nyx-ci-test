//! Server-side SOCKS5 handshake (RFC 1928 + RFC 1929), hand-rolled — no new deps.
//!
//! The bridge accepts `CONNECT` (cmd `0x01`) only; BIND and UDP ASSOCIATE are
//! rejected with reply `0x07`. Auth method selection is bind-aware (P0-10):
//!  - loopback binds run auth-less (method `0x00` only) — local, safe;
//!  - non-loopback binds REQUIRE RFC 1929 username/password auth (`0x02`),
//!    enforced by `run_socks` (it refuses to start an open proxy). When creds
//!    are configured the greeting requires `0x02` and refuses clients that
//!    don't offer it (no `0x00` fallback — that would open an unauthenticated
//!    tunnel through configured creds).
//!
//! Each function takes a SINGLE combined `AsyncRead + AsyncWrite` stream and
//! uses it for both reading the request and writing the reply — the handshake
//! is strictly sequential, so no split is needed until the bidirectional ferry
//! (see [`super::relay`], which `tokio::io::split`s after the handshake).

use std::net::{Ipv4Addr, Ipv6Addr};

use anyhow::{anyhow, bail, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// The target address a SOCKS5 client asked us to reach. The bridge passes the
/// string form to the implant's connect; note the implant is currently IPv4-only
/// (`inet_addr` in pivot.rs rejects hostnames + IPv6), so `Domain`/`Ipv6`
/// targets will fail at connect — a documented v1 limitation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SocksTarget {
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
    Domain(String),
}

impl SocksTarget {
    /// String form for the implant's connect `host` field.
    pub fn to_host(&self) -> String {
        match self {
            SocksTarget::Ipv4(a) => a.to_string(),
            SocksTarget::Ipv6(a) => a.to_string(),
            SocksTarget::Domain(d) => d.clone(),
        }
    }

    /// True only for dotted-quad IPv4 (the one target type the implant can
    /// actually reach today). Used to warn on unsupported targets.
    pub fn implant_reachable(&self) -> bool {
        matches!(self, SocksTarget::Ipv4(_))
    }
}

/// Read the SOCKS5 greeting `[05][nmethods][methods…]` and select an auth
/// method (RFC 1928 §3), then write the method-selection reply.
///
/// Auth policy (P0-10 — prevents an open proxy on non-loopback binds):
///  - `auth = Some(_)` (non-loopback bind, RFC 1929 creds configured): REQUIRE
///    method `0x02` (username/password). If the client doesn't offer `0x02`,
///    reply `[05][FF]` and bail — never fall back to `0x00`, since that would
///    open an unauthenticated tunnel through configured creds.
///  - `auth = None` (loopback only): accept `0x00` exclusively.
///  - Otherwise reply `[05][FF]` (no acceptable method) and bail.
///
/// When `0x02` is selected, the RFC 1929 username/password sub-negotiation is
/// performed inline by [`read_userpass_auth`].
pub async fn read_greeting<S>(s: &mut S, auth: Option<&(String, String)>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let ver = s.read_u8().await?;
    if ver != 0x05 {
        bail!("not SOCKS5 (version byte {ver})");
    }
    let nmethods = s.read_u8().await? as usize;
    let mut methods = vec![0u8; nmethods];
    s.read_exact(&mut methods).await?;

    let selected = if auth.is_some() {
        if methods.contains(&0x02) {
            0x02 // username/password (RFC 1929)
        } else {
            // Auth is configured, so an open NO-AUTH tunnel would defeat it.
            // Require 0x02 — never fall back to 0x00 even if the client offers it.
            0xFF
        }
    } else if methods.contains(&0x00) {
        0x00
    } else {
        0xFF
    };

    s.write_all(&[0x05, selected]).await?;
    if selected == 0xFF {
        bail!(
            "client offered no acceptable SOCKS5 auth method (got {:?})",
            methods
        );
    }
    if selected == 0x02 {
        let creds = auth.expect("0x02 selected only when auth is Some");
        read_userpass_auth(s, creds).await?;
    }
    Ok(())
}

/// RFC 1929 username/password sub-negotiation. Reads
/// `VER(0x01) ULEN(1) UNAME(ULEN) PLEN(1) PASSWD(PLEN)`, validates against
/// `creds`, and replies `VER(0x01) STATUS(0=ok / 1=fail)`. Bails on a mismatch
/// or malformed frame so the caller drops the connection.
///
/// The compare is not constant-time: this guards an open proxy, not a
/// high-value secret, and the username length already leaks via ULEN anyway.
/// ULEN/PLEN are bounded by u8 (≤255), so the reads cannot be a memory DoS.
async fn read_userpass_auth<S>(s: &mut S, creds: &(String, String)) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let ver = s.read_u8().await?;
    if ver != 0x01 {
        // RFC 1929 fixes the sub-negotiation version at 0x01.
        let _ = s.write_all(&[0x01, 0x01]).await; // status = failure
        bail!("bad RFC1929 auth version ({ver})");
    }
    let ulen = s.read_u8().await? as usize;
    let mut uname = vec![0u8; ulen];
    s.read_exact(&mut uname).await?;
    let plen = s.read_u8().await? as usize;
    let mut passwd = vec![0u8; plen];
    s.read_exact(&mut passwd).await?;

    let ok = uname.as_slice() == creds.0.as_bytes() && passwd.as_slice() == creds.1.as_bytes();
    s.write_all(&[0x01, if ok { 0x00 } else { 0x01 }]).await?;
    if !ok {
        bail!("SOCKS5 username/password authentication failed");
    }
    Ok(())
}

/// Read the SOCKS5 request `[05][cmd][00][atyp][dst.addr][dst.port BE]`.
/// Supports cmd CONNECT (`0x01`) and atyp IPv4 (`0x01`), domain (`0x03`),
/// IPv6 (`0x04`). Writes the appropriate failure reply and bails for
/// unsupported cmd/atyp so the caller just drops the connection.
pub async fn read_request<S>(s: &mut S) -> Result<(SocksTarget, u16)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let ver = s.read_u8().await?;
    let cmd = s.read_u8().await?;
    let _rsv = s.read_u8().await?;
    let atyp = s.read_u8().await?;
    if ver != 0x05 {
        bail!("bad SOCKS5 version in request ({ver})");
    }
    if cmd != 0x01 {
        // Command not supported (BIND=0x02, UDP=0x03).
        write_reply_failure(s, 0x07).await?;
        bail!("unsupported SOCKS5 cmd {cmd} (only CONNECT=1)");
    }
    let target = match atyp {
        0x01 => {
            let mut a = [0u8; 4];
            s.read_exact(&mut a).await?;
            SocksTarget::Ipv4(Ipv4Addr::from(a))
        }
        0x03 => {
            let len = s.read_u8().await? as usize;
            let mut d = vec![0u8; len];
            s.read_exact(&mut d).await?;
            SocksTarget::Domain(String::from_utf8_lossy(&d).into_owned())
        }
        0x04 => {
            let mut a = [0u8; 16];
            s.read_exact(&mut a).await?;
            SocksTarget::Ipv6(Ipv6Addr::from(a))
        }
        other => {
            // Address type not supported.
            write_reply_failure(s, 0x08).await?;
            bail!("unsupported SOCKS5 atyp {other}");
        }
    };
    let port = s.read_u16().await?;
    Ok((target, port))
}

/// Write the SOCKS5 success reply (BND.ADDR=0.0.0.0 / BND.PORT=0 — the implant
/// does not report a real bound address; the client only needs the success code).
pub async fn write_reply_success<W: AsyncWrite + Unpin>(w: &mut W) -> Result<()> {
    // [VER=05][REP=00 success][RSV=00][ATYP=01 IPv4][BND.ADDR=0.0.0.0][BND.PORT=0]
    w.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await?;
    Ok(())
}

/// Write a SOCKS5 failure reply with the given REP code (e.g. `0x05` connection
/// refused, `0x07` command not supported).
pub async fn write_reply_failure<W: AsyncWrite + Unpin>(w: &mut W, code: u8) -> Result<()> {
    w.write_all(&[0x05, code, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await?;
    Ok(())
}

// Keep the helper referenced when only failure/success paths are exercised.
#[allow(dead_code)]
fn _unused() -> Result<()> {
    Err(anyhow!("unreachable"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn greeting_accepts_no_auth() {
        let (mut client, mut server) = tokio::io::duplex(64);
        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        read_greeting(&mut server, None).await.unwrap();
        let mut reply = [0u8; 2];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [0x05, 0x00]);
    }

    #[tokio::test]
    async fn greeting_rejects_when_no_noauth() {
        let (mut client, mut server) = tokio::io::duplex(64);
        // Only username/password (0x02) offered.
        client.write_all(&[0x05, 0x01, 0x02]).await.unwrap();
        let res = read_greeting(&mut server, None).await;
        assert!(res.is_err());
        let mut reply = [0u8; 2];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [0x05, 0xFF]);
    }

    #[tokio::test]
    async fn request_parses_domain_and_port() {
        let (mut client, mut server) = tokio::io::duplex(128);
        let mut req = vec![0x05, 0x01, 0x00, 0x03, 9]; // CONNECT, domain, len=9
        req.extend_from_slice(b"localhost");
        req.extend_from_slice(&80u16.to_be_bytes());
        client.write_all(&req).await.unwrap();
        let (target, port) = read_request(&mut server).await.unwrap();
        assert_eq!(port, 80);
        assert_eq!(target, SocksTarget::Domain("localhost".to_string()));
    }

    #[tokio::test]
    async fn request_parses_ipv4() {
        let (mut client, mut server) = tokio::io::duplex(128);
        let mut req = vec![0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1];
        req.extend_from_slice(&443u16.to_be_bytes());
        client.write_all(&req).await.unwrap();
        let (target, port) = read_request(&mut server).await.unwrap();
        assert_eq!(port, 443);
        assert_eq!(target, SocksTarget::Ipv4(Ipv4Addr::new(127, 0, 0, 1)));
    }

    #[tokio::test]
    async fn request_rejects_bind() {
        let (mut client, mut server) = tokio::io::duplex(128);
        let mut req = vec![0x05, 0x02, 0x00, 0x01, 127, 0, 0, 1]; // cmd=BIND
        req.extend_from_slice(&80u16.to_be_bytes());
        client.write_all(&req).await.unwrap();
        let res = read_request(&mut server).await;
        assert!(res.is_err());
        let mut reply = [0u8; 10];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[1], 0x07); // command not supported
    }

    #[tokio::test]
    async fn reply_success_emits_exact_bytes() {
        let (mut client, mut server) = tokio::io::duplex(64);
        write_reply_success(&mut server).await.unwrap();
        let mut buf = [0u8; 10];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(buf, [0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
    }

    #[tokio::test]
    async fn greeting_prefers_userpass_when_configured() {
        // Non-loopback policy: auth configured + client offers both 0x02 and
        // 0x00 → server MUST select 0x02 (prefer auth over the open fallback).
        let (mut client, mut server) = tokio::io::duplex(128);
        client.write_all(&[0x05, 0x02, 0x00, 0x02]).await.unwrap();
        let creds = ("op".to_string(), "s3cret".to_string());
        // 0x02 selected → server now expects the RFC 1929 frame.
        client
            .write_all(&[0x01, 2, b'o', b'p', 6, b's', b'3', b'c', b'r', b'e', b't'])
            .await
            .unwrap();
        read_greeting(&mut server, Some(&creds)).await.unwrap();
        let mut reply = [0u8; 2];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [0x05, 0x02]); // method = username/password
        let mut status = [0u8; 2];
        client.read_exact(&mut status).await.unwrap();
        assert_eq!(status, [0x01, 0x00]); // RFC 1929 success
    }

    #[tokio::test]
    async fn greeting_userpass_rejects_wrong_creds() {
        let (mut client, mut server) = tokio::io::duplex(128);
        client.write_all(&[0x05, 0x01, 0x02]).await.unwrap();
        let creds = ("op".to_string(), "s3cret".to_string());
        // Wrong password.
        client
            .write_all(&[0x01, 2, b'o', b'p', 4, b'w', b'r', b'o', b'n'])
            .await
            .unwrap();
        let res = read_greeting(&mut server, Some(&creds)).await;
        assert!(res.is_err());
        // Server first writes the method-selection reply [0x05, 0x02], then
        // the RFC 1929 status frame [0x01, 0x01] (failure). Drain both.
        let mut method = [0u8; 2];
        client.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [0x05, 0x02]);
        let mut status = [0u8; 2];
        client.read_exact(&mut status).await.unwrap();
        assert_eq!(status, [0x01, 0x01]); // RFC 1929 failure
    }

    #[tokio::test]
    async fn greeting_rejects_noauth_when_configured() {
        // Auth configured but client only offers 0x00 → must NOT fall back to
        // NO-AUTH; reply 0xFF (no acceptable method) and close. Falling back
        // here would open an unauthenticated tunnel through configured creds.
        let (mut client, mut server) = tokio::io::duplex(64);
        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let creds = ("op".to_string(), "s3cret".to_string());
        let res = read_greeting(&mut server, Some(&creds)).await;
        assert!(res.is_err());
        let mut reply = [0u8; 2];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [0x05, 0xFF]);
    }

    #[tokio::test]
    async fn greeting_rejects_when_auth_required_but_only_noauth_offered_without_creds() {
        // Loopback policy (auth=None): client offers only 0x02 → must reject
        // with 0xFF (no acceptable method), since 0x00 isn't offered and there
        // are no configured creds to validate 0x02 anyway.
        let (mut client, mut server) = tokio::io::duplex(64);
        client.write_all(&[0x05, 0x01, 0x02]).await.unwrap();
        let res = read_greeting(&mut server, None).await;
        assert!(res.is_err());
        let mut reply = [0u8; 2];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [0x05, 0xFF]);
    }
}
