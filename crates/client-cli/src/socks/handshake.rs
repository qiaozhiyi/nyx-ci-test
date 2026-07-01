//! Server-side SOCKS5 handshake (RFC 1928), hand-rolled — no new deps.
//!
//! The bridge accepts ONLY method `0x00` (NO AUTH) and ONLY `CONNECT` (cmd
//! `0x01`); BIND and UDP ASSOCIATE are rejected with reply `0x07`. Supporting
//! SOCKS username/password auth would add nothing: the operator API bearer
//! token already authenticates the bridge to the team server, and the local
//! listener binds to loopback by default.
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

/// Read the SOCKS5 greeting `[05][nmethods][methods…]`, accept iff method
/// `0x00` (NO AUTH) is offered, and write the method-selection reply. Writes
/// `[05][FF]` (no acceptable method) and bails otherwise.
pub async fn read_greeting<S>(s: &mut S) -> Result<()>
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
    if methods.contains(&0x00) {
        s.write_all(&[0x05, 0x00]).await?;
    } else {
        // No acceptable methods — reply then close.
        s.write_all(&[0x05, 0xFF]).await?;
        bail!("client offered no NO-AUTH (0x00) method");
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
        read_greeting(&mut server).await.unwrap();
        let mut reply = [0u8; 2];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [0x05, 0x00]);
    }

    #[tokio::test]
    async fn greeting_rejects_when_no_noauth() {
        let (mut client, mut server) = tokio::io::duplex(64);
        // Only username/password (0x02) offered.
        client.write_all(&[0x05, 0x01, 0x02]).await.unwrap();
        let res = read_greeting(&mut server).await;
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
}
