//! TLS configuration for the team server's HTTPS listener.
//!
//! Pure-Rust: [`rustls`] with the `ring` crypto provider — no C/OpenSSL deps.
//! The server accepts TLS either via:
//! - an operator-supplied cert+key (PEM on disk, `NYX_CERT` / `NYX_KEY`), or
//! - a self-signed dev cert generated in-memory (when `NYX_TLS=on` with no PEM).
//!
//! Self-signed is for dev only — operators should front the server with a
//! redirector / real cert in engagements. With `rustls::ServerConfig` in hand,
//! `tokio_rustls::TlsAcceptor` wraps the TCP listener.

use std::sync::Arc;
use std::sync::OnceLock;

use anyhow::{anyhow, Context, Result};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

/// A ready-to-use TLS acceptor, built from PEM cert/key on disk or (dev) a
/// freshly minted self-signed pair. Returns `Ok(None)` when no cert source is
/// configured so the caller can fall back to plaintext HTTP.
pub fn build_acceptor() -> Result<Option<tokio_rustls::TlsAcceptor>> {
    let tls_on = std::env::var("NYX_TLS").ok().is_some();
    let cert_path = std::env::var("NYX_CERT").ok();
    let key_path = std::env::var("NYX_KEY").ok();

    // No TLS requested at all.
    if cert_path.is_none() && key_path.is_none() && !tls_on {
        return Ok(None);
    }

    // Build the ServerConfig (cached when self-signed, since the key is not Clone).
    let cfg: Arc<rustls::ServerConfig> = match (cert_path, key_path) {
        (Some(c), Some(k)) => {
            let cert = load_pem_cert(&c)?;
            let key = load_pem_key(&k)?;
            server_config(cert, key)?
        }
        (Some(_), None) | (None, Some(_)) => {
            return Err(anyhow!(
                "NYX_TLS: set both NYX_CERT and NYX_KEY (or neither for self-signed)"
            ));
        }
        (None, None) => self_signed_config()?,
    };
    Ok(Some(tokio_rustls::TlsAcceptor::from(cfg)))
}

fn server_config(
    cert: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<Arc<rustls::ServerConfig>> {
    let cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert, key)
        .map_err(|e| anyhow!("rustls ServerConfig: {e}"))?;
    Ok(Arc::new(cfg))
}

fn load_pem_cert(path: &str) -> Result<Vec<CertificateDer<'static>>> {
    let pem = std::fs::read(path).with_context(|| format!("read cert {path}"))?;
    let certs: Vec<_> = rustls_pemfile::certs(&mut &pem[..])
        .collect::<Result<_, _>>()
        .map_err(|e| anyhow!("parse cert PEM {path}: {e}"))?;
    if certs.is_empty() {
        return Err(anyhow!("no certificates found in {path}"));
    }
    Ok(certs)
}

fn load_pem_key(path: &str) -> Result<PrivateKeyDer<'static>> {
    let pem = std::fs::read(path).with_context(|| format!("read key {path}"))?;
    let key = rustls_pemfile::private_key(&mut &pem[..])
        .map_err(|e| anyhow!("parse key PEM {path}: {e}"))?
        .ok_or_else(|| anyhow!("no private keys found in {path}"))?;
    Ok(key)
}

/// Cached self-signed ServerConfig. The generated key is ephemeral and reused
/// for the process lifetime — `PrivateKeyDer` is not `Clone`, so we cache the
/// finished config instead.
static SELF_SIGNED_CFG: OnceLock<Arc<rustls::ServerConfig>> = OnceLock::new();

fn self_signed_config() -> Result<Arc<rustls::ServerConfig>> {
    if let Some(cfg) = SELF_SIGNED_CFG.get() {
        return Ok(cfg.clone());
    }
    let san = hostname_or_localhost();
    tracing::warn!(
        san = %san,
        "NYX_TLS=on with no NYX_CERT/NYX_KEY: generating a SELF-SIGNED dev cert (do NOT use in engagements)"
    );
    let params =
        rcgen::CertificateParams::new(vec![san]).map_err(|e| anyhow!("rcgen params: {e}"))?;
    let kp = rcgen::KeyPair::generate().map_err(|e| anyhow!("rcgen keypair: {e}"))?;
    let cert = params
        .self_signed(&kp)
        .map_err(|e| anyhow!("rcgen self_signed: {e}"))?;
    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::try_from(kp.serialize_der())
        .map_err(|e| anyhow!("key der conversion: {e}"))?;
    let cfg = server_config(vec![cert_der], key_der)?;
    let _ = SELF_SIGNED_CFG.set(cfg.clone());
    Ok(cfg)
}

fn hostname_or_localhost() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_else(|_| "localhost".to_string())
}

/// A stream wrapper that first yields a buffered preamble (the ClientHello
/// bytes the sniffer consumed) and then reads through to the underlying stream.
/// This lets us peek the ClientHello for JA3/JA4 *before* rustls takes over,
/// then replay those bytes so the TLS handshake completes normally.
pub struct PreambleStream<S> {
    preamble: std::io::Cursor<Vec<u8>>,
    inner: S,
}

impl<S> PreambleStream<S> {
    /// `preamble` is the bytes already read from `inner`'s head (e.g. the
    /// ClientHello record); `inner` is positioned just past them.
    pub fn new(preamble: Vec<u8>, inner: S) -> Self {
        Self {
            preamble: std::io::Cursor::new(preamble),
            inner,
        }
    }
}

impl<S: std::io::Read> std::io::Read for PreambleStream<S> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        // Drain the preamble first, then delegate to the real stream.
        if (self.preamble.position() as usize) < self.preamble.get_ref().len() {
            return std::io::Read::read(&mut self.preamble, buf);
        }
        self.inner.read(buf)
    }
}

impl<S: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for PreambleStream<S> {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let pos = this.preamble.position() as usize;
        let data = this.preamble.get_ref();
        if pos < data.len() {
            // Serve preamble bytes synchronously.
            let remaining = &data[pos..];
            let n = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..n]);
            this.preamble.set_position((pos + n) as u64);
            return std::task::Poll::Ready(Ok(()));
        }
        // Preamble exhausted — delegate to the underlying async stream.
        std::pin::Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for PreambleStream<S> {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        // S: Unpin, so a &mut S can be pinned safely.
        std::pin::Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }
    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }
    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}
