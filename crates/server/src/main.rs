use std::sync::Arc;

use nyx_protocol::ServerKeypair;
use nyx_server::{load_or_create_keypair, load_profile, load_script, router, AppState};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // rustls 0.23 no longer auto-selects a CryptoProvider at first use — even
    // with the `ring` feature enabled, if more than one provider is in the
    // dependency graph (e.g. aws-lc-rs pulled transitively) the first TLS op
    // panics with "Could not automatically determine the process-level
    // CryptoProvider". Install ring explicitly, early, before any TLS use.
    // No-op if a provider is already installed (e.g. by another crate).
    let _ = rustls::crypto::ring::default_provider().install_default();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "nyx_server=info,info".into()),
        )
        .init();

    // Load a Malleable C2 profile (lint-checked) if NYX_PROFILE is set. The
    // server then also serves the beacon endpoint at the profile's URIs.
    let profile = match std::env::var("NYX_PROFILE") {
        Ok(path) => {
            let p = load_profile(std::path::Path::new(&path))?;
            let get = p
                .http_get()
                .and_then(|b| b.get("uri"))
                .map(|u| u.as_str().into_owned());
            let post = p
                .http_post()
                .and_then(|b| b.get("uri"))
                .map(|u| u.as_str().into_owned());
            tracing::info!(?get, ?post, "loaded Malleable C2 profile");
            Some(p)
        }
        Err(_) => None,
    };

    // Guardrails: an optional API token (Bearer auth on /api/*) and a kill date.
    let api_token = std::env::var("NYX_TOKEN").ok().filter(|s| !s.is_empty());
    let killdate = std::env::var("NYX_KILLDATE")
        .ok()
        .and_then(|s| s.parse::<u64>().ok());
    if let Some(kd) = killdate {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(u64::MAX); // Err on the side of caution: kill-date active if clock is broken
        if now >= kd {
            anyhow::bail!("kill date {kd} has passed (now={now}); refusing to start");
        }
        tracing::info!(
            killdate = kd,
            "kill date active; server will stop serving after it"
        );
    }
    if api_token.is_some() {
        tracing::info!("control-API bearer-token guard enabled (NYX_TOKEN)");
    }

    let keypair = match std::env::var("NYX_KEYFILE") {
        Ok(p) => {
            let kp = load_or_create_keypair(std::path::Path::new(&p))?;
            tracing::info!(keyfile = %p, "persisted server identity loaded");
            kp
        }
        Err(_) => ServerKeypair::generate(),
    };

    // Persistent credential store (Phase 2). Loads on every boot so creds
    // SURVIVE a server restart — unlike the in-memory sessions (which are lost
    // even with NYX_KEYFILE, since only the keypair persists, not the registry).
    // Path from NYX_CREDS, else ~/.nyx/server-creds.db.
    let creds_path = match std::env::var("NYX_CREDS") {
        Ok(p) => p,
        Err(_) => {
            let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
            format!("{home}/.nyx/server-creds.db")
        }
    };
    let cred_store = nyx_store::CredStore::open(std::path::Path::new(&creds_path))
        .map_err(|e| anyhow::anyhow!("failed to open cred store at {creds_path}: {e}"))?;
    tracing::info!(
        creds = %creds_path,
        restored = cred_store.count().unwrap_or(0),
        "credential store loaded"
    );

    // Phase 3: named-operator registry + action audit log.
    let operators_path = match std::env::var("NYX_OPERATORS_FILE") {
        Ok(p) => std::path::PathBuf::from(p),
        Err(_) => {
            let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
            std::path::PathBuf::from(format!("{home}/.nyx/operators.json"))
        }
    };
    let operators = nyx_server::operators::OperatorRegistry::load_or_bootstrap(
        &operators_path,
        std::env::var("NYX_TOKEN").ok().as_deref(),
        std::env::var("NYX_BOOTSTRAP_OPERATOR").ok().as_deref(),
    )?;
    let auth_mode = if !operators.is_open() {
        "named-operators"
    } else if std::env::var("NYX_TOKEN").is_ok() {
        "legacy-token"
    } else {
        "open"
    };
    tracing::info!(
        operators = %operators_path.display(),
        count = operators.list().len(),
        mode = auth_mode,
        "operator registry loaded"
    );

    let audit_path = match std::env::var("NYX_AUDIT_LOG") {
        Ok(p) => std::path::PathBuf::from(p),
        Err(_) => {
            let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
            std::path::PathBuf::from(format!("{home}/.nyx/audit.jsonl"))
        }
    };
    let audit_writer = nyx_server::audit::AuditWriter::open(&audit_path)?;
    tracing::info!(audit = %audit_path.display(), "action audit log opened");

    let mut state = AppState {
        keypair,
        sessions: Default::default(),
        profile,
        api_token,
        killdate,
        events: nyx_scripting::EventBus::new(),
        fingerprints: Default::default(),
        creds: Arc::new(cred_store),
        operators: Arc::new(operators),
        audit: Some(Arc::new(audit_writer)),
    };
    state.register_default_hooks();
    // Optional operator automation: a Rhai script run on session/result events.
    if let Ok(p) = std::env::var("NYX_SCRIPT") {
        match load_script(std::path::Path::new(&p)) {
            Ok(hook) => {
                tracing::info!(script = %p, "loaded operator Rhai script");
                state.events.register(Box::new(hook));
            }
            Err(e) => {
                tracing::error!(error = %e, "failed to load NYX_SCRIPT; continuing without it")
            }
        }
    }
    let state = Arc::new(state);

    let pubkey = hex::encode(state.keypair.public_bytes());
    let addr = std::env::var("NYX_BIND").unwrap_or_else(|_| "0.0.0.0:8443".to_string());

    let app = router(state.clone());
    let listener = tokio::net::TcpListener::bind(&addr).await?;

    // HTTPS (NYX_TLS): peek the ClientHello before rustls consumes the stream,
    // compute JA3/JA4, stash them keyed by peer addr (the beacon handler pops
    // them on check-in), then replay the bytes via PreambleStream so the TLS
    // handshake completes normally. When TLS is off, fall back to plaintext.
    match nyx_server::tls::build_acceptor()? {
        Some(acceptor) => {
            tracing::info!(%pubkey, %addr, scheme = "https", "Nyx team server listening (TLS); bake server_pub={pubkey} into implants");
            loop {
                let (stream, peer) = listener.accept().await?;
                let acc = acceptor.clone();
                let app = app.clone();
                let fps = state.fingerprints.clone();
                tokio::spawn(async move {
                    let timeout_dur = std::time::Duration::from_secs(5);
                    // Read the ClientHello (blocking, tiny) off the stream first.
                    let stream =
                        match tokio::time::timeout(timeout_dur, sniff_and_store(stream, peer, fps))
                            .await
                        {
                            Ok(Ok(s)) => s,
                            _ => {
                                tracing::debug!(%peer, "ClientHello sniff timed out or failed");
                                return;
                            }
                        };

                    match tokio::time::timeout(timeout_dur, acc.accept(stream)).await {
                        Ok(Ok(tls)) => {
                            let io = hyper_util::rt::TokioIo::new(tls);
                            let builder = hyper_util::server::conn::auto::Builder::new(
                                hyper_util::rt::TokioExecutor::new(),
                            );
                            // into_make_service_with_connect_info feeds
                            // ConnectInfo<SocketAddr> to the beacon handler
                            // so it can look up the fingerprint cache.
                            let make_svc = app
                                .clone()
                                .into_make_service_with_connect_info::<std::net::SocketAddr>();
                            // Manually drive the MakeService for this connection
                            // (axum::serve does this internally, but we handle
                            // the accept loop ourselves for TLS + fingerprinting).
                            let svc = tower::ServiceExt::oneshot(make_svc, peer).await.unwrap();
                            let svc = hyper_util::service::TowerToHyperService::new(svc);
                            let _ = builder.serve_connection(io, svc).await;
                        }
                        _ => tracing::debug!(%peer, "TLS handshake timed out or failed"),
                    }
                });
            }
        }
        None => {
            tracing::info!(%pubkey, %addr, scheme = "http", "Nyx team server listening (plaintext); bake server_pub={pubkey} into implants");
            // into_make_service_with_connect_info feeds ConnectInfo<SocketAddr>
            // to the beacon handler so it can look up the fingerprint cache
            // (always empty on plaintext, but the extractor must still resolve).
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .await?;
        }
    }
    Ok(())
}

/// Peek the TLS ClientHello off a freshly-accepted TCP stream, compute JA3/JA4,
/// store them under `peer` in the fingerprint cache, and return a stream that
/// replays the consumed bytes in front of the rest of the connection.
async fn sniff_and_store(
    mut stream: tokio::net::TcpStream,
    peer: std::net::SocketAddr,
    fps: dashmap::DashMap<std::net::SocketAddr, nyx_server::Fingerprint>,
) -> std::io::Result<nyx_server::tls::PreambleStream<tokio::net::TcpStream>> {
    use tokio::io::AsyncReadExt;
    // Read the 5-byte TLS record header, then the record body. Use a small
    // fixed buffer; ClientHello records are well under 16 KiB.
    let mut header = [0u8; 5];
    stream.read_exact(&mut header).await?;
    if header[0] != 22 {
        // Not a TLS handshake — return the preamble (header bytes) and let the
        // TLS acceptor fail naturally. No fingerprint stored.
        return Ok(nyx_server::tls::PreambleStream::new(
            header.to_vec(),
            stream,
        ));
    }
    let rec_len = ((header[3] as usize) << 8) | header[4] as usize;
    if rec_len > 16384 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "ClientHello record size exceeds TLS maximum",
        ));
    }
    let mut payload = vec![0u8; rec_len];
    stream.read_exact(&mut payload).await?;

    let mut record = Vec::with_capacity(5 + payload.len());
    record.extend_from_slice(&header);
    record.extend_from_slice(&payload);

    // Compute JA3/JA4 from the captured record.
    let (ja3, ja4) = match nyx_transport::parse_client_hello(&record) {
        Ok(ch) => (Some(nyx_transport::ja3(&ch)), Some(nyx_transport::ja4(&ch))),
        Err(_) => (None, None),
    };
    if ja3.is_some() || ja4.is_some() {
        tracing::debug!(%peer, ja3 = ?ja3, ja4 = ?ja4, "captured inbound TLS fingerprint");
    }
    fps.insert(peer, nyx_server::Fingerprint { ja3, ja4 });
    Ok(nyx_server::tls::PreambleStream::new(record, stream))
}
