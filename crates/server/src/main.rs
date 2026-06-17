use std::sync::Arc;

use nyx_protocol::ServerKeypair;
use nyx_server::{load_or_create_keypair, load_profile, load_script, router, AppState};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
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
            .unwrap_or(0);
        if now >= kd {
            anyhow::bail!("kill date {kd} has passed (now={now}); refusing to start");
        }
        tracing::info!(killdate = kd, "kill date active; server will stop serving after it");
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

    let mut state = AppState {
        keypair,
        sessions: Default::default(),
        profile,
        api_token,
        killdate,
        events: nyx_scripting::EventBus::new(),
    };
    state.register_default_hooks();
    // Optional operator automation: a Rhai script run on session/result events.
    if let Ok(p) = std::env::var("NYX_SCRIPT") {
        match load_script(std::path::Path::new(&p)) {
            Ok(hook) => {
                tracing::info!(script = %p, "loaded operator Rhai script");
                state.events.register(Box::new(hook));
            }
            Err(e) => tracing::error!(error = %e, "failed to load NYX_SCRIPT; continuing without it"),
        }
    }
    let state = Arc::new(state);

    let pubkey = hex::encode(state.keypair.public_bytes());
    let addr = std::env::var("NYX_BIND").unwrap_or_else(|_| "0.0.0.0:8443".to_string());

    let app = router(state);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!(%pubkey, %addr, "Nyx team server listening; bake server_pub={pubkey} into implants");

    axum::serve(listener, app).await?;
    Ok(())
}
