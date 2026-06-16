use std::sync::Arc;

use nyx_protocol::ServerKeypair;
use nyx_server::{load_profile, router, AppState};

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

    let state = Arc::new(AppState {
        keypair: ServerKeypair::generate(),
        sessions: Default::default(),
        profile,
    });

    let pubkey = hex::encode(state.keypair.public_bytes());
    let addr = std::env::var("NYX_BIND").unwrap_or_else(|_| "0.0.0.0:8443".to_string());

    let app = router(state);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!(%pubkey, %addr, "Nyx team server listening; bake server_pub={pubkey} into implants");

    axum::serve(listener, app).await?;
    Ok(())
}
