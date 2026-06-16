use std::sync::Arc;

use nyx_protocol::ServerKeypair;
use nyx_server::{router, AppState};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "nyx_server=info,info".into()),
        )
        .init();

    let state = Arc::new(AppState {
        keypair: ServerKeypair::generate(),
        sessions: Default::default(),
    });

    let pubkey = hex::encode(state.keypair.public_bytes());
    let addr = std::env::var("NYX_BIND").unwrap_or_else(|_| "0.0.0.0:8443".to_string());

    let app = router(state);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!(%pubkey, %addr, "Nyx team server listening; bake server_pub={pubkey} into implants");

    axum::serve(listener, app).await?;
    Ok(())
}
