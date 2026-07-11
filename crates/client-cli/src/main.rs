//! Nyx operator TUI — opencode-style fullscreen client.
//!
//! Entry point. `main` parses the few launch flags and hands off to the TUI.

mod parse;
mod rest;
mod socks;
mod theme;
mod tui;
mod types;

use std::net::SocketAddr;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "nyx-cli", version, about = "Nyx operator TUI")]
struct Cli {
    /// Team server URL.
    #[arg(long, env = "NYX_SERVER", default_value = "http://127.0.0.1:8443")]
    server: String,

    /// Optional API bearer token (matches the server's NYX_TOKEN gate).
    #[arg(long, env = "NYX_TOKEN")]
    token: Option<String>,

    /// Optional subcommand. Bare `nyx-cli` (no subcommand) launches the TUI —
    /// every existing invocation keeps working unchanged.
    #[command(subcommand)]
    cmd: Option<CliCmd>,
}

#[derive(Subcommand)]
enum CliCmd {
    /// Run a headless SOCKS5 listener that bridges local SOCKS5 traffic to an
    /// implant session's relay channels (Phase 4 operator-side relay).
    Socks {
        /// The 64-hex-char session id to relay through.
        session: String,
        /// Local address:port to bind the SOCKS5 listener on.
        #[arg(long, default_value = "127.0.0.1:1080")]
        listen: SocketAddr,
        /// `/api/results` poll interval in milliseconds.
        #[arg(long, default_value_t = 500)]
        poll_ms: u64,
        /// Max concurrent relay channels (the implant caps at 16).
        #[arg(long, default_value_t = 14)]
        max_chan: usize,
        /// SOCKS5 username (RFC 1929 method 0x02). REQUIRED for non-loopback
        /// `--listen` binds (otherwise the listener is an open proxy).
        /// Optional on loopback.
        #[arg(long)]
        socks_user: Option<String>,
        /// SOCKS5 password (RFC 1929). Paired with --socks-user.
        #[arg(long)]
        socks_pass: Option<String>,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Some(CliCmd::Socks {
            session,
            listen,
            poll_ms,
            max_chan,
            socks_user,
            socks_pass,
        }) => {
            // P0-10: socks auth must be both-or-neither. A lone user without a
            // pass (or vice-versa) is a misconfiguration. run_socks separately
            // refuses a non-loopback bind that has no auth configured.
            let socks_auth = match (socks_user, socks_pass) {
                (Some(u), Some(p)) => Some((u, p)),
                (None, None) => None,
                _ => {
                    anyhow::bail!(
                        "--socks-user and --socks-pass must be set together, or both omitted \
                         for a loopback (NO-AUTH) listener"
                    );
                }
            };
            // Headless: own a multi-thread runtime (the SOCKS relay needs
            // concurrent per-connection tasks + a TcpListener). This runtime is
            // distinct from the TUI worker's current-thread one.
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;
            rt.block_on(socks::run_socks(
                cli.server, cli.token, session, listen, poll_ms, max_chan, socks_auth,
            ))
        }
        None => tui::run(&cli.server, cli.token.as_deref()),
    }
}
