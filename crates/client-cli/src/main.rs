//! Nyx operator TUI — opencode-style fullscreen client.
//!
//! Entry point. `main` parses the few launch flags and hands off to the TUI.

mod parse;
mod rest;
mod theme;
mod tui;
mod types;

use clap::Parser;

#[derive(Parser)]
#[command(name = "nyx-cli", version, about = "Nyx operator TUI")]
struct Cli {
    /// Team server URL.
    #[arg(long, env = "NYX_SERVER", default_value = "http://127.0.0.1:8443")]
    server: String,

    /// Optional API bearer token (matches the server's NYX_TOKEN gate).
    #[arg(long, env = "NYX_TOKEN")]
    token: Option<String>,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    tui::run(&cli.server, cli.token.as_deref())
}
