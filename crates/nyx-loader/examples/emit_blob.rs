//! Emit a real NYX2 blob to disk for the Unicorn full-blob probe:
//!   cargo run -p nyx-loader --example emit_blob -- <dll> [out.bin]
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let dll = args.next().ok_or("usage: emit_blob <dll> [out.bin]")?;
    let out = args.next().unwrap_or_else(|| "blob.bin".into());
    let dll_bytes = std::fs::read(&dll)?;
    let blob = nyx_loader::wrap_payload(&dll_bytes, &nyx_loader::LoaderConfig::random())?;
    std::fs::write(&out, &blob)?;
    println!(
        "wrote {} ({} bytes) from {}",
        PathBuf::from(&out).display(),
        blob.len(),
        dll
    );
    Ok(())
}
