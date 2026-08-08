//! nyx-bof-host-dumper — extract the reachable PIC closure of the B3 BOF host.
//!
//! Usage:
//!   nyx-bof-host-dumper <nyx_bof_host.dll> <bof-host.bin> [--verbose]
//!   nyx-bof-host-dumper --check-decoder <nyx_bof_host.dll>   (print addr:len
//!                                                          per instruction;
//!                                                          the regen script
//!                                                          diffs this against
//!                                                          objdump)
//!
//! Exits nonzero on any validation failure — a malformed host must never
//! silently produce a blob.
//!
//! The extraction engine (PE parsing, x86-64 length/operand decoder, BFS
//! reachability relayout) is SHARED with the LAYER2 nyx-pic-dumper via
//! #[path] includes — the same validated code, parameterized here on the
//! `nyx_bof_host_entry` export (DumpOpts.entry_name).

#[path = "../../../nyx-loader/pic-loader/dumper/src/decoder.rs"]
mod decoder;
#[path = "../../../nyx-loader/pic-loader/dumper/src/pe.rs"]
mod pe;
#[path = "../../../nyx-loader/pic-loader/dumper/src/relayout.rs"]
mod relayout;

use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.len() >= 2 && args[1] == "--check-decoder" {
        let dll = args
            .get(2)
            .expect("usage: nyx-bof-host-dumper --check-decoder <dll>");
        return check_decoder(dll);
    }
    if args.len() < 3 {
        eprintln!(
            "usage: nyx-bof-host-dumper <nyx_bof_host.dll> <bof-host.bin> [--verbose]\n\
             \x20      nyx-bof-host-dumper --check-decoder <nyx_bof_host.dll>"
        );
        return ExitCode::from(2);
    }
    let dll_path = &args[1];
    let out_path = &args[2];
    let verbose = args.iter().any(|a| a == "--verbose");

    let data = match std::fs::read(dll_path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("cannot read {dll_path}: {e}");
            return ExitCode::FAILURE;
        }
    };
    let pe = match pe::Pe::parse(data) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{dll_path}: {e}");
            return ExitCode::FAILURE;
        }
    };

    let blob = match relayout::dump(
        &pe,
        &relayout::DumpOpts { entry_name: "nyx_bof_host_entry", debug: verbose },
    ) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("dump failed: {e}");
            return ExitCode::FAILURE;
        }
    };

    if let Err(e) = std::fs::write(out_path, &blob) {
        eprintln!("cannot write {out_path}: {e}");
        return ExitCode::FAILURE;
    }

    let relocs = pe.reloc_targets().len();
    println!(
        "bof-host.bin: {} bytes (code+data closure), entry 'nyx_bof_host_entry' at offset 0, \
         source relocations: {relocs}",
        blob.len()
    );
    if verbose {
        println!("wrote {out_path}");
    }
    ExitCode::SUCCESS
}

fn check_decoder(dll_path: &str) -> ExitCode {
    let data = match std::fs::read(dll_path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("cannot read {dll_path}: {e}");
            return ExitCode::FAILURE;
        }
    };
    let pe = match pe::Pe::parse(data) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{dll_path}: {e}");
            return ExitCode::FAILURE;
        }
    };
    let Some(text) = pe.section(".text") else {
        eprintln!("no .text");
        return ExitCode::FAILURE;
    };
    let code = pe.section_bytes(".text").unwrap();
    let text_lo = text.vaddr as u64;
    let text_hi = text_lo + text.vsize as u64;
    let mut addr = text_lo;
    let mut bad = 0u32;
    while addr < text_hi {
        let at = (addr - text_lo) as usize;
        if at >= code.len() {
            break;
        }
        match decoder::decode(code, at, addr) {
            Ok(d) => {
                println!("{addr:08x}: {:02x} {}", d.len, bytes_fmt(&code[at..at + d.len]));
                addr += d.len as u64;
            }
            Err(e) => {
                println!("{addr:08x}: DECODE-ERROR {} @{:#x}", e.msg, e.at);
                bad += 1;
                break;
            }
        }
    }
    if bad > 0 {
        eprintln!("{bad} decode failures");
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

fn bytes_fmt(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect::<Vec<_>>().join(" ")
}
