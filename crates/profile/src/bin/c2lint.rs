//! `c2lint` — parse and lint a Malleable C2 profile, CS-style.
//!
//! Usage:
//!   c2lint path/to/profile.profile     # lint a file
//!   c2lint -                            # lint profile source from stdin
//!   some-cmd | c2lint -                 # same, via a pipe
//!
//! Exit codes: `0` no errors (warnings allowed), `1` parse error, `2` lint
//! errors. Output mimics `c2lint`: `[-]` error, `[!]` warning, `[+]` note.

use std::io::Read;

use nyx_profile::{lint, parse, Severity};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let src = match read_input(&args) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[-] could not read input: {e}");
            std::process::exit(1);
        }
    };

    let profile = match parse(&src) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("[-] parse error: {e}");
            std::process::exit(1);
        }
    };

    let diags = lint(&profile);
    let (mut errors, mut warnings) = (0usize, 0usize);
    for d in &diags {
        let (tag, line) = match d.severity {
            Severity::Error => {
                errors += 1;
                ("[-]", d.line)
            }
            Severity::Warning => {
                warnings += 1;
                ("[!]", d.line)
            }
            Severity::Note => ("[+]", d.line),
        };
        let at = if line > 0 {
            format!(" line {line}: ")
        } else {
            String::from(": ")
        };
        println!("{tag}{at}{}", d.message);
    }

    if errors > 0 {
        println!("[-] {errors} error(s), {warnings} warning(s)");
        std::process::exit(2);
    }
    println!("[+] {warnings} warning(s), no errors");
    std::process::exit(0);
}

fn read_input(args: &[String]) -> std::io::Result<String> {
    match args.first().map(String::as_str) {
        None | Some("-") => {
            let mut s = String::new();
            std::io::stdin().read_to_string(&mut s)?;
            Ok(s)
        }
        Some(path) => std::fs::read_to_string(path),
    }
}
