# Fuzzing the nyx-protocol wire codec

`cargo-fuzz` harness that polices an absolute contract of the attacker-facing
decoder:

> Decoding an **arbitrary** byte string via `Task::decode_vec`,
> `TaskResponse::decode_vec`, or any `wire::Reader` method must **always** return
> `Ok(..)` or `Err(..)` — never `panic!`.

On the team server `panic = "abort"` is set (implant size constraint), so an
unhandled decode path in a decrypted beacon body kills the process — a DoS. The
fuzz harness deliberately also builds with `panic = "abort"` so a panic surfaces
as a libFuzzer crash, modelling exactly that threat.

## Prerequisites

```sh
rustup toolchain install nightly      # sanitizer/-Z flags need nightly
cargo install cargo-fuzz              # one-time, installs the cargo subcommand
```

The repo's `rust-toolchain.toml` pins stable for the rest of the workspace;
cargo-fuzz is forced onto nightly via `RUSTUP_TOOLCHAIN=nightly` (see below).

## Run

From inside `crates/protocol/` (cargo-fuzz discovers `fuzz/` relative to cwd):

```sh
# quick smoke (30s)
RUSTUP_TOOLCHAIN=nightly cargo fuzz run decode_vec -- -max_total_time=30

# compile-check only
RUSTUP_TOOLCHAIN=nightly cargo fuzz build decode_vec

# longer campaign; libFuzzer grows the corpus under fuzz/corpus/decode_vec/
RUSTUP_TOOLCHAIN=nightly cargo fuzz run decode_vec -- -max_total_time=600
```

> NOTE: `cd` must be inside `crates/protocol/` (or a subshell) so cargo-fuzz
> resolves `./fuzz/Cargo.toml`. The `RUSTUP_TOOLCHAIN=nightly` env is required
> because the root `rust-toolchain.toml` pins stable, which lacks
> `-Zsanitizer=address`.

## Target layout

- `fuzz_targets/decode_vec.rs` — one `fuzz_target!`. Input layout is
  `[route_tag][rest]`; `route_tag % 4` selects which decode surface gets `rest`:
  `0` → `Task::decode_vec`, `1` → `TaskResponse::decode_vec`, `2` → raw
  `Reader` blob/str/u32 walk, `3` → both batch decoders. Splitting one corpus
  across surfaces avoids any single one starving the others.
- `corpus/decode_vec/seed_*` — curated seed inputs (happy-path batches + one
  deliberately malformed over-long blob prefix to seed the bounds path). These
  are committed; the libFuzzer-grown corpus is `.gitignore`d.

## If a crash is found

libFuzzer writes a `crash-<sha>` reproducer into the target dir. Reproduce +
minimize:

```sh
RUSTUP_TOOLCHAIN=nightly cargo fuzz run decode_vec -- crash-<sha>
RUSTUP_TOOLCHAIN=nightly cargo fuzz tmin decode_vec -- crash-<sha>
```

A crash here is a real server-DoS bug in the decode path: report the minimized
input + the panic message.
