# nyx-client-tauri — desktop operator client

Tauri v2 (Rust core) + React/TS frontend. The "堪比 CS 最新版" operator surface:
sessions table, beacon console, auto-refresh. Talks to the team server's REST API.

> **Build note:** this is a standalone Tauri project (not a Cargo workspace
> member) because it needs `npm` for the frontend. It is **not** built by the
> top-level `cargo` commands.

## Run it

```bash
cd crates/client-tauri
npm install                 # frontend deps
# generate icons (one-time; required for `tauri build`, optional for `tauri dev`)
# npx tauri icon path/to/logo.png
npm run tauri dev           # launches the app, hot-reloads the frontend
```

Point it at a running team server (default `http://127.0.0.1:8443`) via the URL
field in the header.

## Layout

- `src/`                 — React/TS frontend (sessions table + console)
- `src-tauri/src/lib.rs` — Tauri commands proxying the server REST API
- `src-tauri/tauri.conf.json`, `capabilities/` — Tauri v2 config

## Commands exposed to the frontend

| command | args | returns |
|---|---|---|
| `list_sessions` | `server` | `Session[]` |
| `shell` | `server, session, args` | output `string` (blocks until encrypted reply) |
| `exit_session` | `server, session` | `()` |

Same REST surface used by [`nyx-cli`](../client-cli).
