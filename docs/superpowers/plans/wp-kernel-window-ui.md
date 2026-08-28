# Kernel time-window UI (T2 leftover)

Server already has `POST /api/kernel/window` (Admin-only, mounted only when
`NYX_KERNEL_DAEMON` is set). This leftover is operator GUI + auto-open around
inject/hashdump. **Not** implant signaling; no wire-protocol change; no invented
kernel undo.

## Settings

- Open / Close buttons + optional EDR pid (neutralize freeze).
- Calls existing route via Tauri `kernel_window` → `rest::kernel_window`.
- Render HTTP status + JSON body as-is. Close `restored: false, reason: "no undo op"`
  is honesty, not a GUI bug.

## Auto-open

Lives in Tauri `send_command` (every UI path that tasks inject/hashdump).

1. Best-effort `phase=open` first (pid = last Settings Open/Close pid, if any).
2. HTTP 404 (daemon routes unregistered) or network error: still enqueue the task.
3. HTTP 502 (`failed_step`): emit `nyx://notice`, still enqueue the task.
4. Do not fail-closed the beacon task because kernel lab is off.

## Out of scope

- Implant commands / beacon-initiated window.
- New kernel IOCTLs; WFP in the default window; invented undo on Close.
