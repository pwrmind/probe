#![allow(non_snake_case)]

use std::ffi::c_void;

pub const MEM_COMMIT: u32 = 0x1000;
pub const MEM_RESERVE: u32 = 0x2000;
pub const MEM_RELEASE: u32 = 0x8000;
pub const PAGE_EXECUTE_READWRITE: u32 = 0x40;

#[link(name = "kernel32")]
extern "system" {
    pub fn VirtualAlloc(
        addr: *const c_void,
        size: usize,
        alloc_type: u32,
        protect: u32,
    ) -> *mut c_void;

    pub fn VirtualFree(addr: *mut c_void, size: usize, free_type: u32) -> i32;

    pub fn LoadLibraryA(name: *const u8) -> *mut c_void;
    pub fn GetProcAddress(module: *mut c_void, name: *const u8) -> *mut c_void;
}

/// Выделяет исполняемую память (RWX) произвольного размера.
pub unsafe fn alloc_rwx(size: usize) -> Option<*mut u8> {
    let p = VirtualAlloc(
        std::ptr::null(),
        size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE,
    );
    if p.is_null() { None } else { Some(p as *mut u8) }
}

/// Выделяет память по конкретному адресу (для PE-образа).
pub unsafe fn alloc_at(addr: usize, size: usize, protect: u32) -> Option<*mut u8> {
    let p = VirtualAlloc(
        addr as *const c_void,
        size,
        MEM_COMMIT | MEM_RESERVE,
        protect,
    );
    if p.is_null() { None } else { Some(p as *mut u8) }
}