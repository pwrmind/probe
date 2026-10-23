// crackme.rs  (cdylib)
// rustc --crate-type=cdylib --target i686-pc-windows-msvc -O crackme.rs ^
//   -C link-arg=/BASE:0x10000000 ^
//   -C link-arg=/DYNAMICBASE:NO ^
//   -C link-arg=/FIXED:NO ^
//   -o crackme.dll

#[no_mangle]
pub static mut G_ADMIN_FLAG: i32 = 0;

#[inline(never)]
#[no_mangle]
pub extern "C" fn is_admin() -> i32 {
    unsafe { std::ptr::read_volatile(&raw const G_ADMIN_FLAG) }
}

#[inline(never)]
#[no_mangle]
pub extern "C" fn check_password(pass: *const u8) -> i32 {
    if pass.is_null() {
        return 0;
    }
    unsafe {
        let p = std::slice::from_raw_parts(pass, 7);
        if p == b"s3cr3t\0" { 1 } else { 0 }
    }
}

#[inline(never)]
#[no_mangle]
pub extern "C" fn login(_user: *const u8, pass: *const u8) -> i32 {
    if is_admin() != 0 {
        return 1;
    }
    if check_password(pass) != 0 {
        return 1;
    }
    0
}

/// Заполняет буфер заданным байтом.
/// Для теста `--diff`: fill(buf, byte, len) -> len
#[inline(never)]
#[no_mangle]
pub extern "C" fn fill(buf: *mut u8, byte: u32, len: u32) -> u32 {
    if buf.is_null() || len == 0 {
        return 0;
    }
    unsafe {
        for i in 0..len as usize {
            *buf.add(i) = byte as u8;
        }
    }
    len
}

/// Копирует `len` байт из src в dst, переводя строчные латинские в заглавные.
/// Для теста `--diff`: copy_upper(src, dst, len) -> len
#[inline(never)]
#[no_mangle]
pub extern "C" fn copy_upper(src: *const u8, dst: *mut u8, len: u32) -> u32 {
    if src.is_null() || dst.is_null() || len == 0 {
        return 0;
    }
    unsafe {
        for i in 0..len as usize {
            let c = *src.add(i);
            *dst.add(i) = if (b'a'..=b'z').contains(&c) { c - 32 } else { c };
        }
    }
    len
}