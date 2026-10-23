// crackme.rs  (cdylib-версия)
//
// Сборка:
//   rustc --crate-type=cdylib --target i686-pc-windows-msvc -O crackme.rs ^
//     -C link-arg=/BASE:0x10000000 ^
//     -C link-arg=/DYNAMICBASE:NO ^
//     -C link-arg=/FIXED:NO ^
//     -o crackme.dll
//
// Экспортирует: is_admin, check_password, login, G_ADMIN_FLAG.
// Экспорт появляется автоматически благодаря #[no_mangle] + crate-type=cdylib.

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