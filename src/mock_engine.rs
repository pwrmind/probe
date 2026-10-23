use crate::context::{CallingConvention, Mock, MockBehavior};
use crate::ffi;

/// Смещение счётчика от начала аллокации. Код заглушки занимает
/// 6 (inc) + 5 (mov) + до 3 (ret imm16) = до 14 байт, так что 16 —
/// безопасное выравнивание.
const COUNTER_OFFSET: usize = 16;
/// Полный размер RWX-страницы под один мок: 16 байт кода + 4 байта counter.
const MOCK_SIZE: usize = COUNTER_OFFSET + 4;

/// Собирает x86-байткод заглушки.
///
/// Формат:
///     inc dword ptr [counter_addr]    ; FF 05 xx xx xx xx  (6 байт)
///     mov eax, retval                 ; B8 xx xx xx xx     (5 байт)
///     ret  /  ret N                   ; C3   /  C2 N N      (1 / 3 байта)
fn generate(
    behavior: MockBehavior,
    conv: CallingConvention,
    counter_addr: u32,
) -> [u8; MOCK_SIZE] {
    let val = match behavior {
        MockBehavior::Passthrough => 0,
        MockBehavior::Default => 0,
        MockBehavior::Custom(v) => v,
    };

    let mut buf = [0u8; MOCK_SIZE];
    let mut off = 0usize;

    // inc dword ptr [counter_addr]
    buf[off] = 0xFF;
    off += 1;
    buf[off] = 0x05;
    off += 1;
    buf[off..off + 4].copy_from_slice(&counter_addr.to_le_bytes());
    off += 4;

    // mov eax, retval
    buf[off] = 0xB8;
    off += 1;
    buf[off..off + 4].copy_from_slice(&val.to_le_bytes());
    off += 4;

    // ret / ret imm16
    match conv {
        CallingConvention::Cdecl => {
            buf[off] = 0xC3;
        }
        CallingConvention::StdCall { arg_bytes } => {
            if arg_bytes == 0 {
                buf[off] = 0xC3;
            } else {
                buf[off] = 0xC2;
                buf[off + 1..off + 3].copy_from_slice(&arg_bytes.to_le_bytes());
            }
        }
    }

    buf
}

/// Создаёт реальный мок в памяти. Возвращает `Ok(None)` для Passthrough.
pub fn create_mock(
    behavior: MockBehavior,
    conv: CallingConvention,
) -> Result<Option<Mock>, String> {
    if matches!(behavior, MockBehavior::Passthrough) {
        return Ok(None);
    }

    unsafe {
        let p = ffi::alloc_rwx(MOCK_SIZE)
            .ok_or_else(|| "VirtualAlloc for mock failed".to_string())?;
        let addr = p as u32;
        let counter_addr = addr + COUNTER_OFFSET as u32;

        let bytes = generate(behavior, conv, counter_addr);
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), p, MOCK_SIZE);

        Ok(Some(Mock {
            addr,
            size: MOCK_SIZE,
            behavior,
            counter_addr,
        }))
    }
}