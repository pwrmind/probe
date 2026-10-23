use crate::context::{CallingConvention, Mock, MockBehavior};
use crate::ffi;

const MOCK_SIZE: usize = 16;

/// Генерирует x86-байты заглушки под заданное поведение.
fn generate(behavior: MockBehavior, conv: CallingConvention) -> Option<[u8; MOCK_SIZE]> {
    let val = match behavior {
        MockBehavior::Passthrough => return None,
        MockBehavior::Default => 0u32,
        MockBehavior::Custom(v) => v,
    };

    let mut buf = [0u8; MOCK_SIZE];
    // mov eax, imm32
    buf[0] = 0xB8;
    buf[1..5].copy_from_slice(&val.to_le_bytes());

    match conv {
        CallingConvention::Cdecl => {
            buf[5] = 0xC3; // ret
        }
        CallingConvention::StdCall { arg_bytes } => {
            if arg_bytes == 0 {
                buf[5] = 0xC3;
            } else {
                buf[5] = 0xC2;
                buf[6..8].copy_from_slice(&arg_bytes.to_le_bytes());
            }
        }
    }
    Some(buf)
}

/// Создаёт реальный мок в памяти. Возвращает None для Passthrough.
pub fn create_mock(behavior: MockBehavior, conv: CallingConvention) -> Result<Option<Mock>, String> {
    let bytes = match generate(behavior, conv) {
        None => return Ok(None),
        Some(b) => b,
    };
    unsafe {
        let p = ffi::alloc_rwx(MOCK_SIZE)
            .ok_or_else(|| "VirtualAlloc for mock failed".to_string())?;
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), p, MOCK_SIZE);
        Ok(Some(Mock {
            addr: p as u32,
            size: MOCK_SIZE,
            behavior,
        }))
    }
}