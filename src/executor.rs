use crate::context::{FunctionMeta, Mock};
use crate::ffi;
use crate::parser::Argument;

// На i686-pc-windows-msvc C-символы получают префикс `_`.
// extern "C" ищет `_probe_call_with_stack`, поэтому метка — с подчёркиванием.
#[cfg(target_arch = "x86")]
std::arch::global_asm!(
    r#"
    .global _probe_call_with_stack
_probe_call_with_stack:
    push ebp
    mov ebp, esp
    push ebx
    push esi
    push edi

    mov ebx, esp
    mov esp, [ebp+12]
    mov esi, [ebp+16]
    mov edi, [ebp+20]

1:
    test edi, edi
    jz 2f
    dec edi
    push dword ptr [esi + edi*4]
    jmp 1b
2:
    call dword ptr [ebp+8]

    mov esp, ebx
    pop edi
    pop esi
    pop ebx
    pop ebp
    ret
"#
);

#[cfg(target_arch = "x86")]
extern "C" {
    fn probe_call_with_stack(
        func: u32,
        new_esp: u32,
        args_ptr: *const u32,
        arg_count: u32,
    ) -> u32;
}

struct Patch {
    address: u32,
    original: [u8; 5],
}

pub struct InvokeResult {
    pub eax: u32,
    pub patch_count: usize,
    /// Адреса функций, чьи CALL были перенаправлены на моки.
    pub patched_targets: Vec<u32>,
}

/// Патчит прямые CALL на моки, готовит стек, вызывает, восстанавливает патчи.
pub unsafe fn invoke(
    function: &FunctionMeta,
    args: &[Argument],
    mocks: &std::collections::HashMap<u32, Mock>,
) -> Result<InvokeResult, String> {
    // 1. Патчим прямые CALL, чья цель имеет мок.
    let mut patches: Vec<Patch> = Vec::new();
    let mut patched_targets: Vec<u32> = Vec::new();
    for call in &function.calls {
        if let Some(mock) = mocks.get(&call.target) {
            let p = call.address as *mut u8;
            let mut orig = [0u8; 5];
            std::ptr::copy_nonoverlapping(p, orig.as_mut_ptr(), 5);

            let rel = (mock.addr as i64 - (call.address as i64 + 5)) as i32;
            let mut newbytes = [0u8; 5];
            newbytes[0] = 0xE8;
            newbytes[1..5].copy_from_slice(&rel.to_le_bytes());
            std::ptr::copy_nonoverlapping(newbytes.as_ptr(), p, 5);

            patches.push(Patch { address: call.address, original: orig });
            patched_targets.push(call.target);
        }
    }

    // 2. Готовим аргументы: строки копируем в приватную память.
    let mut heap_ptrs: Vec<*mut u8> = Vec::new();
    let mut arg_vals: Vec<u32> = Vec::with_capacity(args.len());
    for a in args {
        match a {
            Argument::Integer(v) => arg_vals.push(*v),
            Argument::Pointer(p) => arg_vals.push(*p),
            Argument::StringLiteral(s) => {
                let mut bytes = s.as_bytes().to_vec();
                bytes.push(0);
                let p = ffi::alloc_rwx(bytes.len())
                    .ok_or_else(|| "string alloc failed".to_string())?;
                std::ptr::copy_nonoverlapping(bytes.as_ptr(), p, bytes.len());
                heap_ptrs.push(p);
                arg_vals.push(p as u32);
            }
        }
    }

    // 3. Аллоцируем изолированный стек (64 KB).
    let stack_size = 64 * 1024;
    let stack_ptr = ffi::alloc_rwx(stack_size)
        .ok_or_else(|| "stack alloc failed".to_string())?;
    let stack_top = (stack_ptr as u32) + (stack_size as u32) - 16;
    let sandbox_esp = stack_top & !0xF;

    // 4. Вызов трамплина.
    let eax = probe_call_with_stack(
        function.address,
        sandbox_esp,
        arg_vals.as_ptr(),
        arg_vals.len() as u32,
    );

    // 5. Восстанавливаем оригинальные байты CALL.
    for p in &patches {
        std::ptr::copy_nonoverlapping(p.original.as_ptr(), p.address as *mut u8, 5);
    }

    // 6. Освобождаем временную память.
    ffi::VirtualFree(stack_ptr as *mut _, 0, ffi::MEM_RELEASE);
    for p in heap_ptrs {
        ffi::VirtualFree(p as *mut _, 0, ffi::MEM_RELEASE);
    }

    Ok(InvokeResult {
        eax,
        patch_count: patches.len(),
        patched_targets,
    })
}