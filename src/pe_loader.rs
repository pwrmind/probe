use std::collections::HashMap;
use std::fs;
use std::path::Path;

use goblin::pe::PE;

use crate::context::{FunctionMeta, MockBehavior, SandboxContext};
use crate::ffi;
use crate::function_discovery::discover_functions;
use crate::mock_engine;

pub fn load_and_analyze(path: &Path) -> Result<SandboxContext, String> {
    let file_data = fs::read(path).map_err(|e| format!("read: {}", e))?;
    let pe = PE::parse(&file_data).map_err(|e| format!("PE parse: {}", e))?;

    if pe.header.coff_header.machine != 0x14c {
        return Err(format!(
            "not x86 PE (machine=0x{:04X}, want 0x014c)",
            pe.header.coff_header.machine
        ));
    }

    let image_base = pe.image_base as u32;
    let image_size = pe
        .header
        .optional_header
        .map(|oh| oh.windows_fields.size_of_image as usize)
        .ok_or("missing optional header")?;

    let img_ptr = unsafe {
        ffi::alloc_at(image_base as usize, image_size, ffi::PAGE_EXECUTE_READWRITE)
            .ok_or_else(|| format!("VirtualAlloc at 0x{:08X} failed", image_base))?
    };

    let header_size = pe
        .header
        .optional_header
        .map(|oh| oh.windows_fields.size_of_headers as usize)
        .unwrap_or(0x400);
    unsafe {
        let copy_len = header_size.min(file_data.len());
        std::ptr::copy_nonoverlapping(file_data.as_ptr(), img_ptr, copy_len);
    }

    for section in &pe.sections {
        let va = section.virtual_address as usize;
        let vsize = section.virtual_size as usize;
        let raw_size = section.size_of_raw_data as usize;
        let raw_off = section.pointer_to_raw_data as usize;

        if raw_size == 0 || raw_off == 0 || raw_off + raw_size > file_data.len() {
            continue;
        }
        let copy_len = raw_size.min(vsize.max(raw_size));
        unsafe {
            let dst = img_ptr.add(va);
            std::ptr::copy_nonoverlapping(
                file_data[raw_off..raw_off + copy_len].as_ptr(),
                dst,
                copy_len,
            );
        }
    }

    resolve_imports(&pe, img_ptr)?;

    // Seeds: entry + экспорты.
    let entry = image_base.wrapping_add(pe.entry as u32);
    let mut seeds: Vec<u32> = vec![entry];
    let mut export_names: HashMap<u32, String> = HashMap::new();
    for exp in &pe.exports {
        let addr = image_base.wrapping_add(exp.rva as u32);
        seeds.push(addr);
        if let Some(name) = exp.name.as_ref() {
            export_names.insert(addr, name.to_string());
        }
    }
    seeds.sort_unstable();
    seeds.dedup();

    let functions: HashMap<u32, FunctionMeta> =
        discover_functions(image_base, image_size, seeds);

    let mut mocks = HashMap::new();
    for (addr, meta) in &functions {
        if let Ok(Some(mock)) =
            mock_engine::create_mock(MockBehavior::Default, meta.convention)
        {
            mocks.insert(*addr, mock);
        }
    }

    Ok(SandboxContext {
        file_path: path.to_path_buf(),
        image_base,
        image_size,
        entry_point: entry,
        is_loaded: true,
        functions,
        mocks,
        export_names,
    })
}

fn resolve_imports(pe: &PE, img: *mut u8) -> Result<(), String> {
    for imp in &pe.imports {
        let dll_name = imp.dll.to_string();
        let mut dll_cstr = dll_name.clone().into_bytes();
        dll_cstr.push(0);

        let func_name = imp.name.to_string();
        if func_name.is_empty() || func_name.starts_with('#') {
            continue;
        }
        let mut fn_cstr = func_name.clone().into_bytes();
        fn_cstr.push(0);

        let h = unsafe { ffi::LoadLibraryA(dll_cstr.as_ptr()) };
        if h.is_null() {
            return Err(format!(
                "LoadLibraryA({}) failed",
                String::from_utf8_lossy(&dll_cstr)
            ));
        }
        let p = unsafe { ffi::GetProcAddress(h, fn_cstr.as_ptr()) };
        if p.is_null() {
            return Err(format!(
                "GetProcAddress({}!{}) failed",
                String::from_utf8_lossy(&dll_cstr),
                func_name
            ));
        }

        unsafe {
            let slot = img.add(imp.rva) as *mut u32;
            *slot = p as u32;
        }
    }
    Ok(())
}