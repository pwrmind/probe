use std::collections::HashMap;
use std::path::PathBuf;

use crate::ffi;
use crate::parser::TargetRef;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CallingConvention {
    Cdecl,
    StdCall { arg_bytes: u16 },
}

#[derive(Debug, Clone)]
pub struct CallSite {
    pub address: u32,
    pub target: u32,
}

#[derive(Debug, Clone)]
pub struct FunctionMeta {
    pub address: u32,
    pub size: usize,
    pub calls: Vec<CallSite>,
    pub internal_calls: Vec<u32>,
    pub import_calls: Vec<String>,
    pub convention: CallingConvention,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum MockBehavior {
    Default,
    Custom(u32),
    Passthrough,
}

pub struct Mock {
    pub addr: u32,
    pub size: usize,
    pub behavior: MockBehavior,
    /// Адрес 4-байтовой ячейки внутри той же RWX-страницы, куда
    /// заглушка делает `inc dword [counter_addr]` при каждом вызове.
    pub counter_addr: u32,
}

impl Drop for Mock {
    fn drop(&mut self) {
        unsafe {
            ffi::VirtualFree(self.addr as *mut _, 0, ffi::MEM_RELEASE);
        }
    }
}

pub struct SandboxContext {
    pub file_path: PathBuf,
    pub image_base: u32,
    pub image_size: usize,
    pub entry_point: u32,
    pub is_loaded: bool,
    pub functions: HashMap<u32, FunctionMeta>,
    pub mocks: HashMap<u32, Mock>,
    pub export_names: HashMap<u32, String>,
    pub allocated: HashMap<u32, usize>,
}

impl SandboxContext {
    pub fn empty() -> Self {
        Self {
            file_path: PathBuf::new(),
            image_base: 0,
            image_size: 0,
            entry_point: 0,
            is_loaded: false,
            functions: HashMap::new(),
            mocks: HashMap::new(),
            export_names: HashMap::new(),
            allocated: HashMap::new(),
        }
    }

    pub fn name_of(&self, addr: u32) -> Option<&String> {
        self.export_names.get(&addr)
    }

    pub fn resolve_target(&self, t: &TargetRef) -> Option<u32> {
        match t {
            TargetRef::Addr(a) => Some(*a),
            TargetRef::Name(n) => self
                .export_names
                .iter()
                .find(|(_, v)| v.as_str() == n.as_str())
                .map(|(k, _)| *k),
        }
    }
}