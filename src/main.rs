#[cfg(not(target_arch = "x86"))]
compile_error!("probe must be built for i686-pc-windows-msvc (32-bit)");

mod commands;
mod context;
mod executor;
mod ffi;
mod function_discovery;
mod mock_engine;
mod parser;
mod pe_loader;
mod repl;

use std::env;
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();

    let context = if args.len() > 1 {
        let path = PathBuf::from(&args[1]);
        println!("[*] Loading PE image: {}", path.display());
        match pe_loader::load_and_analyze(&path) {
            Ok(ctx) => {
                println!(
                    "[+] Mapped {} ({} bytes) at 0x{:08X}; {} functions; entry = 0x{:08X}",
                    ctx.file_path.display(),
                    ctx.image_size,
                    ctx.image_base,
                    ctx.functions.len(),
                    ctx.entry_point,
                );
                println!(
                    "[+] Default mocks generated for {} functions (EAX=0)",
                    ctx.mocks.len()
                );
                ctx
            }
            Err(e) => {
                eprintln!("[-] Fatal: {}", e);
                std::process::exit(1);
            }
        }
    } else {
        println!("[!] No target. Usage: probe.exe <target.exe>");
        context::SandboxContext::empty()
    };

    repl::run(context)?;
    Ok(())
}