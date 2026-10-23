use iced_x86::{Decoder, DecoderOptions, Formatter, Instruction, IntelFormatter};

use crate::context::{CallLogEntry, FunctionMeta, Mock, MockBehavior, SandboxContext};
use crate::executor;
use crate::ffi;
use crate::mock_engine;
use crate::parser::{
    Argument, Command, FunctionColumn, MockColumn, MockMode, ResetTarget, TargetRef,
};

pub fn dispatch(cmd: Command, ctx: &mut SandboxContext) {
    match cmd {
        Command::FindFunction { sort, filter } => show_functions(ctx, sort, filter),
        Command::FindMock { sort, filter } => show_mocks(ctx, sort, filter),
        Command::GetFunction { target } => show_function(ctx, target),
        Command::InvokeFunction { target, args, diff_window } => invoke(ctx, target, args, diff_window),
        Command::InvokeMock { target, args } => invoke_mock(ctx, target, args),
        Command::SetMock { target, mode } => set_mock(ctx, target, mode),
        Command::ResetMock { target } => reset_mock(ctx, target),
        Command::Alloc { size } => cmd_alloc(ctx, size),
        Command::Disasm { target, count } => cmd_disasm(ctx, target, count),
        Command::Peek { address, size } => cmd_peek(address, size),
        Command::Poke { address, bytes } => cmd_poke(address, &bytes),
        Command::CallLog { clear } => {
            if clear {
                ctx.call_log.clear();
                println!("[+] call log cleared");
            } else {
                show_call_log(ctx);
            }
        }
        Command::Help => print_help(),
        Command::Exit => unreachable!(),
    }
}

fn cmd_alloc(ctx: &mut SandboxContext, size: u32) {
    unsafe {
        match ffi::alloc_rwx(size as usize) {
            Some(p) => {
                let addr = p as u32;
                ctx.allocated.insert(addr, size as usize);
                println!("[+] allocated {} bytes at 0x{:08X}", size, addr);
                println!("    hint: use THIS exact address in subsequent invoke calls");
            }
            None => println!("[-] alloc failed for {} bytes", size),
        }
    }
}

fn cmd_disasm(ctx: &SandboxContext, target: TargetRef, count: u32) {
    let Some(address) = ctx.resolve_target(&target) else {
        println!("[-] cannot resolve: {:?}", target);
        return;
    };
    let want_bytes = ((count as usize) * 15).clamp(64, 2048);
    let Some(bytes) = (unsafe { ffi::read_self(address, want_bytes) }) else {
        println!("[-] cannot read memory at 0x{:08X}", address);
        return;
    };

    println!("; disasm 0x{:08X}, up to {} instructions", address, count);
    let mut decoder = Decoder::with_ip(32, &bytes, address as u64, DecoderOptions::NONE);
    let mut instr = Instruction::default();
    let mut formatter = IntelFormatter::new();
    let mut out = String::new();

    for _ in 0..count {
        if !decoder.can_decode() { break; }
        let start = decoder.position();
        decoder.decode_out(&mut instr);
        let end = decoder.position();
        let ip = instr.ip() as u32;
        let hx: Vec<String> = bytes[start..end].iter().map(|b| format!("{:02X}", b)).collect();
        out.clear();
        formatter.format(&instr, &mut out);
        println!("  0x{:08X}  {:<28}  {}", ip, hx.join(" "), out);
    }
}

fn cmd_peek(address: u32, size: u32) {
    let Some(bytes) = (unsafe { ffi::read_self(address, size as usize) }) else {
        println!("[-] cannot read memory at 0x{:08X} ({} bytes)", address, size);
        return;
    };
    println!("; peek 0x{:08X}, {} bytes", address, bytes.len());
    for (i, chunk) in bytes.chunks(16).enumerate() {
        let off = address + (i * 16) as u32;
        let hx: Vec<String> = chunk.iter().map(|b| format!("{:02X}", b)).collect();
        let ascii: String = chunk.iter()
            .map(|&b| if b.is_ascii_graphic() || b == b' ' { b as char } else { '.' })
            .collect();
        println!("  {:08X}  {:<47}  {}", off, hx.join(" "), ascii);
    }
}

fn cmd_poke(address: u32, bytes: &[u8]) {
    match unsafe { ffi::write_self(address, bytes) } {
        Some(written) if written == bytes.len() => {
            println!("[+] wrote {} byte(s) to 0x{:08X}", written, address);
            if let Some(buf) = unsafe { ffi::read_self(address, bytes.len()) } {
                let hx: Vec<String> = buf.iter().map(|b| format!("{:02X}", b)).collect();
                println!("    0x{:08X}: {}", address, hx.join(" "));
            }
        }
        Some(written) => println!(
            "[!] partial write: {}/{} bytes to 0x{:08X}",
            written, bytes.len(), address
        ),
        None => println!(
            "[-] write failed at 0x{:08X} (bad address or page not writable)",
            address
        ),
    }
}

fn show_call_log(ctx: &SandboxContext) {
    if ctx.call_log.is_empty() {
        println!("(call log is empty). Every `invoke` appends an entry.");
        return;
    }

    println!(
        "{:>3}  {:<28} {:<12} {:<8} {:>7} {:>8}",
        "#", "Function", "EAX", "Status", "Patch", "Hits"
    );
    println!("{}", "-".repeat(74));
    for e in &ctx.call_log {
        let display_name = if e.name.chars().count() > 28 {
            let truncated: String = e.name.chars().take(25).collect();
            format!("{}...", truncated)
        } else {
            e.name.clone()
        };
        let status = if e.crash {
            match e.crash_code {
                Some(c) => format!("AV/0x{:X}", c & 0xFFFF),
                None => "CRASH".to_string(),
            }
        } else {
            "ok".to_string()
        };
        println!(
            "{:>3}  {:<28} 0x{:08X}  {:<8} {:>7} {:>8}",
            e.index, display_name, e.eax, status, e.patch_count, e.total_hits
        );
    }

    let unnamed: Vec<&CallLogEntry> = ctx.call_log.iter().filter(|e| e.name == "-").collect();
    if !unnamed.is_empty() {
        println!();
        println!("unnamed entries:");
        for e in unnamed {
            println!("  #{}: 0x{:08X}", e.index, e.address);
        }
    }

    println!();
    println!("tip: `call log clear` resets the log.");
}

fn fmt_name(ctx: &SandboxContext, addr: u32) -> String {
    ctx.name_of(addr).cloned().unwrap_or_else(|| "-".to_string())
}

fn show_functions(ctx: &SandboxContext, sort: Option<FunctionColumn>, filter: Option<String>) {
    let mut items: Vec<&FunctionMeta> = ctx.functions.values().collect();

    if let Some(expr) = filter {
        let p: Vec<&str> = expr.split_whitespace().collect();
        if p.len() >= 3 {
            let (col, op, val) = (p[0], p[1], p[2]);
            items.retain(|f| match (col, op) {
                ("size", ">") => (f.size as i64) > val.parse().unwrap_or(0),
                ("size", "<") => (f.size as i64) < val.parse().unwrap_or(i64::MAX),
                ("size", "==") => (f.size as i64) == val.parse().unwrap_or(-1),
                ("calls", ">") => (f.calls.len() as i64) > val.parse().unwrap_or(0),
                ("calls", "<") => (f.calls.len() as i64) < val.parse().unwrap_or(i64::MAX),
                ("calls", "==") => (f.calls.len() as i64) == val.parse().unwrap_or(-1),
                ("name", "==") => ctx.name_of(f.address).map(|s| s.as_str()) == Some(val),
                _ => true,
            });
        }
    }

    match sort {
        Some(FunctionColumn::Address) | None => items.sort_by_key(|f| f.address),
        Some(FunctionColumn::Name) => items.sort_by_key(|f| ctx.name_of(f.address).cloned().unwrap_or_default()),
        Some(FunctionColumn::Size) => items.sort_by_key(|f| std::cmp::Reverse(f.size)),
        Some(FunctionColumn::Calls) => items.sort_by_key(|f| std::cmp::Reverse(f.calls.len())),
        Some(FunctionColumn::Imports) => items.sort_by_key(|f| std::cmp::Reverse(f.import_calls.len())),
    }

    println!("{:<10} {:<16} {:>6} {:>6}  Convention", "Address", "Name", "Size", "Calls");
    println!("{}", "-".repeat(60));
    for f in items {
        let name = fmt_name(ctx, f.address);
        let conv = match f.convention {
            crate::context::CallingConvention::Cdecl => "cdecl".to_string(),
            crate::context::CallingConvention::StdCall { arg_bytes } => format!("stdcall {}", arg_bytes),
        };
        println!("0x{:08X} {:<16} {:>6} {:>6}  {}", f.address, name, f.size, f.calls.len(), conv);
    }
}

fn show_mocks(ctx: &SandboxContext, sort: Option<MockColumn>, filter: Option<String>) {
    let mut items: Vec<(u32, &Mock)> = ctx.mocks.iter().map(|(k, v)| (*k, v)).collect();

    if let Some(expr) = filter {
        let p: Vec<&str> = expr.split_whitespace().collect();
        if p.len() >= 3 {
            let (col, op, val) = (p[0], p[1], p[2]);
            items.retain(|(addr, m)| {
                let rv = match m.behavior {
                    MockBehavior::Custom(v) => v as i64,
                    MockBehavior::Default => 0,
                    MockBehavior::Passthrough => -1,
                };
                match (col, op) {
                    ("return_value", "==") => rv == val.parse().unwrap_or(i64::MIN),
                    ("return_value", "!=") => rv != val.parse().unwrap_or(i64::MIN),
                    ("address", "==") => u32::from_str_radix(val.trim_start_matches("0x"), 16).unwrap_or(0) == *addr,
                    ("name", "==") => ctx.name_of(*addr).map(|s| s.as_str()) == Some(val),
                    _ => true,
                }
            });
        }
    }

    match sort {
        Some(MockColumn::Address) | None => items.sort_by_key(|(a, _)| *a),
        Some(MockColumn::Name) => items.sort_by_key(|(a, _)| ctx.name_of(*a).cloned().unwrap_or_default()),
        Some(MockColumn::Type) => items.sort_by_key(|(_, m)| format!("{:?}", m.behavior)),
        Some(MockColumn::ReturnValue) => items.sort_by_key(|(_, m)| match m.behavior {
            MockBehavior::Custom(v) => v,
            _ => 0,
        }),
    }

    if items.is_empty() {
        println!("(no mocks). Default mocks are auto-generated only for exported functions.");
        return;
    }

    println!(
        "{:<10} {:<16} {:<12} {:>12} {:>5}",
        "MockAddr", "Name", "Type", "Return", "Hits"
    );
    println!("{}", "-".repeat(64));
    for (addr, m) in items {
        let name = fmt_name(ctx, addr);
        let (t, r) = match m.behavior {
            MockBehavior::Default => ("default", "0".to_string()),
            MockBehavior::Custom(v) => ("custom", format!("0x{:08X}", v)),
            MockBehavior::Passthrough => ("passthrough", "-".to_string()),
        };
        let hits = unsafe { std::ptr::read(m.counter_addr as *const u32) };
        println!("0x{:08X} {:<16} {:<12} {:>12} {:>5}", addr, name, t, r, hits);
    }
    println!();
    println!("Hits reflects the LAST invoke; counters reset before each call.");
}

fn show_function(ctx: &SandboxContext, target: TargetRef) {
    let Some(address) = ctx.resolve_target(&target) else {
        println!("[-] cannot resolve: {:?}", target);
        return;
    };
    match ctx.functions.get(&address) {
        Some(f) => {
            let name = fmt_name(ctx, address);
            println!("Function 0x{:08X} ({})", address, name);
            println!("  size: {}", f.size);
            println!("  convention: {:?}", f.convention);
            println!("  mock: {:?}", ctx.mocks.get(&address).map(|m| m.behavior));
            println!("  calls ({}):", f.calls.len());
            for c in &f.calls {
                let tname = fmt_name(ctx, c.target);
                println!("    0x{:08X} -> 0x{:08X}  {}", c.address, c.target, tname);
            }
        }
        None => println!("[-] function not found at 0x{:08X}", address),
    }
}

fn invoke(ctx: &mut SandboxContext, target: TargetRef, args: Vec<Argument>, diff_window: Option<u32>) {
    let Some(address) = ctx.resolve_target(&target) else {
        println!("[-] cannot resolve: {:?}", target);
        return;
    };
    let Some(func) = ctx.functions.get(&address).cloned() else {
        println!("[-] function not found at 0x{:08X}", address);
        return;
    };

    // Если для самой target-функции установлен Custom mock — предупредим,
    // что `invoke function` его НЕ применит (моки — только для вызовов
    // ИЗ ДРУГИХ функций). Для проверки stub используйте `invoke mock X`.
    if let Some(m) = ctx.mocks.get(&address) {
        if matches!(m.behavior, MockBehavior::Custom(_)) {
            println!(
                "[!] note: a custom mock is set for {}. `invoke function` runs the real code;",
                fmt_name(ctx, address)
            );
            println!(
                "    the mock only affects CALLERS of this function. Use `invoke mock {}` to exercise the stub.",
                fmt_name(ctx, address)
            );
        }
    }

    for (i, a) in args.iter().enumerate() {
        if let Argument::Pointer(p) = a {
            if *p == 0 { continue; }
            let readable = unsafe { ffi::read_self(*p, 1).is_some() };
            if !readable {
                println!("[!] warning: arg #{} (0x{:08X}) is not readable; any dereference will fault", i, p);
            }
        }
    }

    let mut crt_mocked: Vec<String> = Vec::new();
    for call in &func.calls {
        if let Some(mock) = ctx.mocks.get(&call.target) {
            if let Some(name) = ctx.name_of(call.target) {
                if is_crt_like(name) {
                    crt_mocked.push(name.clone());
                }
            } else if mock.behavior == MockBehavior::Default {
                crt_mocked.push(format!("0x{:08X}", call.target));
            }
        }
    }
    if !crt_mocked.is_empty() {
        println!("[!] warning: this function calls mocked helpers ({}). Side effects suppressed.", crt_mocked.join(", "));
    }

    let diff_desc = match diff_window {
        None => "false".to_string(),
        Some(n) => format!("true (window {} bytes)", n),
    };
    println!(
        "[*] invoke {} (0x{:08X}) args={:?} diff={}",
        fmt_name(ctx, address), address, args, diff_desc
    );

    let entry_name = fmt_name(ctx, address);

    match unsafe { executor::invoke(&func, &args, &ctx.mocks, diff_window, &ctx.allocated) } {
        Ok(r) => {
            if r.crash {
                println!("[!] sandbox crashed (code 0x{:08X})", r.fault_code.unwrap_or(0));
                if let Some(instr) = r.fault_instr {
                    println!("    fault instruction: 0x{:08X}", instr);
                }
                if let Some(data) = r.fault_data {
                    println!("    fault memory access: 0x{:08X}", data);
                }
                println!("    EAX marker = 0x{:08X}", r.eax);
            } else if r.abnormal {
                println!("[!] sandbox thread terminated abnormally (VEH did not recover)");
                println!("    EAX = 0x{:08X}", r.eax);
            } else {
                println!("[+] done: EAX = 0x{:08X} ({})", r.eax, r.eax as i32);
            }
            println!("    patched call sites: {}", r.patch_count);
            if !r.patched_targets.is_empty() {
                println!("    mock targets:");
                for t in &r.patched_targets {
                    println!("      -> 0x{:08X}  {}", t, fmt_name(ctx, *t));
                }
            }
            if !r.runtime_hits.is_empty() {
                println!("    runtime mock hits:");
                for (t, count) in &r.runtime_hits {
                    println!("      -> 0x{:08X}  {:<16} x{}", t, fmt_name(ctx, *t), count);
                }
            } else if r.patch_count > 0 {
                println!("    runtime mock hits: (none — all patched calls skipped by branches)");
            }
            if diff_window.is_some() {
                print_buffer_diffs(&r.buffer_diffs);
            }

            let total_hits: u32 = r.runtime_hits.iter().map(|(_, c)| c).sum();
            ctx.call_log.push(CallLogEntry {
                index: ctx.call_log.len() as u32 + 1,
                address,
                name: entry_name,
                eax: r.eax,
                crash: r.crash,
                crash_code: r.fault_code,
                patch_count: r.patch_count,
                total_hits,
            });
        }
        Err(e) => println!("[-] invoke failed: {}", e),
    }
}

fn invoke_mock(ctx: &mut SandboxContext, target: TargetRef, args: Vec<Argument>) {
    let Some(address) = ctx.resolve_target(&target) else {
        println!("[-] cannot resolve: {:?}", target);
        return;
    };
    let Some(func) = ctx.functions.get(&address).cloned() else {
        println!("[-] function not found at 0x{:08X}", address);
        return;
    };
    let Some(mock) = ctx.mocks.get(&address) else {
        println!("[-] no mock set for {} (0x{:08X})", fmt_name(ctx, address), address);
        println!("    hint: use `set mock` first, or `invoke function` to run the real code");
        return;
    };

    let mock_meta = FunctionMeta {
        address: mock.addr,
        size: mock.size,
        calls: vec![],
        internal_calls: vec![],
        import_calls: vec![],
        convention: func.convention,
    };

    println!(
        "[*] invoke mock {} (stub 0x{:08X}) args={:?}",
        fmt_name(ctx, address), mock.addr, args
    );

    let log_name = format!("mock:{}", fmt_name(ctx, address));

    match unsafe { executor::invoke(&mock_meta, &args, &ctx.mocks, None, &ctx.allocated) } {
        Ok(r) => {
            if r.crash {
                println!("[!] mock crashed?! (code 0x{:08X})", r.fault_code.unwrap_or(0));
            } else {
                println!("[+] done: EAX = 0x{:08X} ({})", r.eax, r.eax as i32);
            }
            let total_hits: u32 = r.runtime_hits.iter().map(|(_, c)| c).sum();
            ctx.call_log.push(CallLogEntry {
                index: ctx.call_log.len() as u32 + 1,
                address: mock.addr,
                name: log_name,
                eax: r.eax,
                crash: r.crash,
                crash_code: r.fault_code,
                patch_count: r.patch_count,
                total_hits,
            });
        }
        Err(e) => println!("[-] invoke mock failed: {}", e),
    }
}

fn is_crt_like(name: &str) -> bool {
    matches!(name,
        "memset" | "memcpy" | "memmove" | "memcmp" | "memchr"
        | "strlen" | "strcpy" | "strncpy" | "strcmp" | "strncmp"
        | "malloc" | "free" | "realloc"
        | "printf" | "sprintf" | "snprintf" | "puts" | "putchar")
}

fn print_buffer_diffs(diffs: &[executor::BufferDiff]) {
    if diffs.is_empty() {
        println!("    --- diff: no buffers watched ---");
        return;
    }
    println!("    --- diff: {} buffer(s) watched ---", diffs.len());
    for d in diffs {
        if !d.readable() {
            let note = match (&d.before, &d.after) {
                (None, None) => "unreadable (both before and after)",
                (None, Some(_)) => "unreadable before, readable after",
                (Some(_), None) => "readable before, unreadable after",
                _ => unreachable!(),
            };
            println!("    addr 0x{:08X} ({} bytes) [{}]", d.address, d.size, note);
            continue;
        }
        if d.changed() {
            println!("    addr 0x{:08X} ({} bytes) [{} bytes changed]", d.address, d.size, d.changed_count());
            println!("      before: {}", hexdump(d.before.as_ref().unwrap(), 32));
            println!("      after:  {}", hexdump(d.after.as_ref().unwrap(), 32));
        } else {
            println!("    addr 0x{:08X} ({} bytes) [unchanged]", d.address, d.size);
        }
    }
}

fn hexdump(bytes: &[u8], max: usize) -> String {
    let n = bytes.len().min(max);
    let mut s = String::new();
    for (i, b) in bytes[..n].iter().enumerate() {
        if i > 0 { s.push(' '); }
        s.push_str(&format!("{:02X}", b));
    }
    if bytes.len() > max { s.push_str(" ..."); }
    s
}

fn set_mock(ctx: &mut SandboxContext, target: TargetRef, mode: MockMode) {
    let Some(address) = ctx.resolve_target(&target) else {
        println!("[-] cannot resolve: {:?}", target);
        return;
    };
    let Some(func) = ctx.functions.get(&address) else {
        println!("[-] function not found at 0x{:08X}", address);
        return;
    };
    let conv = func.convention;
    let behavior = match mode {
        MockMode::Return(v) => MockBehavior::Custom(v),
        MockMode::Passthrough => MockBehavior::Passthrough,
    };

    match mock_engine::create_mock(behavior, conv) {
        Ok(Some(m)) => {
            ctx.mocks.insert(address, m);
            println!("[+] mock {} (0x{:08X}) = {:?}", fmt_name(ctx, address), address, behavior);
        }
        Ok(None) => {
            ctx.mocks.remove(&address);
            println!("[+] mock removed (passthrough) for {} (0x{:08X})", fmt_name(ctx, address), address);
        }
        Err(e) => println!("[-] mock error: {}", e),
    }
}

fn reset_mock(ctx: &mut SandboxContext, target: ResetTarget) {
    match target {
        ResetTarget::All => {
            let functions = &ctx.functions;
            let export_names = &ctx.export_names;
            let mocks = &mut ctx.mocks;
            mocks.clear();
            let mut count = 0;
            for addr in export_names.keys() {
                if let Some(meta) = functions.get(addr) {
                    if let Ok(Some(m)) = mock_engine::create_mock(MockBehavior::Default, meta.convention) {
                        mocks.insert(*addr, m);
                        count += 1;
                    }
                }
            }
            println!("[+] all mocks reset to Default ({} entries, exports only)", count);
        }
        ResetTarget::Address(t) => {
            let Some(address) = ctx.resolve_target(&t) else {
                println!("[-] cannot resolve: {:?}", t);
                return;
            };
            let Some(meta) = ctx.functions.get(&address) else {
                println!("[-] function not found at 0x{:08X}", address);
                return;
            };
            let conv = meta.convention;
            match mock_engine::create_mock(MockBehavior::Default, conv) {
                Ok(Some(m)) => {
                    ctx.mocks.insert(address, m);
                    println!("[+] mock for {} (0x{:08X}) reset to Default (return 0)", fmt_name(ctx, address), address);
                }
                Ok(None) => println!("[-] unexpected: Default mock returned None"),
                Err(e) => println!("[-] mock reset failed: {}", e),
            }
        }
    }
}

pub fn print_help() {
    println!("\nCommands:");
    println!("  find function [--sort address|name|size|calls|imports] [--filter \"col op val\"]");
    println!("  find mock     [--sort address|name|type|return_value]   [--filter \"col op val\"]");
    println!("  get function <target>");
    println!("  invoke function <target> [arg...] [--diff [N]]");
    println!("      runs the REAL function (patching its CALLs to mocks)");
    println!("  invoke mock <target> [arg...]");
    println!("      runs the STUB set via `set mock` (useful to verify the stub)");
    println!("      arg types: 123 (int) / 0x1234 (POINTER) / \"str\" (ANSI) / w\"str\" (UTF-16LE)");
    println!("                 note: 0xFF is a pointer, not int 255. Use decimal 255 for int.");
    println!("  set mock <target> --return <value> | --passthrough");
    println!("  reset mock <target> | --all");
    println!("  alloc <size>");
    println!("  disasm <target> [count]");
    println!("  peek 0x<addr> [size]");
    println!("  poke 0x<addr> <bytes...>       (0xNN / decimal / \"str\")");
    println!("  call log [clear]");
    println!("  help | exit");
    println!();
    println!("Mock scope: mocks intercept CALLs from OTHER functions, not from `invoke function` itself.");
    println!("Use `invoke mock <target>` to test the stub directly.");
    println!();
}