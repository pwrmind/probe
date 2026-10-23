use crate::context::{FunctionMeta, Mock, MockBehavior, SandboxContext};
use crate::executor;
use crate::mock_engine;
use crate::parser::{
    Argument, Command, FunctionColumn, MockColumn, MockMode, ResetTarget, TargetRef,
};

pub fn dispatch(cmd: Command, ctx: &mut SandboxContext) {
    match cmd {
        Command::FindFunction { sort, filter } => show_functions(ctx, sort, filter),
        Command::FindMock { sort, filter } => show_mocks(ctx, sort, filter),
        Command::GetFunction { target } => show_function(ctx, target),
        Command::InvokeFunction { target, args, diff } => invoke(ctx, target, args, diff),
        Command::SetMock { target, mode } => set_mock(ctx, target, mode),
        Command::ResetMock { target } => reset_mock(ctx, target),
        Command::Help => print_help(),
        Command::Exit => unreachable!(),
    }
}

fn fmt_name(ctx: &SandboxContext, addr: u32) -> String {
    ctx.name_of(addr).cloned().unwrap_or_else(|| "-".to_string())
}

fn show_functions(
    ctx: &SandboxContext,
    sort: Option<FunctionColumn>,
    filter: Option<String>,
) {
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
                ("name", "==") => {
                    ctx.name_of(f.address).map(|s| s.as_str()) == Some(val)
                }
                _ => true,
            });
        }
    }

    match sort {
        Some(FunctionColumn::Address) | None => items.sort_by_key(|f| f.address),
        Some(FunctionColumn::Name) => items.sort_by_key(|f| {
            ctx.name_of(f.address).cloned().unwrap_or_default()
        }),
        Some(FunctionColumn::Size) => items.sort_by_key(|f| std::cmp::Reverse(f.size)),
        Some(FunctionColumn::Calls) => items.sort_by_key(|f| std::cmp::Reverse(f.calls.len())),
        Some(FunctionColumn::Imports) => {
            items.sort_by_key(|f| std::cmp::Reverse(f.import_calls.len()))
        }
    }

    println!(
        "{:<10} {:<16} {:>6} {:>6}  Convention",
        "Address", "Name", "Size", "Calls"
    );
    println!("{}", "-".repeat(60));
    for f in items {
        let name = fmt_name(ctx, f.address);
        let conv = match f.convention {
            crate::context::CallingConvention::Cdecl => "cdecl".to_string(),
            crate::context::CallingConvention::StdCall { arg_bytes } => {
                format!("stdcall {}", arg_bytes)
            }
        };
        println!(
            "0x{:08X} {:<16} {:>6} {:>6}  {}",
            f.address,
            name,
            f.size,
            f.calls.len(),
            conv
        );
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
                    ("address", "==") => {
                        u32::from_str_radix(val.trim_start_matches("0x"), 16).unwrap_or(0)
                            == *addr
                    }
                    ("name", "==") => {
                        ctx.name_of(*addr).map(|s| s.as_str()) == Some(val)
                    }
                    _ => true,
                }
            });
        }
    }

    match sort {
        Some(MockColumn::Address) | None => items.sort_by_key(|(a, _)| *a),
        Some(MockColumn::Name) => items.sort_by_key(|(a, _)| {
            ctx.name_of(*a).cloned().unwrap_or_default()
        }),
        Some(MockColumn::Type) => items.sort_by_key(|(_, m)| format!("{:?}", m.behavior)),
        Some(MockColumn::ReturnValue) => items.sort_by_key(|(_, m)| match m.behavior {
            MockBehavior::Custom(v) => v,
            _ => 0,
        }),
    }

    println!(
        "{:<10} {:<16} {:>5} {:<12} {:>12}",
        "MockAddr", "Name", "Size", "Type", "Return"
    );
    println!("{}", "-".repeat(64));
    for (addr, m) in items {
        let name = fmt_name(ctx, addr);
        let (t, r) = match m.behavior {
            MockBehavior::Default => ("default", "0".to_string()),
            MockBehavior::Custom(v) => ("custom", format!("0x{:08X}", v)),
            MockBehavior::Passthrough => ("passthrough", "-".to_string()),
        };
        println!(
            "0x{:08X} {:<16} {:>5} {:<12} {:>12}",
            addr, name, m.size, t, r
        );
    }
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
            println!(
                "  mock: {:?}",
                ctx.mocks.get(&address).map(|m| m.behavior)
            );
            println!("  calls ({}):", f.calls.len());
            for c in &f.calls {
                let tname = fmt_name(ctx, c.target);
                println!(
                    "    0x{:08X} -> 0x{:08X}  {}",
                    c.address, c.target, tname
                );
            }
        }
        None => println!("[-] function not found at 0x{:08X}", address),
    }
}

fn invoke(ctx: &mut SandboxContext, target: TargetRef, args: Vec<Argument>, diff: bool) {
    let Some(address) = ctx.resolve_target(&target) else {
        println!("[-] cannot resolve: {:?}", target);
        return;
    };
    let Some(func) = ctx.functions.get(&address).cloned() else {
        println!("[-] function not found at 0x{:08X}", address);
        return;
    };

    println!(
        "[*] invoke {} (0x{:08X}) args={:?} diff={}",
        fmt_name(ctx, address),
        address,
        args,
        diff
    );

    match unsafe { executor::invoke(&func, &args, &ctx.mocks) } {
        Ok(r) => {
            println!("[+] done: EAX = 0x{:08X} ({})", r.eax, r.eax as i32);
            println!("    patched call sites: {}", r.patch_count);
            if !r.patched_targets.is_empty() {
                println!("    mock targets:");
                for t in &r.patched_targets {
                    println!("      -> 0x{:08X}  {}", t, fmt_name(ctx, *t));
                }
            }
            if diff {
                println!("    (--diff not implemented in MVP)");
            }
        }
        Err(e) => println!("[-] invoke failed: {}", e),
    }
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
            println!(
                "[+] mock {} (0x{:08X}) = {:?}",
                fmt_name(ctx, address),
                address,
                behavior
            );
        }
        Ok(None) => {
            ctx.mocks.remove(&address);
            println!(
                "[+] mock removed (passthrough) for {} (0x{:08X})",
                fmt_name(ctx, address),
                address
            );
        }
        Err(e) => println!("[-] mock error: {}", e),
    }
}

fn reset_mock(ctx: &mut SandboxContext, target: ResetTarget) {
    match target {
        ResetTarget::All => {
            ctx.mocks.clear();
            println!("[+] all mocks cleared");
        }
        ResetTarget::Address(t) => {
            let Some(address) = ctx.resolve_target(&t) else {
                println!("[-] cannot resolve: {:?}", t);
                return;
            };
            ctx.mocks.remove(&address);
            println!(
                "[+] mock removed for {} (0x{:08X})",
                fmt_name(ctx, address),
                address
            );
        }
    }
}

pub fn print_help() {
    println!("\nCommands:");
    println!("  find function [--sort address|name|size|calls|imports] [--filter \"col op val\"]");
    println!("  find mock     [--sort address|name|type|return_value]   [--filter \"col op val\"]");
    println!("  get function <target>");
    println!("  invoke function <target> [arg...] [--diff]");
    println!("      target: 0x10001040 or export name (e.g. login)");
    println!("      arg types: 123 / 0x1234 (pointer) / \"string\"");
    println!("  set mock <target> --return <value>");
    println!("  set mock <target> --passthrough");
    println!("  reset mock <target> | --all");
    println!("  help | exit\n");
}