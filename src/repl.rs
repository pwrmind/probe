use rustyline::error::ReadlineError;
use rustyline::DefaultEditor;

use crate::commands;
use crate::context::SandboxContext;
use crate::parser::{self, Command};

pub fn run(mut ctx: SandboxContext) -> Result<(), Box<dyn std::error::Error>> {
    let mut rl = DefaultEditor::new()?;

    println!("[+] probe ready. type 'help' for commands.");

    loop {
        let prompt = if ctx.is_loaded { "probe> " } else { "no-target> " };
        match rl.readline(prompt) {
            Ok(line) => {
                let trimmed = line.trim();
                if trimmed.is_empty() { continue; }
                let _ = rl.add_history_entry(trimmed);

                match parser::parse_command(trimmed) {
                    Ok(Command::Exit) => break,
                    Ok(Command::Help) => commands::print_help(),
                    Ok(cmd) => {
                        if !ctx.is_loaded {
                            println!("[-] no target loaded");
                            continue;
                        }
                        commands::dispatch(cmd, &mut ctx);
                    }
                    Err(e) => println!("[-] syntax: {}", e),
                }
            }
            Err(ReadlineError::Interrupted) => {
                println!("[*] Ctrl-C (type 'exit' to quit)");
            }
            Err(ReadlineError::Eof) => break,
            Err(e) => {
                eprintln!("[-] readline error: {:?}", e);
                break;
            }
        }
    }
    Ok(())
}