//! Command-line interface for the TraceScript toolchain.
//!
//! Subcommands:
//!
//! - `lex`     — tokenize a script and print the token stream
//! - `parse`   — tokenize + parse and print the AST
//! - `check`   — tokenize + parse + run the semantic analyzer
//! - `run`     — full pipeline: lex + parse + check + execute (interpreter by default,
//!                `--vm` to use the bytecode VM)
//! - `compile` — emit a `.traceb` bytecode module
//! - `vm`      — execute a `.traceb` bytecode module
//!
//! `run` and `vm` accept `--pcap <PATH>` to override the script's own `source` decl,
//! which is useful for replaying the same script against different captures.

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::Result;
use clap::{Parser, Subcommand};

const BUILD_INFO: &str = concat!(
    "TraceScript ",
    env!("CARGO_PKG_VERSION"),
    " (",
    env!("TRACESCRIPT_GIT_SHA"),
    ", built ",
    env!("TRACESCRIPT_BUILD_DATE"),
    ")"
);

use crate::bytecode::vm::VM;
use crate::interp::{value::Value, Interpreter};
use crate::lexer::Lexer;
use crate::parser::{Decl, Parser as TsParser};
use crate::runtime;
use crate::sema::Analyzer;

#[derive(Debug, Parser)]
#[command(
    name = "tracescript",
    version = BUILD_INFO,
    about = "Forensic scripting language for packet-capture analysis",
    long_about = None
)]
pub struct Cli {
    #[command(subcommand)]
    pub cmd: Cmd,
}

#[derive(Debug, Subcommand)]
pub enum Cmd {
    /// Tokenize and print tokens.
    Lex {
        /// Path to the .trace script.
        script: PathBuf,
    },
    /// Tokenize, parse, and print the AST.
    Parse {
        script: PathBuf,
    },
    /// Lex + parse + semantic check.
    Check {
        script: PathBuf,
    },
    /// Execute the script against a pcap source using the tree-walking interpreter.
    Run {
        script: PathBuf,
        /// Override the pcap path declared in the script.
        #[arg(long)]
        pcap: Option<String>,
        /// Use the bytecode VM instead of the interpreter.
        #[arg(long)]
        vm: bool,
        /// Also print all tables at the end.
        #[arg(long)]
        print_tables: bool,
        /// BPF-style filter applied before event dispatch.
        #[arg(long)]
        filter: Option<String>,
        /// Substring filter applied to decoded event fields (case-insensitive).
        #[arg(long)]
        grep: Option<String>,
        /// Append each alert to this JSONL file (for chain-of-custody).
        #[arg(long)]
        log_file: Option<PathBuf>,
    },
    /// Compile a script to bytecode and write it to disk.
    Compile {
        script: PathBuf,
        /// Output path for the .traceb file. Defaults to `<script>.traceb`.
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Execute a previously-compiled bytecode module.
    Vm {
        module: PathBuf,
        /// Override the pcap path baked into the module.
        #[arg(long)]
        pcap: Option<String>,
        /// BPF-style filter applied before event dispatch.
        #[arg(long)]
        filter: Option<String>,
        /// Substring filter applied to decoded event fields (case-insensitive).
        #[arg(long)]
        grep: Option<String>,
        /// Append each alert to this JSONL file.
        #[arg(long)]
        log_file: Option<PathBuf>,
    },
    /// Read-eval-print loop. Type expressions or statements interactively.
    Repl,
    /// Extract frames matching a filter (and optional substring grep) into a new
    /// pcap file. Useful for preserving evidence subsets for downstream tools.
    Extract {
        /// Input pcap file.
        input: PathBuf,
        /// Output pcap file (will be overwritten if it exists).
        #[arg(short, long)]
        output: PathBuf,
        /// BPF-style filter (e.g. "tcp port 80").
        #[arg(long)]
        filter: Option<String>,
        /// Substring filter applied to decoded fields (case-insensitive).
        #[arg(long)]
        grep: Option<String>,
    },
}

pub fn run(args: Vec<String>) -> Result<ExitCode> {
    let cli = Cli::parse_from(args);
    match cli.cmd {
        Cmd::Lex { script } => lex_cmd(&script),
        Cmd::Parse { script } => parse_cmd(&script),
        Cmd::Check { script } => check_cmd(&script),
        Cmd::Run {
            script,
            pcap,
            vm,
            print_tables,
            filter,
            grep,
            log_file,
        } => run_cmd(
            &script,
            pcap.as_deref(),
            vm,
            print_tables,
            filter.as_deref(),
            grep.as_deref(),
            log_file.as_deref(),
        ),
        Cmd::Compile { script, output } => compile_cmd(&script, output.as_deref()),
        Cmd::Vm {
            module,
            pcap,
            filter,
            grep,
            log_file,
        } => vm_cmd(
            &module,
            pcap.as_deref(),
            filter.as_deref(),
            grep.as_deref(),
            log_file.as_deref(),
        ),
        Cmd::Repl => repl_cmd(),
        Cmd::Extract {
            input,
            output,
            filter,
            grep,
        } => extract_cmd(&input, &output, filter.as_deref(), grep.as_deref()),
    }
    .map(|_| ExitCode::from(0))
    .map_err(|e| e.into())
}

fn read_source(path: &std::path::Path) -> Result<String> {
    Ok(std::fs::read_to_string(path)?)
}

fn lex_cmd(path: &std::path::Path) -> Result<()> {
    let src = read_source(path)?;
    let toks = Lexer::new(&src).tokenize()?;
    for t in &toks {
        println!("{:>4}:{:>3}  {}", t.pos.line, t.pos.col, t.token);
    }
    Ok(())
}

fn parse_cmd(path: &std::path::Path) -> Result<()> {
    let src = read_source(path)?;
    let prog = TsParser::from_source(&src)?.parse_program()?;
    println!("{:#?}", prog);
    Ok(())
}

fn check_cmd(path: &std::path::Path) -> Result<()> {
    let src = read_source(path)?;
    let prog = TsParser::from_source(&src)?.parse_program()?;
    let mut a = Analyzer::new();
    a.analyze(&prog)?;
    println!("ok — {} declarations", prog.declarations.len());
    Ok(())
}

fn run_cmd(
    script: &std::path::Path,
    pcap: Option<&str>,
    use_vm: bool,
    _print_tables: bool,
    filter: Option<&str>,
    grep: Option<&str>,
    log_file: Option<&std::path::Path>,
) -> Result<()> {
    let src = read_source(script)?;
    let prog = TsParser::from_source(&src)?.parse_program()?;
    let mut a = Analyzer::new();
    a.analyze(&prog)?;
    let symbols = a.into_symbols();
    let filt = match filter {
        Some(s) => Some(crate::filter::Filter::parse(s)?),
        None => None,
    };
    let grep_owned = grep.map(|s| s.to_string());

    if use_vm {
        let module = crate::bytecode::codegen::compile(&prog)
            .map_err(|e| anyhow::anyhow!("compile error: {}", e))?;
        let mut vm = VM::new(module)?;
        let src_path = vm.source_path().map(|s| s.to_string());
        runtime::run_script_with_filter_and_grep(
            &mut vm,
            src_path.as_deref(),
            pcap,
            &filt,
            &grep_owned,
        )?;
        vm.run_finish()?;
        println!("\nALERTS ({}):", vm.alerts.len());
        if vm.alerts.is_empty() {
            println!("(none)");
        }
        if let Some(path) = log_file {
            write_alerts_jsonl(path, &vm.alerts)?;
            eprintln!("appended {} alerts to {}", vm.alerts.len(), path.display());
        }
    } else {
        let mut interp = Interpreter::new(&prog, &symbols)?;
        let src_path = interp.source_path().map(|s| s.to_string());
        runtime::run_script_with_filter_and_grep(
            &mut interp,
            src_path.as_deref(),
            pcap,
            &filt,
            &grep_owned,
        )?;
        interp.run_finish()?;
        println!("\nALERTS ({}):", interp.alerts.len());
        if interp.alerts.is_empty() {
            println!("(none)");
        }
        if let Some(path) = log_file {
            write_alerts_jsonl(path, &interp.alerts)?;
            eprintln!("appended {} alerts to {}", interp.alerts.len(), path.display());
        }
    }
    Ok(())
}

fn write_alerts_jsonl(path: &std::path::Path, alerts: &[Vec<Value>]) -> Result<()> {
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    for alert in alerts {
        let parts: Vec<String> = alert.iter().map(|v| v.to_string()).collect();
        let line = serde_json::json!({
            "ts": std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            "message": parts.join(" "),
        });
        writeln!(f, "{}", line)?;
    }
    Ok(())
}

fn compile_cmd(script: &std::path::Path, output: Option<&std::path::Path>) -> Result<()> {
    let src = read_source(script)?;
    let prog = TsParser::from_source(&src)?.parse_program()?;
    let mut a = Analyzer::new();
    a.analyze(&prog)?;
    let module = crate::bytecode::codegen::compile(&prog)
        .map_err(|e| anyhow::anyhow!("compile error: {}", e))?;
    let out_path = match output {
        Some(p) => p.to_path_buf(),
        None => {
            let mut p = script.as_os_str().to_owned();
            p.push(".traceb");
            PathBuf::from(p)
        }
    };
    module
        .save(&out_path)
        .map_err(|e| anyhow::anyhow!("save error: {}", e))?;
    println!(
        "wrote {} ({} constants, {} functions, {} event handlers, {} finish handlers)",
        out_path.display(),
        module.constants.len(),
        module.functions.len(),
        module.event_handlers.len(),
        module.finish_handlers.len(),
    );
    Ok(())
}

fn vm_cmd(
    module_path: &std::path::Path,
    pcap: Option<&str>,
    filter: Option<&str>,
    grep: Option<&str>,
    log_file: Option<&std::path::Path>,
) -> Result<()> {
    let module = crate::bytecode::opcode::BytecodeModule::load(module_path)
        .map_err(|e| anyhow::anyhow!("load error: {}", e))?;
    let mut vm = VM::new(module)?;
    let src_path = vm.source_path().map(|s| s.to_string());
    let filt = match filter {
        Some(s) => Some(crate::filter::Filter::parse(s)?),
        None => None,
    };
    let grep_owned = grep.map(|s| s.to_string());
    runtime::run_script_with_filter_and_grep(
        &mut vm,
        src_path.as_deref(),
        pcap,
        &filt,
        &grep_owned,
    )?;
    vm.run_finish()?;
    println!("\nALERTS ({}):", vm.alerts.len());
    if vm.alerts.is_empty() {
        println!("(none)");
    }
    if let Some(path) = log_file {
        write_alerts_jsonl(path, &vm.alerts)?;
        eprintln!("appended {} alerts to {}", vm.alerts.len(), path.display());
    }
    Ok(())
}

/// Read-eval-print loop. Reads lines from stdin, parses each as a sequence of
/// declarations or a single expression, and prints the result.
///
/// REPL is restricted to expression evaluation and let-bindings because the
/// event-driven model needs a pcap source to be meaningful.
fn repl_cmd() -> Result<()> {
    use std::io::{BufRead, Write, stdin, stdout};
    println!("TraceScript REPL. Type `:quit` to exit, `:help` for help.");
    let stdin = stdin();
    let mut input = String::new();
    let mut env: std::collections::HashMap<String, Value> = std::collections::HashMap::new();
    loop {
        print!(">>> ");
        stdout().flush().ok();
        input.clear();
        let n = stdin.lock().read_line(&mut input)?;
        if n == 0 {
            println!();
            return Ok(());
        }
        let line = input.trim();
        if line.is_empty() {
            continue;
        }
        match line {
            ":quit" | ":exit" => return Ok(()),
            ":help" => {
                println!("REPL accepts:");
                println!("  expressions: 1 + 2, len(\"hello\")");
                println!("  let bindings: let x = 1 + 2    -> shows =>");
                println!("  statements:  print x, alert(\"hi\", x), if x > 0 {{ ... }}");
                println!("  functions:   hash_sha256(s), ends_with(s, \".xyz\")");
                println!("               (function calls return values; bind with let)");
                println!("  :reset       clear all bindings");
                continue;
            }
            ":reset" => {
                env.clear();
                println!("bindings cleared");
                continue;
            }
            _ => {}
        }
        // Wrap the user's text in a synthetic function so we can evaluate it through
        // the existing interpreter plumbing. We then call `eval_repl_block` which
        // runs every statement and returns the value of the last expression-
        // evaluating statement.
        let script = format!("function __repl__() {{ {} }}", line);
        let prog = match TsParser::from_source(&script) {
            Ok(mut p) => match p.parse_program() {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("parse error: {}", e);
                    continue;
                }
            },
            Err(e) => {
                eprintln!("lex error: {}", e);
                continue;
            }
        };
        // Skip semantic analysis for REPL: REPL bindings are runtime-only and the
        // analyzer doesn't see them. The interpreter still catches most errors
        // (unknown identifiers become runtime errors anyway).
        let symbols = crate::sema::SymbolTable::default();
        let mut interp = match Interpreter::new(&prog, &symbols) {
            Ok(i) => i,
            Err(e) => {
                eprintln!("init error: {}", e);
                continue;
            }
        };
        // Seed the locals with prior bindings.
        interp.preload_locals(env.clone());
        let stmt = match &prog.declarations[0] {
            Decl::Function(f) => f.body.clone(),
            _ => {
                eprintln!("internal error");
                continue;
            }
        };
        match interp.eval_repl_block(&stmt) {
            Ok(v) => {
                if !matches!(v, Value::Unit) {
                    println!("=> {}", v);
                }
                env = interp.snapshot_locals();
            }
            Err(e) => eprintln!("runtime error: {}", e),
        }
    }
}
fn extract_cmd(
    input: &std::path::Path,
    output: &std::path::Path,
    filter: Option<&str>,
    grep: Option<&str>,
) -> Result<()> {
    let filt = match filter {
        Some(s) => Some(crate::filter::Filter::parse(s)?),
        None => None,
    };
    let grep_owned = grep.map(|s| s.to_string());
    let n = runtime::extract_matching_frames(input, output, &filt, &grep_owned)?;
    println!("wrote {} matching frames to {}", n, output.display());
    Ok(())
}
