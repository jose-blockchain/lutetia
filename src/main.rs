//! Lutetia CLI — EVM bytecode decompiler.

use anyhow::Result;
use clap::Parser;
use lutetia::decompiler::{decompile_bytecode, DecompilerConfig, OutputFormat};
use std::io::{IsTerminal, Read};

#[derive(Parser, Debug)]
#[command(
    name = "lutetia",
    version,
    about = "EVM bytecode decompiler — a Rust rewrite of Panoramix"
)]
struct Cli {
    /// Bytecode as a hex string (with or without 0x prefix).
    #[arg(value_name = "BYTECODE")]
    bytecode: Option<String>,

    /// Read bytecode from a file instead.
    #[arg(short = 'f', long)]
    file: Option<String>,

    /// Output format: text (default), asm, json.
    #[arg(short = 'o', long, default_value = "text")]
    format: String,

    /// Execution timeout in seconds.
    #[arg(short = 't', long, default_value_t = 60)]
    timeout: u64,

    /// Disable coloured output.
    #[arg(long)]
    no_color: bool,

    /// Print version and exit.
    #[arg(long)]
    version_info: bool,
}

fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn")).init();

    let cli = Cli::parse();

    if cli.version_info {
        println!("lutetia {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }

    // Determine the hex bytecode.
    let hex_code = if let Some(ref path) = cli.file {
        let mut buf = String::new();
        std::fs::File::open(path)?.read_to_string(&mut buf)?;
        buf.trim().to_string()
    } else if let Some(ref code) = cli.bytecode {
        code.trim().to_string()
    } else if std::io::stdin().is_terminal() {
        anyhow::bail!("no bytecode provided — pass it as an argument, via -f, or pipe to stdin");
    } else {
        let mut buf = String::new();
        std::io::stdin().read_to_string(&mut buf)?;
        buf.trim().to_string()
    };

    if hex_code.is_empty() {
        anyhow::bail!("empty bytecode");
    }

    let format = match cli.format.as_str() {
        "asm" => OutputFormat::Asm,
        "json" => OutputFormat::Json,
        _ => OutputFormat::Text,
    };

    let config = DecompilerConfig {
        timeout_secs: cli.timeout,
        format,
        color: !cli.no_color,
    };

    let result = decompile_bytecode(&hex_code, &config)?;
    println!("{}", result.text);

    Ok(())
}
