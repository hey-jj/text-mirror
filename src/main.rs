//! Command line interface for text-mirror.
//!
//! Every verb writes JSON to stdout and never prompts. Conversion is
//! deterministic and fail-closed, so there is nothing to ask.
//!
//! Exit codes:
//!
//! - 0: the verb completed. A run with failed or unsupported records
//!   still exits 0, because those are recorded outcomes.
//! - 1: the verb could not complete. stdout carries `{"error": ...}`.
//! - 2: usage error from argument parsing.
//! - 3: the verb is not yet implemented. stdout carries
//!   `{"error": "not_implemented"}`.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

use text_mirror::pipeline::{self, Rules, RunOptions};
use text_mirror::walk::WalkOptions;

#[derive(Parser)]
#[command(
    name = "text-mirror",
    version,
    about = "Converts files into plain text and builds a replica text-mirror tree \
             beside a provenance manifest"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Dry-run inventory of a root by detected format
    Scan {
        /// The directory tree to inventory
        root: PathBuf,
    },
    /// Convert a division root into the mirror tree
    Run {
        /// The division root to convert
        root: PathBuf,
        /// The mirror tree root
        #[arg(long)]
        mirror: PathBuf,
        /// The directory holding manifest shards
        #[arg(long)]
        manifest: PathBuf,
        /// The division name, also the shard file stem
        #[arg(long)]
        division: String,
    },
    /// Coverage per division over terminal manifest records
    Status {
        /// The directory holding manifest shards
        #[arg(long)]
        manifest: PathBuf,
    },
    /// Print every manifest record for one source path
    Explain {
        /// Source path relative to its division root
        path: String,
        /// The directory holding manifest shards
        #[arg(long)]
        manifest: PathBuf,
    },
    /// Package a division for handoff (not yet implemented)
    Bundle {
        /// Ignored until the verb ships
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, hide = true)]
        args: Vec<String>,
    },
    /// Check a bundle on the receiving side (not yet implemented)
    Verify {
        /// Ignored until the verb ships
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, hide = true)]
        args: Vec<String>,
    },
    /// Combine per-division bundles (not yet implemented)
    Merge {
        /// Ignored until the verb ships
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, hide = true)]
        args: Vec<String>,
    },
}

fn execute(command: Command) -> Result<String, text_mirror::Error> {
    let rules = Rules::builtin()?;
    let json = match command {
        Command::Scan { root } => {
            let report = pipeline::scan(&root, &rules, &WalkOptions::default())?;
            serde_json::to_string_pretty(&report)
        }
        Command::Run {
            root,
            mirror,
            manifest,
            division,
        } => {
            let report = pipeline::run(
                &rules,
                &RunOptions {
                    root: &root,
                    mirror_root: &mirror,
                    manifest_dir: &manifest,
                    division: &division,
                    walk: WalkOptions::default(),
                },
            )?;
            serde_json::to_string_pretty(&report)
        }
        Command::Status { manifest } => {
            let report = pipeline::status(&manifest)?;
            serde_json::to_string_pretty(&report)
        }
        Command::Explain { path, manifest } => {
            let entries = pipeline::explain(&manifest, &path)?;
            serde_json::to_string_pretty(&entries)
        }
        Command::Bundle { .. } | Command::Verify { .. } | Command::Merge { .. } => {
            unreachable!("handled before execute")
        }
    };
    json.map_err(|e| text_mirror::Error::Encode {
        path: PathBuf::from("stdout"),
        message: e.to_string(),
    })
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    if matches!(
        cli.command,
        Command::Bundle { .. } | Command::Verify { .. } | Command::Merge { .. }
    ) {
        println!("{}", serde_json::json!({ "error": "not_implemented" }));
        return ExitCode::from(3);
    }
    match execute(cli.command) {
        Ok(json) => {
            println!("{json}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            println!("{}", serde_json::json!({ "error": e.to_string() }));
            ExitCode::from(1)
        }
    }
}
