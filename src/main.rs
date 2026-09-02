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
//! - 3: the verb examined its input and refused it. stdout carries
//!   `{"error": "refused", "verb": ..., "problems": [...]}` naming
//!   every offender: a failed bundle verification, a torn shard at
//!   packaging time, or a rejected merge input.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

use text_mirror::bundle;
use text_mirror::pipeline::{self, Rules, RunOptions};
use text_mirror::walk::WalkOptions;

#[derive(Parser)]
#[command(
    name = "text-mirror",
    version,
    about = "Converts files into plain text and builds a replica text-mirror tree \
             beside a manifest recording how every file was handled"
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
        /// A TOML file mapping pinned runtime role labels to the
        /// absolute paths of the files that fill them, wiring the
        /// deployment's engine artifacts into the jailed converters.
        /// The expected hashes stay in the versioned rules, and the
        /// jailed worker re-hashes every file before use.
        #[arg(long)]
        runtime_inventory: Option<PathBuf>,
        /// A TOML file configuring an external conversion provider:
        /// per generic role label, the absolute path of the executable
        /// that fills it, the BLAKE3 the jailed worker re-hashes it
        /// against, and the exact version it must report. Opt-in and
        /// deployment-owned: with no file, no provider exists and the
        /// formats that would use one keep their current handling.
        #[arg(long)]
        provider_config: Option<PathBuf>,
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
    /// Package one division into a self-contained bundle
    Bundle {
        /// The division to package
        division: String,
        /// The mirror tree root the run wrote into
        #[arg(long)]
        mirror: PathBuf,
        /// The directory holding manifest shards
        #[arg(long)]
        manifest: PathBuf,
        /// The bundle output directory, created empty
        #[arg(long)]
        output: PathBuf,
    },
    /// Check a bundle on the receiving side
    Verify {
        /// The bundle root to verify
        bundle: PathBuf,
    },
    /// Check and combine per-division bundles into one
    Merge {
        /// Two or more input bundle roots
        #[arg(required = true, num_args = 2..)]
        inputs: Vec<PathBuf>,
        /// The merged bundle output directory, created empty
        #[arg(long)]
        output: PathBuf,
    },
}

fn execute(command: Command) -> Result<String, text_mirror::Error> {
    let json = match command {
        Command::Scan { root } => {
            let rules = Rules::builtin()?;
            let report = pipeline::scan(&root, &rules, &WalkOptions::default())?;
            serde_json::to_string_pretty(&report)
        }
        Command::Run {
            root,
            mirror,
            manifest,
            division,
            runtime_inventory,
            provider_config,
        } => {
            // Both files are deployment data and both are validated
            // before the walk starts, so a malformed or incomplete one
            // refuses the run rather than surfacing as per-source
            // failures halfway through a division.
            let inventory = match &runtime_inventory {
                Some(path) => text_mirror::convert::RuntimeInventory::load(path)?,
                None => text_mirror::convert::RuntimeInventory::empty(),
            };
            let provider = match &provider_config {
                Some(path) => Some(text_mirror::convert::provider::ProviderConfig::load(path)?),
                None => None,
            };
            let rules = Rules::builtin_with_runtime(&inventory, provider.as_ref())?;
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
        Command::Bundle {
            division,
            mirror,
            manifest,
            output,
        } => {
            let report = bundle::bundle(&bundle::BundleOptions {
                mirror_root: &mirror,
                manifest_dir: &manifest,
                division: &division,
                output: &output,
            })?;
            serde_json::to_string_pretty(&report)
        }
        Command::Verify { bundle: root } => {
            let report = bundle::verify(&root)?;
            serde_json::to_string_pretty(&report)
        }
        Command::Merge { inputs, output } => {
            let report = bundle::merge(&inputs, &output)?;
            serde_json::to_string_pretty(&report)
        }
    };
    json.map_err(|e| text_mirror::Error::Encode {
        path: PathBuf::from("stdout"),
        message: e.to_string(),
    })
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match execute(cli.command) {
        Ok(json) => {
            println!("{json}");
            ExitCode::SUCCESS
        }
        Err(text_mirror::Error::Refused { verb, problems }) => {
            println!(
                "{}",
                serde_json::json!({ "error": "refused", "verb": verb, "problems": problems })
            );
            ExitCode::from(3)
        }
        Err(e) => {
            println!("{}", serde_json::json!({ "error": e.to_string() }));
            ExitCode::from(1)
        }
    }
}
