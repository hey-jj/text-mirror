//! The text-mirror sandbox worker binary.
//!
//! This binary is never run by hand. The library's subprocess runner
//! spawns it, first in its sandbox helper mode to engage the jail,
//! which then execs it into an adapter mode. The first argument
//! selects the mode. See `text_mirror::runner::worker`.

use std::process::ExitCode;

#[cfg(unix)]
fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(mode) = args.first() else {
        eprintln!("worker_missing_mode: this binary is spawned by the runner, not run by hand");
        return ExitCode::from(2);
    };
    text_mirror::runner::worker::worker_main(mode, &args[1..])
}

#[cfg(not(unix))]
fn main() -> ExitCode {
    eprintln!("worker_unsupported_platform: the sandbox worker needs a unix jail backend");
    ExitCode::from(2)
}
