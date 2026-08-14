//! Converts binary and rich files into plain text and builds a replica
//! text-mirror tree beside a provenance manifest.
//!
//! The manifest schema `text-mirror/manifest@1` is the public
//! interface. The [`manifest`] module holds its serde types. See
//! `docs/DESIGN.md` for the architecture.
//!
//! In-process converters cover text, Office and OpenDocument
//! documents, and spreadsheets. Text-layer PDF and the media adapters
//! run behind the sandbox [`runner`] in a jailed worker. A format no
//! converter claims, or one whose adapter engine is not pinned yet, is
//! inventoried by [`detect`] and recorded as `unsupported`, so the
//! manifest always reports the true denominator.

#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};

use thiserror::Error as ThisError;

pub mod bundle;
pub mod convert;
pub mod detect;
pub mod hash;
pub mod manifest;
pub mod mirror;
pub mod pipeline;
pub mod report;
#[cfg(unix)]
pub mod runner;
pub mod segments;
pub mod walk;

/// The typed adapter request and response bodies, re-exported so
/// transcript rendering and tests reach them on every platform. On a
/// unix target these are the same types the [`runner`] protocol uses.
#[cfg(unix)]
pub use runner::protocol::bodies as runner_bodies;

/// Standalone copies of the transcript-shaped bodies for platforms
/// without a jail backend, so transcript rendering still type-checks.
#[cfg(not(unix))]
pub mod runner_bodies {
    use serde::{Deserialize, Serialize};

    /// One transcribed speech segment.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct AsrSegment {
        /// Segment start in seconds.
        pub start_seconds: f64,
        /// Segment end in seconds.
        pub end_seconds: f64,
        /// One-based speaker index.
        pub speaker: u32,
        /// The transcribed text.
        pub text: String,
    }

    /// One deduplicated on-screen text state.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ScreenState {
        /// When this state first appeared, in seconds.
        pub first_seen_seconds: f64,
        /// The on-screen text.
        pub text: String,
    }
}

/// Errors returned by this library.
///
/// Conversion failures are not errors. They are recorded outcomes in
/// the manifest. This type covers the cases where the pipeline itself
/// cannot proceed.
#[derive(Debug, ThisError)]
pub enum Error {
    /// A filesystem operation failed.
    #[error("{op} {path}: {source}")]
    Io {
        /// The operation that failed, such as `open` or `read`.
        op: &'static str,
        /// The path the operation touched.
        path: PathBuf,
        /// The underlying error.
        #[source]
        source: std::io::Error,
    },

    /// A rules file failed to parse or validate.
    #[error("rules file {name}: {message}")]
    Rules {
        /// The rules file name.
        name: String,
        /// What went wrong.
        message: String,
    },

    /// A manifest shard failed to parse or validate.
    #[error("manifest {path} line {line}: {message}")]
    Manifest {
        /// The shard path.
        path: PathBuf,
        /// The one-based line number.
        line: usize,
        /// What went wrong.
        message: String,
    },

    /// A manifest record could not be encoded.
    #[error("encode manifest record for {path}: {message}")]
    Encode {
        /// The shard path.
        path: PathBuf,
        /// What went wrong.
        message: String,
    },

    /// A division name is not usable as a shard file name.
    #[error("invalid division name {name:?}: use ASCII letters, digits, hyphen, underscore")]
    Division {
        /// The rejected name.
        name: String,
    },

    /// The run layout is invalid.
    #[error("invalid layout: {message}")]
    Layout {
        /// What is wrong with the layout.
        message: String,
    },

    /// A bundle verb examined its input and refused it, naming every
    /// offender. Refusal is an outcome, distinct from a verb that
    /// could not run.
    #[error("{verb} refused: {}", problems.join("; "))]
    Refused {
        /// The verb that refused.
        verb: &'static str,
        /// Every offending file, record, or field.
        problems: Vec<String>,
    },
}

impl Error {
    pub(crate) fn io(op: &'static str, path: &Path, source: std::io::Error) -> Self {
        Error::Io {
            op,
            path: path.to_path_buf(),
            source,
        }
    }
}

/// The result type used across this library.
pub type Result<T> = std::result::Result<T, Error>;
