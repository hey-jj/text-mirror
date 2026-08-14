//! Converts binary and rich files into plain text and builds a replica
//! text-mirror tree beside a provenance manifest.
//!
//! The manifest schema `text-mirror/manifest@1` is the public
//! interface. The [`manifest`] module holds its serde types. See
//! `docs/DESIGN.md` for the architecture.
//!
//! The current release ships the pure-Rust core. The only converter is
//! the plain text passthrough. Every other known format is inventoried
//! by [`detect`] and recorded as `unsupported`, so the manifest always
//! reports the true denominator.

#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};

use thiserror::Error as ThisError;

pub mod convert;
pub mod detect;
pub mod hash;
pub mod manifest;
pub mod mirror;
pub mod pipeline;
pub mod report;
pub mod walk;

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
