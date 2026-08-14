//! Converts binary and rich files into text and builds a replica
//! text-mirror tree with a provenance manifest.
//!
//! The manifest schema `text-mirror/manifest@1` is the public interface.
//! See `docs/DESIGN.md` for the architecture.

pub mod convert {}
pub mod detect {}
pub mod hash {}
pub mod manifest {}
pub mod mirror {}
pub mod report {}
pub mod walk {}
