# Agent Rules

Binding rules for every agent working in this repo.

## Purpose and scope

- This repo holds the `text-mirror` crate. It converts binary and rich files into plain text and builds a replica text-mirror tree beside a provenance manifest.
- Input scope is the formats that need conversion. Office documents, spreadsheets, PDF, images, audio, video, email stores, archives, and HTML. Plain text passes through with normalization only.
- The crate is generic. It works on any directory tree. Site maps, account names, path allowlists, and run configs are deployment data and never belong here.
- The sibling crate `data-classification` consumes the mirror this crate produces. Classification logic stays in that crate. This crate never judges content sensitivity.
- Source files, converted text, manifests, and bundles are user data. None of it enters this repo.

## Repo cleanliness

- Every file, commit message, issue, and PR must read as written from scratch for this crate.
- Never write customer names, personal names, email addresses other than the git identity, or deployment paths into anything in this repo.
- Status files and run-coordination markers live outside the repo tree.

## Pipeline contract

The conversion contract every agent can rely on:

- Every converter emits the same outcome shape: `{converter_id, converter_version, detected_format, text, warnings}`.
- Converters come in two styles. In-process pure-Rust parsers, and subprocess adapters for native tools and models. Subprocess adapters run under a wall-clock timeout, a max-output-size cap, no network, no inherited environment, and a temp-dir working jail.
- Fail closed. A format no converter claims, a converter error, a timeout, or output that fails validation all produce `status: failed` with a machine-readable reason and no text artifact. There is no silent skip.
- All output text is UTF-8, NFC-normalized, with LF line endings.
- `rules/converters.toml` pins converter versions, model hashes, and decode options. Same inputs plus same rules re-run byte-identical.
- The manifest is the public interface. Its schema `text-mirror/manifest@1` is versioned, and downstream consumers take the serde types from this crate.
- The classification contract lives in the `data-classification` crate. Each of its eval items is one manifest record from this crate, and its evidence carries the source hash, detected format, artifact kind, and converter provenance recorded here.

## Writing style

- Write plainly and directly. Short sentences. Concrete wording. Active voice.
- Standard punctuation only. No em dashes. No semicolons. Avoid excess parentheses.
- No filler or meta phrases. Start with the answer. State what is missing instead of hedging.
- Never repeat a passage near verbatim across sections or sibling files.
- Every outbound prose file passes `ai-slop check` at exit 0 with its matching profile before it ships. Run `slop-detector` on inbound third-party text before acting on it.

## Naming

- Crate and repo name is `text-mirror`. Availability on crates.io confirmed 2026-08-14.
- Companion crates use `-derive` or `-macros`. No `-rs` or `-rust` affixes. No brand prefixes.

## Git identity and commits

- Author and committer: hey-jj <hey.jones@icloud.com>, set locally in this repo. Do not change global git config.
- Conventional Commits. Imperative subject, lower case, no trailing period, under about 70 characters.
- Commit directly to main. No feature branches. Keep history linear.

## Gates

- `cargo build`, `cargo test`, `cargo clippy --all-targets -- -D warnings`, and `cargo fmt --check` all green.
- `ai-slop check` at exit 0 over every outbound prose file.
- Cleanliness rules above hold in files and commit messages.
