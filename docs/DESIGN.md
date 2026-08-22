# text-mirror design

Architecture for the `text-mirror` crate. The crate converts binary and rich files into plain text and builds a replica text-mirror tree beside a provenance manifest. The manifest schema `text-mirror/manifest@1` is the public interface.

## Shape

A pure library plus a thin binary. Modules:

- `walk`: scoped deterministic traversal. Configured division roots, ignore rules, sorted order.
- `detect`: format detection, magic bytes first with the extension as tiebreak, against a versioned format table. Declared and detected types are both recorded, with a mismatch flag when they disagree. A declared id the table marks as a refinement of what magic saw, svg over bare xml, resolves to the declared id with the flag down, since the two observations agree. Magic that resolves to a format outside the table cannot contradict the declared id, so it leaves the flag down and appends a warning naming what the bytes showed.
- `convert`: the `Converter` trait, a registry, a sandboxed subprocess runner, and a text-native passthrough that strips markup.
- `mirror`: path mapping and atomic writes.
- `manifest`: the serde schema for `text-mirror/manifest@1`.
- `hash`: BLAKE3 content hashing and the dedup index.
- `report`: agent-consumable JSON summaries.
- `rules/`: versioned data. The converter registry, pinned versions and model hashes, the format table, and the transcript-format spec.
- `skills/text-mirror/`: the operator skill for agent-managed runs.

## Converter boundary

One trait, two implementation styles. In-process converters are pure-Rust parsers for documents and spreadsheets. Subprocess adapters wrap native tools and models for text-layer PDF, transcription, media decoding, and OCR. Both styles emit the same outcome: `{converter_id, converter_version, detected_format, text, warnings}`, with an optional media block for audio and video.

Subprocess adapters run under a wall-clock timeout, a max-output-size cap, no network, no inherited environment, and a temp-dir working jail. They speak a stdin/stdout JSON protocol, so an adapter is swappable without touching the core. Hostile bytes crash a child process and never the pipeline.

The runner enforces those terms concretely. Each frame on stdin and stdout is a four-byte big-endian length prefix followed by one UTF-8 JSON value, and the reader checks the declared length against a cap before it allocates, so an oversized declaration is refused without buying its buffer. The parent drains stdout and stderr on separate threads under their own caps while a monotonic deadline runs, and at the deadline, or on any cap breach, it kills the child's process group with SIGKILL and discards every partial frame. A response counts only from a child that wrote exactly one frame, nothing after it, and exited cleanly, so a crash that prints plausible JSON is still refused. The spawn is two stages: the parent builds the child with a cleared environment, the jail as working directory, piped stdio, and a fresh process group, and the child starts in a single-threaded sandbox helper that engages the platform jail, sets address-space, CPU, and file-size limits, closes stray descriptors, and only then execs the adapter. No sandbox work runs in a post-fork closure. Network denial is enforced by the platform, user and network namespaces with a seccomp allow-list and Landlock on Linux, a deny-first Seatbelt profile on macOS, behind one trait: no backend means no run, and a startup probe proves IPv4, IPv6, Unix socket, and UDP egress all fail before any adapter executes. The macOS backend is development containment, because its profile language carries no third-party stability promise, so a release decision rests on the Linux path.

A subprocess adapter whose engine is not pinned yet fails closed. Until `rules/converters.toml` records an engine version and model hash for it, a format routed to that adapter records `unsupported` with reason `engine-unpinned` in the error field and writes no artifact, the same interim shape the spreadsheet visibility gap uses. The checkpoint key includes the rules version, so the bump that pins an engine re-runs every such record with no manual sweep.

Fail closed everywhere. A format no converter claims, a converter error, a timeout, or output that fails validation (invalid UTF-8, suspiciously empty) all produce `status: failed` with a machine-readable reason and no text artifact. A failed conversion is a countable outcome the manifest reports alongside successes. There is no silent skip and no silently empty file.

Every `unsupported` record names its reason in the error field. A declared entry in `rules/converters.toml` wins, and a detected format with no converter entry and no declared reason records the floor reason `no-converter`. The declared vocabulary: `engine-unpinned` for media formats awaiting a pinned engine, `hidden-visibility-unresolved` for spreadsheet formats with no visibility reader, `converter-deferred` for recognized data formats awaiting a converter, `container-deferred` for archive formats awaiting container expansion, `proprietary-binary` for design-tool binaries with no public text extraction worth building, and `pickle-deserialization-unsafe` for pickle files. That last one is a permanent security exclusion: deserializing a pickle stream executes arbitrary code, so never add a pickle deserializer to this tree and never parse pickle bytes. A script can bucket the whole unconverted remainder on these strings alone.

Determinism: `rules/converters.toml` pins converter versions, model hashes, and decode options. The registry is data, so a rules bump is a visible versioned event, and same inputs plus same rules re-run byte-identical. All output is UTF-8, NFC-normalized, LF line endings. Normalization is NFC. NFKC is prohibited because it rewrites identifiers.

In-process coverage today: the text-native passthrough, a document adapter for Office documents, presentations, rich text, OpenDocument files, and EPUB, and a workbook converter for xls, xlsx, xlsm, and ods. Text-layer PDF runs through the subprocess runner, because a PDF parser over hostile bytes belongs in a jailed child that can crash without taking the pipeline down. A PDF with no extractable text layer fails with reason `pdf_no_text_layer`. Failed records re-run every pass, so those files convert automatically once an OCR converter lands. The passthrough accepts UTF-8, and UTF-16 behind a required byte order mark: the mark is consumed, the text transcodes, and the record carries a transcoding warning naming the source encoding. A UTF-16 file with no mark fails as `invalid_utf8`, and a UTF-32 mark fails with `unsupported-encoding: utf-32`, since a guessed encoding would emit decoded noise as a converted artifact.

Legacy Office conversions run a differential check against a second, independent extraction. Agreement is silent, and disagreement appends a structured warning while the artifact stands. When the primary extracted under half of what the secondary found, the conversion fails with reason `differential-divergence`, because an artifact missing that much content must not present as converted. A secondary crash appends `differential-unavailable` and never sinks a sound primary conversion.

Workbooks render cell values row by row, and a formula cell renders its cached value with the formula as inert text, never evaluated. Hidden sheets, rows, and columns render inline, unmarked. The marks live out of band in the segments file: a span for every sheet with its hidden flag, and hidden-true spans over hidden rows and hidden-column cells. A workbook whose visibility cannot be resolved fails instead of emitting unmarked content, and a spreadsheet format with no visibility reader yet records `unsupported` with reason `hidden-visibility-unresolved` in the error field.

Each segments record is one JSONL line with these fields: `schema` (the literal `text-mirror/segments@1`), `kind` (`span`, or the zero-width boundaries `page`, `sheet`, `slide`), `start` and `end` as half-open offsets, `unit` (`utf8_bytes`), and the optional `source` (`document`, `sheet`, `row`, `column`), `name`, and `hidden`. Records are ordered by start, then end. A passthrough text file emits one whole-file `document` span, so every converted artifact has a segments file.

## The mirror tree

The mirror parallels each division's source tree exactly under `mirror/<division>/`, with the text extension appended: `Q3 Budget.xlsx` in division `emea` lives at `mirror/emea/Q3 Budget.xlsx.txt` under the bundle root. The record's `text_path` value is mirror-root-relative and begins with the record's division segment: `emea/Q3 Budget.xlsx.txt`. Appending preserves source identity and keeps sources that differ only by extension from colliding on one output path, and the division segment keeps two divisions holding the same source path from colliding in a merged bundle. Division names are one non-empty ASCII path segment each, unique under ASCII case folding across a configuration.

Containers expand into a sibling directory. `update.msg` yields `update.msg.txt` plus `update.msg.d/report.pdf.txt`, and each child record carries a `parent_source` link. Nested members become child artifacts, and the manifest records the explicit container chain for each one. Expansion runs under hard limits: max nesting depth, max children per container, max expanded bytes, max single member size.

Artifacts are pure text with no in-band provenance header, so the mirror doubles as a training corpus. Provenance lives in the manifest. The one exception is AV transcripts, which carry in-band timecodes as content.

## Artifact envelope

Each converted source yields one artifact envelope with metadata strictly out of band:

- The content text: the canonical downstream input, in the mirror tree. It contains no provenance header, no front matter, no injected page markers. In-band metadata creates false findings downstream, contaminates language detection, and shifts every byte offset.
- The provenance record: `artifact.json` fields carried as the source's manifest record (see below). Authoritative for identity, status, and completeness.
- `<source>.segments.jsonl`: ordered spans mapping the content text back to source structure. Page, sheet, and slide boundaries are zero-width boundary records here, and the content text stays free of marker strings. Offsets are half-open UTF-8 byte spans, labeled by unit, because bytes, scalars, UTF-16 units, and graphemes are four different counts.
- `<source>.review.md`: an optional derived human view, explicitly non-canonical.

Each document yields exactly one artifact, whatever its page count. Per-page splitting breaks cross-page entities and tables.

Security-scan binding: when a scan verdict is recorded for a source, it binds the exact hash scanned, the engine version, the signature version and its update time, and the scan time. The status vocabulary includes `not-run` and `unknown`, and a missing verdict never reads as a pass. For containers the record states what was scanned, the outer file only or every extracted member.

## Manifest

Append-only JSONL, sharded per division: `manifest/<division>.jsonl`. One record per source file per outcome. Fields:

- `schema`: the literal string `text-mirror/manifest@1`, the first field of every record
- source path (relative to the division root), source hash, source size
- declared and detected format, mismatch flag
- `status`: `converted`, `failed`, `unsupported`, `skipped_unchanged`, `dedup`
- text path and text hash
- `artifact_kind`: `text`, `transcript`, `ocr`, `mixed`
- converter id and version, tool version, rules version
- optional `media` block: duration, language, model id and hash, decode-options hash, speaker count
- `parent_source`, `dedup_of`, warnings, error, duration

Every record self-describes its schema, so a shard separated from its bundle stays verifiable. A consumer must reject any record whose `schema` value it does not recognize. After manifest@1 freezes, any change to the record field set, including an addition, bumps the version to manifest@2. Strict consumers reject unknown fields, so additive changes are breaking.

Incremental and idempotent: the manifest is the checkpoint. The key is (source_path, source_hash, converter_version, rules_version). A match means `skipped_unchanged` with no work done. Traversal is sorted, so a killed run resumes by re-walking and skipping completed records, with no separate journal to corrupt. Path plus size plus mtime is never sufficient to skip.

Dedup: an identical source hash converts once, but every duplicate still gets a real text file at its parallel path so the mirror stays complete, and the duplicate's `dedup_of` points at the canonical copy for corpus assembly.

A division is a configured root subtree plus its manifest shard. Divisions never interleave, and shards merge independently.

## Transcript format

One text artifact per media file, in a versioned transcript format shipped in `rules/` and documented publicly so downstream parsers can rely on it. Speech segments and OCR'd on-screen text interleave by timestamp:

```
[00:00:12 -> 00:00:19] Speaker 1: ...spoken content...
[on-screen @ 00:03:02] Q3 revenue: $4.2M
```

Derived-from-media marking lives in the manifest: `artifact_kind: transcript` plus the `media` block. Downstream consumers can slice results by `artifact_kind` and score transcript-sourced outcomes separately, so transcription noise is distinguishable from consumer error. Timestamps let a reviewer jump to the moment in the source recording.

On-screen text is deduplicated by screen state before it enters the transcript, so a slide shown for ten minutes appears once.

## Two-machine bundle handoff

Conversion and consumption can run on different machines. The interface is a self-contained bundle from `text-mirror bundle`: the mirror tree (text only, source binaries never leave the conversion machine), the manifest shards, the `rules/` snapshot that produced them, and a `BUNDLE.json` with `schema` (`text-mirror/bundle@1`), `manifest_schema` (`text-mirror/manifest@1`), run ids, divisions, counts, coverage, and a top-level hash over a per-artifact checksum file.

The receiving machine runs `text-mirror verify <bundle>` first. Verify refuses a bundle whose `schema`, `manifest_schema`, or any record `schema` value it does not recognize. It recomputes every file hash against the checksum file, refuses any bundle file the checksum file does not list and any entry outside the bundle layout, confirms every manifest text path exists and matches, and confirms counts and coverage denominators exactly. Any mismatch refuses the whole bundle and names every offender. Bundles are always written clean: packaging refuses a shard that ends in a torn line instead of repairing it, because the remedy is resuming the run, so every line of every shard in a verified bundle ends with a newline and parses as a complete record. The checksum chain detects corruption and partial transfer. It does not detect tampering, because nothing signs `BUNDLE.json`, and authenticity, if ever needed, travels out of band. Bundles are per-division and mergeable, so divisions transfer as they complete. Failed and unsupported records travel in the manifest, so the receiver always knows the true denominator and the enumerated unconverted remainder.

## CLI

All verbs emit JSON, use meaningful exit codes, and never prompt. Conversion is deterministic and fail-closed, so there is nothing to ask.

- `scan`: dry-run inventory by detected format, with size outliers.
- `run`: convert. Emits progress events, safe to kill and re-run.
- `status`: coverage percentages per division.
- `explain`: why a file failed, or which converter handled it.
- `verify`: check a bundle on the receiving side.
- `bundle`: package a division for handoff.
- `merge`: combine per-division bundles.

## Agent operation

An agent runs the pipeline through the skill in `skills/text-mirror/`. The loop per division: scan, review the inventory to surface unexpected formats and size outliers before spending hours of transcription, run in the background while polling status, triage failures with explain (retry transient causes, report unsupported formats upward), bundle, report coverage. The agent sequences and reports and makes no content judgments.

Media conversion dominates wall-clock time, so AV runs as its own pass within a division.

## Relationship to data-classification

The `data-classification` crate consumes the bundle, mirror plus manifest, and never source binaries. Each eval item is a manifest record. The classifier reads the text path for content and carries source hash, detected format, `artifact_kind`, and converter provenance into its evidence, so every finding traces back to the original file by hash. The manifest schema `text-mirror/manifest@1` is the contract. A consumer may depend on this crate's serde types once published, or conform to the schema independently. Every bundle and every record carries its schema string, so a conforming consumer can fail closed on versions it does not recognize.
