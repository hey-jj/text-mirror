# Changelog

All notable changes to this project are documented here. The format
follows Keep a Changelog, and the project adheres to Semantic
Versioning.

## [0.7.0] - 2026-08-30

### Added

- An optional svg raster leg, gated behind a new `svg-provider`
  feature that builds on `image-ocr`. A vector source keeps the
  passthrough primary it has always had, and a deployment that
  configures an external rasterizer additionally gets the recognized
  text of the source's rendering as a visible derived child at
  `<source>.d/#image-ocr`, attributed to `image-pixel-ocr` with
  `artifact_kind: "ocr"` and spans labelled `source: "ocr"`. With no
  provider configured there is no child, no child directory, and no
  change of any kind to the source's own artifact, which is every
  default run. A source whose rendering holds no readable text writes
  no child either. `manifest@1` is unchanged: the child reuses the
  derived-child record shape a container member already uses.
- A deployment-owned provider configuration, supplied through the new
  `--provider-config` flag on `text-mirror run` and the new
  `ProviderConfig` type. It names, per generic role label, the
  absolute path of the executable that fills it, the enumerated
  closure it loads its dependencies from, and the two jail parameters
  its runtime needs: the
  service namespace it registers under, written as an anchored dotted
  prefix, and the name of an extra temp-directory variable. Both
  parameters have closed shapes, and a value outside them refuses the
  run with `provider-parameter-invalid` before the walk starts, so a
  supplied value cannot widen the jail beyond the names under one
  prefix. A closure is enumerated, never a shared root: each entry is
  granted its own subpath in the jail, a configuration naming a
  package store, an application directory, or any other directory
  many unrelated programs live in is refused, and a role that
  enumerates a closure must have that closure pinned or the run is
  refused at registry construction. Every configured path is resolved
  when the configuration is read: a component or entry that cannot be
  resolved, an entry that is a symlink or anything but a directory or
  a regular file, an executable that is not a regular file, or a path
  written with `.` or `..` is refused, the executable must lie inside
  one of its entries on the resolved paths, and the jail grants the
  resolved paths. A refusal from the runner or the jail names the
  fault, and a grant or entry by its position, never a path, so no
  deployment path can reach a record. That closes the same message
  for every granted runtime, the audio engine's included. The two
  `Rules` constructors that exist for tests, `from_parts_provider_not_built`
  and `from_parts_with_runtime_under_template`, live behind the
  `test-adapters` feature with the fake engines. What the worker asserts about each
  executable, the BLAKE3, the exact version, and the aggregate closure
  digest over every regular file and symlink target under each
  enumerated entry, is versioned
  rules data in the new `[image_ocr.svg_provider]` section, pinned per
  role label like every other engine expectation. The crate ships no
  path and no default. The schema
  is `text-mirror/provider@1`, carries exactly one provider with
  exactly two roles, `raster-browser` and `raster-magick`, and refuses
  unknown fields, so a configuration naming another provider or
  another role is a run configuration error raised before the walk. It
  is never a silently ignored table.
- A provider jail class: a separate measured profile for the external
  components, which spawn helper processes, load a larger runtime
  closure, and register their own services. It shares nothing with the
  accelerator class, and its allowances key on the class together with
  the wired components, so no other worker mode can reach them. The
  class holds every control the narrower classes hold: no egress on
  any address family, no read or write outside the per-run jail, no
  execution of an undeclared program, no inherited environment, no
  process left behind at the deadline, and a fresh working root per
  execution, which is where a component's profile state lives because
  no profile flag is ever passed. Those controls are permanent tests
  that run against a synthetic closure, so they hold wherever the
  class is built, not only where an installation exists. The class is
  refused on platforms with no measured profile for it.
- The complete provider reason vocabulary, every value static and
  naming a generic role label only: `rasterizer-missing`,
  `rasterizer-hash-drift`, `rasterizer-version-drift`,
  `raster-exec-failed`, `raster-geometry-mismatch`, and
  `encoder-area-cap`. A configured provider that cannot run records a
  failed child, never an unsupported one, and no path, product name,
  version output, or host identity reaches a record.
- Per-execution verification in the cold jailed worker: presence, a
  fresh BLAKE3, the aggregate digest over the enumerated closure, and
  the exact version.
  Each assertion runs before its own execution, not once for the pair,
  so a component swapped between the two still fails closed. The rendered raster must then match the source's declared
  aspect within one pixel on both cross-axis derivations and sit under
  the encoder-input area cap before the flatten runs, and the
  flattened raster must keep the dimensions the assertion accepted.
  The flatten always carries the ordered options ending in the
  metadata-chunk exclusion, without which the raster is not
  byte-stable across cold starts.
- Explicit geometry resolution for vector sources: the declared root
  size in absolute units, or the view box, decides the render size.
  Percentages and font- and viewport-relative units resolve against
  nothing this leg has. They fail closed with
  `raster-geometry-mismatch`, so no host default viewport ever decides
  the render size.
- The effective rules version. `Rules::version()` yields the numeric
  rules version alone with no provider configured, and that version
  plus a digest of the provider's identity with one, as
  `10+svg.<digest>`. The digest covers provider presence, the generic
  role labels, the rules-pinned hashes and versions, the adapter
  version,
  and the geometry and flatten options, and excludes every absolute
  path, so enabling, disabling, or repinning a provider re-runs the
  affected sources, while moving an identical installation to another
  path re-runs nothing. `manifest@1` is unchanged: `rules_version` was already a
  string field.

- An in-jail audio transcription converter for wav, mp3, flac, and
  m4a, gated behind a new `audio-asr` feature. The source is decoded
  by the pure-Rust symphonia crate inside the subprocess sandbox into
  a wav at the decoder-reported sample rate and channel count, never
  the container's declared rate, and the pinned speech engine reads
  that wav. Resampling and channel mixing stay inside the engine, so
  no resampler enters this crate. The converter ships as
  `asr-adapter/2.0.0` and stamps transcripts with
  `ArtifactKind::Transcript` and a `media` block naming the decoded
  duration, the pinned language, and the engine identity as a role
  label plus hashes. A build without the feature records the four
  formats as `unsupported` with reason `audio-asr-not-built`. The
  engine identity is pinned for one machine class, so a featured
  build on any other platform records them as `unsupported` with
  reason `engine-unpinned` until that platform gains its own pin.
- The audio jail profile as versioned rules data, the `[asr]` section:
  a one-hour decoded-duration ceiling asserted in-jail from the
  decoded frame count with a sixteen-frame priming allowance
  (`asr-duration-exceeded`, never truncation), a 1 GiB decoded-size
  preflight (`asr-decoded-too-large`) sitting under the file-size
  rlimit so the preflight is always the arbiter, wall, cpu, response,
  stderr, and process ceilings, and the pinned runtime hashes. A
  sub-LSB waveform fails as `asr-no-speech`. A louder waveform whose
  engine response holds no segments fails as `empty_output`. Neither
  ever writes an empty artifact, and the engine's output envelope is
  size-checked against the same response ceiling before it is read.
- The complete audio reason vocabulary, every value static and free
  of role paths: `audio-asr-not-built`, `engine-unpinned`,
  `asr-decode-failed`, `asr-codec-unsupported`,
  `asr-duration-exceeded`, `asr-decoded-too-large`, `asr-no-speech`,
  `empty_output`, `asr-runtime-missing`, `asr-runtime-mismatch`,
  `asr-backend-unavailable`, and `asr-protocol-error` on records,
  plus the runner codes `worker-memory-exceeded`,
  `memory-monitor-failed`, and `process-count-unavailable`.
- m4a admission for the low-complexity AAC profile only, decided by a
  first-party bounded reader over the track's decoder configuration:
  spectral-band replication signaled on the flag bit (the sync word
  alone never rejects), parametric coding, a non-low-complexity
  object type, a reserved rate index, a container rate that disagrees
  with the configuration rate, a lossless-codec track, more than one
  track, and a truncated configuration all fail closed with
  `asr-codec-unsupported`.
- A parent-side resident-memory guard in the runner. When a limit
  profile carries `max_resident_bytes`, the parent polls the worker's
  whole process group, engine child included, sums resident bytes
  with checked arithmetic, kills the group when the sum crosses the
  ceiling, and fails closed with `worker-memory-exceeded`. A failed
  measurement is itself a failure, `memory-monitor-failed`, and the
  output drains keep running through the termination. When the leader
  exits, one final group measurement runs before the cleanup kill, so
  a fast exit cannot carry a ballooned descendant past the guard, and
  a member whose records cannot be read fails the query unless a
  recheck confirms the member already exited. The audio profile uses
  the guard at 6 GiB with the address-space limit unset, the same
  shape as the image profile on this platform.
- A runtime-inventory mechanism shared by the image-OCR and audio
  converters. A deployment maps generic role labels to file paths
  through the new `RuntimeInventory` type, the
  `Rules::builtin_with_inventory` constructor, or the new
  `--runtime-inventory` flag on `text-mirror run`. The expected
  BLAKE3 values live in the versioned rules (`[image_ocr.inventory]`
  and `[asr.inventory]`). Grant assembly is pin-first: a supplied
  path for a role the rules do not pin earns no jail grant and no
  wire entry, and the worker reports that role missing. The jail
  grants each qualifying file as a literal path, never a directory:
  directories and symlinks are refused when the inventory is
  configured and again right before every spawn. The audio worker
  mode alone, with its engine wired, additionally receives the
  measured accelerator allowances one real in-jail transcription
  required: device property reads, device access scoped to the
  accelerator user-client class, and a listing-only allowance on
  each granted binary's own directory, whose sibling files stay
  unreadable. The jail profile a worker runs under is an explicit
  class on its spawn spec, and the allowances key on that class
  alone, never on grant presence, so an image worker carrying its own
  engine grant keeps the base profile, and a grant-free jail of any
  class keeps the base profile. The engine child's
  output streams land in jail-owned files, its home and temp
  directories point into the jail, and the process ceiling is
  applied as headroom above the user's pre-existing process count,
  so the spawn budget the rules bound stays enforceable on a busy
  host. A count the host will not answer refuses the spawn with
  `process-count-unavailable`, never a substituted baseline standing
  in for the number being bounded. The cold worker re-hashes every file against its pinned hash
  right before preflight and execution, so a swap after parent-side
  validation still fails closed. Failures name role labels only.
- A flac row in the format table, so flac detects as its own format
  instead of falling to `unknown`.

### Changed

- The `image-pixel-ocr` converter moves from 1.0.0 to 1.1.0: the same
  converter gained the svg input route and the child-specific segment
  source. Direct png, jpeg, and webp conversion is unchanged, spans
  included, but the version is part of the checkpoint key, so every
  existing raster OCR record re-runs once under this release.
- A build without the `svg-provider` feature that is nonetheless given
  a provider configuration records the warning
  `svg-provider-not-built` on each vector source, so a deployment that
  asked for the leg is told the binary cannot run it.
- A source that previously ran an auxiliary derived-child leg and no
  longer does now retires the child it used to own, the same way a
  re-expanded container retires a member it no longer holds. Turning a
  provider off removes its children instead of leaving them behind
  with nothing to produce them.
- The public `Rules` struct gained private fields, so it can no longer
  be built with a struct literal. The new `Rules::from_parts`
  constructor takes a format table and a registry and is the
  replacement for that. The public jail `SpawnSpec` gained a
  `provider` field and the public `RuntimeProfile` gained a `Provider`
  variant, so external code that constructs the first exhaustively or
  matches the second exhaustively must account for them. The
  public `ImageOcrLimits` struct gained an `svg_provider` map of the
  provider pins. The jail's `ProviderJail` parameters have private
  fields and one validating constructor, so the closed grammar the
  configuration enforces is enforced at the render boundary too, and
  no caller can hand the renderer a value the configuration would have
  refused. The image-OCR ceilings `IMAGE_OCR_MAX_AREA_PX`,
  `IMAGE_OCR_VALIDATED_LONG_EDGE`, and `IMAGE_OCR_DECODE_ALLOC` moved
  up to the `convert` module, where the provider leg also reads them.
- The rules version moves from 9 to 10. Every record whose format
  routing changed, the audio family above all, re-runs once under
  this release.
- The public `Outcome` struct gained a `media` field and the public
  `CanonicalArtifact` struct gained a `media` field, so a
  transcript's media block survives conversion, the checkpoint, and
  both dedup paths. Both structs are exhaustive, so external code that
  constructs them by listing every field must add the new one. The
  on-disk `manifest@1` is unchanged: `media` was already an optional
  record field.
- The public runner `Limits` struct changed shape:
  `address_space_bytes` is now an `Option`, `None` leaving the rlimit
  unset, and the struct gained `max_resident_bytes` for the new
  resident-memory guard. The public `ImageOcrLimits` struct gained an
  `inventory` map, the sandbox helper's public `HelperConfig` gained
  the grant lists and the optional address-space value, and the jail
  `SpawnSpec` gained the `exec_grants` and `read_grants` fields, so
  an external jail backend that constructs it exhaustively must add
  them. External code that constructs any of these by listing every
  field must account for the changes.
- The `AsrRequest` wire body gained required `max_duration_seconds`
  and optional `inventory` fields, and `OcrRequest` gained an
  optional `inventory` field that stays off the wire when empty. The
  adapter schema identifiers are unchanged, and parent and worker
  ship in one binary, so no mixed-version pairing exists for the
  required field to trip.
- The speech adapter's constructor now takes the parsed `[asr]`
  profile and a runtime inventory instead of a bare runner, and the
  image-OCR converter's constructor takes the inventory beside its
  limits. The engine-unpinned speech scaffold and its fake worker
  response are gone. The fake engine stage now runs behind a
  dedicated worker mode that shares the production decode and
  preflight layers.
- An accepted consequence of the crate-wide 128 MiB source ceiling:
  an hour-long uncompressed wav at 44.1 or 48 kHz exceeds it and
  records `resource_limit` before any decode, while hour-long mp3,
  m4a, and flac sources fit. Raising that ceiling is a crate-wide
  decision for a later release.

## [0.6.0] - 2026-08-24

### Added

- A default noise policy on the directory walk. `WalkOptions` gained an
  `ignore_suffixes` list, matched against a bare entry name at any depth
  the way `ignore_names` already matched by exact equality, and a
  skipped directory still hides its whole subtree. `WalkOptions::default()`
  now carries the shipped policy: the `.DS_Store` sidecar by name, and
  the `-wal`, `-shm`, and `.tmp` suffixes. The `scan` and `run` commands
  build their options that way, so the excludes are on for both.
  Data-bearing dotfiles stay in scope: `.env`, ssh keys, `.gitconfig`,
  and `.config`-style files are classification targets, and a `.d`
  config directory is walked as a source.
- An in-jail image-metadata converter that lifts the textual metadata a
  raster image carries and records it as a hidden derived child. One
  image source yields two independent artifacts: the pixel text from
  the image-OCR converter as the primary artifact, and the metadata as
  a child at `<source>.d/#image-metadata`, every row marked hidden,
  reusing the same derived-child record shape a container member
  already uses. The leg runs for png, jpeg, webp, and heic. It does not
  run for svg, whose raw-text primary artifact already carries every
  metadata string verbatim. The exif, png text-chunk, container-packet,
  xmp, iptc, and iso base media file format parsers all run behind the
  same subprocess jail as the records worker, and a decompression bomb,
  an xml event flood, or a box-count flood fails the child closed
  without touching the pipeline or the primary leg. The converter is
  gated behind a new `image-metadata` feature. A build without it does
  not run the leg, and records the warning `image-metadata-not-built`
  on each image so a later build that carries the converter mints the
  child instead of skipping the image as unchanged. `manifest@1` is
  unchanged. This adds the public `ImageMetadataLimits` rules struct
  and the `ImageMetadata` converter, both additive.
- An in-jail image-OCR converter for png, jpeg, and webp. The raster is
  decoded by the pure-Rust `image` crate inside the subprocess sandbox,
  the encoder-input area cap is asserted before the full decode, and the
  canonical pixels are handed to the pinned vision engine inside the
  jail. The converter is gated behind a new `image-ocr` feature. A build
  without it routes those formats to the `image-ocr-not-built` capability
  gap. This release wires no engine, so a build with the feature decodes
  the raster and then fails closed with `image-ocr-runtime-missing` until
  a deployment supplies the pinned runtime.
- Capability gaps carried into this release: pixel OCR for heic and for
  svg is not built. A heic source fails closed with reason
  `no-jailed-rasterizer`, because decoding it needs an external
  rasterizer and that provider lands in a later release. An svg source
  passes through as raw markup, and pixel OCR over its rendered form
  waits for the same rasterizer provider.

### Changed

- The rules version moves from 8 to 9, so every image is re-run once
  under this release and gains its metadata child where one applies.
- A malformed png, jpeg, webp, or heic now yields two failed records
  where it yielded one: its primary image record, and a failed
  `<source>.d/#image-metadata` child with a machine-readable reason,
  the same two-record shape a container gives an unreadable member. A
  metadata-bearing image likewise adds one converted child. Run failure
  and record counts over a corpus rise by those children. A clean image
  with no metadata adds nothing.
- The public `WalkOptions` struct gained an `ignore_suffixes` field.
  The struct is exhaustive, so external code that builds it with a
  struct literal must add the field. A caller that wants the previous
  behaviour passes an empty list.
- The public `Outcome` struct gained an `artifact_kind` field and the
  `OcrOk` struct gained a `warnings` field. Both structs are exhaustive,
  so external code that constructs them or destructures them by listing
  every field must account for the new fields. This is a breaking change
  for those callers, which is why this release moves to 0.6.0. The
  on-disk `manifest@1` and `adapter-response@1` serialization stays the
  same: `artifact_kind` is an existing optional manifest field, and
  `OcrOk.warnings` is omitted from the wire when empty, so a
  warning-free success is byte-identical to the previous reader and only
  an actual warning trips a mixed-version pairing.

## [0.5.0] - 2026-08-22

### Changed

- The public `PdfConversion` and `PdfOk` structs gained a `recovered`
  field that records whether a document's text came from the direct
  extraction path. Because both structs are exhaustive, external code
  that constructs or destructures them by listing every field must
  account for the new field. This is a breaking change for those
  callers, which is why this release moves to 0.5.0. The on-disk
  `manifest@1` and `bundle@1` serialization stays the same: the field is
  omitted from the wire when false, so a 0.4.0 reader sees identical
  bytes for any non-recovered outcome.

### Fixed

- A PDF with a real but small text layer set against heavy vector
  artwork was misclassified as image-based and failed closed with
  `pdf_no_text_layer`, dropping text that was there to be read. The PDF
  converter now attempts a direct text extraction whenever the primary
  path declines a page as image-based. When a readable text layer is
  present, it is extracted and the document converts, carrying the
  stable `pdf_partial_text` warning that routes the file to OCR review.
  A page whose only recoverable characters are blank, control, or
  invisible still fails closed with `pdf_no_text_layer`. Recovered text
  is recorded under a converter id that names the recovery path, so the
  manifest attributes it to the extractor that produced it. The
  `manifest@1` and `bundle@1` schemas and every reason code stay
  unchanged. The fix narrows which PDFs receive `pdf_no_text_layer` and
  leaves what the code means alone.
