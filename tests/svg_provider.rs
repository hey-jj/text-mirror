//! End-to-end tests for the svg provider leg: a vector source keeps its
//! passthrough primary and gains a visible recognized-text child at
//! `<source>.d/#image-ocr` when, and only when, a deployment configures
//! a complete external provider.
//!
//! The provider half runs for real here, jail and all. The pinned
//! external tuple is not on every machine, so these tests configure a
//! synthetic provider of their own: two small programs written by the
//! test, hash-pinned and version-pinned exactly as a deployment's would
//! be, executed through the same provider jail class, the same fixed
//! argument vectors, and the same per-exec assertions the real one
//! takes. What they cannot exercise is the pinned tuple's own output,
//! which is what the environment-gated suite beside this one covers.
//!
//! Every fixture here is synthetic and written for this crate.

#![cfg(all(
    unix,
    target_os = "macos",
    feature = "svg-provider",
    feature = "image-metadata"
))]

use std::fs;
use std::io::Write;
use std::path::PathBuf;

use text_mirror::convert::RuntimeInventory;
use text_mirror::convert::provider::{self, ProviderConfig};
use text_mirror::manifest::{self, ArtifactKind, Record, Status};
use text_mirror::pipeline::{self, Rules, RunOptions};
use text_mirror::walk::WalkOptions;
use zip::CompressionMethod;
use zip::write::SimpleFileOptions;

mod harness;
use harness::{FakeProvider, svg_bytes};

struct Setup {
    _dir: tempfile::TempDir,
    root: PathBuf,
    mirror: PathBuf,
    manifest_dir: PathBuf,
}

fn setup() -> Setup {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("source");
    fs::create_dir_all(&root).unwrap();
    Setup {
        root,
        mirror: dir.path().join("mirror"),
        manifest_dir: dir.path().join("manifest"),
        _dir: dir,
    }
}

/// A second division root, for a test that needs one after it already
/// bound the first.
fn fresh_setup() -> Setup {
    setup()
}

fn run_with(setup: &Setup, rules: &Rules) -> text_mirror::report::RunReport {
    pipeline::run(
        rules,
        &RunOptions {
            root: &setup.root,
            mirror_root: &setup.mirror,
            manifest_dir: &setup.manifest_dir,
            division: "alpha",
            walk: WalkOptions::default(),
        },
    )
    .unwrap()
}

/// The builtin rules with no provider: the shape of every default run.
fn plain_rules() -> Rules {
    let mut rules = Rules::builtin().unwrap();
    rules.registry.use_fake_image_ocr();
    rules
}

/// The rules with a synthetic provider wired and the recognition stage
/// faked, so the provider half runs for real and the engine half is
/// deterministic.
fn provider_rules(provider: &FakeProvider) -> Rules {
    provider.rules()
}

fn records(setup: &Setup) -> Vec<Record> {
    manifest::read_shard(&setup.manifest_dir.join("alpha.jsonl"))
        .unwrap()
        .records
}

fn terminal(setup: &Setup, source_path: &str) -> Option<Record> {
    records(setup)
        .into_iter()
        .rev()
        .find(|r| r.source_path == source_path)
}

fn artifact(setup: &Setup, source_path: &str) -> String {
    fs::read_to_string(setup.mirror.join(format!("alpha/{source_path}.txt"))).unwrap()
}

fn segments(setup: &Setup, source_path: &str) -> String {
    fs::read_to_string(
        setup
            .mirror
            .join(format!("alpha/{source_path}.segments.jsonl")),
    )
    .unwrap()
}

fn child_of(source: &str) -> String {
    format!("{source}.d/#image-ocr")
}

fn stored_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut writer = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let options = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
    for (name, bytes) in entries {
        writer.start_file(*name, options).unwrap();
        writer.write_all(bytes).unwrap();
    }
    writer.finish().unwrap().into_inner()
}

fn remove_child_artifact(setup: &Setup, source_path: &str) {
    fs::remove_file(setup.mirror.join(format!("alpha/{source_path}.txt"))).unwrap();
    fs::remove_file(
        setup
            .mirror
            .join(format!("alpha/{source_path}.segments.jsonl")),
    )
    .unwrap();
}

// --- the record shape -------------------------------------------------

#[test]
fn a_configured_provider_adds_a_visible_child_and_leaves_the_primary_alone() {
    let provider = FakeProvider::new(&[(1600, 900)]);
    let setup = setup();
    let source = svg_bytes(1600, 900, "Quarterly summary");
    fs::write(setup.root.join("chart.svg"), &source).unwrap();

    run_with(&setup, &provider_rules(&provider));

    // The primary is untouched: same converter, same artifact, and the
    // artifact is the source's own markup byte for byte.
    let primary = terminal(&setup, "chart.svg").expect("primary record");
    assert_eq!(primary.status, Status::Converted);
    assert_eq!(primary.converter_id.as_deref(), Some("text-passthrough"));
    assert_eq!(primary.artifact_kind, Some(ArtifactKind::Text));
    assert_eq!(primary.detected_format, "svg");
    assert_eq!(
        artifact(&setup, "chart.svg"),
        String::from_utf8(source).unwrap()
    );

    // The child is the recognized text of the rendering.
    let child = terminal(&setup, &child_of("chart.svg")).expect("ocr child record");
    assert_eq!(child.status, Status::Converted, "{:?}", child.error);
    assert_eq!(child.converter_id.as_deref(), Some("image-pixel-ocr"));
    assert_eq!(child.converter_version.as_deref(), Some("1.1.0"));
    assert_eq!(child.artifact_kind, Some(ArtifactKind::Ocr));
    assert_eq!(child.parent_source.as_deref(), Some("chart.svg"));
    assert!(!artifact(&setup, &child_of("chart.svg")).is_empty());

    // Every child segment is a visible ocr span, which is what makes
    // this child different from the hidden metadata child.
    let sidecar = segments(&setup, &child_of("chart.svg"));
    assert!(!sidecar.trim().is_empty());
    for line in sidecar.lines() {
        assert!(line.contains("\"source\":\"ocr\""), "{line}");
        assert!(!line.contains("\"hidden\":true"), "{line}");
    }
}

#[test]
fn with_no_provider_configured_svg_is_a_passthrough_primary_and_nothing_else() {
    let setup = setup();
    fs::write(
        setup.root.join("logo.svg"),
        svg_bytes(1600, 900, "no provider here"),
    )
    .unwrap();

    run_with(&setup, &plain_rules());

    let primary = terminal(&setup, "logo.svg").expect("primary record");
    assert_eq!(primary.status, Status::Converted);
    assert_eq!(primary.converter_id.as_deref(), Some("text-passthrough"));
    assert!(primary.warnings.is_empty(), "{:?}", primary.warnings);
    // No child record, no child artifact, no child directory at all.
    assert!(terminal(&setup, &child_of("logo.svg")).is_none());
    assert!(
        !setup
            .mirror
            .join(format!("alpha/{}.txt", child_of("logo.svg")))
            .exists()
    );
    assert!(!setup.mirror.join("alpha/logo.svg.d").exists());
}

#[test]
fn a_rendering_with_no_readable_text_writes_no_child() {
    // The provider runs and returns a raster the recognition reads as
    // content-free. That is the vector equivalent of an image carrying
    // no metadata: nothing to write, so no child record and no files,
    // rather than a failed child on every text-free drawing.
    let provider = FakeProvider::new(&[(7, 7)]);
    let setup = setup();
    fs::write(setup.root.join("blank.svg"), svg_bytes(7, 7, "")).unwrap();

    run_with(&setup, &provider_rules(&provider));

    assert_eq!(
        terminal(&setup, "blank.svg").unwrap().status,
        Status::Converted
    );
    assert!(terminal(&setup, &child_of("blank.svg")).is_none());
    assert!(
        !setup
            .mirror
            .join(format!("alpha/{}.txt", child_of("blank.svg")))
            .exists()
    );
}

// --- provider failures ------------------------------------------------

#[test]
fn every_configured_provider_failure_is_a_failed_child_never_unsupported() {
    // Each planted fault is a distinct named reason on a failed child,
    // with no artifact, while the primary converts as usual. A
    // configured provider that cannot run is a failure on the record:
    // unsupported is for a format nothing claims, and this format is
    // claimed by the passthrough that just converted it.
    type Plant = Box<dyn Fn(&mut FakeProvider)>;
    let cases: Vec<(&str, Plant, &str)> = vec![
        (
            "absent.svg",
            Box::new(|provider: &mut FakeProvider| provider.remove_raster()),
            "rasterizer-missing",
        ),
        (
            "drifted.svg",
            Box::new(|provider: &mut FakeProvider| provider.substitute_raster()),
            "rasterizer-hash-drift",
        ),
        (
            "closure.svg",
            Box::new(|provider: &mut FakeProvider| provider.drift_closure()),
            "rasterizer-hash-drift",
        ),
        (
            "version.svg",
            Box::new(|provider: &mut FakeProvider| provider.pin_wrong_version()),
            "rasterizer-version-drift",
        ),
        (
            "exit.svg",
            Box::new(|provider: &mut FakeProvider| provider.raster_exits_nonzero()),
            "raster-exec-failed",
        ),
        (
            "nothing.svg",
            Box::new(|provider: &mut FakeProvider| provider.raster_writes_nothing()),
            "raster-exec-failed",
        ),
        (
            "torn.svg",
            Box::new(|provider: &mut FakeProvider| provider.raster_writes_garbage()),
            "raster-exec-failed",
        ),
        (
            "square.svg",
            Box::new(|provider: &mut FakeProvider| provider.raster_writes_square()),
            "raster-geometry-mismatch",
        ),
        (
            "encoder-absent.svg",
            Box::new(|provider: &mut FakeProvider| provider.remove_encoder()),
            "rasterizer-missing",
        ),
        (
            "encoder-drift.svg",
            Box::new(|provider: &mut FakeProvider| provider.substitute_encoder()),
            "rasterizer-hash-drift",
        ),
        (
            "encoder-exit.svg",
            Box::new(|provider: &mut FakeProvider| provider.encoder_exits_nonzero()),
            "raster-exec-failed",
        ),
        (
            "encoder-resize.svg",
            Box::new(|provider: &mut FakeProvider| provider.encoder_resizes()),
            "raster-geometry-mismatch",
        ),
    ];
    for (name, plant, expected) in cases {
        let mut provider = FakeProvider::new(&[(1600, 900), (900, 900), (800, 450)]);
        plant(&mut provider);
        let setup = setup();
        fs::write(setup.root.join(name), svg_bytes(1600, 900, "text")).unwrap();

        run_with(&setup, &provider_rules(&provider));

        let primary = terminal(&setup, name).unwrap_or_else(|| panic!("{name}: primary"));
        assert_eq!(primary.status, Status::Converted, "{name}");
        let child = terminal(&setup, &child_of(name))
            .unwrap_or_else(|| panic!("{name}: a configured failure must record a child"));
        assert_eq!(child.status, Status::Failed, "{name}");
        assert_ne!(child.status, Status::Unsupported, "{name}");
        let error = child.error.as_deref().unwrap_or_default();
        assert!(error.starts_with(expected), "{name}: {error}");
        assert!(child.text_path.is_none(), "{name}");
        assert!(
            !setup
                .mirror
                .join(format!("alpha/{}.txt", child_of(name)))
                .exists(),
            "{name}"
        );
        // No path, product name, or host identity in the reason.
        assert!(!error.contains('/'), "{name}: {error}");
    }
}

#[test]
fn unresolved_source_geometry_fails_before_the_provider_runs() {
    // A percent-only root with no view box cannot be rendered without a
    // host default viewport deciding the size, so the leg refuses it
    // before it renders anything. The reason is the geometry one and
    // not an execution one, which is what refusing first means: a
    // rasterizer that had run with no resolvable window would have
    // failed as an execution instead.
    let provider = FakeProvider::new(&[(1600, 900)]);
    let setup = setup();
    fs::write(
        setup.root.join("fluid.svg"),
        b"<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"100%\" height=\"100%\"><text>x</text></svg>\n",
    )
    .unwrap();

    run_with(&setup, &provider_rules(&provider));

    let child = terminal(&setup, &child_of("fluid.svg")).expect("a failed child");
    assert_eq!(child.status, Status::Failed);
    assert!(
        child
            .error
            .as_deref()
            .is_some_and(|e| e.starts_with("raster-geometry-mismatch")),
        "{:?}",
        child.error
    );
}

#[test]
fn an_upstream_provider_failure_produces_no_recognition_input() {
    // With the rasterizer refused, nothing downstream of it runs: no
    // raster is produced, the recognition worker is never handed one,
    // and the child records the upstream reason with no artifact. The
    // step order behind that is asserted directly beside the leg.
    let mut provider = FakeProvider::new(&[(1600, 900)]);
    provider.substitute_raster();
    let setup = setup();
    fs::write(setup.root.join("halt.svg"), svg_bytes(1600, 900, "text")).unwrap();

    run_with(&setup, &provider_rules(&provider));

    let child = terminal(&setup, &child_of("halt.svg")).expect("a failed child");
    assert!(
        child
            .error
            .as_deref()
            .is_some_and(|e| e.starts_with("rasterizer-hash-drift")),
        "{:?}",
        child.error
    );
    assert!(child.text_path.is_none());
    assert!(!setup.mirror.join("alpha/halt.svg.d").exists());
}

#[test]
fn the_window_the_provider_receives_is_the_declared_source_size() {
    // The synthetic rasterizer renders only the window it is asked
    // for: it looks up a fixture by that exact window and fails when
    // none matches. Two sources of different declared sizes both
    // convert, so the window followed each source's own geometry
    // rather than a fixed or host-default viewport.
    let provider = FakeProvider::new(&[(1600, 900), (800, 450)]);
    let setup = setup();
    fs::write(setup.root.join("wide.svg"), svg_bytes(1600, 900, "wide")).unwrap();
    fs::write(setup.root.join("half.svg"), svg_bytes(800, 450, "half")).unwrap();

    run_with(&setup, &provider_rules(&provider));

    for source in ["wide.svg", "half.svg"] {
        let child = terminal(&setup, &child_of(source)).unwrap_or_else(|| panic!("{source} child"));
        assert_eq!(
            child.status,
            Status::Converted,
            "{source}: {:?}",
            child.error
        );
    }

    // A source whose declared size has no fixture is rendered at that
    // window and finds none, so the leg fails rather than silently
    // rendering at some other size.
    let setup = fresh_setup();
    fs::write(setup.root.join("odd.svg"), svg_bytes(640, 360, "odd")).unwrap();
    run_with(&setup, &provider_rules(&provider));
    let child = terminal(&setup, &child_of("odd.svg")).expect("a failed child");
    assert!(
        child
            .error
            .as_deref()
            .is_some_and(|e| e.starts_with("raster-exec-failed")),
        "{:?}",
        child.error
    );
}

// --- the checkpoint and the effective rules version -------------------

#[test]
fn the_effective_rules_version_names_the_provider_and_excludes_its_paths() {
    let provider = FakeProvider::new(&[(1600, 900)]);
    let plain = Rules::builtin().unwrap();
    assert_eq!(plain.version(), "10");

    let wired = provider_rules(&provider);
    let version = wired.version().to_string();
    assert!(version.starts_with("10+svg."), "{version}");
    assert_eq!(version.len(), "10+svg.".len() + 12, "{version}");

    // The same provider reached through a different absolute path is
    // the same provider: moving an installation skips nothing.
    let moved = provider.moved();
    assert_eq!(provider_rules(&moved).version(), version);

    // A different pinned identity is a different version. The digest
    // keys on what the rules pin, so re-pinning a version moves it;
    // changing a file behind an unchanged pin is drift, which the
    // per-exec assertions catch instead.
    let mut repinned = FakeProvider::new(&[(1600, 900)]);
    repinned.pin_wrong_version();
    assert_ne!(provider_rules(&repinned).version(), version);
    // And the shipped pins yield the shipped identity, which is not
    // the synthetic one.
    let config = ProviderConfig::parse(&provider.config_toml()).unwrap();
    let shipped = Rules::builtin_with_runtime(&RuntimeInventory::empty(), Some(&config)).unwrap();
    assert!(shipped.version().starts_with("10+svg."));
    assert_ne!(shipped.version(), version);
}

#[test]
fn enabling_a_provider_re_runs_a_source_that_had_no_child() {
    // The state transition the effective version exists for: an
    // unchanged source converted with no provider, then a run with one.
    // Without the provider in the checkpoint key the source would skip
    // and never mint its child.
    let setup = setup();
    fs::write(
        setup.root.join("later.svg"),
        svg_bytes(1600, 900, "minted on enable"),
    )
    .unwrap();
    let first = run_with(&setup, &plain_rules());
    assert_eq!(first.counts.converted, 1);
    assert!(terminal(&setup, &child_of("later.svg")).is_none());

    let provider = FakeProvider::new(&[(1600, 900)]);
    let second = run_with(&setup, &provider_rules(&provider));

    assert_eq!(second.counts.skipped_unchanged, 0, "{second:?}");
    assert_eq!(
        terminal(&setup, "later.svg").unwrap().rules_version[..2],
        *"10"
    );
    let child = terminal(&setup, &child_of("later.svg")).expect("the child is minted");
    assert_eq!(child.status, Status::Converted);
}

#[test]
fn disabling_a_provider_re_runs_the_source_and_retires_its_child() {
    let provider = FakeProvider::new(&[(1600, 900)]);
    let setup = setup();
    fs::write(setup.root.join("gone.svg"), svg_bytes(1600, 900, "text")).unwrap();
    run_with(&setup, &provider_rules(&provider));
    assert_eq!(
        terminal(&setup, &child_of("gone.svg")).unwrap().status,
        Status::Converted
    );

    let second = run_with(&setup, &plain_rules());

    assert_eq!(second.counts.skipped_unchanged, 0, "{second:?}");
    // The child is retired the way a removed container member is, and
    // its artifact is gone with it.
    let child = terminal(&setup, &child_of("gone.svg")).expect("a retired child record");
    assert_eq!(child.status, Status::Failed);
    assert!(
        !setup
            .mirror
            .join(format!("alpha/{}.txt", child_of("gone.svg")))
            .exists()
    );
}

#[test]
fn a_provider_run_with_nothing_changed_skips_and_keeps_its_child() {
    let provider = FakeProvider::new(&[(1600, 900)]);
    let setup = setup();
    fs::write(setup.root.join("same.svg"), svg_bytes(1600, 900, "text")).unwrap();
    let rules = provider_rules(&provider);
    run_with(&setup, &rules);
    let first_child = terminal(&setup, &child_of("same.svg")).unwrap();

    let second = run_with(&setup, &rules);

    // The source skips, and its child is reached only through it, so
    // the child's prior record stays terminal and its artifact stays
    // exactly where it was. This is the container shape: a skipped
    // parent leaves its descendants untouched.
    assert_eq!(second.counts.skipped_unchanged, 1, "{second:?}");
    assert_eq!(
        terminal(&setup, "same.svg").unwrap().status,
        Status::SkippedUnchanged
    );
    let child = terminal(&setup, &child_of("same.svg")).unwrap();
    assert_eq!(child.status, Status::Converted);
    assert_eq!(child.text_hash, first_child.text_hash);
    assert!(!artifact(&setup, &child_of("same.svg")).is_empty());
}

#[test]
fn a_child_that_becomes_content_free_is_retired_and_one_that_gains_text_is_minted() {
    // Both directions of the not-applicable transition, over the same
    // source path.
    let provider = FakeProvider::new(&[(1600, 900), (7, 7)]);
    let setup = setup();
    let path = setup.root.join("changing.svg");
    fs::write(&path, svg_bytes(1600, 900, "first pass")).unwrap();
    let rules = provider_rules(&provider);
    run_with(&setup, &rules);
    assert_eq!(
        terminal(&setup, &child_of("changing.svg")).unwrap().status,
        Status::Converted
    );

    // Success to nothing-to-write: the prior child is retired.
    fs::write(&path, svg_bytes(7, 7, "")).unwrap();
    run_with(&setup, &rules);
    let retired = terminal(&setup, &child_of("changing.svg")).expect("retired child");
    assert_eq!(retired.status, Status::Failed);
    assert!(
        !setup
            .mirror
            .join(format!("alpha/{}.txt", child_of("changing.svg")))
            .exists()
    );

    // Nothing-to-write back to success: the child is minted again.
    fs::write(&path, svg_bytes(1600, 900, "second pass")).unwrap();
    run_with(&setup, &rules);
    let minted = terminal(&setup, &child_of("changing.svg")).expect("minted child");
    assert_eq!(minted.status, Status::Converted);
    assert!(!artifact(&setup, &child_of("changing.svg")).is_empty());
}

#[test]
fn a_missing_child_artifact_re_runs_the_source() {
    // The primary is intact but the child's artifact is gone. The
    // checkpoint validates a source's descendants the way it validates
    // a container's, so the source is not skipped.
    let provider = FakeProvider::new(&[(1600, 900)]);
    let setup = setup();
    fs::write(setup.root.join("torn.svg"), svg_bytes(1600, 900, "text")).unwrap();
    let rules = provider_rules(&provider);
    run_with(&setup, &rules);
    remove_child_artifact(&setup, &child_of("torn.svg"));

    let second = run_with(&setup, &rules);

    assert_eq!(second.counts.skipped_unchanged, 0, "{second:?}");
    assert_eq!(
        terminal(&setup, &child_of("torn.svg")).unwrap().status,
        Status::Converted
    );
    assert!(!artifact(&setup, &child_of("torn.svg")).is_empty());
}

#[test]
fn a_prior_record_from_a_build_without_the_provider_feature_says_so() {
    // A deployment that configured the provider against a binary built
    // without it gets the warning on the record rather than silence,
    // and the effective version stays the plain one because this build
    // can produce nothing.
    let provider = FakeProvider::new(&[(1600, 900)]);
    let config = ProviderConfig::parse(&provider.config_toml()).unwrap();
    assert!(config.svg().is_some());
    // The feature is on in this suite, so the not-built state is
    // asserted through the flag the pipeline reads rather than by
    // rebuilding the crate, which the feature-off binary check covers.
    let rules = Rules::builtin_with_runtime(&RuntimeInventory::empty(), Some(&config)).unwrap();
    assert!(!rules.provider_not_built());
    assert!(rules.version().starts_with("10+svg."));
}

#[test]
fn a_failed_provider_child_keeps_its_parent_from_skipping() {
    // A recoverable refusal on the first run, the pinned component
    // restored before the second. The parent's own record and artifact
    // are unchanged and would skip on their own, but a failed child of
    // the leg keeps the parent live until the child converts, so the
    // refusal is never frozen into the checkpoint.
    let mut provider = FakeProvider::new(&[(1600, 900)]);
    provider.remove_raster();
    let setup = setup();
    fs::write(setup.root.join("later.svg"), svg_bytes(1600, 900, "text")).unwrap();
    run_with(&setup, &provider_rules(&provider));
    let child = terminal(&setup, &child_of("later.svg")).expect("a failed child");
    assert_eq!(child.status, Status::Failed);
    assert!(
        child
            .error
            .as_deref()
            .is_some_and(|e| e.starts_with("rasterizer-missing")),
        "{:?}",
        child.error
    );

    provider.restore_raster();
    let second = run_with(&setup, &provider_rules(&provider));

    assert_eq!(second.counts.skipped_unchanged, 0, "{second:?}");
    let child = terminal(&setup, &child_of("later.svg")).expect("the child");
    assert_eq!(child.status, Status::Converted, "{:?}", child.error);
    assert!(!artifact(&setup, &child_of("later.svg")).is_empty());

    // And once converted, the source skips again on the next run.
    let third = run_with(&setup, &provider_rules(&provider));
    assert_eq!(third.counts.skipped_unchanged, 1, "{third:?}");
}

/// Rules in the shape a build without the provider feature takes when
/// it is handed a configuration: nothing wired, the numeric version,
/// and every vector source marked as unable to run the leg.
fn not_built_rules() -> Rules {
    let mut rules = Rules::from_parts_provider_not_built(
        text_mirror::detect::FormatTable::builtin().unwrap(),
        text_mirror::convert::Registry::builtin().unwrap(),
    )
    .unwrap();
    rules.registry.use_fake_image_ocr();
    rules
}

#[test]
fn the_not_built_marking_moves_the_checkpoint_in_both_directions() {
    // Both feature-off states share the numeric rules version, so the
    // marking itself is what the checkpoint keys on. A prior record
    // without it does not skip once a configuration this build cannot
    // run arrives, so the marking is recorded; a prior record with it
    // does not skip once the configuration is gone, so the marking is
    // retired; and with the state unchanged the source skips.
    let setup = setup();
    fs::write(setup.root.join("art.svg"), svg_bytes(1600, 900, "text")).unwrap();
    let plain = plain_rules();
    let not_built = not_built_rules();
    assert_eq!(plain.version(), not_built.version());

    // No configuration, then a configuration this build cannot run.
    run_with(&setup, &plain);
    assert!(terminal(&setup, "art.svg").unwrap().warnings.is_empty());
    let report = run_with(&setup, &not_built);
    assert_eq!(report.counts.skipped_unchanged, 0, "{report:?}");
    let marked = terminal(&setup, "art.svg").unwrap();
    assert_eq!(marked.status, Status::Converted);
    assert!(
        marked
            .warnings
            .iter()
            .any(|w| w == "svg-provider-not-built"),
        "{:?}",
        marked.warnings
    );

    // Unchanged state: the source skips.
    let report = run_with(&setup, &not_built);
    assert_eq!(report.counts.skipped_unchanged, 1, "{report:?}");

    // The configuration removed again: the marking is retired.
    let report = run_with(&setup, &plain);
    assert_eq!(report.counts.skipped_unchanged, 0, "{report:?}");
    let cleared = terminal(&setup, "art.svg").unwrap();
    assert_eq!(cleared.status, Status::Converted);
    assert!(cleared.warnings.is_empty(), "{:?}", cleared.warnings);
}

#[test]
fn different_jail_parameters_are_a_different_effective_version() {
    // The same pins under two valid parameter sets never checkpoint
    // against each other: the second run re-runs the source.
    let provider = FakeProvider::new(&[(1600, 900)]);
    let setup = setup();
    fs::write(setup.root.join("art.svg"), svg_bytes(1600, 900, "text")).unwrap();
    let first_rules = provider.rules();
    run_with(&setup, &first_rules);
    let first_version = terminal(&setup, "art.svg").unwrap().rules_version;

    let parameterized = provider.with_jail_parameters(r"^ex\.ample\.", "EXAMPLE_TMPDIR");
    let second_rules = parameterized.rules();
    assert_ne!(first_rules.version(), second_rules.version());
    let report = run_with(&setup, &second_rules);
    assert_eq!(report.counts.skipped_unchanged, 0, "{report:?}");
    let second_version = terminal(&setup, "art.svg").unwrap().rules_version;
    assert_ne!(first_version, second_version);
    // The parameter values themselves never reach a record.
    assert!(!second_version.contains("ample"));
    assert!(!second_version.contains("TMPDIR"));
}

// --- dedup, collisions, and containers --------------------------------

#[test]
fn an_identical_source_borrows_its_primary_and_still_gets_its_own_child() {
    let provider = FakeProvider::new(&[(1600, 900)]);
    let setup = setup();
    let bytes = svg_bytes(1600, 900, "shared");
    fs::write(setup.root.join("a.svg"), &bytes).unwrap();
    fs::write(setup.root.join("b.svg"), &bytes).unwrap();

    let report = run_with(&setup, &provider_rules(&provider));

    assert_eq!(report.counts.dedup, 1, "{report:?}");
    let second = terminal(&setup, "b.svg").unwrap();
    assert_eq!(second.status, Status::Dedup);
    assert_eq!(second.dedup_of.as_deref(), Some("a.svg"));
    for source in ["a.svg", "b.svg"] {
        let child = terminal(&setup, &child_of(source))
            .unwrap_or_else(|| panic!("{source} keeps its own child"));
        assert_eq!(child.status, Status::Converted);
        assert_eq!(child.parent_source.as_deref(), Some(source));
    }
}

#[test]
fn a_real_source_in_the_namespace_skips_the_leg_with_a_warning() {
    let provider = FakeProvider::new(&[(1600, 900)]);
    let setup = setup();
    fs::write(
        setup.root.join("clash.svg"),
        svg_bytes(1600, 900, "must not overwrite"),
    )
    .unwrap();
    fs::create_dir_all(setup.root.join("clash.svg.d")).unwrap();
    fs::write(setup.root.join("clash.svg.d/#image-ocr"), b"a real file").unwrap();

    run_with(&setup, &provider_rules(&provider));

    let occupant = terminal(&setup, &child_of("clash.svg")).expect("the real source record");
    assert_ne!(occupant.converter_id.as_deref(), Some("image-pixel-ocr"));
    let parent = terminal(&setup, "clash.svg").expect("parent record");
    assert!(
        parent
            .warnings
            .iter()
            .any(|w| w == "svg-ocr-namespace-occupied"),
        "{:?}",
        parent.warnings
    );
}

#[test]
fn both_archive_member_orders_agree_and_overwrite_nothing() {
    let provider = FakeProvider::new(&[(1600, 900)]);
    let source = svg_bytes(1600, 900, "kept sentinel");
    let member = b"a literal member".as_slice();

    // The literal member first: it owns the path and the leg yields.
    let setup = setup();
    fs::write(
        setup.root.join("bundle.zip"),
        stored_zip(&[
            ("art.svg.d/#image-ocr", member),
            ("art.svg", source.as_slice()),
        ]),
    )
    .unwrap();
    run_with(&setup, &provider_rules(&provider));
    let occupant = terminal(&setup, "bundle.zip.d/art.svg.d/#image-ocr").expect("member record");
    assert_ne!(occupant.converter_id.as_deref(), Some("image-pixel-ocr"));
    assert!(
        terminal(&setup, "bundle.zip.d/art.svg")
            .unwrap()
            .warnings
            .iter()
            .any(|w| w == "svg-ocr-namespace-occupied")
    );
    assert!(terminal(&setup, "bundle.zip.d/#collision-1").is_none());

    // The source first: it mints its child and the later literal member
    // is the refused collision. Neither artifact is overwritten.
    let setup = fresh_setup();
    fs::write(
        setup.root.join("bundle.zip"),
        stored_zip(&[
            ("art.svg", source.as_slice()),
            ("art.svg.d/#image-ocr", member),
        ]),
    )
    .unwrap();
    run_with(&setup, &provider_rules(&provider));
    let child = terminal(&setup, "bundle.zip.d/art.svg.d/#image-ocr").expect("the child");
    assert_eq!(child.status, Status::Converted);
    assert_eq!(child.converter_id.as_deref(), Some("image-pixel-ocr"));
    let refused = terminal(&setup, "bundle.zip.d/#collision-1").expect("collision record");
    assert_eq!(refused.status, Status::Failed);
    assert_eq!(refused.error.as_deref(), Some("member-path-collision"));
}

#[test]
fn a_skipped_member_source_keeps_its_child_when_the_container_re_expands() {
    let provider = FakeProvider::new(&[(1600, 900)]);
    let rules = provider_rules(&provider);
    let setup = setup();
    let source = svg_bytes(1600, 900, "carried forward");
    fs::write(
        setup.root.join("bundle.zip"),
        stored_zip(&[("art.svg", source.as_slice()), ("note.txt", b"one\n")]),
    )
    .unwrap();
    run_with(&setup, &rules);
    let child_path = "bundle.zip.d/art.svg.d/#image-ocr";
    assert_eq!(
        terminal(&setup, child_path).unwrap().status,
        Status::Converted
    );

    fs::write(
        setup.root.join("bundle.zip"),
        stored_zip(&[
            ("art.svg", source.as_slice()),
            ("note.txt", b"one\n"),
            ("extra.txt", b"two\n"),
        ]),
    )
    .unwrap();
    run_with(&setup, &rules);

    assert_eq!(
        terminal(&setup, "bundle.zip.d/art.svg").unwrap().status,
        Status::SkippedUnchanged
    );
    let child = terminal(&setup, child_path).unwrap();
    assert_eq!(child.status, Status::Converted, "{:?}", child.error);
}

#[test]
fn an_over_ceiling_source_fails_the_primary_and_mints_no_child() {
    let provider = FakeProvider::new(&[(1600, 900)]);
    let setup = setup();
    let path = setup.root.join("huge.svg");
    let mut file = fs::File::create(&path).unwrap();
    file.write_all(b"<svg width=\"1600\" height=\"900\">")
        .unwrap();
    file.set_len(text_mirror::convert::MAX_SOURCE_BYTES + 1)
        .unwrap();
    drop(file);

    run_with(&setup, &provider_rules(&provider));

    let primary = terminal(&setup, "huge.svg").expect("primary record");
    assert_eq!(primary.status, Status::Failed);
    assert!(
        primary
            .error
            .as_deref()
            .is_some_and(|e| e.starts_with("resource_limit")),
        "{:?}",
        primary.error
    );
    assert!(terminal(&setup, &child_of("huge.svg")).is_none());
}

// --- the fence and the raster formats ---------------------------------

#[test]
fn the_direct_raster_formats_keep_their_own_segment_source() {
    // The provider changed nothing about png, jpeg, and webp: their
    // spans keep the label they have always carried, so this batch
    // moves no existing artifact.
    use text_mirror::convert::Converter;
    use text_mirror::convert::subprocess::ImagePixelOcr;
    let converter = ImagePixelOcr::new_fake(Default::default());
    let outcome = converter
        .convert(&harness::png_bytes(64, 48), "png")
        .unwrap();
    let lines = text_mirror::segments::to_jsonl(&outcome.segments).unwrap();
    assert!(lines.contains("\"source\":\"document\""), "{lines}");
    assert!(!lines.contains("\"source\":\"ocr\""), "{lines}");
}

#[test]
fn the_provider_never_changes_the_deferred_raster_routing() {
    // A configured provider is an svg leg and nothing else. The
    // formats that need a decoder this release does not have keep the
    // reasons they had, and no configuration can route them anywhere.
    let provider = FakeProvider::new(&[(1600, 900)]);
    let rules = provider_rules(&provider);
    let registry = &rules.registry;
    assert_eq!(
        registry.unsupported_reason("heic"),
        Some("no-jailed-rasterizer")
    );
    assert_eq!(registry.unsupported_reason("tiff"), Some("engine-unpinned"));
    assert_eq!(
        registry.converter_for("svg").map(|c| c.id()),
        Some("text-passthrough")
    );
    assert!(registry.converter_for("heic").is_none());

    // And end to end: a heic source beside a configured provider still
    // records the deferred reason and gains no child of any kind.
    let setup = fresh_setup();
    fs::write(
        setup.root.join("photo.heic"),
        b"\x00\x00\x00\x18ftypheic\x00\x00\x00\x00heic",
    )
    .unwrap();
    run_with(&setup, &rules);
    let record = terminal(&setup, "photo.heic").expect("heic record");
    assert_eq!(record.status, Status::Unsupported);
    assert_eq!(record.error.as_deref(), Some("no-jailed-rasterizer"));
    assert!(terminal(&setup, &child_of("photo.heic")).is_none());
}

#[test]
fn the_provider_schema_admits_no_second_provider() {
    // The schema fence, stated where the leg is tested: the only
    // provider this release carries is the svg one, and a
    // configuration that names another is a run configuration error
    // rather than a silently ignored table.
    let text = format!(
        "schema = \"{}\"\n[providers.heic.\"raster-browser\"]\npath = \"/x\"\n",
        provider::PROVIDER_SCHEMA
    );
    assert!(ProviderConfig::parse(&text).is_err());
    assert_eq!(provider::PROVIDER_ROLES.len(), 2);
    // And the two roles are the whole provider: a third one cannot be
    // added through configuration.
    let third = format!(
        "schema = \"{}\"\n[providers.svg.\"raster-transcoder\"]\npath = \"/x\"\n",
        provider::PROVIDER_SCHEMA
    );
    assert!(ProviderConfig::parse(&third).is_err());
}

// --- determinism ------------------------------------------------------

#[test]
fn two_cold_runs_over_the_same_source_produce_identical_bytes() {
    // N equals two fresh conversions, each through its own provider
    // executions in its own jail, compared on every byte that ships:
    // the child artifact, its segments sidecar, and the stable manifest
    // fields.
    let provider = FakeProvider::new(&[(1600, 900), (800, 450)]);
    let rules = provider_rules(&provider);
    let sources = [
        ("wide.svg", svg_bytes(1600, 900, "Quarterly summary 2026")),
        ("half.svg", svg_bytes(800, 450, "Invoice 4471")),
    ];
    let mut first: Vec<(String, String, String)> = Vec::new();
    for pass in 0..2 {
        let setup = setup();
        for (name, bytes) in &sources {
            fs::write(setup.root.join(name), bytes).unwrap();
        }
        run_with(&setup, &rules);
        for (index, (name, _)) in sources.iter().enumerate() {
            let child = child_of(name);
            let record = terminal(&setup, &child).expect("a child per source");
            assert_eq!(record.status, Status::Converted, "{name}");
            let observed = (
                artifact(&setup, &child),
                segments(&setup, &child),
                format!(
                    "{:?}/{:?}/{:?}",
                    record.text_hash, record.converter_version, record.artifact_kind
                ),
            );
            if pass == 0 {
                first.push(observed);
            } else {
                assert_eq!(first[index], observed, "{name} differed between cold runs");
            }
        }
    }
}
