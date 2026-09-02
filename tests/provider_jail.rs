//! Contract tests for the provider jail class.
//!
//! The provider profile is wider than the base one: it grants a
//! subpath closure, service registration, and unscoped device access,
//! because the external components measured need them. Wider is not
//! open, and this file is what holds that line. Every control the
//! narrower classes are held to is re-run here against the widened
//! profile: no egress, no read or write outside the jail, no execution
//! of an undeclared program, no inherited environment, no process left
//! behind at the deadline, and a fresh profile root per execution.
//!
//! The controls run against a synthetic closure, so they are permanent
//! and run everywhere the class exists rather than only where a pinned
//! external installation happens to be. The two tests that need the
//! pinned tuple say so and skip honestly when it is absent.

#![cfg(all(unix, target_os = "macos", feature = "svg-provider"))]

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use text_mirror::runner::jail::{ProviderJail, RuntimeProfile, platform_backend};
use text_mirror::runner::{Limits, Runner, locate_worker};

mod harness;
use harness::{FakeProvider, svg_bytes};

fn worker_path() -> PathBuf {
    locate_worker().expect("the worker binary sits beside the test binary")
}

fn brisk_limits() -> Limits {
    Limits {
        wall_timeout: Duration::from_secs(6),
        max_response_bytes: 4 * 1024 * 1024,
        max_stderr_bytes: 64 * 1024,
        ..Limits::default()
    }
}

/// A runner under the provider class, with a synthetic closure standing
/// in for an installed component tree.
fn provider_runner(provider: &FakeProvider, limits: Limits) -> Runner {
    Runner::with_provider_jail(
        platform_backend().expect("this platform has a jail backend"),
        worker_path(),
        limits,
        vec![
            provider.raster_path().to_path_buf(),
            provider.encoder_path().to_path_buf(),
        ],
        Vec::new(),
        ProviderJail {
            closures: vec![
                provider.raster_path().parent().unwrap().to_path_buf(),
                PathBuf::from("/bin"),
            ],
            service_prefix: Some("^ex\\.ample\\.".to_string()),
            temp_env: None,
        },
    )
}

fn existing_host_file() -> String {
    for candidate in ["/etc/hosts", "/etc/services", "/etc/passwd"] {
        if Path::new(candidate).exists() {
            return candidate.to_string();
        }
    }
    panic!("no known host file exists to prove the read confinement");
}

// --- the escape controls, run against the widened profile -------------

#[test]
fn the_provider_jail_denies_every_egress_path() {
    // The same four-way egress probe the narrower classes pass: an
    // IPv4 connect, an IPv6 connect, a Unix socket connect to a
    // listener the parent holds outside the jail, and a UDP send must
    // each fail before the probe deadline. The provider profile allows
    // socket binding inside its own jail subpath, which is what the
    // measured components need, and this proves that allowance reaches
    // no address family the deny covers.
    let provider = FakeProvider::new(&[(64, 48)]);
    let runner = provider_runner(&provider, brisk_limits());
    runner
        .backend()
        .probe(&runner)
        .expect("the provider jail must deny every egress path");
}

#[test]
fn the_provider_jail_refuses_reads_and_writes_outside_itself() {
    // A real host file the test asserts exists, so a denial is the
    // policy rather than a missing file, and a write to the host temp
    // directory, which the base classes also refuse.
    let provider = FakeProvider::new(&[(64, 48)]);
    let runner = provider_runner(&provider, brisk_limits());
    let host_file = existing_host_file();
    assert!(Path::new(&host_file).exists());
    let response = runner
        .run(
            "harness-escape",
            serde_json::json!({
                "read_path": host_file,
                "list_path": std::env::temp_dir().to_str().unwrap(),
            }),
            &[],
        )
        .expect("the provider jail runs the escape probe");
    let ok = response.ok.expect("harness-escape succeeds");
    let read = ok.get("read").and_then(|v| v.as_str()).unwrap_or_default();
    let write = ok.get("write").and_then(|v| v.as_str()).unwrap_or_default();
    let list = ok.get("list").and_then(|v| v.as_str()).unwrap_or_default();
    assert!(read.contains("denied"), "read escaped: {read}");
    assert!(write.contains("denied"), "write escaped: {write}");
    assert!(list.contains("denied"), "listing escaped: {list}");
}

#[test]
fn the_provider_jail_refuses_an_undeclared_program() {
    // The closure is granted for execution, and nothing else is. A
    // program outside it cannot be spawned even though this profile,
    // unlike the base one, permits spawning at all.
    let provider = FakeProvider::new(&[(64, 48)]);
    let runner = provider_runner(&provider, brisk_limits());
    let response = runner
        .run(
            "harness-survivor",
            serde_json::json!({ "program": "/usr/bin/true" }),
            &[],
        )
        .expect("the provider jail runs the spawn probe");
    let error = response
        .error
        .expect("spawning an undeclared program must fail");
    assert_eq!(error.code, "spawn_failed", "{error:?}");
}

#[test]
fn the_provider_jail_scrubs_the_environment() {
    // The parent clears its environment before the spawn, so no secret
    // the host holds reaches a component. The one tolerated key is the
    // text-encoding hint the platform injects through the sandbox
    // wrapper itself.
    let provider = FakeProvider::new(&[(64, 48)]);
    let runner = provider_runner(&provider, brisk_limits());
    let response = runner
        .run("harness-env", serde_json::json!({}), &[])
        .expect("the provider jail runs the environment probe");
    let ok = response.ok.expect("harness-env succeeds");
    let env = ok.get("env").and_then(|v| v.as_array()).expect("env array");
    const RUNTIME_INJECTED: &[&str] = &["__CF_USER_TEXT_ENCODING"];
    for pair in env {
        let key = pair
            .as_array()
            .and_then(|kv| kv.first())
            .and_then(|k| k.as_str())
            .unwrap_or_default();
        assert!(
            RUNTIME_INJECTED.contains(&key),
            "the provider jail inherited {key:?}"
        );
    }
}

#[test]
fn the_provider_jail_kills_a_hung_component_at_the_deadline() {
    let provider = FakeProvider::new(&[(64, 48)]);
    let runner = provider_runner(
        &provider,
        Limits {
            wall_timeout: Duration::from_millis(1500),
            ..brisk_limits()
        },
    );
    let error = runner
        .run("harness-sleep", serde_json::json!({}), &[])
        .expect_err("a hung component must be killed");
    assert_eq!(error.code, "adapter_timeout", "{error}");
}

#[test]
fn every_provider_execution_gets_a_fresh_working_root() {
    // Two runs, and the second sees nothing the first left behind. The
    // jail is the only writable tree, and it is created per run and
    // discarded with it, which is where a component's profile state
    // lives because no profile flag is ever passed on the command
    // line.
    let provider = FakeProvider::new(&[(64, 48)]);
    let runner = provider_runner(&provider, brisk_limits());
    let planted = "planted-by-the-first-run";
    let first = runner
        .run(
            "harness-escape",
            serde_json::json!({ "read_path": existing_host_file() }),
            &[(planted, b"marker" as &[u8])],
        )
        .expect("first run");
    assert!(first.ok.is_some());
    // The second run reads the same bare name from its own working
    // directory. A shared or reused root would still hold it.
    let second = runner
        .run(
            "harness-escape",
            serde_json::json!({ "read_path": planted }),
            &[],
        )
        .expect("second run");
    let ok = second.ok.expect("harness-escape succeeds");
    let read = ok.get("read").and_then(|v| v.as_str()).unwrap_or_default();
    assert!(
        read.contains("denied"),
        "the second run saw the first run's file: {read}"
    );
}

#[test]
fn the_provider_class_is_refused_without_a_wired_provider() {
    // The class is the authorization and the wired components are the
    // necessity. A runner that names the class with nothing wired
    // cannot render the widened profile, so it refuses rather than
    // running under something narrower or wider than measured.
    let runner = Runner::with_provider_jail(
        platform_backend().unwrap(),
        worker_path(),
        brisk_limits(),
        Vec::new(),
        Vec::new(),
        ProviderJail::default(),
    );
    let error = runner
        .run("harness-echo", serde_json::json!({}), &[])
        .expect_err("an unwired provider class must refuse");
    assert_eq!(error.code, "sandbox_unavailable", "{error}");
}

#[test]
fn the_provider_class_keys_the_capability_probe_on_its_own_parameters() {
    // Two runners identical but for the closure they grant must not
    // share a cached probe pass, or a proof taken under one component
    // tree would stand in for another.
    let provider = FakeProvider::new(&[(64, 48)]);
    let first = provider_runner(&provider, brisk_limits());
    let other = FakeProvider::new(&[(64, 48)]);
    let second = provider_runner(&other, brisk_limits());
    assert_ne!(
        first.policy_digest().unwrap(),
        second.policy_digest().unwrap()
    );
    // And the class itself is part of the key, so a base-class pass can
    // never satisfy the provider class.
    let plain = Runner::with_grants(
        platform_backend().unwrap(),
        worker_path(),
        brisk_limits(),
        vec![provider.raster_path().to_path_buf()],
        Vec::new(),
        RuntimeProfile::Plain,
    );
    assert_ne!(
        first.policy_digest().unwrap(),
        plain.policy_digest().unwrap()
    );
}

// --- the flag that belongs to one argument vector ---------------------

#[test]
fn the_internal_sandbox_flag_appears_in_the_provider_vector_only() {
    // The flag that turns off a component's own internal sandboxing
    // belongs to the provider vector and nowhere else, because the
    // crate's jail is the boundary that is measured and tested. This
    // scans the shipped source for it: exactly one module names it, and
    // no other worker's spawn or argument vector does.
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    let flag = format!("--{}", "no-sandbox");
    let mut naming = Vec::new();
    let mut stack = vec![root.clone()];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let text = fs::read_to_string(&path).unwrap();
            if text.contains(&flag) {
                let relative = path.strip_prefix(&root).unwrap().display().to_string();
                naming.push(relative);
            }
        }
    }
    naming.sort();
    assert_eq!(
        naming,
        vec!["convert/svg_raster.rs".to_string()],
        "{naming:?}"
    );
}

// --- the pinned tuple, when a deployment supplies it ------------------

/// The provider configuration a deployment named through the
/// environment, or `None` when this host has none.
fn pinned_config() -> Option<(String, text_mirror::convert::provider::ProviderConfig)> {
    let path = std::env::var("TEXT_MIRROR_SVG_PROVIDER_CONFIG").ok()?;
    let config = text_mirror::convert::provider::ProviderConfig::load(Path::new(&path))
        .expect("the provider configuration file loads");
    config.svg()?;
    Some((path, config))
}

/// Runs one division with the given rules and returns the mirror root.
fn convert_one(
    rules: &text_mirror::pipeline::Rules,
    sources: &[(&str, Vec<u8>)],
) -> (tempfile::TempDir, PathBuf, PathBuf) {
    use text_mirror::pipeline::{RunOptions, run};
    use text_mirror::walk::WalkOptions;
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("source");
    fs::create_dir_all(&root).unwrap();
    for (name, bytes) in sources {
        fs::write(root.join(name), bytes).unwrap();
    }
    let mirror = dir.path().join("mirror");
    let manifest = dir.path().join("manifest");
    run(
        rules,
        &RunOptions {
            root: &root,
            mirror_root: &mirror,
            manifest_dir: &manifest,
            division: "alpha",
            walk: WalkOptions::default(),
        },
    )
    .unwrap();
    (dir, mirror, manifest)
}

#[test]
fn the_pinned_provider_renders_identically_across_cold_processes() {
    // The determinism gate, run against the real installation when one
    // is configured. Each pass is a fresh conversion whose provider
    // executions are new processes in a new jail, and the child
    // artifact and its sidecar must be byte-identical between them.
    let Some((path, config)) = pinned_config() else {
        eprintln!(
            "skipped: TEXT_MIRROR_SVG_PROVIDER_CONFIG is not set, no pinned provider on this host"
        );
        return;
    };
    eprintln!("running the pinned provider from {path}");
    let mut rules = text_mirror::pipeline::Rules::builtin_with_runtime(
        &text_mirror::convert::RuntimeInventory::empty(),
        Some(&config),
    )
    .unwrap();
    rules.registry.use_fake_image_ocr();
    let sources = vec![
        ("wide.svg", svg_bytes(1600, 900, "Quarterly summary 2026")),
        ("square.svg", svg_bytes(900, 900, "Invoice 4471")),
    ];
    let mut first: Vec<(String, String)> = Vec::new();
    for pass in 0..2 {
        let (_dir, mirror, _manifest) = convert_one(&rules, &sources);
        for (index, (name, _)) in sources.iter().enumerate() {
            let child = format!("alpha/{name}.d/#image-ocr");
            let text = fs::read_to_string(mirror.join(format!("{child}.txt")))
                .unwrap_or_else(|e| panic!("{name}: {e}"));
            let sidecar =
                fs::read_to_string(mirror.join(format!("{child}.segments.jsonl"))).unwrap();
            if pass == 0 {
                first.push((text, sidecar));
            } else {
                assert_eq!(first[index], (text, sidecar), "{name} differed");
            }
        }
    }
}

#[test]
fn a_substituted_pinned_component_is_refused_by_its_hash() {
    // The fence: with the real configuration in hand, plant one fault
    // at a time and the leg must refuse on the hash before it runs
    // anything. Three plantings per role: a different file at the
    // configured path, a rules pin that no longer matches the file, and
    // a real, current installation of the same product standing where
    // the pinned one should be, which is the drift this pin exists to
    // catch.
    let Some((_, config)) = pinned_config() else {
        eprintln!(
            "skipped: TEXT_MIRROR_SVG_PROVIDER_CONFIG is not set, no pinned provider on this host"
        );
        return;
    };
    let svg = config.svg().expect("a complete provider");
    let dir = tempfile::tempdir().unwrap();
    let substitute = dir.path().join("substitute");
    fs::write(&substitute, b"#!/bin/sh\nexit 0\n").unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = fs::metadata(&substitute).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&substitute, permissions).unwrap();
    }
    // Canonicalized, so the literal jail grant names the file the
    // worker will actually open: an uncanonicalized path would be
    // refused for being unreadable, which is a different control.
    let substitute = substitute.canonicalize().unwrap();
    let raster_role = text_mirror::convert::provider::PROVIDER_ROLE_RASTER;
    let encoder_role = text_mirror::convert::provider::PROVIDER_ROLE_ENCODER;
    // A different build of the same product, installed on this host
    // outside the pinned copy. It runs, it is the right kind of thing,
    // and it is not what the rules pin, so it must be refused.
    let live = std::env::var("TEXT_MIRROR_SVG_PROVIDER_LIVE_SUBSTITUTE")
        .ok()
        .map(PathBuf::from)
        .filter(|path| path.is_file());

    let mut plantings: Vec<(&str, &str, Option<PathBuf>)> = vec![
        (raster_role, "substituted file", Some(substitute.clone())),
        (raster_role, "repinned rules", None),
        (encoder_role, "substituted file", Some(substitute.clone())),
        (encoder_role, "repinned rules", None),
    ];
    if let Some(live) = &live {
        plantings.push((raster_role, "live installation", Some(live.clone())));
    } else {
        eprintln!(
            "note: TEXT_MIRROR_SVG_PROVIDER_LIVE_SUBSTITUTE is unset, the live-installation planting is not exercised"
        );
    }

    for (planted_role, planting, swap_to) in plantings {
        let role_block = |label: &str, role: &text_mirror::convert::provider::ProviderRole| {
            let path = match (&swap_to, label == planted_role) {
                (Some(swap), true) => swap.display().to_string(),
                _ => role.path.display().to_string(),
            };
            // The closure and the jail parameters travel unchanged, so
            // the only difference from a working configuration is the
            // planted fault.
            let closure = match &role.closure_root {
                Some(root) => format!("closure_root = \"{}\"\n", root.display()),
                None => String::new(),
            };
            let mut jail = String::new();
            if let Some(prefix) = &role.jail_service_prefix {
                jail.push_str(&format!(
                    "jail_service_prefix = \"{}\"\n",
                    prefix.replace('\\', "\\\\")
                ));
            }
            if let Some(env) = &role.jail_temp_env {
                jail.push_str(&format!("jail_temp_env = \"{env}\"\n"));
            }
            format!("[providers.svg.\"{label}\"]\npath = \"{path}\"\n{closure}{jail}\n")
        };
        let text = format!(
            "schema = \"{}\"\n\n{}{}",
            text_mirror::convert::provider::PROVIDER_SCHEMA,
            role_block(raster_role, &svg.raster),
            role_block(encoder_role, &svg.encoder),
        );
        let config = text_mirror::convert::provider::ProviderConfig::parse(&text).unwrap();
        // The rules: shipped as they are, or with this role's pin
        // moved off the file it names.
        let rules_text = fs::read_to_string(
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rules/converters.toml"),
        )
        .unwrap();
        let rules_text = if swap_to.is_none() {
            let section = format!("[image_ocr.svg_provider.\"{planted_role}\"]\nblake3 = \"");
            let at = rules_text.find(&section).expect("the role is pinned") + section.len();
            let end = at + 64;
            format!(
                "{}{}{}",
                &rules_text[..at],
                "0".repeat(64),
                &rules_text[end..]
            )
        } else {
            rules_text
        };
        let registry = text_mirror::convert::Registry::parse_with_runtime(
            &rules_text,
            "converters.toml",
            &text_mirror::convert::RuntimeInventory::empty(),
            Some(&config),
        )
        .unwrap();
        let mut rules = text_mirror::pipeline::Rules::from_parts_with_runtime(
            text_mirror::detect::FormatTable::builtin().unwrap(),
            registry,
            Some(&config),
        )
        .unwrap();
        rules.registry.use_fake_image_ocr();
        let label = format!("{planted_role}/{planting}");
        let (_dir, mirror, manifest) =
            convert_one(&rules, &[("doc.svg", svg_bytes(1600, 900, "text"))]);
        let child = text_mirror::manifest::read_shard(&manifest.join("alpha.jsonl"))
            .unwrap()
            .records
            .into_iter()
            .rev()
            .find(|record| record.source_path == "doc.svg.d/#image-ocr")
            .unwrap_or_else(|| panic!("{label}: a failed child"));
        assert_eq!(
            child.status,
            text_mirror::manifest::Status::Failed,
            "{label}"
        );
        assert!(
            child
                .error
                .as_deref()
                .is_some_and(|e| e.starts_with("rasterizer-hash-drift")),
            "{label}: {:?}",
            child.error
        );
        assert!(child.text_path.is_none(), "{label}");
        assert!(
            !mirror.join("alpha/doc.svg.d/#image-ocr.txt").exists(),
            "{label}"
        );
    }
}
