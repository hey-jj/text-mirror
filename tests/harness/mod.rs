//! Shared fixtures for the provider tests: synthetic vector sources and
//! a synthetic provider whose two components are small programs the
//! test writes, pins by hash and version, and runs through the real
//! provider jail.
//!
//! Nothing here stands in for the pinned external tuple. It stands in
//! for a deployment: the configuration shape, the per-exec assertions,
//! the jail class, and the argument vectors are the production ones,
//! and only the programs at the end of them are the test's own. The
//! pinned tuple's own behavior is covered by the environment-gated
//! suite instead.

#![allow(dead_code)]

use std::fs;
use std::path::{Path, PathBuf};

use image::{ExtendedColorType, ImageEncoder, RgbImage};

/// A synthetic vector source of a declared size carrying visible text.
pub fn svg_bytes(width: u32, height: u32, text: &str) -> Vec<u8> {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <svg xmlns=\"http://www.w3.org/2000/svg\" width=\"{width}\" height=\"{height}\" \
         viewBox=\"0 0 {width} {height}\">\n\
         <rect width=\"{width}\" height=\"{height}\" fill=\"none\"/>\n\
         <text x=\"40\" y=\"120\" font-size=\"48\">{text}</text>\n\
         </svg>\n"
    )
    .into_bytes()
}

/// A deterministic raster fixture: a gradient, so the bytes are a real
/// image rather than a solid block.
pub fn png_bytes(width: u32, height: u32) -> Vec<u8> {
    let image = RgbImage::from_fn(width, height, |x, y| {
        image::Rgb([(x % 256) as u8, (y % 256) as u8, 128])
    });
    let mut out = Vec::new();
    image::codecs::png::PngEncoder::new(&mut out)
        .write_image(image.as_raw(), width, height, ExtendedColorType::Rgb8)
        .unwrap();
    out
}

/// The version each synthetic component reports.
const RASTER_VERSION: &str = "3.1.4";
const ENCODER_VERSION: &str = "9.9.9";

/// A synthetic provider: two executable programs, their raster
/// fixtures, and the pins a deployment would write down for them.
pub struct FakeProvider {
    dir: tempfile::TempDir,
    raster: PathBuf,
    encoder: PathBuf,
    /// The pins as configured. They are taken once, at construction, so
    /// a later change to a program on disk is drift exactly as a
    /// substituted executable would be.
    raster_blake3: String,
    encoder_blake3: String,
    closure_blake3: String,
    raster_version: String,
    encoder_version: String,
    raster_present: bool,
    encoder_present: bool,
}

fn write_program(path: &Path, body: &str) {
    fs::write(path, body).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = fs::metadata(path).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(path, permissions).unwrap();
    }
}

/// The aggregate closure digest over a directory, computed the way the
/// worker computes it: every executable file except the launcher, by
/// sorted relative path and content hash.
fn closure_digest(root: &Path, launcher: &Path) -> String {
    let mut rows: Vec<(Vec<u8>, PathBuf)> = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            let metadata = fs::symlink_metadata(&path).unwrap();
            if metadata.file_type().is_symlink() {
                continue;
            }
            if metadata.is_dir() {
                stack.push(path);
                continue;
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if metadata.permissions().mode() & 0o111 == 0 {
                    continue;
                }
            }
            if path == launcher {
                continue;
            }
            let relative = path
                .strip_prefix(root)
                .unwrap()
                .as_os_str()
                .as_encoded_bytes()
                .to_vec();
            rows.push((relative, path));
        }
    }
    rows.sort();
    let mut hasher = blake3::Hasher::new();
    for (relative, path) in rows {
        let hash = text_mirror::hash::hash_file(&path).unwrap();
        hasher.update(&relative);
        hasher.update(b"\n");
        hasher.update(hash.as_bytes());
        hasher.update(b"\n");
    }
    hasher.finalize().to_hex().to_string()
}

impl FakeProvider {
    /// A working provider with a raster fixture for each named size.
    pub fn new(sizes: &[(u32, u32)]) -> FakeProvider {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        for (width, height) in sizes {
            fs::write(
                // Named by the window the rasterizer is given, which
                // is the comma form its argument carries.
                root.join(format!("raw-{width},{height}.png")),
                png_bytes(*width, *height),
            )
            .unwrap();
        }
        let raster = root.join("raster");
        let encoder = root.join("encoder");
        write_program(&raster, &Self::raster_body(&root, "render"));
        write_program(&encoder, &Self::encoder_body(&root, "copy"));
        FakeProvider {
            raster_blake3: text_mirror::hash::hash_file(&raster).unwrap(),
            encoder_blake3: text_mirror::hash::hash_file(&encoder).unwrap(),
            closure_blake3: closure_digest(&root, &raster),
            raster_version: RASTER_VERSION.to_string(),
            encoder_version: ENCODER_VERSION.to_string(),
            raster_present: true,
            encoder_present: true,
            raster,
            encoder,
            dir,
        }
    }

    fn dir_root(&self) -> PathBuf {
        self.dir.path().canonicalize().unwrap()
    }

    /// The rasterizer program. It answers the version check, then
    /// copies the fixture named by the window it was given, so a window
    /// that does not match the source's declared size finds no fixture
    /// and fails.
    fn raster_body(_root: &Path, mode: &str) -> String {
        // The program finds its own fixtures relative to itself, so a
        // copy installed elsewhere is byte-identical to this one and
        // pins to the same hash, exactly as a real installation does.
        let render = match mode {
            "render" => "cp \"${0%/*}/raw-$size.png\" \"$out\" || exit 9\n".to_string(),
            "square" => "cp \"${0%/*}/raw-900,900.png\" \"$out\" || exit 9\n".to_string(),
            "garbage" => "printf 'not a raster at all' > \"$out\"\n".to_string(),
            "nothing" => String::new(),
            "fail" => "exit 3\n".to_string(),
            other => panic!("unknown rasterizer mode {other}"),
        };
        format!(
            "#!/bin/sh\n\
             size=\"\"\n\
             out=\"\"\n\
             for a in \"$@\"; do\n\
             \x20 case \"$a\" in\n\
             \x20   --version) echo \"synthetic rasterizer {RASTER_VERSION}\"; exit 0;;\n\
             \x20   --window-size=*) size=${{a#--window-size=}};;\n\
             \x20   --screenshot=*) out=${{a#--screenshot=}};;\n\
             \x20 esac\n\
             done\n\
             [ -n \"$out\" ] || exit 8\n\
             {render}exit 0\n"
        )
    }

    /// The encoder program. It answers the version check, then writes
    /// its last argument from its first, which keeps the dimensions the
    /// geometry assertion already accepted.
    fn encoder_body(_root: &Path, mode: &str) -> String {
        let body = match mode {
            "copy" => "cp \"$in\" \"$out\" || exit 9\n".to_string(),
            "resize" => "cp \"${0%/*}/raw-800,450.png\" \"$out\" || exit 9\n".to_string(),
            "fail" => "exit 4\n".to_string(),
            other => panic!("unknown encoder mode {other}"),
        };
        format!(
            "#!/bin/sh\n\
             case \"$1\" in --version) echo \"synthetic encoder {ENCODER_VERSION}\"; exit 0;; esac\n\
             in=\"$1\"\n\
             eval out=\\${{$#}}\n\
             {body}exit 0\n"
        )
    }

    /// The configuration a deployment would write for this provider:
    /// paths and jail parameters only. The expectations live in the
    /// rules text below, exactly as a real deployment's do.
    ///
    /// The rasterizer's closure is its own directory; the encoder's is
    /// the system program directory its interpreter and helpers live in,
    /// which the rules pin by version rather than by aggregate digest.
    pub fn config_toml(&self) -> String {
        let schema = text_mirror::convert::provider::PROVIDER_SCHEMA;
        let raster_role = text_mirror::convert::provider::PROVIDER_ROLE_RASTER;
        let encoder_role = text_mirror::convert::provider::PROVIDER_ROLE_ENCODER;
        let root = self.dir_root();
        format!(
            "schema = \"{schema}\"\n\n\
             [providers.svg.\"{raster_role}\"]\n\
             path = \"{raster}\"\n\
             closure_root = \"{root}\"\n\n\
             [providers.svg.\"{encoder_role}\"]\n\
             path = \"{encoder}\"\n\
             closure_root = \"/bin\"\n",
            raster = self.raster.display(),
            root = root.display(),
            encoder = self.encoder.display(),
        )
    }

    /// The versioned rules with this provider's expectations pinned in
    /// place of the shipped ones: the built-in converters file up to
    /// its provider section, then this provider's pins.
    pub fn rules_text(&self) -> String {
        let shipped = fs::read_to_string(
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rules/converters.toml"),
        )
        .unwrap();
        let marker = "[image_ocr.svg_provider.";
        let head = &shipped[..shipped
            .find(marker)
            .expect("the shipped rules pin a provider")];
        let raster_role = text_mirror::convert::provider::PROVIDER_ROLE_RASTER;
        let encoder_role = text_mirror::convert::provider::PROVIDER_ROLE_ENCODER;
        format!(
            "{head}[image_ocr.svg_provider.\"{raster_role}\"]\n\
             blake3 = \"{raster_hash}\"\n\
             version = \"{raster_version}\"\n\
             closure_blake3 = \"{closure}\"\n\n\
             [image_ocr.svg_provider.\"{encoder_role}\"]\n\
             blake3 = \"{encoder_hash}\"\n\
             version = \"{encoder_version}\"\n",
            raster_hash = self.raster_blake3,
            raster_version = self.raster_version,
            closure = self.closure_blake3,
            encoder_hash = self.encoder_blake3,
            encoder_version = self.encoder_version,
        )
    }

    /// Rules over this provider's pins with the provider configured and
    /// the recognition stage faked, so the provider half runs for real
    /// and the engine half is deterministic.
    pub fn rules(&self) -> text_mirror::pipeline::Rules {
        let config =
            text_mirror::convert::provider::ProviderConfig::parse(&self.config_toml()).unwrap();
        let registry = text_mirror::convert::Registry::parse_with_runtime(
            &self.rules_text(),
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
        rules
    }

    /// The same provider installed somewhere else: identical programs
    /// and identical pins under different absolute paths.
    pub fn moved(&self) -> FakeProvider {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        for entry in fs::read_dir(self.dir_root()).unwrap() {
            let path = entry.unwrap().path();
            let target = root.join(path.file_name().unwrap());
            fs::copy(&path, &target).unwrap();
        }
        let raster = root.join("raster");
        let encoder = root.join("encoder");
        // The programs name their own directory, so a moved copy is
        // re-written for its new home and re-pinned there. The pins
        // that matter for the version test, the closure digest and the
        // versions, are recomputed the same way a deployment would.
        write_program(&raster, &Self::raster_body(&root, "render"));
        write_program(&encoder, &Self::encoder_body(&root, "copy"));
        FakeProvider {
            raster_blake3: text_mirror::hash::hash_file(&raster).unwrap(),
            encoder_blake3: text_mirror::hash::hash_file(&encoder).unwrap(),
            closure_blake3: closure_digest(&root, &raster),
            raster_version: RASTER_VERSION.to_string(),
            encoder_version: ENCODER_VERSION.to_string(),
            raster_present: true,
            encoder_present: true,
            raster,
            encoder,
            dir,
        }
    }

    /// The rasterizer's configured path, for the tests that plant a
    /// fault at it directly.
    pub fn raster_path(&self) -> &Path {
        &self.raster
    }

    /// The encoder's configured path.
    pub fn encoder_path(&self) -> &Path {
        &self.encoder
    }

    // --- planted faults ----------------------------------------------

    /// The configured executable is gone.
    pub fn remove_raster(&mut self) {
        fs::remove_file(&self.raster).unwrap();
        self.raster_present = false;
    }

    /// A different program stands at the configured path.
    pub fn substitute_raster(&mut self) {
        write_program(&self.raster, "#!/bin/sh\nexit 0\n");
    }

    /// A helper beside the launcher drifts while the launcher itself
    /// stands still, which is what the aggregate digest exists to see.
    pub fn drift_closure(&mut self) {
        write_program(&self.dir_root().join("helper"), "#!/bin/sh\nexit 0\n");
    }

    /// The configuration pins a version the executable does not report.
    pub fn pin_wrong_version(&mut self) {
        self.raster_version = "0.0.1".to_string();
    }

    pub fn raster_exits_nonzero(&mut self) {
        self.rewrite_raster("fail");
    }

    pub fn raster_writes_nothing(&mut self) {
        self.rewrite_raster("nothing");
    }

    pub fn raster_writes_garbage(&mut self) {
        self.rewrite_raster("garbage");
    }

    pub fn raster_writes_square(&mut self) {
        self.rewrite_raster("square");
    }

    pub fn remove_encoder(&mut self) {
        fs::remove_file(&self.encoder).unwrap();
        self.encoder_present = false;
    }

    pub fn substitute_encoder(&mut self) {
        write_program(&self.encoder, "#!/bin/sh\nexit 0\n");
    }

    pub fn encoder_exits_nonzero(&mut self) {
        self.rewrite_encoder("fail");
    }

    pub fn encoder_resizes(&mut self) {
        self.rewrite_encoder("resize");
    }

    /// Rewrites the rasterizer and re-pins it, so the planted fault is
    /// in its behavior rather than in its hash.
    fn rewrite_raster(&mut self, mode: &str) {
        let root = self.dir_root();
        write_program(&self.raster, &Self::raster_body(&root, mode));
        self.raster_blake3 = text_mirror::hash::hash_file(&self.raster).unwrap();
        self.closure_blake3 = closure_digest(&root, &self.raster);
    }

    /// Rewrites the encoder and re-pins it, including the closure
    /// digest, which covers the encoder because it sits beside the
    /// rasterizer in the same directory.
    fn rewrite_encoder(&mut self, mode: &str) {
        let root = self.dir_root();
        write_program(&self.encoder, &Self::encoder_body(&root, mode));
        self.encoder_blake3 = text_mirror::hash::hash_file(&self.encoder).unwrap();
        self.closure_blake3 = closure_digest(&root, &self.raster);
    }
}
