//! The in-jail svg raster path, run only inside the provider sandbox.
//!
//! A vector source has no pixels of its own, so the pixel leg needs an
//! external renderer. This module is the whole of that leg, and every
//! line of it runs inside the jailed worker:
//!
//! 1. GEOMETRY. The source's declared root size, or its view box, is
//!    parsed by a small explicit scanner over the root element alone.
//!    Percent-only and otherwise unresolved geometry fails closed here,
//!    before any host default viewport can decide the output size.
//! 2. RASTERIZER VERIFICATION. The configured executable must be
//!    present as a regular file, re-hash to its pinned BLAKE3 in this
//!    cold worker, report exactly its pinned version, and, when the
//!    deployment pinned one, match the aggregate digest over its whole
//!    enumerated closure. The closure digest is the integrity control
//!    that stands in for a finer jail grant: helper and framework
//!    binaries are readable as a subpath, so the digest is what proves
//!    they are the validated ones.
//! 3. RASTERIZE. A fixed argument vector, derived from the geometry and
//!    the jail paths and nothing else, renders the source to a raster
//!    in a fresh profile root that dies with the jail.
//! 4. GEOMETRY ASSERTION. The output aspect must match the source on
//!    both cross-axis checks within one pixel, then the decoded area
//!    must sit under the encoder-input cap.
//! 5. ENCODER VERIFICATION and FLATTEN. The same presence, hash, and
//!    version assertions run again immediately before the flatten, and
//!    the flattened raster must keep the raw dimensions.
//!
//! Every failure carries a static reason naming a generic role label.
//! No path, product name, version output, or host identity reaches a
//! record: the executables' own output is read for the version
//! comparison and discarded inside this module.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::convert::provider::{
    PROVIDER_FLATTEN_ARGS, PROVIDER_GEOMETRY_TOLERANCE_PX, PROVIDER_ROLE_ENCODER,
    PROVIDER_ROLE_RASTER,
};
use crate::runner::protocol::bodies::{SvgRasterOk, SvgRasterRequest, SvgRoleEntry};

/// The bytes of the source read for geometry: the root element sits at
/// the front of any well-formed document, so the scanner never walks
/// the whole file.
const GEOMETRY_SCAN_BYTES: usize = 64 * 1024;

/// The largest window either axis may take. The area cap is the real
/// bound; this only keeps an absurd declared size from reaching the
/// renderer's command line at all.
const MAX_WINDOW_PX: i64 = 20_000;

/// The staged source name inside the jail.
pub(crate) const JAIL_SOURCE: &str = "doc.svg";

/// The raw raster the rasterizer writes inside the jail.
pub(crate) const JAIL_RAW: &str = "raw.png";

/// The flattened raster the encoder writes inside the jail.
pub(crate) const JAIL_FLAT: &str = "flat.png";

/// A provider failure with a stable reason code. The message names a
/// generic role label and nothing else.
#[derive(Debug)]
pub(crate) struct SvgRasterError {
    /// Stable reason, such as `rasterizer-hash-drift`.
    pub code: &'static str,
    /// Detail for a human reading the manifest.
    pub message: String,
}

impl SvgRasterError {
    fn new(code: &'static str, message: impl Into<String>) -> SvgRasterError {
        SvgRasterError {
            code,
            message: message.into(),
        }
    }
}

/// The declared source geometry, in pixels.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct Geometry {
    pub(crate) width: f64,
    pub(crate) height: f64,
}

impl Geometry {
    /// The integer window the renderer is given: the declared size at
    /// device scale factor 1, so the render fits rather than crops.
    fn window(self) -> Result<(i64, i64), SvgRasterError> {
        let round = |value: f64| -> Result<i64, SvgRasterError> {
            let rounded = value.round();
            if !rounded.is_finite() || rounded < 1.0 || rounded > MAX_WINDOW_PX as f64 {
                return Err(SvgRasterError::new(
                    "raster-geometry-mismatch",
                    "the declared source geometry is outside the renderable range",
                ));
            }
            Ok(rounded as i64)
        };
        Ok((round(self.width)?, round(self.height)?))
    }
}

/// Converts one CSS absolute length to pixels. Unit handling is
/// explicit and closed: the absolute units convert by their fixed
/// ratios to the 96-per-inch reference pixel, and everything else,
/// percentages and font- and viewport-relative units above all, is
/// unresolved and fails closed rather than resolving against a host
/// default.
fn length_to_px(raw: &str) -> Option<f64> {
    let text = raw.trim();
    let (number, unit) = match text.find(|c: char| c.is_ascii_alphabetic() || c == '%') {
        Some(index) => (&text[..index], text[index..].trim()),
        None => (text, ""),
    };
    let value: f64 = number.trim().parse().ok()?;
    if !value.is_finite() || value <= 0.0 {
        return None;
    }
    let ratio = match unit.to_ascii_lowercase().as_str() {
        "" | "px" => 1.0,
        "pt" => 96.0 / 72.0,
        "pc" => 16.0,
        "in" => 96.0,
        "cm" => 96.0 / 2.54,
        "mm" => 96.0 / 25.4,
        "q" => 96.0 / 101.6,
        // Percentages and relative units resolve only against a
        // containing block or a font this leg deliberately has none of.
        _ => return None,
    };
    Some(value * ratio)
}

/// Parses the declared geometry of one source: the root width and
/// height when both resolve, else the view box's own width and height.
/// Anything else is unresolved and fails closed.
///
/// The root element is found by the crate's bounded XML tokenizer, not
/// by a byte search: the first start element is the root, its local
/// name must be `svg`, and only its own attributes are read. A comment,
/// a doctype subset, a CDATA section, or a processing instruction that
/// happens to contain `<svg` before the real root therefore cannot
/// supply a false geometry for the assertion to validate against
/// itself, which is the silent-crop class the pin exists to refuse.
pub(crate) fn parse_geometry(source: &[u8]) -> Result<Geometry, SvgRasterError> {
    use quick_xml::events::Event;
    let unresolved = || {
        SvgRasterError::new(
            "raster-geometry-mismatch",
            "the source declares no resolvable root geometry",
        )
    };
    let head = &source[..source.len().min(GEOMETRY_SCAN_BYTES)];
    let mut reader = quick_xml::Reader::from_reader(head);
    let mut buffer = Vec::new();
    let mut width = None;
    let mut height = None;
    let mut view_box = None;
    loop {
        match reader.read_event_into(&mut buffer) {
            Ok(Event::Start(start)) | Ok(Event::Empty(start)) => {
                if start.local_name().as_ref() != b"svg" {
                    return Err(unresolved());
                }
                for attribute in start.attributes().flatten() {
                    let key = attribute.key.local_name();
                    let value = match std::str::from_utf8(&attribute.value) {
                        Ok(value) => value.to_string(),
                        Err(_) => continue,
                    };
                    match key.as_ref() {
                        b"width" => width = Some(value),
                        b"height" => height = Some(value),
                        b"viewBox" => view_box = Some(value),
                        _ => {}
                    }
                }
                break;
            }
            // Everything before the root is skipped: declarations,
            // comments, doctypes, processing instructions, text. None
            // of it can carry the geometry.
            Ok(Event::Eof) | Err(_) => return Err(unresolved()),
            Ok(_) => {}
        }
        buffer.clear();
    }
    if let (Some(width), Some(height)) = (&width, &height)
        && let (Some(width), Some(height)) = (length_to_px(width), length_to_px(height))
    {
        return Ok(Geometry { width, height });
    }
    let view_box = view_box.ok_or_else(unresolved)?;
    let numbers: Vec<f64> = view_box
        .split(|c: char| c.is_ascii_whitespace() || c == ',')
        .filter(|part| !part.is_empty())
        .filter_map(|part| part.parse::<f64>().ok())
        .collect();
    if numbers.len() != 4 {
        return Err(unresolved());
    }
    let (width, height) = (numbers[2], numbers[3]);
    if !width.is_finite() || !height.is_finite() || width <= 0.0 || height <= 0.0 {
        return Err(unresolved());
    }
    Ok(Geometry { width, height })
}

/// The two cross-axis checks: the output's height at its own width and
/// its width at its own height must both land within the tolerance of
/// the source aspect. One check alone passes a crop on the other axis.
pub(crate) fn assert_geometry(
    source: Geometry,
    out_width: u32,
    out_height: u32,
) -> Result<(), SvgRasterError> {
    let mismatch = || {
        SvgRasterError::new(
            "raster-geometry-mismatch",
            "the rendered raster does not preserve the declared source aspect",
        )
    };
    if out_width == 0 || out_height == 0 {
        return Err(mismatch());
    }
    let (ow, oh) = (f64::from(out_width), f64::from(out_height));
    let expected_height = (ow * source.height / source.width).round();
    let expected_width = (oh * source.width / source.height).round();
    if !expected_height.is_finite() || !expected_width.is_finite() {
        return Err(mismatch());
    }
    let tolerance = PROVIDER_GEOMETRY_TOLERANCE_PX as f64;
    if (expected_height - oh).abs() > tolerance || (expected_width - ow).abs() > tolerance {
        return Err(mismatch());
    }
    Ok(())
}

/// The pinned rasterizer argument vector.
///
/// Every element is fixed. Only the window, derived from the declared
/// source geometry, and the two jail paths are substituted, and the
/// final element is the flag that turns off the renderer's own internal
/// sandboxing. That flag belongs here and only here: the crate's jail
/// is the outer boundary, and the renderer's helpers cannot install
/// their own sandbox inside a restrictive one, so the two are mutually
/// exclusive on this platform and the outer jail is the one that is
/// measured, tested, and enforced.
pub(crate) fn raster_argv(width: i64, height: i64, output: &Path, input: &Path) -> Vec<String> {
    vec![
        "--headless=new".to_string(),
        "--disable-gpu".to_string(),
        "--hide-scrollbars".to_string(),
        format!("--window-size={width},{height}"),
        "--force-device-scale-factor=1".to_string(),
        "--disable-background-networking".to_string(),
        "--disable-component-update".to_string(),
        "--disable-domain-reliability".to_string(),
        "--disable-sync".to_string(),
        "--no-first-run".to_string(),
        "--no-default-browser-check".to_string(),
        "--metrics-recording-only".to_string(),
        "--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE localhost".to_string(),
        format!("--screenshot={}", output.display()),
        format!("file://{}", input.display()),
        "--no-sandbox".to_string(),
    ]
}

/// The flatten argument vector: the input, the settled ordered options,
/// and the output.
pub(crate) fn flatten_argv(input: &Path, output: &Path) -> Vec<String> {
    let mut argv = vec![input.display().to_string()];
    argv.extend(PROVIDER_FLATTEN_ARGS.iter().map(|arg| (*arg).to_string()));
    argv.push(output.display().to_string());
    argv
}

/// The aggregate closure digest over one enumerated closure.
///
/// Each entry is digested on its own: a directory by the sorted
/// relative path and BLAKE3 of every regular file beneath it, with a
/// symlink covered by its relative path and the target it names, a
/// single file by its own name and BLAKE3, with the pinned launcher
/// excluded because it is verified separately. Every regular file is
/// covered, not only the executables, because a component's policy,
/// module registry, and resource files decide its behavior as much as
/// its code does, and the digest is the integrity control over
/// everything the grant makes reachable. The per-entry digests
/// are then sorted and combined, so the value depends on the contents
/// of the closure and not on where it is installed or the order it was
/// written down in.
///
/// The walk is bounded by a file count, so a closure entry pointed at
/// an unexpectedly large tree refuses rather than hashing without end.
pub(crate) fn closure_digest(roots: &[PathBuf], launcher: &Path) -> Result<String, SvgRasterError> {
    let mut digests: Vec<String> = Vec::new();
    for root in roots {
        digests.push(entry_digest(root, launcher)?);
    }
    digests.sort();
    let mut hasher = blake3::Hasher::new();
    for digest in digests {
        hasher.update(digest.as_bytes());
        hasher.update(b"\n");
    }
    Ok(hasher.finalize().to_hex().to_string())
}

/// One closure entry's digest.
fn entry_digest(root: &Path, launcher: &Path) -> Result<String, SvgRasterError> {
    const MAX_CLOSURE_FILES: usize = 4096;
    let unreadable = |detail: &'static str| SvgRasterError::new("rasterizer-hash-drift", detail);
    let metadata = std::fs::symlink_metadata(root)
        .map_err(|_| unreadable("a runtime closure entry cannot be read"))?;
    let mut rows: Vec<(Vec<u8>, ClosureMember)> = Vec::new();
    let name = root
        .file_name()
        .ok_or_else(|| unreadable("a runtime closure entry has no name"))?;
    if metadata.file_type().is_symlink() {
        // An entry must be a real directory or a real regular file.
        // A link entry would be followed by the walk while the grant
        // names the link, so it is refused here as it is at
        // configuration, and never digested.
        return Err(unreadable("a runtime closure entry is a symlink"));
    } else if metadata.is_file() {
        // A single-file entry is named by its own file name, so the
        // digest survives the installation moving.
        rows.push((
            name.as_encoded_bytes().to_vec(),
            ClosureMember::File(root.to_path_buf()),
        ));
    } else {
        let mut stack = vec![root.to_path_buf()];
        while let Some(dir) = stack.pop() {
            let entries = std::fs::read_dir(&dir)
                .map_err(|_| unreadable("the runtime closure cannot be enumerated"))?;
            for entry in entries {
                let entry =
                    entry.map_err(|_| unreadable("the runtime closure cannot be enumerated"))?;
                let path = entry.path();
                let metadata = std::fs::symlink_metadata(&path)
                    .map_err(|_| unreadable("the runtime closure cannot be enumerated"))?;
                let kind = metadata.file_type();
                if kind.is_dir() {
                    stack.push(path);
                    continue;
                }
                let member = if kind.is_symlink() {
                    // A symlink is covered by the name it points at, so
                    // retargeting one moves the digest. It is never
                    // followed: a target inside the closure is hashed
                    // as a member of its own, and one outside it is a
                    // name the jail cannot reach.
                    let target = std::fs::read_link(&path)
                        .map_err(|_| unreadable("a runtime closure link cannot be read"))?;
                    ClosureMember::Link(target.as_os_str().as_encoded_bytes().to_vec())
                } else if kind.is_file() {
                    if path == launcher {
                        continue;
                    }
                    ClosureMember::File(path.clone())
                } else {
                    continue;
                };
                if rows.len() >= MAX_CLOSURE_FILES {
                    return Err(unreadable(
                        "a runtime closure entry holds more files than expected",
                    ));
                }
                let relative = path
                    .strip_prefix(root)
                    .unwrap_or(path.as_path())
                    .as_os_str()
                    .as_encoded_bytes()
                    .to_vec();
                rows.push((relative, member));
            }
        }
    }
    rows.sort();
    let mut hasher = blake3::Hasher::new();
    for (relative, member) in rows {
        hasher.update(&relative);
        hasher.update(b"\n");
        match member {
            ClosureMember::File(path) => {
                let hash = crate::hash::hash_file(&path)
                    .map_err(|_| unreadable("a runtime closure member cannot be read"))?;
                hasher.update(hash.as_bytes());
            }
            ClosureMember::Link(target) => {
                hasher.update(b"link:");
                hasher.update(&target);
            }
        }
        hasher.update(b"\n");
    }
    Ok(hasher.finalize().to_hex().to_string())
}

/// A member of a closure entry: a regular file hashed by content, or a
/// symlink covered by the target it names.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum ClosureMember {
    File(PathBuf),
    Link(Vec<u8>),
}

/// The per-exec assertion order, run in this cold worker immediately
/// before every external execution: present, then hash, then closure
/// digest, then version. Each step has its own named refusal, and the
/// executable runs only after all of them pass.
fn verify_role(entry: &SvgRoleEntry) -> Result<PathBuf, SvgRasterError> {
    let role = entry.role.as_str();
    let path = PathBuf::from(&entry.path);
    let metadata = std::fs::symlink_metadata(&path).map_err(|_| {
        SvgRasterError::new(
            "rasterizer-missing",
            format!("provider component {role} is not present"),
        )
    })?;
    if !metadata.file_type().is_file() {
        return Err(SvgRasterError::new(
            "rasterizer-missing",
            format!("provider component {role} is not a literal regular file"),
        ));
    }
    let actual = crate::hash::hash_file(&path).map_err(|_| {
        SvgRasterError::new(
            "rasterizer-missing",
            format!("provider component {role} cannot be read"),
        )
    })?;
    if actual != entry.expected_blake3 {
        return Err(SvgRasterError::new(
            "rasterizer-hash-drift",
            format!("provider component {role} does not match its pinned hash"),
        ));
    }
    // The paths are re-checked here as well as at configuration: the
    // executable and every entry in normal form, no entry a symlink,
    // and the executable inside an entry on the resolved paths. An
    // aliased path cannot be what the digest was measured over, and an
    // executable outside its closure has no measured tree.
    let drift = |detail: String| SvgRasterError::new("rasterizer-hash-drift", detail);
    if !super::provider::is_normal_form(&path) {
        return Err(drift(format!(
            "provider component {role} path is not in normal form"
        )));
    }
    let real_path = super::provider::canonical(&path)
        .ok_or_else(|| drift(format!("provider component {role} cannot be resolved")))?;
    let mut real_roots = Vec::with_capacity(entry.closure_roots.len());
    for root in &entry.closure_roots {
        let root = Path::new(root);
        if !super::provider::is_normal_form(root) {
            return Err(drift(format!(
                "a closure entry of provider component {role} is not in normal form"
            )));
        }
        if super::provider::is_symlink_entry(root) {
            return Err(drift(format!(
                "a closure entry of provider component {role} is a symlink"
            )));
        }
        real_roots.push(super::provider::canonical(root).ok_or_else(|| {
            drift(format!(
                "a closure entry of provider component {role} cannot be resolved"
            ))
        })?);
    }
    if !real_roots.is_empty()
        && !real_roots
            .iter()
            .any(|root| super::provider::lies_inside(&real_path, root))
    {
        return Err(drift(format!(
            "provider component {role} lies outside its enumerated closure"
        )));
    }
    // The enumerated closure and its digest are a pair here as well
    // as at configuration: a closure with no digest, or a digest with
    // no closure, is refused as drift before anything runs.
    if entry.closure_blake3.is_some() != !entry.closure_roots.is_empty() {
        return Err(SvgRasterError::new(
            "rasterizer-hash-drift",
            format!(
                "provider component {role} enumerates a closure without a pinned digest, or the reverse"
            ),
        ));
    }
    if let Some(expected) = &entry.closure_blake3 {
        let roots: Vec<PathBuf> = entry.closure_roots.iter().map(PathBuf::from).collect();
        let actual = closure_digest(&roots, &path)?;
        if &actual != expected {
            return Err(SvgRasterError::new(
                "rasterizer-hash-drift",
                format!(
                    "the runtime closure of provider component {role} does not match its pinned digest"
                ),
            ));
        }
    }
    assert_version(&path, entry)?;
    Ok(path)
}

/// Runs the bounded version check and compares the reported version for
/// equality with the pinned one. The raw output is parsed here and
/// discarded: only the pinned string, which the deployment already
/// wrote down, can ever reach a record.
fn assert_version(path: &Path, entry: &SvgRoleEntry) -> Result<(), SvgRasterError> {
    let role = entry.role.as_str();
    let drift = || {
        SvgRasterError::new(
            "rasterizer-version-drift",
            format!("provider component {role} does not report its pinned version"),
        )
    };
    let output = Command::new(path)
        .arg("--version")
        .env_clear()
        .stdin(Stdio::null())
        .output()
        .map_err(|_| drift())?;
    if !output.status.success() {
        return Err(drift());
    }
    let text = String::from_utf8_lossy(&output.stdout);
    // The pinned version must appear as a standalone token in the
    // reported line, so a longer build string cannot satisfy a shorter
    // pin and no other part of the output is examined.
    let found = text
        .split(|c: char| c.is_ascii_whitespace() || c == ':' || c == ',')
        .any(|token| token == entry.version);
    if found { Ok(()) } else { Err(drift()) }
}

/// A jail-owned sink for a child's output stream, the same shape the
/// audio path uses: the bytes land in a jail file that is never read
/// and dies with the jail.
fn discard_file(name: &str) -> std::io::Result<Stdio> {
    Ok(Stdio::from(std::fs::File::create(name)?))
}

/// Runs one verified provider executable over a fixed argument vector.
fn run_provider(
    path: &Path,
    argv: &[String],
    role: &str,
    profile_env: &[(String, String)],
) -> Result<(), SvgRasterError> {
    let failed = || {
        SvgRasterError::new(
            "raster-exec-failed",
            format!("provider component {role} did not complete cleanly"),
        )
    };
    let mut command = Command::new(path);
    command.args(argv).env_clear();
    for (name, value) in profile_env {
        command.env(name, value);
    }
    let status = command
        .stdin(Stdio::null())
        .stdout(discard_file(&format!("{role}.out")).map_err(|_| failed())?)
        .stderr(discard_file(&format!("{role}.err")).map_err(|_| failed())?)
        .status()
        .map_err(|_| failed())?;
    if !status.success() {
        return Err(failed());
    }
    Ok(())
}

/// The dimensions of a raster the provider produced, read from the
/// header by the same pure-Rust decoder the pixel path uses.
fn png_dimensions(path: &Path) -> Result<(u32, u32), SvgRasterError> {
    let bytes = std::fs::read(path).map_err(|_| {
        SvgRasterError::new(
            "raster-exec-failed",
            "the provider produced no readable raster",
        )
    })?;
    let mut reader =
        image::ImageReader::with_format(std::io::Cursor::new(bytes), image::ImageFormat::Png);
    let mut limits = image::Limits::no_limits();
    limits.max_alloc = Some(crate::convert::IMAGE_OCR_DECODE_ALLOC);
    reader.limits(limits);
    reader.into_dimensions().map_err(|_| {
        SvgRasterError::new(
            "raster-exec-failed",
            "the provider produced a raster that does not decode",
        )
    })
}

/// The fresh per-execution profile environment: a home, a framework
/// home, and a temp directory, each its own subdirectory of this
/// invocation's jail, plus any additional temp variable the deployment
/// named. No profile flag is passed on the command line, so this is
/// where the renderer's state lives, and the jail is discarded whole
/// when the invocation ends.
fn profile_environment(
    jail: &Path,
    entry: &SvgRoleEntry,
) -> Result<Vec<(String, String)>, SvgRasterError> {
    let mut env = Vec::new();
    for (name, dir) in [
        ("HOME", "provider-home"),
        ("CFFIXED_USER_HOME", "provider-cfhome"),
        ("TMPDIR", "provider-tmp"),
    ] {
        let path = jail.join(dir);
        std::fs::create_dir_all(&path).map_err(|_| {
            SvgRasterError::new(
                "raster-exec-failed",
                "the provider profile root cannot be created",
            )
        })?;
        env.push((name.to_string(), path.display().to_string()));
    }
    if let Some(name) = &entry.jail_temp_env {
        let path = jail.join("provider-tmp");
        env.push((name.clone(), path.display().to_string()));
    }
    Ok(env)
}

/// The steps the leg takes outside itself, behind one seam.
///
/// The production implementation is the verification, execution, and
/// decode above. The seam exists so the order the assertions run in is
/// itself testable: a jailed process can write nothing a test could
/// observe, which is the point of the jail, so the sequence is proven
/// here rather than through a side channel the jail would have to
/// permit.
pub(crate) trait ProviderRuntime {
    /// Presence, hash, closure digest, and version, in that order.
    fn verify(&self, entry: &SvgRoleEntry) -> Result<PathBuf, SvgRasterError>;
    /// One bounded execution of a verified component.
    fn run(
        &self,
        path: &Path,
        argv: &[String],
        role: &str,
        env: &[(String, String)],
    ) -> Result<(), SvgRasterError>;
    /// The dimensions of a raster the component produced.
    fn dimensions(&self, path: &Path) -> Result<(u32, u32), SvgRasterError>;
    /// The bytes of the finished raster.
    fn read(&self, path: &Path) -> Result<Vec<u8>, SvgRasterError>;
}

/// The production runtime: the real executables under the real jail.
pub(crate) struct JailedRuntime;

impl ProviderRuntime for JailedRuntime {
    fn verify(&self, entry: &SvgRoleEntry) -> Result<PathBuf, SvgRasterError> {
        verify_role(entry)
    }

    fn run(
        &self,
        path: &Path,
        argv: &[String],
        role: &str,
        env: &[(String, String)],
    ) -> Result<(), SvgRasterError> {
        run_provider(path, argv, role, env)
    }

    fn dimensions(&self, path: &Path) -> Result<(u32, u32), SvgRasterError> {
        png_dimensions(path)
    }

    fn read(&self, path: &Path) -> Result<Vec<u8>, SvgRasterError> {
        std::fs::read(path).map_err(|_| {
            SvgRasterError::new(
                "raster-exec-failed",
                "the flattened raster cannot be read back",
            )
        })
    }
}

/// Rasterizes one staged source and returns the flattened raster.
///
/// This is the production symbol and compiles one way in every feature
/// combination. With no provider configured it is never reached: the
/// parent runs this leg only when a complete configuration exists.
pub(crate) fn rasterize(request: &SvgRasterRequest) -> Result<SvgRasterOk, SvgRasterError> {
    rasterize_with(request, &JailedRuntime)
}

/// The leg's whole sequence over one runtime.
pub(crate) fn rasterize_with(
    request: &SvgRasterRequest,
    runtime: &dyn ProviderRuntime,
) -> Result<SvgRasterOk, SvgRasterError> {
    let jail = std::env::current_dir().map_err(|_| {
        SvgRasterError::new("raster-exec-failed", "the provider jail is unreachable")
    })?;
    let source = std::fs::read(Path::new(&request.input)).map_err(|_| {
        SvgRasterError::new("raster-exec-failed", "the staged source cannot be read")
    })?;
    let geometry = parse_geometry(&source)?;
    let (width, height) = geometry.window()?;

    let raster = request
        .roles
        .iter()
        .find(|entry| entry.role == PROVIDER_ROLE_RASTER)
        .ok_or_else(|| {
            SvgRasterError::new(
                "rasterizer-missing",
                format!("provider component {PROVIDER_ROLE_RASTER} is not present"),
            )
        })?;
    let encoder = request
        .roles
        .iter()
        .find(|entry| entry.role == PROVIDER_ROLE_ENCODER)
        .ok_or_else(|| {
            SvgRasterError::new(
                "rasterizer-missing",
                format!("provider component {PROVIDER_ROLE_ENCODER} is not present"),
            )
        })?;

    // Stage 2 and 3: verify immediately before the execution, never
    // once for the pair, so a swap between the two runs still fails.
    let raster_path = runtime.verify(raster)?;
    let raw = jail.join(JAIL_RAW);
    let input = jail.join(&request.input);
    let profile_env = profile_environment(&jail, raster)?;
    runtime.run(
        &raster_path,
        &raster_argv(width, height, &raw, &input),
        PROVIDER_ROLE_RASTER,
        &profile_env,
    )?;

    // Stage 4: geometry on both cross-axis checks, then the area cap.
    let (raw_width, raw_height) = runtime.dimensions(&raw)?;
    assert_geometry(geometry, raw_width, raw_height)?;
    let area = u64::from(raw_width) * u64::from(raw_height);
    if area > crate::convert::IMAGE_OCR_MAX_AREA_PX {
        return Err(SvgRasterError::new(
            "encoder-area-cap",
            format!(
                "the rendered raster is {area} px over the {} px encoder-input area cap",
                crate::convert::IMAGE_OCR_MAX_AREA_PX
            ),
        ));
    }

    // Stage 5: the encoder's own assertions, then the flatten.
    let encoder_path = runtime.verify(encoder)?;
    let flat = jail.join(JAIL_FLAT);
    runtime.run(
        &encoder_path,
        &flatten_argv(&raw, &flat),
        PROVIDER_ROLE_ENCODER,
        &[],
    )?;
    let (flat_width, flat_height) = runtime.dimensions(&flat)?;
    if (flat_width, flat_height) != (raw_width, raw_height) {
        return Err(SvgRasterError::new(
            "raster-geometry-mismatch",
            "the flattened raster does not keep the rendered dimensions",
        ));
    }
    let bytes = runtime.read(&flat)?;
    Ok(SvgRasterOk {
        raster_png_hex: hex_encode(&bytes),
        width: flat_width,
        height: flat_height,
    })
}

/// Lowercase hex encoding, so the raster crosses the response frame as
/// text without pulling an encoding dependency into the jail.
pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from_digit(u32::from(byte >> 4), 16).expect("nibble"));
        out.push(char::from_digit(u32::from(byte & 0x0f), 16).expect("nibble"));
    }
    out
}

/// The inverse of [`hex_encode`], used by the parent to recover the
/// raster bytes from the response.
pub(crate) fn hex_decode(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(text.len() / 2);
    for pair in bytes.chunks_exact(2) {
        let high = char::from(pair[0]).to_digit(16)?;
        let low = char::from(pair[1]).to_digit(16)?;
        out.push((high * 16 + low) as u8);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(role: &str) -> SvgRoleEntry {
        SvgRoleEntry {
            role: role.to_string(),
            path: "/deploy/component".to_string(),
            expected_blake3: "a".repeat(64),
            version: "1.2.3".to_string(),
            closure_roots: Vec::new(),
            closure_blake3: None,
            jail_temp_env: None,
        }
    }

    #[test]
    fn declared_root_geometry_wins_and_units_are_explicit() {
        let svg = |root: &str| format!("<?xml version=\"1.0\"?>\n<svg {root}><text>x</text></svg>");
        let parse = |root: &str| parse_geometry(svg(root).as_bytes());
        assert_eq!(
            parse("xmlns=\"x\" width=\"1600\" height=\"900\"").unwrap(),
            Geometry {
                width: 1600.0,
                height: 900.0
            }
        );
        assert_eq!(
            parse("width=\"1600px\" height=\"900px\"").unwrap(),
            Geometry {
                width: 1600.0,
                height: 900.0
            }
        );
        // The absolute units convert by their fixed ratios.
        let inches = parse("width=\"2in\" height=\"1in\"").unwrap();
        assert_eq!((inches.width, inches.height), (192.0, 96.0));
        let points = parse("width=\"72pt\" height=\"36pt\"").unwrap();
        assert_eq!((points.width, points.height), (96.0, 48.0));
        // Attribute names are matched as names, so a look-alike does
        // not supply the geometry.
        let bordered =
            parse("stroke-width=\"4\" width=\"800\" line-height=\"2\" height=\"600\"").unwrap();
        assert_eq!((bordered.width, bordered.height), (800.0, 600.0));
        // Single quotes and attribute order are both accepted.
        let quoted = parse("height='600' width='800'").unwrap();
        assert_eq!((quoted.width, quoted.height), (800.0, 600.0));
    }

    #[test]
    fn a_view_box_is_the_fallback_and_percent_only_fails_closed() {
        let view_box = parse_geometry(b"<svg viewBox=\"0 0 1600 900\"></svg>").unwrap();
        assert_eq!((view_box.width, view_box.height), (1600.0, 900.0));
        // Comma separation is the same view box.
        let commas = parse_geometry(b"<svg viewBox=\"0,0,1600,900\"></svg>").unwrap();
        assert_eq!((commas.width, commas.height), (1600.0, 900.0));
        // Percent-only geometry with a view box falls back to the box.
        let percent =
            parse_geometry(b"<svg width=\"100%\" height=\"100%\" viewBox=\"0 0 400 200\"></svg>")
                .unwrap();
        assert_eq!((percent.width, percent.height), (400.0, 200.0));
        // Percent-only with no view box is unresolved and fails closed
        // rather than rendering against a host default viewport.
        for source in [
            b"<svg width=\"100%\" height=\"100%\"></svg>".as_slice(),
            b"<svg width=\"10em\" height=\"4em\"></svg>".as_slice(),
            b"<svg width=\"50vw\" height=\"20vh\"></svg>".as_slice(),
            b"<svg></svg>".as_slice(),
            b"<svg width=\"0\" height=\"0\"></svg>".as_slice(),
            b"<svg width=\"-40\" height=\"20\"></svg>".as_slice(),
            b"<svg viewBox=\"0 0 400\"></svg>".as_slice(),
            b"<svg viewBox=\"0 0 nan 200\"></svg>".as_slice(),
            b"not markup at all".as_slice(),
            b"<svg width=\"10\" height=\"10\"".as_slice(),
        ] {
            let error = parse_geometry(source).unwrap_err();
            assert_eq!(error.code, "raster-geometry-mismatch", "{source:?}");
        }
    }

    #[test]
    fn markup_before_the_root_cannot_supply_a_false_geometry() {
        // Each of these carries the byte sequence `<svg` with a
        // convincing size before the real root. A byte search would
        // take it as the root and validate the render against a
        // geometry the document never declared, which is a silent
        // crop. The tokenizer reads the real root, which here declares
        // nothing usable, so each is refused.
        let decoys: [&[u8]; 6] = [
            b"<!-- <svg width=\"1600\" height=\"900\"> --><svg><text>x</text></svg>",
            b"<![CDATA[<svg width=\"1600\" height=\"900\">]]><svg><text>x</text></svg>",
            b"<!DOCTYPE svg [ <!ENTITY e \"<svg width='1600' height='900'>\"> ]><svg><text>x</text></svg>",
            b"<?xml version=\"1.0\"?><?decoy <svg width=\"1600\" height=\"900\"> ?><svg><text>x</text></svg>",
            b"<svg><![CDATA[<svg width=\"1600\" height=\"900\">]]></svg>",
            b"<html><svg width=\"1600\" height=\"900\"></svg></html>",
        ];
        for source in decoys {
            let error = parse_geometry(source).unwrap_err();
            assert_eq!(error.code, "raster-geometry-mismatch", "{source:?}");
        }
        // The same decoys in front of a root that DOES declare a size
        // yield that size and never the decoy's.
        for real in [
            b"<!-- <svg width=\"1600\" height=\"900\"> --><svg width=\"800\" height=\"450\"><text>x</text></svg>".as_slice(),
            b"<![CDATA[<svg width=\"1600\" height=\"900\">]]><svg width=\"800\" height=\"450\"><text>x</text></svg>".as_slice(),
        ] {
            let geometry = parse_geometry(real).unwrap();
            assert_eq!((geometry.width, geometry.height), (800.0, 450.0));
        }
    }

    #[test]
    fn only_the_root_element_decides_the_geometry() {
        // A descendant carrying its own size never moves the window.
        let nested = parse_geometry(
            b"<svg width=\"1600\" height=\"900\"><rect width=\"10\" height=\"10\"/></svg>",
        )
        .unwrap();
        assert_eq!((nested.width, nested.height), (1600.0, 900.0));
        // A descendant cannot supply a geometry the root lacks.
        let error = parse_geometry(b"<svg><rect width=\"10\" height=\"10\"/></svg>").unwrap_err();
        assert_eq!(error.code, "raster-geometry-mismatch");
    }

    #[test]
    fn both_cross_axis_checks_hold_within_one_pixel() {
        let source = Geometry {
            width: 1600.0,
            height: 900.0,
        };
        assert!(assert_geometry(source, 1600, 900).is_ok());
        // The tolerance is one pixel on each derivation, not one pixel
        // of slack overall: a rounding difference is accepted only when
        // BOTH derivations land within it. A 16 by 9 source amplifies a
        // single pixel of height into nearly two pixels of derived
        // width, so the pair that stays inside the band on both axes is
        // accepted and the one that does not is refused, which is the
        // ruled algorithm rather than a looser reading of it.
        assert!(assert_geometry(source, 1601, 901).is_ok());
        assert!(assert_geometry(source, 1600, 901).is_err());
        // A square render of a wide source, the historical defect, is
        // refused by the cross-axis pair.
        let error = assert_geometry(source, 1536, 1536).unwrap_err();
        assert_eq!(error.code, "raster-geometry-mismatch");
        // A crop on the long axis alone is refused too.
        assert!(assert_geometry(source, 1440, 900).is_err());
        // Degenerate output is refused rather than dividing by zero.
        assert!(assert_geometry(source, 0, 900).is_err());
        assert!(assert_geometry(source, 1600, 0).is_err());
        // A portrait source keeps the same symmetry.
        let portrait = Geometry {
            width: 816.0,
            height: 1056.0,
        };
        assert!(assert_geometry(portrait, 1186, 1536).is_ok());
        assert!(assert_geometry(portrait, 1536, 1536).is_err());
    }

    #[test]
    fn the_window_is_the_declared_size_and_refuses_the_absurd() {
        let (width, height) = Geometry {
            width: 1600.4,
            height: 899.6,
        }
        .window()
        .unwrap();
        assert_eq!((width, height), (1600, 900));
        assert!(
            Geometry {
                width: 1e9,
                height: 10.0
            }
            .window()
            .is_err()
        );
        assert!(
            Geometry {
                width: 0.2,
                height: 10.0
            }
            .window()
            .is_err()
        );
    }

    #[test]
    fn the_rasterizer_argv_is_a_fixed_tuple_ending_in_the_one_flag() {
        let argv = raster_argv(
            1600,
            900,
            Path::new("/jail/raw.png"),
            Path::new("/jail/doc.svg"),
        );
        assert_eq!(
            argv,
            vec![
                "--headless=new",
                "--disable-gpu",
                "--hide-scrollbars",
                "--window-size=1600,900",
                "--force-device-scale-factor=1",
                "--disable-background-networking",
                "--disable-component-update",
                "--disable-domain-reliability",
                "--disable-sync",
                "--no-first-run",
                "--no-default-browser-check",
                "--metrics-recording-only",
                "--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE localhost",
                "--screenshot=/jail/raw.png",
                "file:///jail/doc.svg",
                "--no-sandbox",
            ]
        );
        // The flag is the last element and appears exactly once, and no
        // profile flag is ever passed: the jail owns the profile root.
        assert_eq!(argv.last().map(String::as_str), Some("--no-sandbox"));
        assert_eq!(argv.iter().filter(|arg| *arg == "--no-sandbox").count(), 1);
        assert!(!argv.iter().any(|arg| arg.contains("--user-data-dir")));
        // Only the window and the two jail paths move.
        let other = raster_argv(
            800,
            600,
            Path::new("/other/raw.png"),
            Path::new("/other/d.svg"),
        );
        let differing: Vec<usize> = argv
            .iter()
            .zip(other.iter())
            .enumerate()
            .filter(|(_, (a, b))| a != b)
            .map(|(index, _)| index)
            .collect();
        assert_eq!(differing, vec![3, 13, 14]);
    }

    #[test]
    fn the_flatten_argv_carries_the_settled_options_in_order() {
        let argv = flatten_argv(Path::new("/jail/raw.png"), Path::new("/jail/flat.png"));
        assert_eq!(
            argv,
            vec![
                "/jail/raw.png",
                "-background",
                "white",
                "-alpha",
                "remove",
                "-alpha",
                "off",
                "-define",
                "png:exclude-chunks=date,time",
                "/jail/flat.png",
            ]
        );
        // The chunk exclusion is never optional: without it the encoder
        // stamps the raster with the time it ran.
        assert!(argv.iter().any(|arg| arg == "png:exclude-chunks=date,time"));
    }

    #[test]
    fn a_missing_or_unreadable_component_is_named_missing_not_drifted() {
        let mut role = entry(PROVIDER_ROLE_RASTER);
        role.path = "/nonexistent/provider/component".to_string();
        let error = verify_role(&role).unwrap_err();
        assert_eq!(error.code, "rasterizer-missing");
        assert!(error.message.contains(PROVIDER_ROLE_RASTER), "{error:?}");
        // The path never reaches the message.
        assert!(!error.message.contains("nonexistent"), "{error:?}");

        // A directory is not a literal regular file.
        let dir = tempfile::tempdir().unwrap();
        role.path = dir.path().to_str().unwrap().to_string();
        let error = verify_role(&role).unwrap_err();
        assert_eq!(error.code, "rasterizer-missing");
    }

    #[test]
    fn a_hash_that_does_not_match_the_pin_is_drift() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("component");
        std::fs::write(&path, b"substituted bytes").unwrap();
        let mut role = entry(PROVIDER_ROLE_RASTER);
        role.path = path.to_str().unwrap().to_string();
        let error = verify_role(&role).unwrap_err();
        assert_eq!(error.code, "rasterizer-hash-drift");
        assert!(error.message.contains(PROVIDER_ROLE_RASTER), "{error:?}");
        assert!(!error.message.contains("substituted"), "{error:?}");
    }

    #[test]
    fn the_closure_digest_is_stable_ordered_and_sees_a_helper_change() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let launcher = root.join("launcher");
        std::fs::write(&launcher, b"launcher").unwrap();
        std::fs::create_dir_all(root.join("helpers/inner")).unwrap();
        let helper = root.join("helpers/helper");
        let inner = root.join("helpers/inner/deep");
        let data = root.join("helpers/resource.dat");
        for (path, bytes) in [
            (&helper, b"helper".as_slice()),
            (&inner, b"deep".as_slice()),
            (&data, b"data".as_slice()),
        ] {
            std::fs::write(path, bytes).unwrap();
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for path in [&launcher, &helper, &inner] {
                let mut permissions = std::fs::metadata(path).unwrap().permissions();
                permissions.set_mode(0o755);
                std::fs::set_permissions(path, permissions).unwrap();
            }
        }
        let roots = vec![root.to_path_buf()];
        let first = closure_digest(&roots, &launcher).unwrap();
        // Stable across calls, and the launcher's own bytes are not in
        // it: it is pinned on its own.
        assert_eq!(first, closure_digest(&roots, &launcher).unwrap());
        std::fs::write(&launcher, b"a different launcher").unwrap();
        assert_eq!(first, closure_digest(&roots, &launcher).unwrap());
        // A helper that drifts while the launcher stands still changes
        // the digest, which is the skew this control exists for.
        std::fs::write(&helper, b"helper, but newer").unwrap();
        assert_ne!(first, closure_digest(&roots, &launcher).unwrap());
    }

    #[test]
    fn an_enumerated_closure_digests_every_entry_and_ignores_their_order() {
        // A closure of several entries, directories and single files
        // alike: every entry is covered, the order they were written
        // down in does not matter, and adding or changing any one of
        // them moves the digest.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let launcher = root.join("launcher");
        std::fs::write(&launcher, b"launcher").unwrap();
        std::fs::create_dir_all(root.join("libs")).unwrap();
        let inside = root.join("libs/one.dylib");
        let standalone = root.join("two.dylib");
        let unrelated = root.join("three.dylib");
        for path in [&inside, &standalone, &unrelated] {
            std::fs::write(path, b"library").unwrap();
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for path in [&launcher, &inside, &standalone, &unrelated] {
                let mut permissions = std::fs::metadata(path).unwrap().permissions();
                permissions.set_mode(0o755);
                std::fs::set_permissions(path, permissions).unwrap();
            }
        }
        let enumerated = vec![root.join("libs"), standalone.clone()];
        let digest = closure_digest(&enumerated, &launcher).unwrap();
        // Order-independent.
        let reversed = vec![standalone.clone(), root.join("libs")];
        assert_eq!(digest, closure_digest(&reversed, &launcher).unwrap());
        // A file entry is covered: changing it moves the digest.
        std::fs::write(&standalone, b"library, but newer").unwrap();
        assert_ne!(digest, closure_digest(&enumerated, &launcher).unwrap());
        std::fs::write(&standalone, b"library").unwrap();
        assert_eq!(digest, closure_digest(&enumerated, &launcher).unwrap());
        // A directory entry is covered too.
        std::fs::write(&inside, b"library, but newer").unwrap();
        assert_ne!(digest, closure_digest(&enumerated, &launcher).unwrap());
        std::fs::write(&inside, b"library").unwrap();
        // A file nobody enumerated is outside the digest, which is why
        // the enumeration is the security boundary and the digest is
        // only the integrity control over what it named.
        std::fs::write(&unrelated, b"nobody named me").unwrap();
        assert_eq!(digest, closure_digest(&enumerated, &launcher).unwrap());
        // Adding an entry changes the digest.
        let widened = vec![root.join("libs"), standalone, unrelated];
        assert_ne!(digest, closure_digest(&widened, &launcher).unwrap());
    }

    #[test]
    fn every_regular_file_and_symlink_target_is_in_the_digest() {
        // The digest is the integrity control standing in for grant
        // granularity, so it covers what the grant makes reachable: a
        // policy file nobody marked executable, and the target a
        // symlink names, both move it.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let launcher = root.join("launcher");
        std::fs::write(&launcher, b"launcher").unwrap();
        std::fs::create_dir_all(root.join("lib/versions/1")).unwrap();
        let policy = root.join("lib/policy.xml");
        std::fs::write(&policy, b"<policymap/>").unwrap();
        let link = root.join("lib/versions/current");
        std::os::unix::fs::symlink("1", &link).unwrap();
        let roots = vec![root.join("lib")];
        let first = closure_digest(&roots, &launcher).unwrap();
        std::fs::write(&policy, b"<policymap><policy/></policymap>").unwrap();
        let edited = closure_digest(&roots, &launcher).unwrap();
        assert_ne!(first, edited);
        std::fs::write(&policy, b"<policymap/>").unwrap();
        assert_eq!(first, closure_digest(&roots, &launcher).unwrap());
        // Retargeting the link, even to a name that does not exist,
        // moves the digest, and the link is never followed.
        std::fs::remove_file(&link).unwrap();
        std::os::unix::fs::symlink("2", &link).unwrap();
        assert_ne!(first, closure_digest(&roots, &launcher).unwrap());
        std::fs::remove_file(&link).unwrap();
        std::os::unix::fs::symlink("1", &link).unwrap();
        assert_eq!(first, closure_digest(&roots, &launcher).unwrap());
        // A link to a tree outside the closure is a name, not a walk.
        let outside = root.join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("big"), vec![0u8; 1024]).unwrap();
        std::os::unix::fs::symlink(&outside, root.join("lib/elsewhere")).unwrap();
        let with_link = closure_digest(&roots, &launcher).unwrap();
        std::fs::write(outside.join("big"), vec![1u8; 1024]).unwrap();
        assert_eq!(with_link, closure_digest(&roots, &launcher).unwrap());
    }

    #[test]
    fn a_closure_entry_that_is_a_symlink_is_refused_before_the_walk() {
        // An entry is a real directory or a real regular file. A link
        // entry would be followed by the walk while the grant names
        // the link, so the digest refuses it, and the per-role check
        // refuses it before the walk, on top of configuration doing
        // the same.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let real = root.join("real");
        std::fs::create_dir_all(&real).unwrap();
        let component = real.join("component");
        std::fs::write(&component, b"component bytes").unwrap();
        let link = root.join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let error = closure_digest(std::slice::from_ref(&link), &component).unwrap_err();
        assert_eq!(error.code, "rasterizer-hash-drift");
        assert!(error.message.contains("symlink"), "{error:?}");
        let mut role = entry(PROVIDER_ROLE_RASTER);
        role.path = component.to_str().unwrap().to_string();
        role.expected_blake3 = crate::hash::hash_file(&component).unwrap();
        role.closure_roots = vec![link.to_str().unwrap().to_string()];
        role.closure_blake3 = Some("b".repeat(64));
        let error = verify_role(&role).unwrap_err();
        assert_eq!(error.code, "rasterizer-hash-drift");
        assert!(error.message.contains("symlink"), "{error:?}");
        // The real entry passes those checks and reaches the digest
        // comparison, which is the next named refusal.
        role.closure_roots = vec![real.to_str().unwrap().to_string()];
        let error = verify_role(&role).unwrap_err();
        assert!(error.message.contains("pinned digest"), "{error:?}");
    }

    #[test]
    fn the_worker_decides_containment_on_resolved_paths() {
        // A component whose written path lies inside an entry but whose
        // resolved path lies outside is refused, and one written
        // through a link that resolves inside is accepted up to the
        // digest comparison.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let closure = root.join("closure");
        let outside = root.join("outside");
        std::fs::create_dir_all(&closure).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        let escaped = outside.join("component");
        std::fs::write(&escaped, b"component bytes").unwrap();
        std::os::unix::fs::symlink(&outside, closure.join("link")).unwrap();
        let mut role = entry(PROVIDER_ROLE_RASTER);
        role.path = closure.join("link/component").to_str().unwrap().to_string();
        role.expected_blake3 = crate::hash::hash_file(&escaped).unwrap();
        role.closure_roots = vec![closure.to_str().unwrap().to_string()];
        role.closure_blake3 = Some("b".repeat(64));
        let error = verify_role(&role).unwrap_err();
        assert_eq!(error.code, "rasterizer-hash-drift");
        assert!(error.message.contains("outside"), "{error:?}");
        let inside = closure.join("component");
        std::fs::write(&inside, b"component bytes").unwrap();
        std::os::unix::fs::symlink(&closure, root.join("alias")).unwrap();
        role.path = root.join("alias/component").to_str().unwrap().to_string();
        let error = verify_role(&role).unwrap_err();
        assert!(error.message.contains("pinned digest"), "{error:?}");
        // A written path that is not in normal form never reaches the
        // resolution at all.
        role.path = closure
            .join("../closure/component")
            .to_str()
            .unwrap()
            .to_string();
        let error = verify_role(&role).unwrap_err();
        assert!(error.message.contains("normal form"), "{error:?}");
    }

    #[test]
    fn a_closure_and_its_digest_are_a_pair_at_the_worker_too() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("component");
        std::fs::write(&path, b"component bytes").unwrap();
        let good = crate::hash::hash_file(&path).unwrap();
        // Roots with no digest: refused before the version check.
        let mut roots_only = entry(PROVIDER_ROLE_RASTER);
        roots_only.path = path.to_str().unwrap().to_string();
        roots_only.expected_blake3 = good.clone();
        roots_only.closure_roots = vec![dir.path().to_str().unwrap().to_string()];
        let error = verify_role(&roots_only).unwrap_err();
        assert_eq!(error.code, "rasterizer-hash-drift");
        assert!(
            error.message.contains("without a pinned digest"),
            "{error:?}"
        );
        // A digest with no roots: refused the same way.
        let mut digest_only = entry(PROVIDER_ROLE_RASTER);
        digest_only.path = path.to_str().unwrap().to_string();
        digest_only.expected_blake3 = good;
        digest_only.closure_blake3 = Some("0".repeat(64));
        let error = verify_role(&digest_only).unwrap_err();
        assert_eq!(error.code, "rasterizer-hash-drift");
    }

    #[test]
    fn hex_round_trips_and_refuses_malformed_text() {
        let bytes: Vec<u8> = (0..=255u8).collect();
        let text = hex_encode(&bytes);
        assert_eq!(text.len(), 512);
        assert_eq!(hex_decode(&text).unwrap(), bytes);
        assert_eq!(hex_encode(&[]), "");
        assert_eq!(hex_decode("").unwrap(), Vec::<u8>::new());
        assert!(hex_decode("abc").is_none());
        assert!(hex_decode("zz").is_none());
    }
}
