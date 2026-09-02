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
//!    executable closure. The closure digest is the integrity control
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

/// Reads one attribute value out of the root element text.
fn attribute<'a>(root: &'a str, name: &str) -> Option<&'a str> {
    let bytes = root.as_bytes();
    let mut from = 0;
    while let Some(offset) = root[from..].find(name) {
        let start = from + offset;
        let before = start.checked_sub(1).map(|i| bytes[i]);
        // The name must stand alone, so `width` never matches inside
        // `stroke-width` and `height` never inside `line-height`.
        let standalone = before.is_none_or(|b| b.is_ascii_whitespace());
        let mut cursor = start + name.len();
        while bytes.get(cursor).is_some_and(|b| b.is_ascii_whitespace()) {
            cursor += 1;
        }
        if standalone && bytes.get(cursor) == Some(&b'=') {
            cursor += 1;
            while bytes.get(cursor).is_some_and(|b| b.is_ascii_whitespace()) {
                cursor += 1;
            }
            let quote = *bytes.get(cursor)?;
            if quote != b'"' && quote != b'\'' {
                return None;
            }
            cursor += 1;
            let end = root[cursor..].find(quote as char)? + cursor;
            return Some(&root[cursor..end]);
        }
        from = start + 1;
    }
    None
}

/// Parses the declared geometry of one source: the root width and
/// height when both resolve, else the view box's own width and height.
/// Anything else is unresolved and fails closed.
pub(crate) fn parse_geometry(source: &[u8]) -> Result<Geometry, SvgRasterError> {
    let unresolved = || {
        SvgRasterError::new(
            "raster-geometry-mismatch",
            "the source declares no resolvable root geometry",
        )
    };
    let head = &source[..source.len().min(GEOMETRY_SCAN_BYTES)];
    let text = String::from_utf8_lossy(head);
    // The root element only: scan from the first `<svg` to its closing
    // angle bracket, so no descendant's attributes are ever read.
    let start = text.find("<svg").ok_or_else(unresolved)?;
    let rest = &text[start..];
    let end = rest.find('>').ok_or_else(unresolved)?;
    let root = &rest[..end];
    if let (Some(width), Some(height)) = (attribute(root, "width"), attribute(root, "height"))
        && let (Some(width), Some(height)) = (length_to_px(width), length_to_px(height))
    {
        return Ok(Geometry { width, height });
    }
    let view_box = attribute(root, "viewBox").ok_or_else(unresolved)?;
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

/// The aggregate closure digest: BLAKE3 over the sorted relative path
/// and BLAKE3 of every executable file under the closure root, with the
/// pinned launcher itself excluded because it is verified on its own.
///
/// The walk is bounded by a file count, so a closure root pointed at an
/// unexpectedly large tree refuses rather than hashing without end.
pub(crate) fn closure_digest(root: &Path, launcher: &Path) -> Result<String, SvgRasterError> {
    const MAX_CLOSURE_FILES: usize = 4096;
    let unreadable = |role_free: &str| SvgRasterError::new("rasterizer-hash-drift", role_free);
    let mut files = Vec::new();
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
            if kind.is_symlink() {
                // A symlink is a name, not a member: its target is
                // hashed on its own when it lies inside the closure.
                continue;
            }
            if kind.is_dir() {
                stack.push(path);
                continue;
            }
            if !kind.is_file() {
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
            if files.len() >= MAX_CLOSURE_FILES {
                return Err(unreadable(
                    "the runtime closure holds more files than expected",
                ));
            }
            files.push(path);
        }
    }
    let mut rows: Vec<(Vec<u8>, PathBuf)> = files
        .into_iter()
        .map(|path| {
            let relative = path
                .strip_prefix(root)
                .unwrap_or(path.as_path())
                .as_os_str()
                .as_encoded_bytes()
                .to_vec();
            (relative, path)
        })
        .collect();
    rows.sort();
    let mut hasher = blake3::Hasher::new();
    for (relative, path) in rows {
        let hash = crate::hash::hash_file(&path)
            .map_err(|_| unreadable("a runtime closure member cannot be read"))?;
        hasher.update(&relative);
        hasher.update(b"\n");
        hasher.update(hash.as_bytes());
        hasher.update(b"\n");
    }
    Ok(hasher.finalize().to_hex().to_string())
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
    if let (Some(root), Some(expected)) = (&entry.closure_root, &entry.closure_blake3) {
        let actual = closure_digest(Path::new(root), &path)?;
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
            closure_root: None,
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
        // Attribute names must stand alone.
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
        ] {
            let error = parse_geometry(source).unwrap_err();
            assert_eq!(error.code, "raster-geometry-mismatch", "{source:?}");
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
        let first = closure_digest(root, &launcher).unwrap();
        // Stable across calls, and the launcher's own bytes are not in
        // it: it is pinned on its own.
        assert_eq!(first, closure_digest(root, &launcher).unwrap());
        std::fs::write(&launcher, b"a different launcher").unwrap();
        assert_eq!(first, closure_digest(root, &launcher).unwrap());
        // A helper that drifts while the launcher stands still changes
        // the digest, which is the skew this control exists for.
        std::fs::write(&helper, b"helper, but newer").unwrap();
        assert_ne!(first, closure_digest(root, &launcher).unwrap());
    }

    /// A runtime that records every step and answers from a script,
    /// so the order the leg runs its assertions in is asserted
    /// directly rather than inferred.
    struct TracingRuntime {
        trace: std::cell::RefCell<Vec<String>>,
        fail_verify: Option<String>,
        dimensions: std::cell::RefCell<Vec<(u32, u32)>>,
    }

    impl TracingRuntime {
        fn new(dimensions: &[(u32, u32)]) -> TracingRuntime {
            TracingRuntime {
                trace: std::cell::RefCell::new(Vec::new()),
                fail_verify: None,
                dimensions: std::cell::RefCell::new(dimensions.to_vec()),
            }
        }

        fn failing_on(role: &str, dimensions: &[(u32, u32)]) -> TracingRuntime {
            TracingRuntime {
                fail_verify: Some(role.to_string()),
                ..TracingRuntime::new(dimensions)
            }
        }

        fn steps(&self) -> Vec<String> {
            self.trace.borrow().clone()
        }
    }

    impl ProviderRuntime for TracingRuntime {
        fn verify(&self, entry: &SvgRoleEntry) -> Result<PathBuf, SvgRasterError> {
            self.trace
                .borrow_mut()
                .push(format!("verify {}", entry.role));
            if self.fail_verify.as_deref() == Some(entry.role.as_str()) {
                return Err(SvgRasterError::new(
                    "rasterizer-hash-drift",
                    format!(
                        "provider component {} does not match its pinned hash",
                        entry.role
                    ),
                ));
            }
            Ok(PathBuf::from(&entry.path))
        }

        fn run(
            &self,
            _path: &Path,
            argv: &[String],
            role: &str,
            env: &[(String, String)],
        ) -> Result<(), SvgRasterError> {
            self.trace
                .borrow_mut()
                .push(format!("run {role} {}", argv.len()));
            if role == PROVIDER_ROLE_RASTER {
                // The rasterizer always receives a fresh profile root
                // under this invocation's jail and nothing else.
                let names: Vec<&str> = env.iter().map(|(name, _)| name.as_str()).collect();
                assert!(names.contains(&"HOME"), "{names:?}");
                assert!(names.contains(&"TMPDIR"), "{names:?}");
            }
            Ok(())
        }

        fn dimensions(&self, _path: &Path) -> Result<(u32, u32), SvgRasterError> {
            let mut queue = self.dimensions.borrow_mut();
            let next = if queue.len() > 1 {
                queue.remove(0)
            } else {
                queue[0]
            };
            self.trace.borrow_mut().push("dimensions".to_string());
            Ok(next)
        }

        fn read(&self, _path: &Path) -> Result<Vec<u8>, SvgRasterError> {
            self.trace.borrow_mut().push("read".to_string());
            Ok(b"flattened bytes".to_vec())
        }
    }

    fn request(dir: &Path) -> SvgRasterRequest {
        std::fs::write(
            dir.join(JAIL_SOURCE),
            b"<svg width=\"1600\" height=\"900\"><text>x</text></svg>",
        )
        .unwrap();
        SvgRasterRequest {
            input: JAIL_SOURCE.to_string(),
            roles: vec![entry(PROVIDER_ROLE_RASTER), entry(PROVIDER_ROLE_ENCODER)],
        }
    }

    /// Runs one request with the jail as the working directory, which
    /// is where the leg reads and writes.
    fn in_jail<T>(body: impl FnOnce(&Path) -> T) -> T {
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        let jail = dir.path().canonicalize().unwrap();
        let previous = std::env::current_dir().unwrap();
        std::env::set_current_dir(&jail).unwrap();
        let result = body(&jail);
        std::env::set_current_dir(previous).unwrap();
        result
    }

    #[test]
    fn every_execution_is_verified_immediately_before_it_runs() {
        // The ruled order, asserted as a sequence: each component is
        // verified and then run, and the second verification happens
        // after the first execution, never hoisted beside it. A
        // verification that covered both components once could not
        // produce this trace.
        let runtime = TracingRuntime::new(&[(1600, 900)]);
        let ok = in_jail(|jail| rasterize_with(&request(jail), &runtime)).unwrap();
        assert_eq!(ok.width, 1600);
        assert_eq!(
            runtime.steps(),
            vec![
                format!("verify {PROVIDER_ROLE_RASTER}"),
                format!("run {PROVIDER_ROLE_RASTER} 16"),
                "dimensions".to_string(),
                format!("verify {PROVIDER_ROLE_ENCODER}"),
                format!("run {PROVIDER_ROLE_ENCODER} 10"),
                "dimensions".to_string(),
                "read".to_string(),
            ]
        );
    }

    #[test]
    fn a_refused_component_stops_the_sequence_at_that_point() {
        // The rasterizer's own refusal stops everything: no execution
        // of either component, and no recognition input produced.
        let runtime = TracingRuntime::failing_on(PROVIDER_ROLE_RASTER, &[(1600, 900)]);
        let error = in_jail(|jail| rasterize_with(&request(jail), &runtime)).unwrap_err();
        assert_eq!(error.code, "rasterizer-hash-drift");
        assert_eq!(
            runtime.steps(),
            vec![format!("verify {PROVIDER_ROLE_RASTER}")]
        );

        // The encoder's refusal comes after the rasterizer has run, and
        // the flatten never happens.
        let runtime = TracingRuntime::failing_on(PROVIDER_ROLE_ENCODER, &[(1600, 900)]);
        let error = in_jail(|jail| rasterize_with(&request(jail), &runtime)).unwrap_err();
        assert_eq!(error.code, "rasterizer-hash-drift");
        assert_eq!(
            runtime.steps(),
            vec![
                format!("verify {PROVIDER_ROLE_RASTER}"),
                format!("run {PROVIDER_ROLE_RASTER} 16"),
                "dimensions".to_string(),
                format!("verify {PROVIDER_ROLE_ENCODER}"),
            ]
        );
    }

    #[test]
    fn a_wrong_aspect_render_never_reaches_the_encoder() {
        // A square render of a wide source fails the cross-axis pair
        // before the encoder is verified, so no flatten runs on a
        // raster the geometry already refused.
        let runtime = TracingRuntime::new(&[(1536, 1536)]);
        let error = in_jail(|jail| rasterize_with(&request(jail), &runtime)).unwrap_err();
        assert_eq!(error.code, "raster-geometry-mismatch");
        assert!(
            !runtime
                .steps()
                .iter()
                .any(|step| step.contains(PROVIDER_ROLE_ENCODER)),
            "{:?}",
            runtime.steps()
        );
    }

    #[test]
    fn an_over_area_render_is_refused_before_the_encoder_too() {
        // 1800 by 1400 keeps the source aspect closely enough to pass
        // the geometry pair and still exceeds the encoder-input area
        // cap, so the area layer is what refuses it.
        let source = b"<svg width=\"1800\" height=\"1400\"><text>x</text></svg>";
        let runtime = TracingRuntime::new(&[(1800, 1400)]);
        let error = in_jail(|jail| {
            std::fs::write(jail.join(JAIL_SOURCE), source).unwrap();
            rasterize_with(
                &SvgRasterRequest {
                    input: JAIL_SOURCE.to_string(),
                    roles: vec![entry(PROVIDER_ROLE_RASTER), entry(PROVIDER_ROLE_ENCODER)],
                },
                &runtime,
            )
        })
        .unwrap_err();
        assert_eq!(error.code, "encoder-area-cap");
        assert!(
            !runtime
                .steps()
                .iter()
                .any(|step| step.contains(PROVIDER_ROLE_ENCODER)),
            "{:?}",
            runtime.steps()
        );
    }

    #[test]
    fn a_flatten_that_changes_the_dimensions_is_refused() {
        // The confirmation after the flatten: an encoder that resizes
        // is refused rather than handing the recognition a raster the
        // geometry assertion never saw.
        let runtime = TracingRuntime::new(&[(1600, 900), (800, 450)]);
        let error = in_jail(|jail| rasterize_with(&request(jail), &runtime)).unwrap_err();
        assert_eq!(error.code, "raster-geometry-mismatch");
    }

    #[test]
    fn a_missing_role_is_refused_before_anything_runs() {
        let runtime = TracingRuntime::new(&[(1600, 900)]);
        let error = in_jail(|jail| {
            let mut request = request(jail);
            request
                .roles
                .retain(|role| role.role != PROVIDER_ROLE_ENCODER);
            rasterize_with(&request, &runtime)
        })
        .unwrap_err();
        assert_eq!(error.code, "rasterizer-missing");
        assert!(error.message.contains(PROVIDER_ROLE_ENCODER));
        assert!(runtime.steps().is_empty(), "{:?}", runtime.steps());
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
