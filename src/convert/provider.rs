//! The deployment-owned provider configuration: the opt-in surface that
//! wires an external rasterizer into the svg leg.
//!
//! Two halves meet here. The expectations, a BLAKE3, an exact version
//! string, and an aggregate digest over the enumerated closure, are
//! versioned rules data, pinned per generic role label in the
//! `[image_ocr.svg_provider]` section exactly as the audio and image
//! runtimes pin theirs. The paths are deployment data: a deployment
//! writes one TOML file naming, per role label, the absolute path of the
//! executable that fills it and the two jail parameters its runtime
//! needs. The crate ships no path, no product name, and no default: with
//! no configuration the svg leg does not exist, and the jailed worker
//! re-hashes every supplied file against the rules-pinned expectation
//! before every execution.
//!
//! The schema is deliberately narrow. It carries exactly one provider,
//! `svg`, with exactly two roles, and `deny_unknown_fields` refuses
//! anything else, so a configuration that names another provider or
//! another role fails the run before traversal rather than quietly
//! enabling a capability this release never validated.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::{Error, Result};

/// The schema identifier every provider configuration must carry.
pub const PROVIDER_SCHEMA: &str = "text-mirror/provider@1";

/// The rasterizer role: the executable that renders the source to a
/// raster. Generic label only.
pub const PROVIDER_ROLE_RASTER: &str = "raster-browser";

/// The encoder role: the executable that flattens the raster onto an
/// opaque background. Generic label only.
pub const PROVIDER_ROLE_ENCODER: &str = "raster-magick";

/// The two roles one complete svg provider is made of. Both must be
/// present, or the configuration is refused.
pub const PROVIDER_ROLES: [&str; 2] = [PROVIDER_ROLE_RASTER, PROVIDER_ROLE_ENCODER];

/// Version of the svg provider adapter: the geometry derivation, the
/// fixed argument vectors, the per-exec assertion order, and the
/// closure verification. It is part of the effective rules version, so
/// a change here re-runs every provider-derived child.
pub const PROVIDER_ADAPTER_VERSION: &str = "1.0.0";

/// The per-axis geometry tolerance, in pixels, applied to both
/// cross-axis checks.
pub const PROVIDER_GEOMETRY_TOLERANCE_PX: i64 = 1;

/// The ordered flatten arguments, one constant so production and test
/// executions cannot drift apart. The trailing chunk exclusion is part
/// of the settled tuple: without it the encoder writes creation-time
/// chunks and the raster stops being byte-stable across cold starts.
pub const PROVIDER_FLATTEN_ARGS: [&str; 8] = [
    "-background",
    "white",
    "-alpha",
    "remove",
    "-alpha",
    "off",
    "-define",
    "png:exclude-chunks=date,time",
];

/// The rules-pinned expectations for one provider role: what the
/// jailed worker re-asserts about the executable a deployment supplies
/// for it, immediately before every execution.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProviderPin {
    /// Expected lowercase hex BLAKE3 of the executable's bytes.
    pub blake3: String,
    /// Exact version string the executable must report. Compared for
    /// equality against a token of its own version output; the raw
    /// output never leaves the worker.
    pub version: String,
    /// Aggregate closure digest over the role's enumerated closure: for
    /// each entry, the sorted relative path and BLAKE3 of every regular
    /// file under it with the pinned launcher excluded, a symlink by
    /// the target it names, then the sorted per-entry digests combined.
    /// Every regular file counts, not only the executables, because a
    /// policy file or a resource decides behavior as much as code does. Asserted before every
    /// execution beside the launcher hash, so a dependency that drifts
    /// while the launcher stands still is refused. Required for any
    /// role whose configuration enumerates a closure.
    #[serde(default)]
    pub closure_blake3: Option<String>,
}

/// One configured role: the deployment's path and the jail parameters
/// its runtime needs. Everything the worker asserts about the file
/// comes from the rules, never from here.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderRole {
    /// Absolute path of the executable filling this role. Deployment
    /// data: it never enters the versioned rules, a manifest record, an
    /// error message, or the effective rules version.
    pub path: PathBuf,
    /// The closure this role additionally needs to read and
    /// execute, enumerated: the helper and framework tree beside a
    /// launcher, or the specific library directories and files an
    /// encoder loads. Each entry is granted as its own subpath in the
    /// provider jail, so a directory grants its subtree and a file
    /// grants itself.
    ///
    /// Enumerate the measured dependencies, never a package store or
    /// any other shared root: everything under an entry is readable and
    /// executable inside the jail, and a shared root would put every
    /// unrelated package, and every other version of this one, inside
    /// the boundary. The rules-pinned aggregate digest over these
    /// entries is the integrity control that stands in for finer
    /// granularity, and it is required whenever this list is non-empty.
    #[serde(default)]
    pub closure_roots: Vec<PathBuf>,
    /// The service namespace the provider jail scopes registration to,
    /// when the role's runtime registers any. Deployment data, because
    /// the namespace names the installed product. Its shape is a closed
    /// grammar, not a free expression: see [`is_service_namespace`].
    #[serde(default)]
    pub jail_service_prefix: Option<String>,
    /// Name of an additional environment variable the worker points at
    /// the jail's temp directory, when the role's runtime reads one.
    /// Deployment data for the same reason, and a bounded identifier.
    #[serde(default)]
    pub jail_temp_env: Option<String>,
}

/// The svg provider: both roles, or no provider at all.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawProviders {
    #[serde(default)]
    svg: Option<BTreeMap<String, ProviderRole>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawProviderConfig {
    schema: String,
    #[serde(default)]
    providers: Option<RawProviders>,
}

/// A validated provider configuration.
///
/// `svg` is `Some` only when both roles were supplied and every field
/// validated. Every other input is either an empty configuration, which
/// leaves svg on its passthrough-only path, or a run configuration
/// error raised before traversal.
#[derive(Debug, Clone, Default)]
pub struct ProviderConfig {
    svg: Option<SvgProvider>,
}

/// The complete svg provider: the rasterizer and the encoder.
#[derive(Debug, Clone)]
pub struct SvgProvider {
    /// The rasterizer role.
    pub raster: ProviderRole,
    /// The encoder role.
    pub encoder: ProviderRole,
}

fn rules_error(message: String) -> Error {
    Error::Rules {
        name: "provider-config".to_string(),
        message,
    }
}

/// Whether a string is a lowercase hex BLAKE3.
fn is_lower_hex_256(value: &str) -> bool {
    value.len() == 64
        && value
            .chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
}

/// Whether a version string is safe to compare and to name in a
/// configuration: printable ASCII without quotes or whitespace, so it
/// can never carry a path, a banner line, or a host identity.
fn is_plain_version(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '+'))
}

/// Whether a value is a service namespace in the one shape the provider
/// jail accepts.
///
/// The grammar is closed and anchored: a caret, then one to eight
/// dot-separated segments of ASCII letters, digits, hyphen, or
/// underscore, each written with the dot escaped as `\.`, ending in
/// one escaped dot. `^a\.b\.C\.` is the whole language. It is a
/// literal namespace prefix, not an expression: no alternation, no
/// classes, no quantifiers, no unescaped metacharacter, so a supplied
/// value can widen the registration allowance to exactly the names
/// under that prefix and to nothing else. A deployment supplying any
/// other shape is refused before the walk starts.
pub fn is_service_namespace(value: &str) -> bool {
    const MAX_SEGMENTS: usize = 8;
    const MAX_SEGMENT: usize = 64;
    if value.len() > 128 {
        return false;
    }
    let Some(rest) = value.strip_prefix('^') else {
        return false;
    };
    let Some(body) = rest.strip_suffix("\\.") else {
        return false;
    };
    let segments: Vec<&str> = body.split("\\.").collect();
    if segments.is_empty() || segments.len() > MAX_SEGMENTS {
        return false;
    }
    segments.iter().all(|segment| {
        !segment.is_empty()
            && segment.len() <= MAX_SEGMENT
            && segment
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    })
}

/// The directories many unrelated programs live in. Granting one whole
/// would put every one of them, and every other version of the pinned
/// component, inside the jail, which is the opposite of an enumerated
/// closure. A configuration naming one is refused before the walk.
///
/// The list is not a security boundary on its own: the boundary is the
/// enumeration a deployment writes down and the aggregate digest the
/// rules pin over it. This refuses the mistakes that would make both
/// meaningless.
const SHARED_ROOTS: &[&str] = &[
    "/",
    "/Applications",
    "/Library",
    "/System",
    "/Users",
    "/bin",
    "/etc",
    "/home",
    "/nix/store",
    "/opt",
    "/opt/homebrew",
    "/opt/homebrew/Cellar",
    "/opt/homebrew/bin",
    "/opt/homebrew/lib",
    "/opt/homebrew/opt",
    "/private/tmp",
    "/private/var",
    "/sbin",
    "/tmp",
    "/usr",
    "/usr/bin",
    "/usr/lib",
    "/usr/local",
    "/usr/local/bin",
    "/usr/local/lib",
    "/usr/sbin",
    "/usr/share",
    "/var",
];

/// Whether a closure entry names one of those shared roots, or is so
/// shallow it can only be one. Judged on the path as written and, when
/// it exists, on the tree it really names, so an alias through `..` or
/// a symlink whose target is a shared root is refused the same way.
pub fn is_shared_root(path: &Path) -> bool {
    if names_shared_root(path) {
        return true;
    }
    match std::fs::canonicalize(path) {
        Ok(real) => names_shared_root(&real),
        Err(_) => false,
    }
}

fn names_shared_root(path: &Path) -> bool {
    let text = path.to_string_lossy();
    let trimmed = text.trim_end_matches('/');
    let normalized = if trimmed.is_empty() { "/" } else { trimmed };
    if SHARED_ROOTS.contains(&normalized) {
        return true;
    }
    // A single top-level directory nobody listed is still a shared root
    // by shape.
    path.components().count() < 3
}

/// Whether a path is absolute and in normal form: the root, then plain
/// components only, no `.` and no `..`. A path that is not cannot be
/// compared with anything by its text.
pub fn is_normal_form(path: &Path) -> bool {
    use std::path::Component;
    path.is_absolute()
        && path
            .components()
            .all(|c| matches!(c, Component::RootDir | Component::Normal(_)))
}

/// Whether a path's last component is itself a symlink. An enumerated
/// entry must be a real directory or a real regular file: the grant
/// is rendered on the path, and the digest never follows a link, so a
/// link entry would grant one tree and measure another.
pub fn is_symlink_entry(path: &Path) -> bool {
    std::fs::symlink_metadata(path)
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false)
}

/// The tree a path really names, or `None` when it cannot be resolved.
/// Every containment decision and every rendered grant is made on this
/// form, never on the text as written.
pub fn canonical(path: &Path) -> Option<PathBuf> {
    std::fs::canonicalize(path).ok()
}

/// Whether one canonical path lies under another, component-wise.
pub fn lies_inside(real_path: &Path, real_root: &Path) -> bool {
    real_path == real_root || real_path.starts_with(real_root)
}

/// Whether an environment variable name is a bounded identifier: an
/// upper-case letter or underscore, then up to sixty-three upper-case
/// letters, digits, or underscores.
pub fn is_env_name(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first.is_ascii_uppercase() || first == '_')
        && value.len() <= 64
        && chars.all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
}

impl ProviderPin {
    /// Validates one rules pin: hashes are lowercase hex and the version
    /// is a plain token.
    pub(crate) fn validate(&self, role: &str) -> std::result::Result<(), String> {
        if !is_lower_hex_256(&self.blake3) {
            return Err(format!(
                "[image_ocr.svg_provider] role {role:?} blake3 is not a lowercase hex BLAKE3"
            ));
        }
        if !is_plain_version(&self.version) {
            return Err(format!(
                "[image_ocr.svg_provider] role {role:?} version is not a plain version string"
            ));
        }
        if let Some(digest) = &self.closure_blake3
            && !is_lower_hex_256(digest)
        {
            return Err(format!(
                "[image_ocr.svg_provider] role {role:?} closure_blake3 is not a lowercase hex BLAKE3"
            ));
        }
        Ok(())
    }
}

/// Checks one configured role against its rules pin: the enumerated
/// closure and its pinned digest are a pair. A closure with no digest
/// would grant a subtree nothing asserts the contents of, and a digest
/// with no closure asserts nothing at all.
pub(crate) fn check_closure_is_pinned(
    role: &str,
    configured: &ProviderRole,
    pin: Option<&ProviderPin>,
) -> std::result::Result<(), String> {
    let pinned = pin.and_then(|pin| pin.closure_blake3.as_ref()).is_some();
    let enumerated = !configured.closure_roots.is_empty();
    match (enumerated, pinned) {
        (true, false) => Err(format!(
            "provider role {role:?} enumerates a closure that [image_ocr.svg_provider] does not pin"
        )),
        (false, true) => Err(format!(
            "provider role {role:?} has a pinned closure digest but enumerates no closure to compute it over"
        )),
        _ => Ok(()),
    }
}

/// Validates the `[image_ocr.svg_provider]` rules section: the two
/// roles and no other, both present when any is, every value in shape.
pub(crate) fn validate_pins(
    pins: &BTreeMap<String, ProviderPin>,
) -> std::result::Result<(), String> {
    for role in pins.keys() {
        if !PROVIDER_ROLES.contains(&role.as_str()) {
            return Err(format!(
                "[image_ocr.svg_provider] names unknown role {role:?}"
            ));
        }
    }
    if !pins.is_empty() {
        for role in PROVIDER_ROLES {
            if !pins.contains_key(role) {
                return Err(format!(
                    "[image_ocr.svg_provider] is missing role {role:?}: both roles form one complete provider"
                ));
            }
        }
    }
    for (role, pin) in pins {
        pin.validate(role)?;
    }
    Ok(())
}

impl ProviderRole {
    /// Validates one role's fields. Paths must be absolute and the jail
    /// parameters must fit their closed shapes; the file itself is
    /// re-checked and re-hashed in the jailed worker before every
    /// execution, so nothing here is trusted later.
    fn validated(&self, role: &str) -> Result<ProviderRole> {
        if !self.path.is_absolute() {
            return Err(rules_error(format!(
                "provider role {role:?} needs an absolute path"
            )));
        }
        if !is_normal_form(&self.path) {
            return Err(rules_error(format!(
                "provider role {role:?} path is not in normal form: write the real absolute path without . or .. components"
            )));
        }
        // The executable and every entry are resolved to the trees
        // they really name, and everything after this point, the
        // shared-root refusal, containment, the rendered grants, and
        // the worker's own checks, sees only those. A path that cannot
        // be resolved is refused here rather than carried forward as
        // text nothing can vouch for.
        let real_path = canonical(&self.path).ok_or_else(|| {
            rules_error(format!(
                "provider role {role:?} path {} cannot be resolved",
                self.path.display()
            ))
        })?;
        let mut real_roots = Vec::with_capacity(self.closure_roots.len());
        for root in &self.closure_roots {
            if !root.is_absolute() {
                return Err(rules_error(format!(
                    "provider role {role:?} needs absolute closure_roots"
                )));
            }
            if !is_normal_form(root) {
                return Err(rules_error(format!(
                    "provider role {role:?} closure_roots entry {} is not in normal form: write the real absolute path without . or .. components",
                    root.display()
                )));
            }
            if is_symlink_entry(root) {
                return Err(rules_error(format!(
                    "provider role {role:?} closure_roots entry {} is a symlink: enumerate the real path it names",
                    root.display()
                )));
            }
            if is_shared_root(root) {
                return Err(rules_error(format!(
                    "provider role {role:?} closure_roots entry {} is a shared root: enumerate the measured dependencies instead",
                    root.display()
                )));
            }
            let real_root = canonical(root).ok_or_else(|| {
                rules_error(format!(
                    "provider role {role:?} closure_roots entry {} cannot be resolved",
                    root.display()
                ))
            })?;
            if is_shared_root(&real_root) {
                return Err(rules_error(format!(
                    "provider role {role:?} closure_roots entry {} is a shared root: enumerate the measured dependencies instead",
                    root.display()
                )));
            }
            real_roots.push(real_root);
        }
        // A role that enumerates a closure must sit inside it: the
        // executable is what the closure exists for, and an executable
        // outside every entry would be authorized by its literal grant
        // alone while its own tree stays unmeasured. Inside is decided
        // on the resolved paths, component-wise, so neither `..` nor a
        // symlinked ancestor can place an executable in a closure it
        // does not really lie in.
        if !real_roots.is_empty() && !real_roots.iter().any(|root| lies_inside(&real_path, root)) {
            return Err(rules_error(format!(
                "provider role {role:?} executable lies outside every closure_roots entry"
            )));
        }
        if let Some(prefix) = &self.jail_service_prefix
            && !is_service_namespace(prefix)
        {
            return Err(rules_error(format!(
                "provider-parameter-invalid: provider role {role:?} jail_service_prefix is not an anchored dotted namespace"
            )));
        }
        if let Some(name) = &self.jail_temp_env
            && !is_env_name(name)
        {
            return Err(rules_error(format!(
                "provider-parameter-invalid: provider role {role:?} jail_temp_env is not a bounded identifier"
            )));
        }
        Ok(ProviderRole {
            path: real_path,
            closure_roots: real_roots,
            jail_service_prefix: self.jail_service_prefix.clone(),
            jail_temp_env: self.jail_temp_env.clone(),
        })
    }
}

impl ProviderConfig {
    /// A configuration with no provider: the shape a run has when no
    /// configuration file is supplied.
    pub fn empty() -> ProviderConfig {
        ProviderConfig::default()
    }

    /// The svg provider, when the configuration carries a complete one.
    pub fn svg(&self) -> Option<&SvgProvider> {
        self.svg.as_ref()
    }

    /// Parses and validates one configuration text.
    pub fn parse(text: &str) -> Result<ProviderConfig> {
        let raw: RawProviderConfig =
            toml::from_str(text).map_err(|e| rules_error(e.to_string()))?;
        if raw.schema != PROVIDER_SCHEMA {
            return Err(rules_error(format!(
                "unrecognized provider schema {:?}, expected {PROVIDER_SCHEMA:?}",
                raw.schema
            )));
        }
        let Some(providers) = raw.providers else {
            return Ok(ProviderConfig::empty());
        };
        let Some(roles) = providers.svg else {
            return Ok(ProviderConfig::empty());
        };
        for name in roles.keys() {
            if !PROVIDER_ROLES.contains(&name.as_str()) {
                return Err(rules_error(format!(
                    "[providers.svg] names unknown role {name:?}"
                )));
            }
        }
        for role in PROVIDER_ROLES {
            if !roles.contains_key(role) {
                return Err(rules_error(format!(
                    "[providers.svg] is missing role {role:?}: both roles form one complete provider"
                )));
            }
        }
        let mut resolved = Vec::new();
        for role in PROVIDER_ROLES {
            resolved.push(roles[role].validated(role)?);
        }
        let encoder = resolved.pop().expect("both roles resolved");
        let raster = resolved.pop().expect("both roles resolved");
        Ok(ProviderConfig {
            svg: Some(SvgProvider { raster, encoder }),
        })
    }

    /// Loads a configuration from a TOML file.
    pub fn load(path: &Path) -> Result<ProviderConfig> {
        let text = std::fs::read_to_string(path).map_err(|e| Error::io("read", path, e))?;
        ProviderConfig::parse(&text)
    }

    /// The material the effective rules version digests for a configured
    /// provider: presence, the generic role labels, the rules-pinned
    /// hashes and versions, the adapter version, the geometry and
    /// flatten options, and the jail identity, which is the profile
    /// template's BLAKE3 together with the two parameter values the
    /// deployment supplied.
    ///
    /// Absolute paths are deliberately excluded, so moving an identical
    /// pinned provider to another path re-runs nothing. The parameter
    /// values enter as digest material only, so they never appear in a
    /// record: two runs under different values, or under an edited
    /// template, are different effective versions and never checkpoint
    /// against each other.
    pub fn digest_material(
        pins: &BTreeMap<String, ProviderPin>,
        jail: &ProviderJailIdentity,
    ) -> Option<String> {
        let mut material = String::from("provider=svg\n");
        for label in PROVIDER_ROLES {
            let pin = pins.get(label)?;
            material.push_str(&format!("role={label}\n"));
            material.push_str(&format!("blake3={}\n", pin.blake3));
            material.push_str(&format!("version={}\n", pin.version));
            if let Some(digest) = &pin.closure_blake3 {
                material.push_str(&format!("closure={digest}\n"));
            }
        }
        material.push_str(&format!("adapter={PROVIDER_ADAPTER_VERSION}\n"));
        material.push_str(&format!(
            "geometry-tolerance-px={PROVIDER_GEOMETRY_TOLERANCE_PX}\n"
        ));
        material.push_str(&format!("flatten={}\n", PROVIDER_FLATTEN_ARGS.join(" ")));
        material.push_str(&format!(
            "area-cap={}\n",
            crate::convert::IMAGE_OCR_MAX_AREA_PX
        ));
        material.push_str(&format!(
            "template={}\n",
            jail.template_blake3.as_deref().unwrap_or("none")
        ));
        material.push_str(&format!(
            "service-prefix={}\n",
            jail.service_prefix.as_deref().unwrap_or_default()
        ));
        material.push_str(&format!(
            "temp-env={}\n",
            jail.temp_env.as_deref().unwrap_or_default()
        ));
        Some(material)
    }

    /// The effective-version suffix a configured provider contributes
    /// under the given pins and jail identity, or `None` when the pins
    /// are incomplete. The form is `svg.<12 hex>`, appended to the
    /// numeric rules version with a `+`.
    pub fn version_suffix(
        pins: &BTreeMap<String, ProviderPin>,
        jail: &ProviderJailIdentity,
    ) -> Option<String> {
        let material = Self::digest_material(pins, jail)?;
        let digest = crate::hash::hash_bytes(material.as_bytes());
        Some(format!("svg.{}", &digest[..12]))
    }

    /// The jail identity this configuration runs under: the profile
    /// template's BLAKE3 on this platform and the two parameter values
    /// the rasterizer role supplied.
    pub fn jail_identity(&self) -> ProviderJailIdentity {
        let raster = self.svg.as_ref().map(|svg| &svg.raster);
        ProviderJailIdentity {
            template_blake3: crate::runner_template_blake3(),
            service_prefix: raster.and_then(|role| role.jail_service_prefix.clone()),
            temp_env: raster.and_then(|role| role.jail_temp_env.clone()),
        }
    }
}

/// The parts of a provider's identity that come from the jail rather
/// than the pins: which profile template renders it, and the two
/// parameter values it was rendered with.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProviderJailIdentity {
    /// BLAKE3 of the provider profile template, `None` where no
    /// provider profile is measured.
    pub template_blake3: Option<String>,
    /// The service namespace the deployment supplied.
    pub service_prefix: Option<String>,
    /// The temp-directory variable the deployment supplied.
    pub temp_env: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(body: &str) -> String {
        format!("schema = \"{PROVIDER_SCHEMA}\"\n{body}")
    }

    /// A deployment on disk: both executables and a dependency in real
    /// directories, because every path is resolved at parse and a path
    /// that cannot be resolved is refused.
    struct Deploy {
        _dir: tempfile::TempDir,
        root: PathBuf,
    }

    impl Deploy {
        fn new() -> Deploy {
            let dir = tempfile::tempdir().unwrap();
            let root = dir.path().canonicalize().unwrap().join("deploy");
            for rel in [
                "raster/bin/raster",
                "encoder/bin/encoder",
                "dependency/lib/dep.dylib",
                "elsewhere/bin/raster",
            ] {
                let path = root.join(rel);
                std::fs::create_dir_all(path.parent().unwrap()).unwrap();
                std::fs::write(&path, b"program").unwrap();
            }
            Deploy { _dir: dir, root }
        }

        fn at(&self, rel: &str) -> String {
            self.root.join(rel).display().to_string()
        }

        fn raster_path_line(&self) -> String {
            format!("path = \"{}\"", self.at("raster/bin/raster"))
        }

        fn raster_roots_line(&self) -> String {
            format!("closure_roots = [\"{}\"]", self.at("raster"))
        }

        fn encoder_path_line(&self) -> String {
            format!("path = \"{}\"", self.at("encoder/bin/encoder"))
        }

        fn encoder_roots_line(&self) -> String {
            format!(
                "closure_roots = [\"{}\", \"{}\"]",
                self.at("encoder"),
                self.at("dependency/lib/dep.dylib")
            )
        }

        fn complete(&self) -> String {
            config(&format!(
                "\n[providers.svg.\"{PROVIDER_ROLE_RASTER}\"]\n{}\n{}\n\
                 jail_service_prefix = \"^ex\\\\.ample\\\\.Product\\\\.\"\n\
                 jail_temp_env = \"EXAMPLE_TMPDIR\"\n\n\
                 [providers.svg.\"{PROVIDER_ROLE_ENCODER}\"]\n{}\n{}\n",
                self.raster_path_line(),
                self.raster_roots_line(),
                self.encoder_path_line(),
                self.encoder_roots_line(),
            ))
        }
    }

    fn pins() -> BTreeMap<String, ProviderPin> {
        let mut pins = BTreeMap::new();
        pins.insert(
            PROVIDER_ROLE_RASTER.to_string(),
            ProviderPin {
                blake3: "a".repeat(64),
                version: "151.0.7922.174".to_string(),
                closure_blake3: Some("b".repeat(64)),
            },
        );
        pins.insert(
            PROVIDER_ROLE_ENCODER.to_string(),
            ProviderPin {
                blake3: "c".repeat(64),
                version: "7.1.2-29".to_string(),
                closure_blake3: None,
            },
        );
        pins
    }

    #[test]
    fn a_complete_configuration_resolves_both_roles() {
        let deploy = Deploy::new();
        let parsed = ProviderConfig::parse(&deploy.complete()).unwrap();
        let svg = parsed.svg().expect("both roles present");
        assert_eq!(svg.raster.path, deploy.root.join("raster/bin/raster"));
        assert_eq!(
            svg.raster.jail_service_prefix.as_deref(),
            Some(r"^ex\.ample\.Product\.")
        );
        assert_eq!(svg.raster.jail_temp_env.as_deref(), Some("EXAMPLE_TMPDIR"));
        assert_eq!(
            svg.encoder.closure_roots,
            vec![
                deploy.root.join("encoder"),
                deploy.root.join("dependency/lib/dep.dylib")
            ]
        );
        assert!(svg.encoder.jail_service_prefix.is_none());
    }

    #[test]
    fn an_empty_or_provider_free_configuration_carries_no_provider() {
        assert!(ProviderConfig::empty().svg().is_none());
        assert!(ProviderConfig::parse(&config("")).unwrap().svg().is_none());
        assert!(
            ProviderConfig::parse(&config("[providers]\n"))
                .unwrap()
                .svg()
                .is_none()
        );
    }

    #[test]
    fn an_incomplete_provider_block_is_a_configuration_error() {
        let one_role = config(&format!(
            "[providers.svg.\"{PROVIDER_ROLE_RASTER}\"]\npath = \"/deploy/raster\"\n"
        ));
        let error = ProviderConfig::parse(&one_role).unwrap_err();
        assert!(error.to_string().contains("missing role"), "{error}");
    }

    #[test]
    fn the_schema_carries_no_other_provider_and_no_other_role() {
        // HEIC has no provider in this schema, so a configuration that
        // names one is refused rather than silently ignored, and the
        // deferred routing cannot be reached through this file.
        let heic = config("[providers.heic.\"raster-browser\"]\npath = \"/x\"\n");
        let error = ProviderConfig::parse(&heic).unwrap_err();
        assert!(error.to_string().contains("unknown field"), "{error}");
        // A third role that was never validated for this leg is
        // refused by name, so the two-role provider cannot grow one
        // through configuration.
        let extra = config("[providers.svg.\"raster-transcoder\"]\npath = \"/x\"\n");
        let error = ProviderConfig::parse(&extra).unwrap_err();
        assert!(error.to_string().contains("unknown role"), "{error}");
        // The expectations are rules data and have no place here.
        let pinned = config(&format!(
            "[providers.svg.\"{PROVIDER_ROLE_RASTER}\"]\npath = \"/x\"\nblake3 = \"{}\"\n",
            "a".repeat(64)
        ));
        assert!(ProviderConfig::parse(&pinned).is_err());
    }

    #[test]
    fn a_wrong_schema_and_a_malformed_file_are_configuration_errors() {
        let error = ProviderConfig::parse("schema = \"text-mirror/provider@2\"\n").unwrap_err();
        assert!(error.to_string().contains("provider schema"), "{error}");
        assert!(ProviderConfig::parse("not = toml = at all").is_err());
        assert!(ProviderConfig::parse("").is_err());
    }

    #[test]
    fn paths_are_validated_before_a_run_starts() {
        let deploy = Deploy::new();
        let relative = deploy
            .complete()
            .replace(&deploy.raster_path_line(), "path = \"relative/raster\"");
        assert!(
            ProviderConfig::parse(&relative)
                .unwrap_err()
                .to_string()
                .contains("absolute path")
        );
        let relative_closure = deploy.complete().replace(
            &deploy.encoder_roots_line(),
            "closure_roots = [\"relative/lib\"]",
        );
        assert!(
            ProviderConfig::parse(&relative_closure)
                .unwrap_err()
                .to_string()
                .contains("closure_roots")
        );
        // A shared package or application root is refused: everything
        // under an entry is readable and executable in the jail, so a
        // store root would carry every unrelated package, and every
        // other version of this one, inside the boundary.
        for shared in [
            "/",
            "/opt",
            "/opt/homebrew",
            "/opt/homebrew/Cellar",
            "/opt/homebrew/opt",
            "/usr/lib",
            "/usr/local/lib",
            "/Applications",
            "/Library",
            "/System",
            "/bin",
            "/opt/homebrew/Cellar/",
        ] {
            let text = deploy.complete().replace(
                &deploy.encoder_roots_line(),
                &format!("closure_roots = [\"{shared}\"]"),
            );
            let error = ProviderConfig::parse(&text).unwrap_err().to_string();
            assert!(error.contains("shared root"), "{shared}: {error}");
        }
        // A specific versioned artifact under one of those roots is
        // exactly what an enumeration should name, so its shape is
        // accepted by the predicate.
        for named in [
            "/opt/homebrew/Cellar/example/1.2.3",
            "/opt/homebrew/Cellar/example/1.2.3/lib/libexample.dylib",
            "/Applications/Example.app",
        ] {
            assert!(!is_shared_root(Path::new(named)), "{named}");
        }
        // A component or an entry that does not exist cannot be
        // resolved, and is refused rather than carried as text.
        let missing = deploy.complete().replace(
            &deploy.raster_path_line(),
            &format!("path = \"{}\"", deploy.at("raster/bin/absent")),
        );
        let error = ProviderConfig::parse(&missing).unwrap_err().to_string();
        assert!(error.contains("cannot be resolved"), "{error}");
        let missing_entry = deploy.complete().replace(
            &deploy.encoder_roots_line(),
            &format!("closure_roots = [\"{}\"]", deploy.at("encoder-absent")),
        );
        let error = ProviderConfig::parse(&missing_entry)
            .unwrap_err()
            .to_string();
        assert!(error.contains("cannot be resolved"), "{error}");
        // A configuration that enumerates a closure the rules do not
        // pin is refused where the two meet, at registry construction.
        let parsed = ProviderConfig::parse(&deploy.complete()).unwrap();
        let svg = parsed.svg().unwrap();
        assert!(
            check_closure_is_pinned(
                PROVIDER_ROLE_RASTER,
                &svg.raster,
                pins().get(PROVIDER_ROLE_RASTER)
            )
            .is_ok()
        );
        let unpinned = ProviderPin {
            blake3: "a".repeat(64),
            version: "1".to_string(),
            closure_blake3: None,
        };
        let error = check_closure_is_pinned(PROVIDER_ROLE_RASTER, &svg.raster, Some(&unpinned))
            .unwrap_err();
        assert!(error.contains("does not pin"), "{error}");
        assert!(check_closure_is_pinned(PROVIDER_ROLE_RASTER, &svg.raster, None).is_err());
    }

    #[test]
    fn the_service_namespace_grammar_is_closed_and_anchored() {
        // The whole language: a caret, escaped-dot-separated segments,
        // a trailing escaped dot.
        for good in [
            r"^a\.",
            r"^com\.example\.",
            r"^com\.example\.Product\.",
            r"^org-name\.some_thing\.X9\.",
        ] {
            assert!(is_service_namespace(good), "{good}");
        }
        // Everything else is refused: a free expression, an unanchored
        // pattern, alternation, classes, quantifiers, an unescaped dot,
        // an empty segment, a missing trailing dot, and an over-long
        // value.
        for bad in [
            "",
            "^",
            r"^\.",
            r"com\.example\.",
            r"^com\.example",
            r"^com.example\.",
            r"^(org\.a|com\.b)\.",
            r"^com\.[a-z]+\.",
            r"^com\..*\.",
            r"^com\.\.example\.",
            r"^com\.exa mple\.",
            r#"^com\.ex"ample\."#,
            r".*",
            "^$",
        ] {
            assert!(!is_service_namespace(bad), "{bad:?}");
        }
        let long = format!("^{}\\.", "a".repeat(130));
        assert!(!is_service_namespace(&long));
        let many = format!("^{}\\.", ["a"; 9].join("\\."));
        assert!(!is_service_namespace(&many));
        let eight = format!("^{}\\.", ["a"; 8].join("\\."));
        assert!(is_service_namespace(&eight));
    }

    #[test]
    fn the_temp_variable_name_is_a_bounded_identifier() {
        for good in ["X", "_X", "MY_TMPDIR", "A1_B2", &"A".repeat(64)] {
            assert!(is_env_name(good), "{good}");
        }
        for bad in [
            "",
            "lower",
            "1ABC",
            "HAS-DASH",
            "HAS SPACE",
            "HAS=EQ",
            &"A".repeat(65),
        ] {
            assert!(!is_env_name(bad), "{bad:?}");
        }
    }

    #[test]
    fn an_out_of_shape_parameter_is_refused_by_name_before_any_run() {
        let deploy = Deploy::new();
        let free = deploy.complete().replace(
            r#"jail_service_prefix = "^ex\\.ample\\.Product\\.""#,
            r#"jail_service_prefix = "^(com\\.a|org\\.b)\\.""#,
        );
        let error = ProviderConfig::parse(&free).unwrap_err().to_string();
        assert!(error.contains("provider-parameter-invalid"), "{error}");
        assert!(error.contains("jail_service_prefix"), "{error}");
        let unanchored = deploy.complete().replace(
            r#"jail_service_prefix = "^ex\\.ample\\.Product\\.""#,
            r#"jail_service_prefix = "ex\\.ample\\.""#,
        );
        assert!(ProviderConfig::parse(&unanchored).is_err());
        let long_name = deploy.complete().replace(
            "jail_temp_env = \"EXAMPLE_TMPDIR\"",
            &format!("jail_temp_env = \"{}\"", "T".repeat(65)),
        );
        let error = ProviderConfig::parse(&long_name).unwrap_err().to_string();
        assert!(error.contains("provider-parameter-invalid"), "{error}");
        assert!(error.contains("jail_temp_env"), "{error}");
        let lower = deploy.complete().replace(
            "jail_temp_env = \"EXAMPLE_TMPDIR\"",
            "jail_temp_env = \"lowercase\"",
        );
        assert!(ProviderConfig::parse(&lower).is_err());
    }

    #[test]
    fn the_rules_pins_are_validated_as_a_pair() {
        assert!(validate_pins(&BTreeMap::new()).is_ok());
        assert!(validate_pins(&pins()).is_ok());
        let mut one = pins();
        one.remove(PROVIDER_ROLE_ENCODER);
        assert!(validate_pins(&one).unwrap_err().contains("missing role"));
        let mut extra = pins();
        extra.insert(
            "raster-transcoder".to_string(),
            ProviderPin {
                blake3: "a".repeat(64),
                version: "1".to_string(),
                closure_blake3: None,
            },
        );
        assert!(validate_pins(&extra).unwrap_err().contains("unknown role"));
        let mut bad_hash = pins();
        bad_hash.get_mut(PROVIDER_ROLE_RASTER).unwrap().blake3 = "SHOUTING".to_string();
        assert!(validate_pins(&bad_hash).unwrap_err().contains("BLAKE3"));
        let mut bad_version = pins();
        bad_version.get_mut(PROVIDER_ROLE_ENCODER).unwrap().version =
            "151 (build 7922)".to_string();
        assert!(validate_pins(&bad_version).unwrap_err().contains("version"));
        let mut bad_closure = pins();
        bad_closure
            .get_mut(PROVIDER_ROLE_RASTER)
            .unwrap()
            .closure_blake3 = Some("zz".to_string());
        assert!(
            validate_pins(&bad_closure)
                .unwrap_err()
                .contains("closure_blake3")
        );
    }

    fn identity() -> ProviderJailIdentity {
        ProviderJailIdentity {
            template_blake3: Some("t".repeat(64)),
            service_prefix: Some(r"^ex\.ample\.".to_string()),
            temp_env: Some("EXAMPLE_TMPDIR".to_string()),
        }
    }

    #[test]
    fn the_effective_version_suffix_covers_identity_and_excludes_paths() {
        let suffix = ProviderConfig::version_suffix(&pins(), &identity()).expect("complete pins");
        assert!(suffix.starts_with("svg."), "{suffix}");
        assert_eq!(suffix.len(), "svg.".len() + 12, "{suffix}");
        // Incomplete pins yield no suffix at all.
        let mut one = pins();
        one.remove(PROVIDER_ROLE_ENCODER);
        assert!(ProviderConfig::version_suffix(&one, &identity()).is_none());
        // Every pinned identity changes it.
        for mutate in [
            |p: &mut BTreeMap<String, ProviderPin>| {
                p.get_mut(PROVIDER_ROLE_RASTER).unwrap().blake3 = "1".repeat(64)
            },
            |p: &mut BTreeMap<String, ProviderPin>| {
                p.get_mut(PROVIDER_ROLE_RASTER).unwrap().closure_blake3 = Some("2".repeat(64))
            },
            |p: &mut BTreeMap<String, ProviderPin>| {
                p.get_mut(PROVIDER_ROLE_ENCODER).unwrap().blake3 = "3".repeat(64)
            },
            |p: &mut BTreeMap<String, ProviderPin>| {
                p.get_mut(PROVIDER_ROLE_ENCODER).unwrap().version = "7.1.2-30".to_string()
            },
        ] {
            let mut changed = pins();
            mutate(&mut changed);
            assert_ne!(
                ProviderConfig::version_suffix(&changed, &identity()),
                Some(suffix.clone())
            );
        }
        // The material names the generic labels, the adapter version,
        // the geometry and flatten options, the template, and the
        // parameters, and no path at all.
        let material = ProviderConfig::digest_material(&pins(), &identity()).unwrap();
        assert!(material.contains(PROVIDER_ROLE_RASTER));
        assert!(material.contains(PROVIDER_ROLE_ENCODER));
        assert!(material.contains(PROVIDER_ADAPTER_VERSION));
        assert!(material.contains("png:exclude-chunks=date,time"));
        assert!(material.contains("geometry-tolerance-px=1"));
        assert!(material.contains(&"t".repeat(64)));
        assert!(material.contains("EXAMPLE_TMPDIR"));
        assert!(!material.contains('/'), "{material}");
    }

    #[test]
    fn the_jail_identity_is_part_of_the_effective_version() {
        // The approved identity is the template plus the two parameter
        // values, so a different value for either, or an edited
        // template, is a different effective version: two such runs
        // never checkpoint against each other.
        let base = ProviderConfig::version_suffix(&pins(), &identity()).unwrap();
        let mut other_namespace = identity();
        other_namespace.service_prefix = Some(r"^an\.other\.".to_string());
        assert_ne!(
            ProviderConfig::version_suffix(&pins(), &other_namespace),
            Some(base.clone())
        );
        let mut other_variable = identity();
        other_variable.temp_env = Some("OTHER_TMPDIR".to_string());
        assert_ne!(
            ProviderConfig::version_suffix(&pins(), &other_variable),
            Some(base.clone())
        );
        let mut edited_template = identity();
        edited_template.template_blake3 = Some("u".repeat(64));
        assert_ne!(
            ProviderConfig::version_suffix(&pins(), &edited_template),
            Some(base.clone())
        );
        let mut no_parameters = identity();
        no_parameters.service_prefix = None;
        no_parameters.temp_env = None;
        assert_ne!(
            ProviderConfig::version_suffix(&pins(), &no_parameters),
            Some(base.clone())
        );
        // And the same identity yields the same version, so the digest
        // is a function of what was supplied and nothing else.
        assert_eq!(
            ProviderConfig::version_suffix(&pins(), &identity()),
            Some(base)
        );
        // A configuration's own identity carries its parameters.
        let deploy = Deploy::new();
        let parsed = ProviderConfig::parse(&deploy.complete()).unwrap();
        let identity = parsed.jail_identity();
        assert_eq!(
            identity.service_prefix.as_deref(),
            Some(r"^ex\.ample\.Product\.")
        );
        assert_eq!(identity.temp_env.as_deref(), Some("EXAMPLE_TMPDIR"));
    }

    #[test]
    fn an_executable_outside_its_own_closure_is_refused() {
        // A role that enumerates a closure must sit inside it, or its
        // literal grant would authorize an executable whose own tree is
        // unmeasured.
        let deploy = Deploy::new();
        let outside = deploy.complete().replace(
            &deploy.raster_roots_line(),
            &format!("closure_roots = [\"{}\"]", deploy.at("elsewhere")),
        );
        let error = ProviderConfig::parse(&outside).unwrap_err().to_string();
        assert!(error.contains("outside every closure_roots"), "{error}");
        // Inside as a subtree member, or as the entry itself, is fine.
        let as_entry = deploy.complete().replace(
            &deploy.raster_roots_line(),
            &format!("closure_roots = [\"{}\"]", deploy.at("raster/bin/raster")),
        );
        assert!(ProviderConfig::parse(&as_entry).is_ok());
        let among = deploy.complete().replace(
            &deploy.raster_roots_line(),
            &format!(
                "closure_roots = [\"{}\", \"{}\"]",
                deploy.at("elsewhere"),
                deploy.at("raster")
            ),
        );
        assert!(ProviderConfig::parse(&among).is_ok());
        // With no closure at all, the executable stands on its literal
        // grant alone, which is the shape of a self-contained component.
        let none = deploy
            .complete()
            .replace(&format!("{}\n", deploy.raster_roots_line()), "");
        assert!(ProviderConfig::parse(&none).is_ok());
    }

    #[test]
    fn containment_is_decided_on_resolved_paths() {
        // Inside means inside the tree the entry really names. A `..`
        // alias is not in normal form and is refused as written; a
        // symlinked ancestor that resolves outside the closure is
        // refused on the resolved path; and a symlinked ancestor that
        // resolves inside is accepted, with the resolved path kept.
        let deploy = Deploy::new();
        let dotted = deploy.complete().replace(
            &deploy.raster_path_line(),
            &format!("path = \"{}\"", deploy.at("raster/../elsewhere/bin/raster")),
        );
        let error = ProviderConfig::parse(&dotted).unwrap_err().to_string();
        assert!(error.contains("not in normal form"), "{error}");

        std::os::unix::fs::symlink(
            deploy.root.join("elsewhere"),
            deploy.root.join("raster/link"),
        )
        .unwrap();
        let escaping = deploy.complete().replace(
            &deploy.raster_path_line(),
            &format!("path = \"{}\"", deploy.at("raster/link/bin/raster")),
        );
        let error = ProviderConfig::parse(&escaping).unwrap_err().to_string();
        assert!(error.contains("outside every closure_roots"), "{error}");

        std::os::unix::fs::symlink(deploy.root.join("raster"), deploy.root.join("alias")).unwrap();
        let entering = deploy.complete().replace(
            &deploy.raster_path_line(),
            &format!("path = \"{}\"", deploy.at("alias/bin/raster")),
        );
        let parsed = ProviderConfig::parse(&entering).unwrap();
        assert_eq!(
            parsed.svg().unwrap().raster.path,
            deploy.root.join("raster/bin/raster")
        );

        // The shared-root refusal is decided the same way: an alias of
        // a shared root is refused as written, and a link whose target
        // is a shared root is refused as an entry.
        let alias = deploy.complete().replace(
            &deploy.encoder_roots_line(),
            "closure_roots = [\"/private/tmp/../tmp\"]",
        );
        let error = ProviderConfig::parse(&alias).unwrap_err().to_string();
        assert!(error.contains("not in normal form"), "{error}");
        std::os::unix::fs::symlink("/usr/lib", deploy.root.join("store")).unwrap();
        let linked = deploy.complete().replace(
            &deploy.encoder_roots_line(),
            &format!("closure_roots = [\"{}\"]", deploy.at("store")),
        );
        let error = ProviderConfig::parse(&linked).unwrap_err().to_string();
        assert!(error.contains("is a symlink"), "{error}");
        // And so is a link to a perfectly good tree: an entry is the
        // real directory or the real file, never a name for one.
        let real_link = deploy.complete().replace(
            &deploy.raster_roots_line(),
            &format!("closure_roots = [\"{}\"]", deploy.at("alias")),
        );
        let error = ProviderConfig::parse(&real_link).unwrap_err().to_string();
        assert!(error.contains("is a symlink"), "{error}");
    }
}
