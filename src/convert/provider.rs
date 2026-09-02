//! The deployment-owned provider configuration: the opt-in surface that
//! wires an external rasterizer into the svg leg.
//!
//! Two halves meet here. The expectations, a BLAKE3, an exact version
//! string, and an aggregate digest over the executable closure, are
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
    /// Aggregate closure digest: BLAKE3 over the sorted relative path
    /// and BLAKE3 of every executable file under the role's closure
    /// root, excluding the pinned launcher itself. Asserted before every
    /// execution beside the launcher hash, so a helper that drifts while
    /// the launcher stands still is refused. Absent for a role whose
    /// closure the rules do not pin.
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
    /// Root of the executable closure this role additionally needs to
    /// read and execute: the helper and framework tree beside a
    /// launcher, or the library store an encoder loads from. Granted as
    /// a subpath in the provider jail, so the rules-pinned aggregate
    /// digest is the integrity control that stands in for finer
    /// granularity.
    #[serde(default)]
    pub closure_root: Option<PathBuf>,
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
    fn validate(&self, role: &str) -> Result<()> {
        if !self.path.is_absolute() {
            return Err(rules_error(format!(
                "provider role {role:?} needs an absolute path"
            )));
        }
        if let Some(root) = &self.closure_root
            && !root.is_absolute()
        {
            return Err(rules_error(format!(
                "provider role {role:?} needs an absolute closure_root"
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
        Ok(())
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
        let mut resolved = Vec::new();
        for role in PROVIDER_ROLES {
            let Some(entry) = roles.get(role) else {
                return Err(rules_error(format!(
                    "[providers.svg] is missing role {role:?}: both roles form one complete provider"
                )));
            };
            entry.validate(role)?;
            resolved.push(entry.clone());
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
    /// hashes and versions, the adapter version, and the geometry and
    /// flatten options.
    ///
    /// Absolute paths are deliberately excluded, so moving an identical
    /// pinned provider does not invalidate a single converted artifact.
    pub fn digest_material(pins: &BTreeMap<String, ProviderPin>) -> Option<String> {
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
        Some(material)
    }

    /// The effective-version suffix a configured provider contributes
    /// under the given pins, or `None` when the pins are incomplete. The
    /// form is `svg.<12 hex>`, appended to the numeric rules version
    /// with a `+`.
    pub fn version_suffix(pins: &BTreeMap<String, ProviderPin>) -> Option<String> {
        let material = Self::digest_material(pins)?;
        let digest = crate::hash::hash_bytes(material.as_bytes());
        Some(format!("svg.{}", &digest[..12]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(body: &str) -> String {
        format!("schema = \"{PROVIDER_SCHEMA}\"\n{body}")
    }

    fn complete() -> String {
        config(&format!(
            r#"
[providers.svg."{PROVIDER_ROLE_RASTER}"]
path = "/deploy/raster"
closure_root = "/deploy/raster-closure"
jail_service_prefix = "^ex\\.ample\\.Product\\."
jail_temp_env = "EXAMPLE_TMPDIR"

[providers.svg."{PROVIDER_ROLE_ENCODER}"]
path = "/deploy/encoder"
closure_root = "/deploy/store"
"#
        ))
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
        let parsed = ProviderConfig::parse(&complete()).unwrap();
        let svg = parsed.svg().expect("both roles present");
        assert_eq!(svg.raster.path, PathBuf::from("/deploy/raster"));
        assert_eq!(
            svg.raster.jail_service_prefix.as_deref(),
            Some(r"^ex\.ample\.Product\.")
        );
        assert_eq!(svg.raster.jail_temp_env.as_deref(), Some("EXAMPLE_TMPDIR"));
        assert_eq!(
            svg.encoder.closure_root,
            Some(PathBuf::from("/deploy/store"))
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
        let relative =
            complete().replace("path = \"/deploy/raster\"", "path = \"relative/raster\"");
        assert!(
            ProviderConfig::parse(&relative)
                .unwrap_err()
                .to_string()
                .contains("absolute path")
        );
        let closure = complete().replace(
            "closure_root = \"/deploy/store\"",
            "closure_root = \"relative/store\"",
        );
        assert!(
            ProviderConfig::parse(&closure)
                .unwrap_err()
                .to_string()
                .contains("closure_root")
        );
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
        let free = complete().replace(
            r#"jail_service_prefix = "^ex\\.ample\\.Product\\.""#,
            r#"jail_service_prefix = "^(com\\.a|org\\.b)\\.""#,
        );
        let error = ProviderConfig::parse(&free).unwrap_err().to_string();
        assert!(error.contains("provider-parameter-invalid"), "{error}");
        assert!(error.contains("jail_service_prefix"), "{error}");
        let unanchored = complete().replace(
            r#"jail_service_prefix = "^ex\\.ample\\.Product\\.""#,
            r#"jail_service_prefix = "ex\\.ample\\.""#,
        );
        assert!(ProviderConfig::parse(&unanchored).is_err());
        let long_name = complete().replace(
            "jail_temp_env = \"EXAMPLE_TMPDIR\"",
            &format!("jail_temp_env = \"{}\"", "T".repeat(65)),
        );
        let error = ProviderConfig::parse(&long_name).unwrap_err().to_string();
        assert!(error.contains("provider-parameter-invalid"), "{error}");
        assert!(error.contains("jail_temp_env"), "{error}");
        let lower = complete().replace(
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

    #[test]
    fn the_effective_version_suffix_covers_identity_and_excludes_paths() {
        let suffix = ProviderConfig::version_suffix(&pins()).expect("complete pins");
        assert!(suffix.starts_with("svg."), "{suffix}");
        assert_eq!(suffix.len(), "svg.".len() + 12, "{suffix}");
        // Incomplete pins yield no suffix at all.
        let mut one = pins();
        one.remove(PROVIDER_ROLE_ENCODER);
        assert!(ProviderConfig::version_suffix(&one).is_none());
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
                ProviderConfig::version_suffix(&changed),
                Some(suffix.clone())
            );
        }
        // The material names the generic labels, the adapter version,
        // and the geometry and flatten options, and no path at all.
        let material = ProviderConfig::digest_material(&pins()).unwrap();
        assert!(material.contains(PROVIDER_ROLE_RASTER));
        assert!(material.contains(PROVIDER_ROLE_ENCODER));
        assert!(material.contains(PROVIDER_ADAPTER_VERSION));
        assert!(material.contains("png:exclude-chunks=date,time"));
        assert!(material.contains("geometry-tolerance-px=1"));
        assert!(!material.contains('/'), "{material}");
    }
}
