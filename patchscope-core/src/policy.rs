//! The update policy: what patchscope may plan and install. Loaded from
//! `patchscope.toml`; every field has a safe default, so the file is
//! optional.
//!
//! ```toml
//! [apply]
//! # Never touch these. Patterns match "manager:id", "manager:name", the id
//! # or the name, case-insensitively, with * as a wildcard.
//! protected = ["xcode*", "mas:497799835", "homebrew:postgresql@*"]
//! allow_os_upgrades = false        # new major OS versions
//! allow_restart_required = true    # updates that need a restart to finish
//! security_only = false            # plan only updates tied to a security finding
//! min_severity = "info"            # skip updates whose findings are all below this
//! max_actions = 100
//!
//! [managers]
//! disabled = ["mas"]
//! ```

use crate::model::{AvailableUpdate, ManagerId, Severity};
use crate::util::glob_match;
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct Policy {
    pub apply: ApplyPolicy,
    pub managers: ManagerPolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct ApplyPolicy {
    /// Protected patterns, in addition to [`DEFAULT_PROTECTED`].
    pub protected: Vec<String>,
    /// Also protect [`DEFAULT_PROTECTED`] (on unless explicitly turned off,
    /// so writing your own `protected` list cannot drop it by accident).
    pub default_protection: bool,
    pub allow_os_upgrades: bool,
    pub allow_restart_required: bool,
    pub security_only: bool,
    pub min_severity: Severity,
    pub max_actions: usize,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct ManagerPolicy {
    pub disabled: Vec<ManagerId>,
}

/// Protected by default: Xcode and its Command Line Tools. A new release
/// can drop support for the Mac it runs on (Xcode 26.6 is Apple-silicon
/// only), and Xcode is a 10+ GB download that should be a deliberate choice.
pub const DEFAULT_PROTECTED: [&str; 2] = ["*xcode*", "mas:497799835"];

impl Default for ApplyPolicy {
    fn default() -> Self {
        ApplyPolicy {
            protected: Vec::new(),
            default_protection: true,
            allow_os_upgrades: false,
            allow_restart_required: true,
            security_only: false,
            min_severity: Severity::Info,
            max_actions: 100,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("reading {path}: {source}")]
    Read {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("{path}: {source}")]
    Parse {
        path: String,
        #[source]
        source: toml::de::Error,
    },
}

impl Policy {
    pub fn from_toml(text: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(text)
    }

    pub fn to_toml(&self) -> String {
        toml::to_string_pretty(self).unwrap_or_default()
    }

    /// Load `path`; a missing file is the default policy, a malformed one
    /// is an error (a typo must not silently widen what gets installed).
    pub fn load(path: &Path) -> Result<Self, PolicyError> {
        match std::fs::read_to_string(path) {
            Ok(t) => Self::from_toml(&t).map_err(|source| PolicyError::Parse {
                path: path.display().to_string(),
                source,
            }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(source) => Err(PolicyError::Read {
                path: path.display().to_string(),
                source,
            }),
        }
    }

    /// Load a file the person named explicitly: a missing file is an error
    /// too, so a mistyped path cannot quietly drop their protections.
    pub fn load_existing(path: &Path) -> Result<Self, PolicyError> {
        if !path.exists() {
            return Err(PolicyError::Read {
                path: path.display().to_string(),
                source: std::io::Error::new(std::io::ErrorKind::NotFound, "no such policy file"),
            });
        }
        Self::load(path)
    }

    /// Load the default policy file location.
    pub fn load_default() -> Result<Self, PolicyError> {
        match crate::paths::policy_file() {
            Some(p) => Self::load(&p),
            None => Ok(Self::default()),
        }
    }

    /// The protected pattern `u` matches, if any.
    pub fn protection_for(&self, u: &AvailableUpdate) -> Option<&str> {
        let m = u.manager.as_str();
        let candidates = [
            format!("{m}:{}", u.id),
            format!("{m}:{}", u.name),
            u.id.clone(),
            u.name.clone(),
        ];
        let defaults = DEFAULT_PROTECTED
            .iter()
            .filter(|_| self.apply.default_protection)
            .copied();
        self.apply
            .protected
            .iter()
            .map(String::as_str)
            .chain(defaults)
            .find(|p| candidates.iter().any(|c| glob_match(p, c)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::UpdateKind;

    fn up(m: ManagerId, id: &str, name: &str) -> AvailableUpdate {
        AvailableUpdate {
            manager: m,
            id: id.into(),
            name: name.into(),
            installed_version: None,
            available_version: "2".into(),
            kind: UpdateKind::Application,
            security: false,
            restart_required: false,
            notes: None,
        }
    }

    #[test]
    fn xcode_and_its_command_line_tools_are_protected_by_default() {
        let p = Policy::default();
        let clt = up(
            ManagerId::Softwareupdate,
            "Command Line Tools for Xcode 26.5-26.5",
            "Command Line Tools for Xcode 26.5",
        );
        assert!(p.protection_for(&up(ManagerId::Mas, "497799835", "Xcode")).is_some());
        assert!(p.protection_for(&up(ManagerId::Homebrew, "xcodes", "xcodes")).is_some());
        assert!(p.protection_for(&clt).is_some());
        assert!(p.protection_for(&up(ManagerId::Homebrew, "git", "git")).is_none());

        // A custom list adds to the defaults rather than replacing them.
        let custom = Policy::from_toml("[apply]\nprotected = [\"homebrew:git\"]\n").unwrap();
        assert!(
            custom
                .protection_for(&up(ManagerId::Mas, "497799835", "Xcode"))
                .is_some()
        );
        assert!(custom.protection_for(&up(ManagerId::Homebrew, "git", "git")).is_some());
        // Only an explicit switch turns them off.
        let off = Policy::from_toml("[apply]\ndefault_protection = false\n").unwrap();
        assert!(off.protection_for(&clt).is_none());
    }

    #[test]
    fn toml_round_trip_and_defaults() {
        let p = Policy::from_toml("[apply]\nsecurity_only = true\nprotected = [\"homebrew:postgresql@*\"]\n[managers]\ndisabled = [\"mas\", \"npm-global\"]\n").unwrap();
        assert!(p.apply.security_only);
        assert!(!p.apply.allow_os_upgrades);
        assert_eq!(p.managers.disabled, [ManagerId::Mas, ManagerId::NpmGlobal]);
        assert!(
            p.protection_for(&up(ManagerId::Homebrew, "postgresql@16", "postgresql@16"))
                .is_some()
        );
        assert_eq!(Policy::from_toml(&p.to_toml()).unwrap(), p);
        assert_eq!(Policy::from_toml("").unwrap(), Policy::default());
    }

    #[test]
    fn typos_are_errors_not_silent_defaults() {
        assert!(Policy::from_toml("[apply]\nallow_os_upgrade = true\n").is_err());
        assert!(Policy::from_toml("[apply]\nmin_severity = \"severe\"\n").is_err());
    }

    #[test]
    fn the_documented_example_policy_parses() {
        let p = Policy::from_toml(include_str!("../../examples/patchscope.toml")).unwrap();
        assert!(p.apply.protected.iter().any(|x| x == "apt:linux-image-*"));
        assert!(!p.apply.allow_os_upgrades);
    }

    #[test]
    fn missing_file_is_default() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(Policy::load(&dir.path().join("none.toml")).unwrap(), Policy::default());
        assert!(
            Policy::load_existing(&dir.path().join("none.toml")).is_err(),
            "a named file must exist"
        );
        let bad = dir.path().join("bad.toml");
        std::fs::write(&bad, "[apply\n").unwrap();
        assert!(Policy::load(&bad).is_err());
    }
}
