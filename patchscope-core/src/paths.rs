//! Where patchscope keeps its cache, audit log and policy file.

use directories::ProjectDirs;
use std::path::PathBuf;

fn dirs() -> Option<ProjectDirs> {
    ProjectDirs::from("io.github", "RobS96", "patchscope")
}

/// Research responses (OSV, KEV, EPSS, endoflife.date).
pub fn cache_dir() -> Option<PathBuf> {
    dirs().map(|d| d.cache_dir().to_path_buf())
}

/// The apply audit log and lock file.
pub fn data_dir() -> Option<PathBuf> {
    dirs().map(|d| d.data_local_dir().to_path_buf())
}

/// `patchscope.toml`, when present.
pub fn policy_file() -> Option<PathBuf> {
    dirs().map(|d| d.config_dir().join("patchscope.toml"))
}

pub fn audit_log() -> Option<PathBuf> {
    data_dir().map(|d| d.join("audit.jsonl"))
}
