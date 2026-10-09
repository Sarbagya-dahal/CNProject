// SPDX-License-Identifier: Apache-2.0
// virtiofsd V1 host-side request-validation filter — configuration

use serde::Deserialize;
use std::path::PathBuf;

/// Top-level filter configuration, loaded from a TOML file at startup.
/// All sections are optional; omitted sections use the defaults shown.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct FilterConfig {
    pub filter: FilterMeta,
    pub operations: OperationsConfig,
    pub names: NamesConfig,
    pub paths: PathsConfig,
    pub symlink: SymlinkConfig,
    pub audit: AuditConfig,
}

impl Default for FilterConfig {
    fn default() -> Self {
        FilterConfig {
            filter: FilterMeta::default(),
            operations: OperationsConfig::default(),
            names: NamesConfig::default(),
            paths: PathsConfig::default(),
            symlink: SymlinkConfig::default(),
            audit: AuditConfig::default(),
        }
    }
}

impl FilterConfig {
    /// Load configuration from a TOML file.
    pub fn from_file(path: &std::path::Path) -> std::io::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        toml::from_str(&content).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("filter config parse error: {}", e),
            )
        })
    }

    /// Validate the configuration, returning an error string if invalid.
    pub fn validate(&self) -> Result<(), String> {
        if !self.filter.enabled {
            return Ok(());
        }
        if self.audit.channel_capacity < 64 {
            return Err(format!(
                "audit.channel_capacity {} is below minimum of 64",
                self.audit.channel_capacity
            ));
        }
        if self.audit.channel_capacity > 65536 {
            return Err(format!(
                "audit.channel_capacity {} exceeds maximum of 65536",
                self.audit.channel_capacity
            ));
        }
        Ok(())
    }
}

/// Master filter settings.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct FilterMeta {
    /// If false, the filter is a transparent pass-through. Default: true.
    pub enabled: bool,
    /// Default verdict when no rule matches: "allow" or "deny". Default: "allow".
    pub default_policy: DefaultPolicy,
}

impl Default for FilterMeta {
    fn default() -> Self {
        FilterMeta {
            enabled: true,
            default_policy: DefaultPolicy::Allow,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DefaultPolicy {
    Allow,
    Deny,
}

/// Per-operation-category policy.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct OperationsConfig {
    /// Opcode::Read, Opcode::Readlink, Opcode::Readdir, Opcode::Readdirplus
    pub allow_read: bool,
    /// Opcode::Write, Opcode::Copyfilerange
    pub allow_write: bool,
    /// Opcode::Open, Opcode::Opendir
    pub allow_open: bool,
    /// Opcode::Create, Opcode::Mknod, Opcode::Mkdir, Opcode::Tmpfile
    pub allow_create: bool,
    /// Opcode::Unlink, Opcode::Rmdir
    pub allow_delete: bool,
    /// Opcode::Rename, Opcode::Rename2
    pub allow_rename: bool,
    /// Opcode::Setattr
    pub allow_setattr: bool,
    /// Opcode::Link
    pub allow_link: bool,
    /// Opcode::Symlink
    pub allow_symlink: bool,
    /// Opcode::Setxattr, Opcode::Getxattr, Opcode::Listxattr, Opcode::Removexattr
    pub allow_xattr: bool,
    /// Opcode::Fallocate
    pub allow_fallocate: bool,
    /// Opcode::Syncfs, Opcode::Fsync, Opcode::Fsyncdir
    pub allow_syncfs: bool,

    /// Fine-grained setattr controls (checked when allow_setattr = true).
    pub setattr: SetAttrConfig,
    /// Fine-grained open flag controls (checked when allow_open or allow_create is true).
    pub open_flags: OpenFlagsConfig,
}

impl Default for OperationsConfig {
    fn default() -> Self {
        OperationsConfig {
            allow_read: true,
            allow_write: true,
            allow_open: true,
            allow_create: true,
            allow_delete: true,
            allow_rename: true,
            allow_setattr: true,
            allow_link: true,
            allow_symlink: true,
            allow_xattr: true,
            allow_fallocate: true,
            allow_syncfs: true,
            setattr: SetAttrConfig::default(),
            open_flags: OpenFlagsConfig::default(),
        }
    }
}

/// Fine-grained setattr sub-policy (checked only when allow_setattr = true).
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SetAttrConfig {
    /// Allow changing file mode bits (chmod).
    pub allow_chmod: bool,
    /// Allow changing file ownership (chown).
    pub allow_chown: bool,
    /// Allow changing file size (truncate).
    pub allow_truncate: bool,
    /// Allow changing timestamps (utime).
    pub allow_utime: bool,
}

impl Default for SetAttrConfig {
    fn default() -> Self {
        SetAttrConfig {
            allow_chmod: true,
            allow_chown: true,
            allow_truncate: true,
            allow_utime: true,
        }
    }
}

/// Fine-grained open flag sub-policy.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct OpenFlagsConfig {
    pub deny_wronly: bool,
    pub deny_rdwr: bool,
    pub deny_append: bool,
    pub deny_trunc: bool,
    pub deny_direct_io: bool,
}

impl Default for OpenFlagsConfig {
    fn default() -> Self {
        OpenFlagsConfig {
            deny_wronly: false,
            deny_rdwr: false,
            deny_append: false,
            deny_trunc: false,
            deny_direct_io: false,
        }
    }
}

/// Leaf-name based policy, applied to all name-bearing operations.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct NamesConfig {
    /// Exact name denylist (case-sensitive byte comparison).
    pub deny_exact: Vec<String>,
    /// Name suffix denylist (e.g. ".key", ".pem").
    pub deny_suffixes: Vec<String>,
    /// Name prefix denylist (e.g. ".ssh", ".gnupg").
    pub deny_prefixes: Vec<String>,
}

impl Default for NamesConfig {
    fn default() -> Self {
        NamesConfig {
            deny_exact: vec![],
            deny_suffixes: vec![],
            deny_prefixes: vec![],
        }
    }
}

/// First-level path policy: only applied when parent_inode == ROOT_ID (1).
/// At that level, `name` is the direct child of the shared root.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PathsConfig {
    /// Exact names that are denied as direct children of the shared root.
    pub deny_root_children: Vec<String>,
}

impl Default for PathsConfig {
    fn default() -> Self {
        PathsConfig {
            deny_root_children: vec![],
        }
    }
}

/// Symlink creation policy (symlink FOLLOWING is handled by openat2 RESOLVE_IN_ROOT).
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SymlinkConfig {
    /// If false, deny symlinks with absolute targets (starting with '/').
    pub allow_absolute_targets: bool,
    /// If false, deny symlinks whose target contains '..' as a path component.
    pub allow_dotdot_targets: bool,
}

impl Default for SymlinkConfig {
    fn default() -> Self {
        SymlinkConfig {
            allow_absolute_targets: true,
            allow_dotdot_targets: true,
        }
    }
}

/// Audit logging configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AuditConfig {
    pub enabled: bool,
    pub destination: AuditDestination,
    /// Path for audit log file; used when destination = "file".
    pub path: PathBuf,
    pub level: AuditLevel,
    /// Bounded MPSC channel capacity. Range: [64, 65536]. Default: 4096.
    pub channel_capacity: usize,
}

impl Default for AuditConfig {
    fn default() -> Self {
        AuditConfig {
            enabled: true,
            destination: AuditDestination::File,
            path: PathBuf::from("/var/log/kata-vfsd-filter.log"),
            level: AuditLevel::Deny,
            channel_capacity: 4096,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuditDestination {
    File,
    Stderr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuditLevel {
    /// Log all events (Allow and Deny).
    All,
    /// Log only denied events.
    Deny,
    /// Disable audit logging.
    None,
}
