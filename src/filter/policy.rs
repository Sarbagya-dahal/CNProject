// SPDX-License-Identifier: Apache-2.0
// virtiofsd V1 host-side request-validation filter — policy engine

use std::collections::HashSet;

use virtiofsd::fuse::ROOT_ID;
use crate::filter::config::{
    DefaultPolicy, FilterConfig, NamesConfig, OpenFlagsConfig, OperationsConfig,
    SetAttrConfig, SymlinkConfig,
};

// ─── FATTR bits from fuse.rs (reused for setattr sub-policy) ────────────────
// These match the FATTR_* constants in src/fuse.rs exactly.
const FATTR_MODE: u32 = 1 << 0;
const FATTR_UID: u32 = 1 << 1;
const FATTR_GID: u32 = 1 << 2;
const FATTR_SIZE: u32 = 1 << 3;
const FATTR_ATIME: u32 = 1 << 4;
const FATTR_MTIME: u32 = 1 << 5;
const FATTR_ATIME_NOW: u32 = 1 << 7;
const FATTR_MTIME_NOW: u32 = 1 << 8;
const FATTR_CTIME: u32 = 1 << 10;

// ─── Op category bitmask positions ──────────────────────────────────────────
pub const OP_READ: u64 = 1 << 0;
pub const OP_WRITE: u64 = 1 << 1;
pub const OP_OPEN: u64 = 1 << 2;
pub const OP_CREATE: u64 = 1 << 3;
pub const OP_DELETE: u64 = 1 << 4;
pub const OP_RENAME: u64 = 1 << 5;
pub const OP_SETATTR: u64 = 1 << 6;
pub const OP_LINK: u64 = 1 << 7;
pub const OP_SYMLINK: u64 = 1 << 8;
pub const OP_XATTR: u64 = 1 << 9;
pub const OP_FALLOCATE: u64 = 1 << 10;
pub const OP_SYNCFS: u64 = 1 << 11;

/// Policy decision returned by all check functions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Allow,
    Deny {
        errno: i32,
        reason: &'static str,
    },
}

impl Verdict {
    pub fn is_allow(&self) -> bool {
        matches!(self, Verdict::Allow)
    }

    pub fn is_deny(&self) -> bool {
        !self.is_allow()
    }
}

/// Name-level policy: exact, suffix, and prefix deny lists.
/// All comparisons are byte-level and case-sensitive.
struct NamePolicy {
    /// AHashSet equivalent using std HashSet — zero external deps, adequate speed
    /// for expected rule counts (< 100 entries). The key is raw bytes with no NUL.
    deny_exact: HashSet<Vec<u8>>,
    /// Ordered list of denied suffixes.
    deny_suffixes: Vec<Vec<u8>>,
    /// Ordered list of denied prefixes.
    deny_prefixes: Vec<Vec<u8>>,
}

impl NamePolicy {
    fn from_config(cfg: &NamesConfig) -> Self {
        NamePolicy {
            deny_exact: cfg
                .deny_exact
                .iter()
                .map(|s| s.as_bytes().to_vec())
                .collect(),
            deny_suffixes: cfg
                .deny_suffixes
                .iter()
                .map(|s| s.as_bytes().to_vec())
                .collect(),
            deny_prefixes: cfg
                .deny_prefixes
                .iter()
                .map(|s| s.as_bytes().to_vec())
                .collect(),
        }
    }

    fn from_string_list(list: &[String]) -> Self {
        NamePolicy {
            deny_exact: list.iter().map(|s| s.as_bytes().to_vec()).collect(),
            deny_suffixes: vec![],
            deny_prefixes: vec![],
        }
    }

    fn is_empty(&self) -> bool {
        self.deny_exact.is_empty()
            && self.deny_suffixes.is_empty()
            && self.deny_prefixes.is_empty()
    }

    /// Returns a Deny verdict if `name_bytes` matches any rule; otherwise returns Allow.
    fn check(&self, name_bytes: &[u8]) -> Verdict {
        // Exact match (HashSet lookup: O(n) where n = name length for hash computation)
        if self.deny_exact.contains(name_bytes) {
            return Verdict::Deny {
                errno: libc::EACCES,
                reason: "name denied by exact match rule",
            };
        }
        // Suffix match (linear scan over typically < 20 short byte slices)
        for suffix in &self.deny_suffixes {
            if name_bytes.ends_with(suffix.as_slice()) {
                return Verdict::Deny {
                    errno: libc::EACCES,
                    reason: "name denied by suffix rule",
                };
            }
        }
        // Prefix match
        for prefix in &self.deny_prefixes {
            if name_bytes.starts_with(prefix.as_slice()) {
                return Verdict::Deny {
                    errno: libc::EACCES,
                    reason: "name denied by prefix rule",
                };
            }
        }
        Verdict::Allow
    }
}

/// Symlink target policy.
struct SymlinkTargetPolicy {
    allow_absolute_targets: bool,
    allow_dotdot_targets: bool,
}

impl SymlinkTargetPolicy {
    fn from_config(cfg: &SymlinkConfig) -> Self {
        SymlinkTargetPolicy {
            allow_absolute_targets: cfg.allow_absolute_targets,
            allow_dotdot_targets: cfg.allow_dotdot_targets,
        }
    }

    fn check(&self, target_bytes: &[u8]) -> Verdict {
        if !self.allow_absolute_targets {
            if target_bytes.first() == Some(&b'/') {
                return Verdict::Deny {
                    errno: libc::EPERM,
                    reason: "absolute symlink target denied by policy",
                };
            }
        }
        if !self.allow_dotdot_targets {
            if contains_dotdot_component(target_bytes) {
                return Verdict::Deny {
                    errno: libc::EPERM,
                    reason: "symlink target with '..' component denied by policy",
                };
            }
        }
        Verdict::Allow
    }
}

/// The main policy engine. Read-only after construction; no locking needed on the hot path.
pub struct PolicyEngine {
    /// Master enable switch. If false, all checks return Allow immediately.
    pub enabled: bool,

    /// Default verdict when no explicit rule matches.
    default: Verdict,

    /// Pre-computed bitmask of denied op categories.
    /// bit == 1 means denied. Checked with a single AND.
    op_deny_mask: u64,

    /// Pre-computed bitmask of denied SetattrValid bits.
    /// Only checked when Setattr op is not denied.
    setattr_deny_mask: u32,

    /// Pre-computed bitmask of denied open flags.
    /// Only checked when Open/Create op is not denied.
    open_flag_deny_mask: u32,

    /// Leaf-name policy applied to all name-bearing operations.
    name_policy: NamePolicy,

    /// First-level path policy: activated when parent_inode == ROOT_ID.
    root_child_policy: NamePolicy,

    /// Symlink target policy.
    symlink_policy: SymlinkTargetPolicy,
}

impl PolicyEngine {
    /// Build a PolicyEngine from a FilterConfig.
    pub fn from_config(cfg: &FilterConfig) -> Self {
        let default = match cfg.filter.default_policy {
            DefaultPolicy::Allow => Verdict::Allow,
            DefaultPolicy::Deny => Verdict::Deny {
                errno: libc::EPERM,
                reason: "operation denied by default policy",
            },
        };

        let op_deny_mask = build_op_deny_mask(&cfg.operations);
        let setattr_deny_mask = build_setattr_deny_mask(&cfg.operations.setattr);
        let open_flag_deny_mask = build_open_flag_deny_mask(&cfg.operations.open_flags);
        let name_policy = NamePolicy::from_config(&cfg.names);
        let root_child_policy = NamePolicy::from_string_list(&cfg.paths.deny_root_children);
        let symlink_policy = SymlinkTargetPolicy::from_config(&cfg.symlink);

        PolicyEngine {
            enabled: cfg.filter.enabled,
            default,
            op_deny_mask,
            setattr_deny_mask,
            open_flag_deny_mask,
            name_policy,
            root_child_policy,
            symlink_policy,
        }
    }

    // ─── Fast-path check helpers ─────────────────────────────────────────────

    /// Check an op-category only (no name). Used by Group B methods.
    #[inline]
    pub fn check_op(&self, op_bit: u64) -> Verdict {
        if !self.enabled {
            return Verdict::Allow;
        }
        if self.op_deny_mask & op_bit != 0 {
            return Verdict::Deny {
                errno: libc::EPERM,
                reason: "operation type denied by policy",
            };
        }
        self.default.clone()
    }

    /// Common check for name-bearing mutating operations (Group A).
    /// Steps: enable check → malformed name → op mask → first-level path → leaf name.
    #[inline]
    pub fn check_name_op(
        &self,
        op_bit: u64,
        parent_inode: u64,
        name_bytes: &[u8],
    ) -> Verdict {
        if !self.enabled {
            return Verdict::Allow;
        }

        // Malformed name validation (always, regardless of other rules).
        if let Err(v) = validate_name_bytes(name_bytes) {
            return v;
        }

        // Op-category check.
        if self.op_deny_mask & op_bit != 0 {
            return Verdict::Deny {
                errno: libc::EPERM,
                reason: "operation type denied by policy",
            };
        }

        // First-level path check (parent is the shared root).
        if parent_inode == ROOT_ID && !self.root_child_policy.is_empty() {
            let v = self.root_child_policy.check(name_bytes);
            if v.is_deny() {
                return v;
            }
        }

        // Leaf name policy check.
        let v = self.name_policy.check(name_bytes);
        if v.is_deny() {
            return v;
        }

        // No rule matched — apply default.
        self.default.clone()
    }

    /// Check for the `symlink` operation specifically.
    /// Includes symlink target policy in addition to name and op checks.
    #[inline]
    pub fn check_symlink(
        &self,
        parent_inode: u64,
        name_bytes: &[u8],
        target_bytes: &[u8],
    ) -> Verdict {
        if !self.enabled {
            return Verdict::Allow;
        }

        // Malformed name validation.
        if let Err(v) = validate_name_bytes(name_bytes) {
            return v;
        }

        // Op-category check.
        if self.op_deny_mask & OP_SYMLINK != 0 {
            return Verdict::Deny {
                errno: libc::EPERM,
                reason: "symlink operation denied by policy",
            };
        }

        // Symlink target policy.
        let v = self.symlink_policy.check(target_bytes);
        if v.is_deny() {
            return v;
        }

        // First-level path check.
        if parent_inode == ROOT_ID && !self.root_child_policy.is_empty() {
            let v = self.root_child_policy.check(name_bytes);
            if v.is_deny() {
                return v;
            }
        }

        // Leaf name policy.
        let v = self.name_policy.check(name_bytes);
        if v.is_deny() {
            return v;
        }

        self.default.clone()
    }

    /// Check open flags. Used by `open` and `create`.
    #[inline]
    pub fn check_open_flags(&self, flags: u32) -> Verdict {
        if !self.enabled {
            return Verdict::Allow;
        }
        if self.open_flag_deny_mask & flags != 0 {
            return Verdict::Deny {
                errno: libc::EACCES,
                reason: "open flags denied by policy",
            };
        }
        Verdict::Allow
    }

    /// Check setattr valid bitmask. Used by `setattr`.
    #[inline]
    pub fn check_setattr_valid(&self, valid: u32) -> Verdict {
        if !self.enabled {
            return Verdict::Allow;
        }
        // First check op-category
        if self.op_deny_mask & OP_SETATTR != 0 {
            return Verdict::Deny {
                errno: libc::EPERM,
                reason: "setattr operation denied by policy",
            };
        }
        // Then check sub-operation bitmask
        if self.setattr_deny_mask & valid != 0 {
            return Verdict::Deny {
                errno: libc::EPERM,
                reason: "setattr sub-operation denied by policy",
            };
        }
        self.default.clone()
    }

    /// For rename: check both old name and new name.
    #[inline]
    pub fn check_rename(
        &self,
        olddir: u64,
        oldname_bytes: &[u8],
        newdir: u64,
        newname_bytes: &[u8],
    ) -> Verdict {
        if !self.enabled {
            return Verdict::Allow;
        }
        // Malformed name checks for both names.
        if let Err(v) = validate_name_bytes(oldname_bytes) {
            return v;
        }
        if let Err(v) = validate_name_bytes(newname_bytes) {
            return v;
        }
        // Op-category check.
        if self.op_deny_mask & OP_RENAME != 0 {
            return Verdict::Deny {
                errno: libc::EPERM,
                reason: "rename operation denied by policy",
            };
        }
        // First-level path checks for both source and destination.
        if olddir == ROOT_ID && !self.root_child_policy.is_empty() {
            let v = self.root_child_policy.check(oldname_bytes);
            if v.is_deny() {
                return v;
            }
        }
        if newdir == ROOT_ID && !self.root_child_policy.is_empty() {
            let v = self.root_child_policy.check(newname_bytes);
            if v.is_deny() {
                return v;
            }
        }
        // Leaf name checks for both names.
        let v = self.name_policy.check(oldname_bytes);
        if v.is_deny() {
            return v;
        }
        let v = self.name_policy.check(newname_bytes);
        if v.is_deny() {
            return v;
        }
        self.default.clone()
    }
}

// ─── Builder helpers ─────────────────────────────────────────────────────────

fn build_op_deny_mask(cfg: &OperationsConfig) -> u64 {
    let mut mask: u64 = 0;
    if !cfg.allow_read {
        mask |= OP_READ;
    }
    if !cfg.allow_write {
        mask |= OP_WRITE;
    }
    if !cfg.allow_open {
        mask |= OP_OPEN;
    }
    if !cfg.allow_create {
        mask |= OP_CREATE;
    }
    if !cfg.allow_delete {
        mask |= OP_DELETE;
    }
    if !cfg.allow_rename {
        mask |= OP_RENAME;
    }
    if !cfg.allow_setattr {
        mask |= OP_SETATTR;
    }
    if !cfg.allow_link {
        mask |= OP_LINK;
    }
    if !cfg.allow_symlink {
        mask |= OP_SYMLINK;
    }
    if !cfg.allow_xattr {
        mask |= OP_XATTR;
    }
    if !cfg.allow_fallocate {
        mask |= OP_FALLOCATE;
    }
    if !cfg.allow_syncfs {
        mask |= OP_SYNCFS;
    }
    mask
}

fn build_setattr_deny_mask(cfg: &SetAttrConfig) -> u32 {
    let mut mask: u32 = 0;
    if !cfg.allow_chmod {
        mask |= FATTR_MODE;
    }
    if !cfg.allow_chown {
        mask |= FATTR_UID | FATTR_GID;
    }
    if !cfg.allow_truncate {
        mask |= FATTR_SIZE;
    }
    if !cfg.allow_utime {
        mask |= FATTR_ATIME | FATTR_MTIME | FATTR_ATIME_NOW | FATTR_MTIME_NOW | FATTR_CTIME;
    }
    mask
}

fn build_open_flag_deny_mask(cfg: &OpenFlagsConfig) -> u32 {
    let mut mask: u32 = 0;
    if cfg.deny_wronly {
        mask |= libc::O_WRONLY as u32;
    }
    if cfg.deny_rdwr {
        mask |= libc::O_RDWR as u32;
    }
    if cfg.deny_append {
        mask |= libc::O_APPEND as u32;
    }
    if cfg.deny_trunc {
        mask |= libc::O_TRUNC as u32;
    }
    if cfg.deny_direct_io {
        mask |= libc::O_DIRECT as u32;
    }
    mask
}

// ─── Validation helpers ──────────────────────────────────────────────────────

/// Validate a name byte slice (from CStr::to_bytes(), no NUL included).
/// Returns Ok(()) if valid, Err(Verdict::Deny{EINVAL, reason}) if malformed.
/// Rules:
///   - Must not be empty
///   - Must not be b"."
///   - Must not be b".."
///   - Must not contain b'/' (this is defense-in-depth; the FUSE protocol should prevent this)
///
/// Note: NUL bytes are already excluded by CStr.
pub fn validate_name_bytes(name: &[u8]) -> Result<(), Verdict> {
    if name.is_empty() {
        return Err(Verdict::Deny {
            errno: libc::EINVAL,
            reason: "empty name is invalid",
        });
    }
    if name == b"." {
        return Err(Verdict::Deny {
            errno: libc::EINVAL,
            reason: "name '.' is not a valid FUSE entry name",
        });
    }
    if name == b".." {
        return Err(Verdict::Deny {
            errno: libc::EINVAL,
            reason: "name '..' is not a valid FUSE entry name",
        });
    }
    if name.contains(&b'/') {
        return Err(Verdict::Deny {
            errno: libc::EINVAL,
            reason: "name contains '/' separator byte",
        });
    }
    Ok(())
}

/// Returns true if `target` contains ".." as a whole path component.
/// A path component is a sequence of bytes between '/' separators (or at string boundaries).
///
/// Fast path: if there is no '.' in the target at all, return false immediately.
/// This avoids the split in the common case of a simple relative path like "foo/bar".
pub fn contains_dotdot_component(target: &[u8]) -> bool {
    // Fast exit: target must contain at least ".." to have a dotdot component.
    if !target.windows(2).any(|w| w == b"..") {
        return false;
    }
    // Full check: split on '/' and look for a component that is exactly b"..".
    target.split(|&b| b == b'/').any(|comp| comp == b"..")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filter::config::FilterConfig;

    fn default_engine() -> PolicyEngine {
        PolicyEngine::from_config(&FilterConfig::default())
    }

    // ─── validate_name_bytes ──────────────────────────────────────────────────

    #[test]
    fn test_validate_name_empty() {
        assert!(validate_name_bytes(b"").is_err());
    }

    #[test]
    fn test_validate_name_dot() {
        let v = validate_name_bytes(b".");
        assert!(v.is_err());
        match v.unwrap_err() {
            Verdict::Deny { errno, .. } => assert_eq!(errno, libc::EINVAL),
            _ => panic!("expected Deny"),
        }
    }

    #[test]
    fn test_validate_name_dotdot() {
        assert!(validate_name_bytes(b"..").is_err());
    }

    #[test]
    fn test_validate_name_slash() {
        assert!(validate_name_bytes(b"a/b").is_err());
    }

    #[test]
    fn test_validate_name_valid() {
        assert!(validate_name_bytes(b"normal_file.txt").is_ok());
        assert!(validate_name_bytes(b".hidden").is_ok());
        assert!(validate_name_bytes(b"file.key").is_ok());
    }

    // ─── contains_dotdot_component ────────────────────────────────────────────

    #[test]
    fn test_dotdot_fast_exit_no_dots() {
        assert!(!contains_dotdot_component(b"foo/bar/baz"));
    }

    #[test]
    fn test_dotdot_component_present() {
        assert!(contains_dotdot_component(b"../escape"));
        assert!(contains_dotdot_component(b"foo/../escape"));
        assert!(contains_dotdot_component(b".."));
    }

    #[test]
    fn test_dotdot_not_a_component() {
        assert!(!contains_dotdot_component(b"notdotdot"));
        assert!(!contains_dotdot_component(b"a..b"));
        assert!(!contains_dotdot_component(b"..hidden")); // starts with ".." but has more bytes
    }

    #[test]
    fn test_dotdot_trailing() {
        // "foo/.." — ends with ".." as a component
        assert!(contains_dotdot_component(b"foo/.."));
    }

    // ─── PolicyEngine: default config ────────────────────────────────────────

    #[test]
    fn test_default_engine_allows_all_ops() {
        let e = default_engine();
        assert_eq!(e.check_op(OP_READ), Verdict::Allow);
        assert_eq!(e.check_op(OP_WRITE), Verdict::Allow);
        assert_eq!(e.check_op(OP_CREATE), Verdict::Allow);
        assert_eq!(e.check_op(OP_DELETE), Verdict::Allow);
        assert_eq!(e.check_op(OP_RENAME), Verdict::Allow);
    }

    #[test]
    fn test_default_engine_allows_valid_name_ops() {
        let e = default_engine();
        assert_eq!(
            e.check_name_op(OP_DELETE, 2, b"file.txt"),
            Verdict::Allow
        );
    }

    // ─── PolicyEngine: op deny ────────────────────────────────────────────────

    #[test]
    fn test_deny_write_op() {
        let mut cfg = FilterConfig::default();
        cfg.operations.allow_write = false;
        let e = PolicyEngine::from_config(&cfg);
        assert!(e.check_op(OP_WRITE).is_deny());
        assert_eq!(e.check_op(OP_READ), Verdict::Allow); // other ops unaffected
    }

    #[test]
    fn test_deny_delete_op() {
        let mut cfg = FilterConfig::default();
        cfg.operations.allow_delete = false;
        let e = PolicyEngine::from_config(&cfg);
        assert!(e.check_op(OP_DELETE).is_deny());
    }

    #[test]
    fn test_deny_create_op() {
        let mut cfg = FilterConfig::default();
        cfg.operations.allow_create = false;
        let e = PolicyEngine::from_config(&cfg);
        assert!(e.check_name_op(OP_CREATE, 1, b"newfile").is_deny());
    }

    // ─── PolicyEngine: name policy ────────────────────────────────────────────

    #[test]
    fn test_deny_exact_name() {
        let mut cfg = FilterConfig::default();
        cfg.names.deny_exact = vec!["shadow".to_string()];
        let e = PolicyEngine::from_config(&cfg);
        assert!(e.check_name_op(OP_DELETE, 2, b"shadow").is_deny());
        assert_eq!(e.check_name_op(OP_DELETE, 2, b"password"), Verdict::Allow);
    }

    #[test]
    fn test_deny_suffix() {
        let mut cfg = FilterConfig::default();
        cfg.names.deny_suffixes = vec![".key".to_string()];
        let e = PolicyEngine::from_config(&cfg);
        assert!(e.check_name_op(OP_CREATE, 2, b"id.key").is_deny());
        assert_eq!(e.check_name_op(OP_CREATE, 2, b"id.txt"), Verdict::Allow);
    }

    #[test]
    fn test_deny_prefix() {
        let mut cfg = FilterConfig::default();
        cfg.names.deny_prefixes = vec![".ssh".to_string()];
        let e = PolicyEngine::from_config(&cfg);
        assert!(e.check_name_op(OP_CREATE, 2, b".ssh").is_deny());
        assert_eq!(e.check_name_op(OP_CREATE, 2, b"normal"), Verdict::Allow);
    }

    // ─── PolicyEngine: first-level path ──────────────────────────────────────

    #[test]
    fn test_root_child_denied() {
        let mut cfg = FilterConfig::default();
        cfg.paths.deny_root_children = vec!["etc".to_string()];
        let e = PolicyEngine::from_config(&cfg);
        // parent == ROOT_ID (1) and name == "etc" -> deny
        assert!(e.check_name_op(OP_CREATE, ROOT_ID, b"etc").is_deny());
        // parent != ROOT_ID -> not checked -> allow
        assert_eq!(e.check_name_op(OP_CREATE, 42, b"etc"), Verdict::Allow);
    }

    #[test]
    fn test_root_child_allowed_different_name() {
        let mut cfg = FilterConfig::default();
        cfg.paths.deny_root_children = vec!["etc".to_string()];
        let e = PolicyEngine::from_config(&cfg);
        assert_eq!(e.check_name_op(OP_CREATE, ROOT_ID, b"data"), Verdict::Allow);
    }

    // ─── PolicyEngine: symlink policy ────────────────────────────────────────

    #[test]
    fn test_symlink_absolute_denied() {
        let mut cfg = FilterConfig::default();
        cfg.symlink.allow_absolute_targets = false;
        let e = PolicyEngine::from_config(&cfg);
        assert!(e.check_symlink(2, b"link", b"/etc/passwd").is_deny());
        assert_eq!(e.check_symlink(2, b"link", b"relative/path"), Verdict::Allow);
    }

    #[test]
    fn test_symlink_absolute_allowed_by_default() {
        let e = default_engine();
        assert_eq!(e.check_symlink(2, b"link", b"/etc/passwd"), Verdict::Allow);
    }

    #[test]
    fn test_symlink_dotdot_denied() {
        let mut cfg = FilterConfig::default();
        cfg.symlink.allow_dotdot_targets = false;
        let e = PolicyEngine::from_config(&cfg);
        assert!(e.check_symlink(2, b"link", b"../../escape").is_deny());
        assert_eq!(e.check_symlink(2, b"link", b"safe/path"), Verdict::Allow);
    }

    #[test]
    fn test_symlink_dotdot_substring_not_component() {
        let mut cfg = FilterConfig::default();
        cfg.symlink.allow_dotdot_targets = false;
        let e = PolicyEngine::from_config(&cfg);
        // "notdotdot" contains ".." as a substring but not a component -> allow
        assert_eq!(e.check_symlink(2, b"link", b"notdotdot"), Verdict::Allow);
    }

    // ─── PolicyEngine: open flags ────────────────────────────────────────────

    #[test]
    fn test_deny_wronly_flag() {
        let mut cfg = FilterConfig::default();
        cfg.operations.open_flags.deny_wronly = true;
        let e = PolicyEngine::from_config(&cfg);
        assert!(e.check_open_flags(libc::O_WRONLY as u32).is_deny());
        assert_eq!(e.check_open_flags(libc::O_RDONLY as u32), Verdict::Allow);
    }

    #[test]
    fn test_deny_trunc_flag() {
        let mut cfg = FilterConfig::default();
        cfg.operations.open_flags.deny_trunc = true;
        let e = PolicyEngine::from_config(&cfg);
        assert!(
            e.check_open_flags((libc::O_RDWR | libc::O_TRUNC) as u32)
                .is_deny()
        );
        assert_eq!(e.check_open_flags(libc::O_RDWR as u32), Verdict::Allow);
    }

    // ─── PolicyEngine: setattr ────────────────────────────────────────────────

    #[test]
    fn test_deny_chmod() {
        let mut cfg = FilterConfig::default();
        cfg.operations.setattr.allow_chmod = false;
        let e = PolicyEngine::from_config(&cfg);
        assert!(e.check_setattr_valid(FATTR_MODE).is_deny());
        // Other valid bits not affected
        assert_eq!(e.check_setattr_valid(FATTR_SIZE), Verdict::Allow);
    }

    #[test]
    fn test_deny_truncate() {
        let mut cfg = FilterConfig::default();
        cfg.operations.setattr.allow_truncate = false;
        let e = PolicyEngine::from_config(&cfg);
        assert!(e.check_setattr_valid(FATTR_SIZE).is_deny());
        assert_eq!(e.check_setattr_valid(FATTR_MODE), Verdict::Allow);
    }

    // ─── PolicyEngine: master disable ────────────────────────────────────────

    #[test]
    fn test_disabled_allows_everything() {
        let mut cfg = FilterConfig::default();
        cfg.filter.enabled = false;
        cfg.operations.allow_write = false;
        cfg.operations.allow_delete = false;
        cfg.names.deny_exact = vec!["shadow".to_string()];
        let e = PolicyEngine::from_config(&cfg);
        assert_eq!(e.check_op(OP_WRITE), Verdict::Allow);
        assert_eq!(e.check_name_op(OP_DELETE, 1, b"shadow"), Verdict::Allow);
    }

    // ─── PolicyEngine: default-deny ──────────────────────────────────────────

    #[test]
    fn test_default_deny_blocks_unmatched_ops() {
        let mut cfg = FilterConfig::default();
        cfg.filter.default_policy = crate::filter::config::DefaultPolicy::Deny;
        let e = PolicyEngine::from_config(&cfg);
        // With default-deny and no explicit allow rules, name ops return Deny.
        // (Op mask is 0 since all allow_* are true, so we reach default.)
        let v = e.check_name_op(OP_CREATE, 2, b"newfile");
        assert!(v.is_deny());
    }

    // ─── PolicyEngine: rename ─────────────────────────────────────────────────

    #[test]
    fn test_rename_denied_new_name_by_suffix() {
        let mut cfg = FilterConfig::default();
        cfg.names.deny_suffixes = vec![".key".to_string()];
        let e = PolicyEngine::from_config(&cfg);
        // Renaming to a denied name should be blocked.
        assert!(e.check_rename(2, b"old.txt", 2, b"new.key").is_deny());
    }

    #[test]
    fn test_rename_denied_old_name_by_suffix() {
        let mut cfg = FilterConfig::default();
        cfg.names.deny_suffixes = vec![".key".to_string()];
        let e = PolicyEngine::from_config(&cfg);
        // Renaming from a denied name (e.g., deleting a protected file) should be blocked.
        assert!(e.check_rename(2, b"id.key", 2, b"new.txt").is_deny());
    }

    #[test]
    fn test_rename_malformed_newname() {
        let e = default_engine();
        assert!(e.check_rename(2, b"old.txt", 2, b"..").is_deny());
    }
}
