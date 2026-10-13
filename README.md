# vfsd-filter

A host-side **request-validation security filter** library for [virtiofsd], the Rust virtio-fs vhost-user device daemon.

## What it is

`vfsd-filter` is a Rust library that provides a `FilteredFs<F>` decorator — a security layer that intercepts every FUSE operation routed through virtiofsd before it reaches the host filesystem.

```
Guest VM  →  FUSE (virtio-fs)  →  virtiofsd  →  [ vfsd-filter ]  →  PassthroughFs  →  Host FS
```

## Components (all original)

| File | What it contains |
|------|-----------------|
| `src/filter/mod.rs` | `FilteredFs<F>` — generic decorator over any `FileSystem + Sync` |
| `src/filter/policy.rs` | `PolicyEngine` — evaluates TOML rules, issues `Allow`/`Deny` verdicts |
| `src/filter/audit.rs` | `AuditLogger` — non-blocking async JSON audit trail via bounded MPSC channel |
| `src/filter/config.rs` | `FilterConfig` — full TOML config schema |

## Security features

- Per-operation-category policy (read, write, open, create, delete, rename, xattr, symlink, fallocate, syncfs)
- Fine-grained setattr controls (chmod, chown, truncate, utime individually)
- Open-flag controls (deny O_WRONLY, O_RDWR, O_APPEND, O_TRUNC, O_DIRECT)
- Leaf-name rules: exact, prefix, and suffix denylists on all name-bearing ops
- Root-child path policy: deny specific direct children of the shared directory
- Path traversal detection on raw byte paths (before any OS resolution)
- Symlink target policy: deny absolute or `..`-containing targets
- Non-blocking audit: bounded channel with drop counting — filter never stalls on I/O

## Usage

Add to your `Cargo.toml`:

```toml
[dependencies]
vfsd-filter = { git = "https://github.com/Sarbagya-dahal/vfsd-filter" }
```

Wire it into virtiofsd:

```rust
use vfsd_filter::filter::{FilteredFs, config::FilterConfig};

let filter_cfg = FilterConfig::from_file(Path::new("/etc/vfsd-filter.toml"))?;
let inner = PassthroughFs::new(fs_cfg)?;
let fs = FilteredFs::from_config(inner, &filter_cfg)?;
```

## Example config

```toml
[filter]
enabled = true
default_policy = "allow"

[operations]
allow_write = false
allow_delete = false

[names]
deny_exact   = ["shadow", "passwd"]
deny_suffixes = [".key", ".pem", ".env"]

[paths]
deny_root_children = [".ssh", ".gnupg"]

[symlink]
allow_absolute_targets = false
allow_dotdot_targets   = false

[audit]
enabled     = true
destination = "file"
path        = "/var/log/vfsd-filter.log"
level       = "deny"
```

## Dependency

This library uses [virtiofsd](https://gitlab.com/virtio-fs/virtiofsd) (v1.14.0) via Cargo git dependency for the `FileSystem` trait, FUSE types, and context types. The virtiofsd source is **not bundled** in this repository.

## License

Apache-2.0
