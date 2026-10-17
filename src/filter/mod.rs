// SPDX-License-Identifier: Apache-2.0
// virtiofsd V1 host-side request-validation filter — FilteredFs decorator

//! `FilteredFs<F>` is a Decorator over any `FileSystem` implementation `F`.
//!
//! Security note
//! =============
//! Root confinement is NOT re-implemented here. It is enforced by two existing
//! mechanisms at lower layers, which this filter augments but never replaces:
//!
//!   1. virtiofsd sandbox: pivot_root/chroot into the shared directory at startup.
//!      virtiofsd's process root IS the shared directory.
//!
//!   2. PassthroughFs::open_relative_to() -> oslib::do_open_relative_to():
//!      openat2(RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS) for every file open.
//!      Enforced by the Linux kernel on every operation.
//!
//! Every inode presented to this filter is therefore guaranteed to be within the
//! shared root. This filter adds name-level and operation-level policy on top.

// Sub-modules
pub mod audit;
pub mod config;
pub mod policy;

use std::ffi::CStr;
use std::fs::File;
use std::io;
use std::time::Duration;
use std::time::Instant;

use virtiofsd::filesystem::{
    Context, Entry, Extensions, FileSystem, FsOptions,
    GetxattrReply, ListxattrReply, OpenOptions, SetattrValid,
    SerializableFileSystem, SetxattrFlags, ZeroCopyReader, ZeroCopyWriter,
};
use virtiofsd::fuse;
use crate::filter::audit::{AuditLogger, OpKind};
use crate::filter::config::FilterConfig;
use crate::filter::policy::{
    PolicyEngine, Verdict, OP_CREATE, OP_DELETE, OP_FALLOCATE, OP_LINK, OP_OPEN, OP_READ,
    OP_SYNCFS, OP_WRITE, OP_XATTR,
};

/// Decorator wrapping any `F: FileSystem + Sync` with request-validation policy.
pub struct FilteredFs<F: FileSystem> {
    inner: F,
    policy: PolicyEngine,
    audit: AuditLogger,
}

impl<F: FileSystem + Sync> FilteredFs<F>
where
    F::Inode: Copy,
    F::Handle: Copy,
{
    pub fn new(inner: F, policy: PolicyEngine, audit: AuditLogger) -> Self {
        FilteredFs {
            inner,
            policy,
            audit,
        }
    }

    /// Convenience constructor from a `FilterConfig`.
    pub fn from_config(inner: F, cfg: &FilterConfig) -> io::Result<Self> {
        cfg.validate().map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidData, e)
        })?;
        let policy = PolicyEngine::from_config(cfg);
        let audit = if cfg.filter.enabled && cfg.audit.enabled {
            AuditLogger::new(&cfg.audit)?
        } else {
            AuditLogger::disabled()
        };
        Ok(FilteredFs { inner, policy, audit })
    }

    /// Measure elapsed time since `start` as a u32 nanosecond count (saturating).
    #[inline(always)]
    fn elapsed_ns(start: Instant) -> u32 {
        start.elapsed().as_nanos().min(u32::MAX as u128) as u32
    }

    /// Convert a Verdict::Deny into an io::Error.
    #[inline(always)]
    fn deny_err(errno: i32) -> io::Error {
        io::Error::from_raw_os_error(errno)
    }
}

// ─── FileSystem trait implementation ─────────────────────────────────────────

impl<F: FileSystem + Sync> FileSystem for FilteredFs<F>
where
    F::Inode: Copy,
    F::Handle: Copy,
{
    type Inode = F::Inode;
    type Handle = F::Handle;
    type DirIter = F::DirIter;

    // ── Lifecycle (Group C — always pass-through) ─────────────────────────────

    fn init(&self, capable: FsOptions) -> io::Result<FsOptions> {
        self.inner.init(capable)
    }

    fn destroy(&self) {
        self.inner.destroy()
    }

    // ── Inode lifecycle (Group C) ──────────────────────────────────────────────

    fn forget(&self, ctx: Context, inode: Self::Inode, count: u64) {
        self.inner.forget(ctx, inode, count)
    }

    fn batch_forget(&self, ctx: Context, requests: Vec<(Self::Inode, u64)>) {
        self.inner.batch_forget(ctx, requests)
    }

    // ── Group A: lookup — malformed name check only (op never denied) ─────────

    fn lookup(&self, ctx: Context, parent: Self::Inode, name: &CStr) -> io::Result<Entry> {
        let start = Instant::now();
        let name_bytes = name.to_bytes();
        let parent_raw: u64 = parent.into();

        // Only malformed-name check for lookup; op itself is always allowed.
        let verdict = self.policy.check_name_op(0u64, parent_raw, name_bytes);
        let latency = Self::elapsed_ns(start);

        self.audit.log(
            &ctx, OpKind::Lookup, parent_raw, 0, name_bytes, &verdict, latency,
        );

        match verdict {
            Verdict::Allow => self.inner.lookup(ctx, parent, name),
            Verdict::Deny { errno, .. } => Err(Self::deny_err(errno)),
        }
    }

    // ── Group C: getattr, statfs, access, lseek ───────────────────────────────

    fn getattr(
        &self,
        ctx: Context,
        inode: Self::Inode,
        handle: Option<Self::Handle>,
    ) -> io::Result<(fuse::Attr, Duration)> {
        self.inner.getattr(ctx, inode, handle)
    }

    fn statfs(&self, ctx: Context, inode: Self::Inode) -> io::Result<libc::statvfs64> {
        self.inner.statfs(ctx, inode)
    }

    fn access(&self, ctx: Context, inode: Self::Inode, mask: u32) -> io::Result<()> {
        self.inner.access(ctx, inode, mask)
    }

    fn lseek(
        &self,
        ctx: Context,
        inode: Self::Inode,
        handle: Self::Handle,
        offset: u64,
        whence: u32,
    ) -> io::Result<u64> {
        self.inner.lseek(ctx, inode, handle, offset, whence)
    }

    // ── Group B: setattr — op + sub-operation check ───────────────────────────

    fn setattr(
        &self,
        ctx: Context,
        inode: Self::Inode,
        attr: fuse::SetattrIn,
        handle: Option<Self::Handle>,
        valid: SetattrValid,
    ) -> io::Result<(fuse::Attr, Duration)> {
        let start = Instant::now();
        let inode_raw: u64 = inode.into();
        let verdict = self.policy.check_setattr_valid(valid.bits());
        let latency = Self::elapsed_ns(start);

        self.audit.log(
            &ctx, OpKind::Setattr, inode_raw, 0, b"", &verdict, latency,
        );

        match verdict {
            Verdict::Allow => self.inner.setattr(ctx, inode, attr, handle, valid),
            Verdict::Deny { errno, .. } => Err(Self::deny_err(errno)),
        }
    }

    // ── Group B: open — flag check ────────────────────────────────────────────

    fn open(
        &self,
        ctx: Context,
        inode: Self::Inode,
        kill_priv: bool,
        flags: u32,
    ) -> io::Result<(Option<Self::Handle>, OpenOptions)> {
        let start = Instant::now();
        let inode_raw: u64 = inode.into();

        // Op-category check first, then flag check.
        let verdict = match self.policy.check_op(OP_OPEN) {
            Verdict::Allow => self.policy.check_open_flags(flags),
            deny => deny,
        };
        let latency = Self::elapsed_ns(start);

        self.audit.log(
            &ctx, OpKind::Open, 0, inode_raw, b"", &verdict, latency,
        );

        match verdict {
            Verdict::Allow => self.inner.open(ctx, inode, kill_priv, flags),
            Verdict::Deny { errno, .. } => Err(Self::deny_err(errno)),
        }
    }

    // ── Group A: create — name + op + flag checks ─────────────────────────────

    fn create(
        &self,
        ctx: Context,
        parent: Self::Inode,
        name: &CStr,
        mode: u32,
        kill_priv: bool,
        flags: u32,
        umask: u32,
        extensions: Extensions,
    ) -> io::Result<(Entry, Option<Self::Handle>, OpenOptions)> {
        let start = Instant::now();
        let name_bytes = name.to_bytes();
        let parent_raw: u64 = parent.into();

        let verdict = match self.policy.check_name_op(OP_CREATE, parent_raw, name_bytes) {
            Verdict::Allow => self.policy.check_open_flags(flags),
            deny => deny,
        };
        let latency = Self::elapsed_ns(start);

        self.audit.log(
            &ctx, OpKind::Create, parent_raw, 0, name_bytes, &verdict, latency,
        );

        match verdict {
            Verdict::Allow => {
                self.inner.create(ctx, parent, name, mode, kill_priv, flags, umask, extensions)
            }
            Verdict::Deny { errno, .. } => Err(Self::deny_err(errno)),
        }
    }

    // ── Group B: read ─────────────────────────────────────────────────────────

    fn read<W: ZeroCopyWriter>(
        &self,
        ctx: Context,
        inode: Self::Inode,
        handle: Self::Handle,
        w: W,
        size: u32,
        offset: u64,
        lock_owner: Option<u64>,
        flags: u32,
    ) -> io::Result<usize> {
        let start = Instant::now();
        let inode_raw: u64 = inode.into();
        let verdict = self.policy.check_op(OP_READ);
        let latency = Self::elapsed_ns(start);

        self.audit.log(&ctx, OpKind::Read, 0, inode_raw, b"", &verdict, latency);

        match verdict {
            Verdict::Allow => {
                self.inner.read(ctx, inode, handle, w, size, offset, lock_owner, flags)
            }
            Verdict::Deny { errno, .. } => Err(Self::deny_err(errno)),
        }
    }

    // ── Group B: write ────────────────────────────────────────────────────────

    fn write<R: ZeroCopyReader>(
        &self,
        ctx: Context,
        inode: Self::Inode,
        handle: Self::Handle,
        r: R,
        size: u32,
        offset: u64,
        lock_owner: Option<u64>,
        delayed_write: bool,
        kill_priv: bool,
        flags: u32,
    ) -> io::Result<usize> {
        let start = Instant::now();
        let inode_raw: u64 = inode.into();
        let verdict = self.policy.check_op(OP_WRITE);
        let latency = Self::elapsed_ns(start);

        self.audit.log(&ctx, OpKind::Write, 0, inode_raw, b"", &verdict, latency);

        match verdict {
            Verdict::Allow => self.inner.write(
                ctx, inode, handle, r, size, offset, lock_owner, delayed_write, kill_priv, flags,
            ),
            Verdict::Deny { errno, .. } => Err(Self::deny_err(errno)),
        }
    }

    // ── Group C: flush, release ───────────────────────────────────────────────

    fn flush(
        &self,
        ctx: Context,
        inode: Self::Inode,
        handle: Self::Handle,
        lock_owner: u64,
    ) -> io::Result<()> {
        self.inner.flush(ctx, inode, handle, lock_owner)
    }

    fn release(
        &self,
        ctx: Context,
        inode: Self::Inode,
        flags: u32,
        handle: Self::Handle,
        flush: bool,
        flock_release: bool,
        lock_owner: Option<u64>,
    ) -> io::Result<()> {
        self.inner
            .release(ctx, inode, flags, handle, flush, flock_release, lock_owner)
    }

    // ── Group B: fsync, fsyncdir, syncfs ──────────────────────────────────────

    fn fsync(
        &self,
        ctx: Context,
        inode: Self::Inode,
        datasync: bool,
        handle: Self::Handle,
    ) -> io::Result<()> {
        let start = Instant::now();
        let verdict = self.policy.check_op(OP_SYNCFS);
        let latency = Self::elapsed_ns(start);
        self.audit.log(&ctx, OpKind::Fsync, 0, inode.into(), b"", &verdict, latency);
        match verdict {
            Verdict::Allow => self.inner.fsync(ctx, inode, datasync, handle),
            Verdict::Deny { errno, .. } => Err(Self::deny_err(errno)),
        }
    }

    fn fsyncdir(
        &self,
        ctx: Context,
        inode: Self::Inode,
        datasync: bool,
        handle: Self::Handle,
    ) -> io::Result<()> {
        let start = Instant::now();
        let verdict = self.policy.check_op(OP_SYNCFS);
        let latency = Self::elapsed_ns(start);
        self.audit.log(&ctx, OpKind::Fsyncdir, 0, inode.into(), b"", &verdict, latency);
        match verdict {
            Verdict::Allow => self.inner.fsyncdir(ctx, inode, datasync, handle),
            Verdict::Deny { errno, .. } => Err(Self::deny_err(errno)),
        }
    }

    fn syncfs(&self, ctx: Context, inode: Self::Inode) -> io::Result<()> {
        let start = Instant::now();
        let verdict = self.policy.check_op(OP_SYNCFS);
        let latency = Self::elapsed_ns(start);
        self.audit.log(&ctx, OpKind::Syncfs, 0, inode.into(), b"", &verdict, latency);
        match verdict {
            Verdict::Allow => self.inner.syncfs(ctx, inode),
            Verdict::Deny { errno, .. } => Err(Self::deny_err(errno)),
        }
    }

    // ── Group B: fallocate ────────────────────────────────────────────────────

    fn fallocate(
        &self,
        ctx: Context,
        inode: Self::Inode,
        handle: Self::Handle,
        mode: u32,
        offset: u64,
        length: u64,
    ) -> io::Result<()> {
        let start = Instant::now();
        let inode_raw: u64 = inode.into();
        let verdict = self.policy.check_op(OP_FALLOCATE);
        let latency = Self::elapsed_ns(start);
        self.audit.log(&ctx, OpKind::Fallocate, 0, inode_raw, b"", &verdict, latency);
        match verdict {
            Verdict::Allow => self.inner.fallocate(ctx, inode, handle, mode, offset, length),
            Verdict::Deny { errno, .. } => Err(Self::deny_err(errno)),
        }
    }

    // ── Group B: copyfilerange ────────────────────────────────────────────────

    fn copyfilerange(
        &self,
        ctx: Context,
        inode_in: Self::Inode,
        handle_in: Self::Handle,
        offset_in: u64,
        inode_out: Self::Inode,
        handle_out: Self::Handle,
        offset_out: u64,
        len: u64,
        flags: u64,
    ) -> io::Result<usize> {
        let start = Instant::now();
        let verdict = self.policy.check_op(OP_WRITE);
        let latency = Self::elapsed_ns(start);
        self.audit.log(&ctx, OpKind::Copyfilerange, inode_in.into(), inode_out.into(), b"", &verdict, latency);
        match verdict {
            Verdict::Allow => self.inner.copyfilerange(
                ctx, inode_in, handle_in, offset_in,
                inode_out, handle_out, offset_out, len, flags,
            ),
            Verdict::Deny { errno, .. } => Err(Self::deny_err(errno)),
        }
    }

    // ── Group B: readlink — enforce the read policy ────────────────────────────

    fn readlink(&self, ctx: Context, inode: Self::Inode) -> io::Result<Vec<u8>> {
        let start = Instant::now();
        let inode_raw: u64 = inode.into();
        let verdict = self.policy.check_op(OP_READ);
        let latency = Self::elapsed_ns(start);

        self.audit.log(
            &ctx, OpKind::Readlink, 0, inode_raw, b"", &verdict, latency,
        );

        match verdict {
            Verdict::Allow => self.inner.readlink(ctx, inode),
            Verdict::Deny { errno, .. } => Err(Self::deny_err(errno)),
        }
    }

    // ── Group A: symlink — op + target + name checks ──────────────────────────

    fn symlink(
        &self,
        ctx: Context,
        linkname: &CStr,
        parent: Self::Inode,
        name: &CStr,
        extensions: Extensions,
    ) -> io::Result<Entry> {
        let start = Instant::now();
        let name_bytes = name.to_bytes();
        let target_bytes = linkname.to_bytes();
        let parent_raw: u64 = parent.into();

        let verdict = self.policy.check_symlink(parent_raw, name_bytes, target_bytes);
        let latency = Self::elapsed_ns(start);

        self.audit.log(
            &ctx, OpKind::Symlink, parent_raw, 0, name_bytes, &verdict, latency,
        );

        match verdict {
            Verdict::Allow => self.inner.symlink(ctx, linkname, parent, name, extensions),
            Verdict::Deny { errno, .. } => Err(Self::deny_err(errno)),
        }
    }

    // ── Group A: mknod ────────────────────────────────────────────────────────

    fn mknod(
        &self,
        ctx: Context,
        inode: Self::Inode,
        name: &CStr,
        mode: u32,
        rdev: u32,
        umask: u32,
        extensions: Extensions,
    ) -> io::Result<Entry> {
        let start = Instant::now();
        let name_bytes = name.to_bytes();
        let parent_raw: u64 = inode.into();

        let verdict = self.policy.check_name_op(OP_CREATE, parent_raw, name_bytes);
        let latency = Self::elapsed_ns(start);

        self.audit.log(
            &ctx, OpKind::Mknod, parent_raw, 0, name_bytes, &verdict, latency,
        );

        match verdict {
            Verdict::Allow => self.inner.mknod(ctx, inode, name, mode, rdev, umask, extensions),
            Verdict::Deny { errno, .. } => Err(Self::deny_err(errno)),
        }
    }

    // ── Group A: mkdir ────────────────────────────────────────────────────────

    fn mkdir(
        &self,
        ctx: Context,
        parent: Self::Inode,
        name: &CStr,
        mode: u32,
        umask: u32,
        extensions: Extensions,
    ) -> io::Result<Entry> {
        let start = Instant::now();
        let name_bytes = name.to_bytes();
        let parent_raw: u64 = parent.into();

        let verdict = self.policy.check_name_op(OP_CREATE, parent_raw, name_bytes);
        let latency = Self::elapsed_ns(start);

        self.audit.log(
            &ctx, OpKind::Mkdir, parent_raw, 0, name_bytes, &verdict, latency,
        );

        match verdict {
            Verdict::Allow => self.inner.mkdir(ctx, parent, name, mode, umask, extensions),
            Verdict::Deny { errno, .. } => Err(Self::deny_err(errno)),
        }
    }

    // ── Group A: unlink, rmdir ────────────────────────────────────────────────

    fn unlink(&self, ctx: Context, parent: Self::Inode, name: &CStr) -> io::Result<()> {
        let start = Instant::now();
        let name_bytes = name.to_bytes();
        let parent_raw: u64 = parent.into();

        let verdict = self.policy.check_name_op(OP_DELETE, parent_raw, name_bytes);
        let latency = Self::elapsed_ns(start);

        self.audit.log(
            &ctx, OpKind::Unlink, parent_raw, 0, name_bytes, &verdict, latency,
        );

        match verdict {
            Verdict::Allow => self.inner.unlink(ctx, parent, name),
            Verdict::Deny { errno, .. } => Err(Self::deny_err(errno)),
        }
    }

    fn rmdir(&self, ctx: Context, parent: Self::Inode, name: &CStr) -> io::Result<()> {
        let start = Instant::now();
        let name_bytes = name.to_bytes();
        let parent_raw: u64 = parent.into();

        let verdict = self.policy.check_name_op(OP_DELETE, parent_raw, name_bytes);
        let latency = Self::elapsed_ns(start);

        self.audit.log(
            &ctx, OpKind::Rmdir, parent_raw, 0, name_bytes, &verdict, latency,
        );

        match verdict {
            Verdict::Allow => self.inner.rmdir(ctx, parent, name),
            Verdict::Deny { errno, .. } => Err(Self::deny_err(errno)),
        }
    }

    // ── Group A: rename ───────────────────────────────────────────────────────

    fn rename(
        &self,
        ctx: Context,
        olddir: Self::Inode,
        oldname: &CStr,
        newdir: Self::Inode,
        newname: &CStr,
        flags: u32,
    ) -> io::Result<()> {
        let start = Instant::now();
        let olddir_raw: u64 = olddir.into();
        let newdir_raw: u64 = newdir.into();
        let old_bytes = oldname.to_bytes();
        let new_bytes = newname.to_bytes();

        let verdict = self.policy.check_rename(olddir_raw, old_bytes, newdir_raw, new_bytes);
        let latency = Self::elapsed_ns(start);

        // Log with old name as the primary name field.
        self.audit.log(
            &ctx, OpKind::Rename, olddir_raw, newdir_raw, old_bytes, &verdict, latency,
        );

        match verdict {
            Verdict::Allow => self.inner.rename(ctx, olddir, oldname, newdir, newname, flags),
            Verdict::Deny { errno, .. } => Err(Self::deny_err(errno)),
        }
    }

    // ── Group A: link ─────────────────────────────────────────────────────────

    fn link(
        &self,
        ctx: Context,
        inode: Self::Inode,
        newparent: Self::Inode,
        newname: &CStr,
    ) -> io::Result<Entry> {
        let start = Instant::now();
        let name_bytes = newname.to_bytes();
        let newparent_raw: u64 = newparent.into();

        let verdict = self.policy.check_name_op(OP_LINK, newparent_raw, name_bytes);
        let latency = Self::elapsed_ns(start);

        self.audit.log(
            &ctx, OpKind::Link, newparent_raw, inode.into(), name_bytes, &verdict, latency,
        );

        match verdict {
            Verdict::Allow => self.inner.link(ctx, inode, newparent, newname),
            Verdict::Deny { errno, .. } => Err(Self::deny_err(errno)),
        }
    }

    // ── Directory operations ───────────────────────────────────────────────────

    // Enforce allow_open before forwarding directory-open requests.
    fn opendir(
        &self,
        ctx: Context,
        inode: Self::Inode,
        flags: u32,
    ) -> io::Result<(Option<Self::Handle>, OpenOptions)> {
        let start = Instant::now();
        let inode_raw: u64 = inode.into();
        let verdict = self.policy.check_op(OP_OPEN);
        let latency = Self::elapsed_ns(start);

        self.audit.log(
            &ctx, OpKind::Opendir, 0, inode_raw, b"", &verdict, latency,
        );

        match verdict {
            Verdict::Allow => self.inner.opendir(ctx, inode, flags),
            Verdict::Deny { errno, .. } => Err(Self::deny_err(errno)),
        }
    }

    // Enforce allow_read before forwarding directory-read requests.
    fn readdir(
        &self,
        ctx: Context,
        inode: Self::Inode,
        handle: Self::Handle,
        size: u32,
        offset: u64,
    ) -> io::Result<Self::DirIter> {
        let start = Instant::now();
        let inode_raw: u64 = inode.into();
        let verdict = self.policy.check_op(OP_READ);
        let latency = Self::elapsed_ns(start);

        self.audit.log(
            &ctx, OpKind::Readdir, 0, inode_raw, b"", &verdict, latency,
        );

        match verdict {
            Verdict::Allow => self.inner.readdir(ctx, inode, handle, size, offset),
            Verdict::Deny { errno, .. } => Err(Self::deny_err(errno)),
        }
    }


    fn releasedir(
        &self,
        ctx: Context,
        inode: Self::Inode,
        flags: u32,
        handle: Self::Handle,
    ) -> io::Result<()> {
        self.inner.releasedir(ctx, inode, flags, handle)
    }

    // ── Group B: xattr operations ─────────────────────────────────────────────

    fn setxattr(
        &self,
        ctx: Context,
        inode: Self::Inode,
        name: &CStr,
        value: &[u8],
        flags: u32,
        extra_flags: SetxattrFlags,
    ) -> io::Result<()> {
        let start = Instant::now();
        let verdict = self.policy.check_op(OP_XATTR);
        let latency = Self::elapsed_ns(start);
        self.audit.log(&ctx, OpKind::Setxattr, 0, inode.into(), name.to_bytes(), &verdict, latency);
        match verdict {
            Verdict::Allow => self.inner.setxattr(ctx, inode, name, value, flags, extra_flags),
            Verdict::Deny { errno, .. } => Err(Self::deny_err(errno)),
        }
    }

    fn getxattr(
        &self,
        ctx: Context,
        inode: Self::Inode,
        name: &CStr,
        size: u32,
    ) -> io::Result<GetxattrReply> {
        let start = Instant::now();
        let verdict = self.policy.check_op(OP_XATTR);
        let latency = Self::elapsed_ns(start);
        self.audit.log(&ctx, OpKind::Getxattr, 0, inode.into(), name.to_bytes(), &verdict, latency);
        match verdict {
            Verdict::Allow => self.inner.getxattr(ctx, inode, name, size),
            Verdict::Deny { errno, .. } => Err(Self::deny_err(errno)),
        }
    }

    fn listxattr(
        &self,
        ctx: Context,
        inode: Self::Inode,
        size: u32,
    ) -> io::Result<ListxattrReply> {
        let start = Instant::now();
        let verdict = self.policy.check_op(OP_XATTR);
        let latency = Self::elapsed_ns(start);
        self.audit.log(&ctx, OpKind::Listxattr, 0, inode.into(), b"", &verdict, latency);
        match verdict {
            Verdict::Allow => self.inner.listxattr(ctx, inode, size),
            Verdict::Deny { errno, .. } => Err(Self::deny_err(errno)),
        }
    }

    fn removexattr(
        &self,
        ctx: Context,
        inode: Self::Inode,
        name: &CStr,
    ) -> io::Result<()> {
        let start = Instant::now();
        let verdict = self.policy.check_op(OP_XATTR);
        let latency = Self::elapsed_ns(start);
        self.audit.log(&ctx, OpKind::Removexattr, 0, inode.into(), name.to_bytes(), &verdict, latency);
        match verdict {
            Verdict::Allow => self.inner.removexattr(ctx, inode, name),
            Verdict::Deny { errno, .. } => Err(Self::deny_err(errno)),
        }
    }

    // ── Not implemented in virtiofsd — pass through as ENOSYS ─────────────────

    fn getlk(&self) -> io::Result<()> {
        self.inner.getlk()
    }
    fn setlk(&self) -> io::Result<()> {
        self.inner.setlk()
    }
    fn setlkw(&self) -> io::Result<()> {
        self.inner.setlkw()
    }
    fn ioctl(&self) -> io::Result<()> {
        self.inner.ioctl()
    }
    fn bmap(&self) -> io::Result<()> {
        self.inner.bmap()
    }
    fn poll(&self) -> io::Result<()> {
        self.inner.poll()
    }
    fn notify_reply(&self) -> io::Result<()> {
        self.inner.notify_reply()
    }
    fn tmpfile(&self) -> io::Result<(Entry, Option<Self::Handle>, OpenOptions)> {
        self.inner.tmpfile()
    }
}

// ─── SerializableFileSystem: unconditional delegation ────────────────────────
// Migration state is managed entirely by the inner PassthroughFs.

impl<F: FileSystem + SerializableFileSystem + Sync> SerializableFileSystem for FilteredFs<F>
where
    F::Inode: Copy,
    F::Handle: Copy,
{
    fn prepare_serialization(&self, cancel: std::sync::Arc<std::sync::atomic::AtomicBool>) {
        self.inner.prepare_serialization(cancel)
    }

    fn serialize(&self, state_pipe: File) -> io::Result<()> {
        self.inner.serialize(state_pipe)
    }

    fn deserialize_and_apply(&self, state_pipe: File) -> io::Result<()> {
        self.inner.deserialize_and_apply(state_pipe)
    }
}

#[cfg(test)]
mod forwarding_regression_tests {
    use super::FilteredFs;
    use virtiofsd::filesystem::{
        Context, DirEntry, DirectoryIterator, Entry, Extensions, FileSystem, OpenOptions,
    };
    use crate::filter::audit::AuditLogger;
    use crate::filter::config::FilterConfig;
    use crate::filter::policy::PolicyEngine;
    use std::ffi::CStr;
    use std::io;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    struct EmptyDirIter;

    impl DirectoryIterator for EmptyDirIter {
        fn next(&mut self) -> Option<DirEntry<'_>> {
            None
        }
    }

    struct RecordingFs {
        symlink_called: Arc<AtomicBool>,
        readlink_called: Arc<AtomicBool>,
        opendir_called: Arc<AtomicBool>,
        readdir_called: Arc<AtomicBool>,
    }

    impl FileSystem for RecordingFs {
        type Inode = u64;
        type Handle = u64;
        type DirIter = EmptyDirIter;

        fn symlink(
            &self,
            _ctx: Context,
            _linkname: &CStr,
            _parent: Self::Inode,
            _name: &CStr,
            _extensions: Extensions,
        ) -> io::Result<Entry> {
            self.symlink_called.store(true, Ordering::SeqCst);
            Err(io::Error::from_raw_os_error(libc::ENOSYS))
        }

        fn readlink(
            &self,
            _ctx: Context,
            _inode: Self::Inode,
        ) -> io::Result<Vec<u8>> {
            self.readlink_called.store(true, Ordering::SeqCst);
            Ok(b"safe-target".to_vec())
        }

        fn opendir(
            &self,
            _ctx: Context,
            _inode: Self::Inode,
            _flags: u32,
        ) -> io::Result<(Option<Self::Handle>, OpenOptions)> {
            self.opendir_called.store(true, Ordering::SeqCst);
            Err(io::Error::from_raw_os_error(libc::ENOSYS))
        }

        fn readdir(
            &self,
            _ctx: Context,
            _inode: Self::Inode,
            _handle: Self::Handle,
            _size: u32,
            _offset: u64,
        ) -> io::Result<Self::DirIter> {
            self.readdir_called.store(true, Ordering::SeqCst);
            Ok(EmptyDirIter)
        }
    }

    fn test_context() -> Context {
        Context {
            uid: 0.into(),
            gid: 0.into(),
            pid: 1,
        }
    }

    #[test]
    fn denied_symlink_does_not_reach_inner_filesystem() {
        let mut config = FilterConfig::default();
        config.operations.allow_symlink = false;

        let called = Arc::new(AtomicBool::new(false));
        let inner = RecordingFs {
            symlink_called: Arc::clone(&called),
            readlink_called: Arc::new(AtomicBool::new(false)),
            opendir_called: Arc::new(AtomicBool::new(false)),
            readdir_called: Arc::new(AtomicBool::new(false)),
        };

        let fs = FilteredFs::new(
            inner,
            PolicyEngine::from_config(&config),
            AuditLogger::disabled(),
        );

        let target = CStr::from_bytes_with_nul(b"safe-target\0").unwrap();
        let name = CStr::from_bytes_with_nul(b"normal-link\0").unwrap();

        let result = fs.symlink(
            test_context(),
            target,
            1,
            name,
            Extensions::default(),
        );

        assert!(result.is_err(), "the denied operation should return an error");
        assert!(
            !called.load(Ordering::SeqCst),
            "a denied symlink must not reach the underlying filesystem"
        );
    }

    #[test]
    fn allowed_symlink_reaches_inner_filesystem() {
        let config = FilterConfig::default();

        let called = Arc::new(AtomicBool::new(false));
        let inner = RecordingFs {
            symlink_called: Arc::clone(&called),
            readlink_called: Arc::new(AtomicBool::new(false)),
            opendir_called: Arc::new(AtomicBool::new(false)),
            readdir_called: Arc::new(AtomicBool::new(false)),
        };

        let fs = FilteredFs::new(
            inner,
            PolicyEngine::from_config(&config),
            AuditLogger::disabled(),
        );

        let target = CStr::from_bytes_with_nul(b"safe-target\0").unwrap();
        let name = CStr::from_bytes_with_nul(b"normal-link\0").unwrap();

        let result = fs.symlink(
            test_context(),
            target,
            1,
            name,
            Extensions::default(),
        );

        assert!(
            called.load(Ordering::SeqCst),
            "an allowed symlink should reach the underlying filesystem"
        );

        match result {
            Err(error) => assert_eq!(error.raw_os_error(), Some(libc::ENOSYS)),
            Ok(_) => panic!("the fake filesystem is expected to return ENOSYS"),
        }
    }

    #[test]
    fn disabled_read_policy_blocks_readlink_and_readdir() {
        let mut config = FilterConfig::default();
        config.operations.allow_read = false;

        let readlink_called = Arc::new(AtomicBool::new(false));
        let readdir_called = Arc::new(AtomicBool::new(false));

        let inner = RecordingFs {
            symlink_called: Arc::new(AtomicBool::new(false)),
            readlink_called: Arc::clone(&readlink_called),
            opendir_called: Arc::new(AtomicBool::new(false)),
            readdir_called: Arc::clone(&readdir_called),
        };

        let fs = FilteredFs::new(
            inner,
            PolicyEngine::from_config(&config),
            AuditLogger::disabled(),
        );

        assert!(fs.readlink(test_context(), 1).is_err());
        assert!(!readlink_called.load(Ordering::SeqCst));

        assert!(fs.readdir(test_context(), 1, 2, 4096, 0).is_err());
        assert!(!readdir_called.load(Ordering::SeqCst));
    }

    #[test]
    fn disabled_open_policy_blocks_opendir() {
        let mut config = FilterConfig::default();
        config.operations.allow_open = false;

        let opendir_called = Arc::new(AtomicBool::new(false));

        let inner = RecordingFs {
            symlink_called: Arc::new(AtomicBool::new(false)),
            readlink_called: Arc::new(AtomicBool::new(false)),
            opendir_called: Arc::clone(&opendir_called),
            readdir_called: Arc::new(AtomicBool::new(false)),
        };

        let fs = FilteredFs::new(
            inner,
            PolicyEngine::from_config(&config),
            AuditLogger::disabled(),
        );

        assert!(fs.opendir(test_context(), 1, 0).is_err());
        assert!(!opendir_called.load(Ordering::SeqCst));
    }

}
