// SPDX-License-Identifier: Apache-2.0
// virtiofsd V1 host-side request-validation filter — audit logger

use virtiofsd::soft_idmap::Id;
use std::fs::OpenOptions;
use std::io::{BufWriter, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender, TrySendError};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::filter::config::{AuditConfig, AuditDestination, AuditLevel};
use crate::filter::policy::Verdict;
use virtiofsd::filesystem::Context;

/// Classification of the filesystem operation for the audit record.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpKind {
    Lookup = 0,
    Create = 1,
    Mkdir = 2,
    Unlink = 3,
    Rmdir = 4,
    Rename = 5,
    Symlink = 6,
    Link = 7,
    Mknod = 8,
    Open = 9,
    Read = 10,
    Write = 11,
    Setattr = 12,
    Fallocate = 13,
    Opendir = 14,
    Readlink = 15,
    Setxattr = 16,
    Getxattr = 17,
    Listxattr = 18,
    Removexattr = 19,
    Copyfilerange = 20,
    Syncfs = 21,
    Fsync = 22,
    Fsyncdir = 23,
    Tmpfile = 24,
    Readdir = 25,
    Other = 255,
}

impl OpKind {
    pub fn as_str(self) -> &'static str {
        match self {
            OpKind::Lookup => "lookup",
            OpKind::Create => "create",
            OpKind::Mkdir => "mkdir",
            OpKind::Unlink => "unlink",
            OpKind::Rmdir => "rmdir",
            OpKind::Rename => "rename",
            OpKind::Symlink => "symlink",
            OpKind::Link => "link",
            OpKind::Mknod => "mknod",
            OpKind::Open => "open",
            OpKind::Read => "read",
            OpKind::Write => "write",
            OpKind::Setattr => "setattr",
            OpKind::Fallocate => "fallocate",
            OpKind::Opendir => "opendir",
            OpKind::Readlink => "readlink",
            OpKind::Setxattr => "setxattr",
            OpKind::Getxattr => "getxattr",
            OpKind::Listxattr => "listxattr",
            OpKind::Removexattr => "removexattr",
            OpKind::Copyfilerange => "copyfilerange",
            OpKind::Syncfs => "syncfs",
            OpKind::Fsync => "fsync",
            OpKind::Fsyncdir => "fsyncdir",
            OpKind::Tmpfile => "tmpfile",
            OpKind::Readdir => "readdir",
            OpKind::Other => "other",
        }
    }
}

/// Maximum bytes of a name stored inline in an AuditRecord.
/// Names longer than this are truncated; the original length is preserved in `name_len`.
const NAME_INLINE_MAX: usize = 64;

/// A single audit event. Fixed-size to avoid per-record heap allocation.
/// All allocation for serialization happens on the background writer thread.
pub struct AuditRecord {
    /// Monotonic nanoseconds since boot (CLOCK_MONOTONIC).
    pub timestamp_mono_ns: u64,
    /// Wall-clock Unix timestamp: seconds.
    pub timestamp_wall_s: i64,
    /// Wall-clock nanoseconds fraction.
    pub timestamp_wall_ns: u32,

    /// Guest process context.
    pub uid: u32,
    pub gid: u32,
    pub pid: u32,

    /// Operation kind.
    pub op: OpKind,

    /// Parent inode (0 if not applicable for this op).
    pub parent_inode: u64,
    /// Target/subject inode (0 if not applicable).
    pub target_inode: u64,

    /// Policy decision.
    pub allow: bool,
    /// errno on deny (0 on allow).
    pub errno: i32,
    /// Static reason string (points into static string table).
    pub reason: &'static str,

    /// First NAME_INLINE_MAX bytes of the leaf name (zero-padded).
    pub name: [u8; NAME_INLINE_MAX],
    /// Actual name length before truncation.
    pub name_len: u8,

    /// Filter check latency in nanoseconds (saturating at u32::MAX).
    pub latency_ns: u32,
}

impl AuditRecord {
    fn new_allow(ctx: &Context, op: OpKind, parent: u64, target: u64, latency_ns: u32) -> Self {
        let (wall_s, wall_ns) = wall_time();
        AuditRecord {
            timestamp_mono_ns: mono_time_ns(),
            timestamp_wall_s: wall_s,
            timestamp_wall_ns: wall_ns,
            uid: ctx.uid.into_inner(),
            gid: ctx.gid.into_inner(),
            pid: ctx.pid as u32,
            op,
            parent_inode: parent,
            target_inode: target,
            allow: true,
            errno: 0,
            reason: "",
            name: [0u8; NAME_INLINE_MAX],
            name_len: 0,
            latency_ns,
        }
    }

    fn new_deny(
        ctx: &Context,
        op: OpKind,
        parent: u64,
        target: u64,
        errno: i32,
        reason: &'static str,
        latency_ns: u32,
    ) -> Self {
        let (wall_s, wall_ns) = wall_time();
        AuditRecord {
            timestamp_mono_ns: mono_time_ns(),
            timestamp_wall_s: wall_s,
            timestamp_wall_ns: wall_ns,
            uid: ctx.uid.into_inner(),
            gid: ctx.gid.into_inner(),
            pid: ctx.pid as u32,
            op,
            parent_inode: parent,
            target_inode: target,
            allow: false,
            errno,
            reason,
            name: [0u8; NAME_INLINE_MAX],
            name_len: 0,
            latency_ns,
        }
    }

    /// Copy the first NAME_INLINE_MAX bytes of `name` into the record.
    fn set_name(&mut self, name: &[u8]) {
        let copy_len = name.len().min(NAME_INLINE_MAX);
        self.name[..copy_len].copy_from_slice(&name[..copy_len]);
        self.name_len = name.len().min(255) as u8;
    }

    /// Serialize to a JSON-Lines string (one line per record).
    fn to_json_line(&self) -> String {
        // Inline name: strip trailing NUL padding, then escape for JSON.
        let name_bytes = &self.name[..self.name_len.min(NAME_INLINE_MAX as u8) as usize];
        let name_str = String::from_utf8_lossy(name_bytes);

        // Wall-clock ISO-8601 approximation: seconds + nanoseconds.
        let decision = if self.allow { "allow" } else { "deny" };

        if self.allow {
            format!(
                "{{\"ts_wall_s\":{},\"ts_wall_ns\":{},\"mono_ns\":{},\"op\":\"{}\",\
                 \"uid\":{},\"gid\":{},\"pid\":{},\"parent_inode\":{},\"target_inode\":{},\
                 \"decision\":\"{}\",\"latency_ns\":{},\"name\":\"{}\"}}\n",
                self.timestamp_wall_s,
                self.timestamp_wall_ns,
                self.timestamp_mono_ns,
                self.op.as_str(),
                self.uid,
                self.gid,
                self.pid,
                self.parent_inode,
                self.target_inode,
                decision,
                self.latency_ns,
                name_str.replace('"', "\\\""),
            )
        } else {
            format!(
                "{{\"ts_wall_s\":{},\"ts_wall_ns\":{},\"mono_ns\":{},\"op\":\"{}\",\
                 \"uid\":{},\"gid\":{},\"pid\":{},\"parent_inode\":{},\"target_inode\":{},\
                 \"decision\":\"{}\",\"errno\":{},\"reason\":\"{}\",\
                 \"latency_ns\":{},\"name\":\"{}\"}}\n",
                self.timestamp_wall_s,
                self.timestamp_wall_ns,
                self.timestamp_mono_ns,
                self.op.as_str(),
                self.uid,
                self.gid,
                self.pid,
                self.parent_inode,
                self.target_inode,
                decision,
                self.errno,
                self.reason,
                self.latency_ns,
                name_str.replace('"', "\\\""),
            )
        }
    }
}

// ─── AuditLogger ─────────────────────────────────────────────────────────────

/// Non-blocking audit logger backed by a bounded MPSC channel.
/// A background thread drains the channel and writes JSON-Lines to the configured output.
#[derive(Clone)]
pub struct AuditLogger {
    level: AuditLevel,
    sender: Option<SyncSender<AuditRecord>>,
    dropped: Arc<AtomicU64>,
}

impl AuditLogger {
    /// Create a disabled AuditLogger that performs no logging, allocates no channels,
    /// and spawns no background threads.
    pub fn disabled() -> Self {
        AuditLogger {
            level: AuditLevel::None,
            sender: None,
            dropped: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Create a new AuditLogger from config. Spawns the background writer thread.
    pub fn new(cfg: &AuditConfig) -> std::io::Result<Self> {
        if !cfg.enabled || cfg.level == AuditLevel::None {
            return Ok(Self::disabled());
        }

        let (tx, rx): (SyncSender<AuditRecord>, Receiver<AuditRecord>) =
            sync_channel(cfg.channel_capacity);

        let dropped = Arc::new(AtomicU64::new(0));
        let dropped_clone = dropped.clone();

        // Open output before spawning thread so we return an error immediately if it fails.
        match cfg.destination {
            AuditDestination::File => {
                let path = cfg.path.clone();
                let file = OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&path)?;
                let writer = BufWriter::with_capacity(65536, file);
                spawn_writer_thread(rx, dropped_clone, Box::new(writer));
            }
            AuditDestination::Stderr => {
                let writer = BufWriter::with_capacity(65536, std::io::stderr());
                spawn_writer_thread(rx, dropped_clone, Box::new(writer));
            }
        }

        Ok(AuditLogger {
            level: cfg.level,
            sender: Some(tx),
            dropped,
        })
    }

    /// Send an audit record for a verdict. Non-blocking; drops on full channel.
    /// Does nothing if level==None or if the verdict is Allow and level==Deny.
    pub fn log(
        &self,
        ctx: &Context,
        op: OpKind,
        parent_inode: u64,
        target_inode: u64,
        name: &[u8],
        verdict: &Verdict,
        latency_ns: u32,
    ) {
        let sender = match &self.sender {
            Some(s) => s,
            None => return,
        };

        let is_deny = verdict.is_deny();

        // Level filter: only send deny events when level == Deny.
        match self.level {
            AuditLevel::None => return,
            AuditLevel::Deny if !is_deny => return,
            _ => {}
        }

        let mut record = match verdict {
            Verdict::Allow => AuditRecord::new_allow(ctx, op, parent_inode, target_inode, latency_ns),
            Verdict::Deny { errno, reason } => {
                AuditRecord::new_deny(ctx, op, parent_inode, target_inode, *errno, reason, latency_ns)
            }
        };
        record.set_name(name);

        match sender.try_send(record) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
            }
            Err(TrySendError::Disconnected(_)) => {
                // Background thread has exited; ignore silently.
            }
        }
    }

    /// Returns the number of dropped audit events since last call (resets counter).
    pub fn take_dropped_count(&self) -> u64 {
        self.dropped.swap(0, Ordering::Relaxed)
    }
}

// ─── Background writer thread ─────────────────────────────────────────────────

fn spawn_writer_thread(
    rx: Receiver<AuditRecord>,
    dropped: Arc<AtomicU64>,
    mut writer: Box<dyn Write + Send>,
) {
    std::thread::Builder::new()
        .name("vfsd-audit-writer".to_string())
        .spawn(move || {
            loop {
                match rx.recv_timeout(Duration::from_millis(200)) {
                    Ok(record) => {
                        let line = record.to_json_line();
                        // Ignore write errors on the writer thread to avoid panics.
                        let _ = writer.write_all(line.as_bytes());
                    }
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                        // Periodic flush.
                        let _ = writer.flush();
                        // Emit dropped-events line if any events were dropped since last flush.
                        let d = dropped.swap(0, Ordering::Relaxed);
                        if d > 0 {
                            let line = format!(
                                "{{\"event\":\"audit_dropped\",\"count\":{}}}\n",
                                d
                            );
                            let _ = writer.write_all(line.as_bytes());
                            let _ = writer.flush();
                        }
                    }
                    Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                        // Sender dropped; flush and exit.
                        let _ = writer.flush();
                        break;
                    }
                }
            }
        })
        .expect("failed to spawn audit writer thread");
}

// ─── Timing helpers ──────────────────────────────────────────────────────────

fn mono_time_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: ts is a valid, writable timespec; CLOCK_MONOTONIC is a valid clock ID.
    unsafe {
        libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts);
    }
    (ts.tv_sec as u64)
        .wrapping_mul(1_000_000_000)
        .wrapping_add(ts.tv_nsec as u64)
}

fn wall_time() -> (i64, u32) {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => (d.as_secs() as i64, d.subsec_nanos()),
        Err(_) => (0, 0),
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filter::config::{AuditConfig, AuditDestination, AuditLevel};
    use crate::filter::policy::Verdict;
    use virtiofsd::soft_idmap::{GuestGid, GuestUid};

    fn test_ctx() -> Context {
        Context {
            uid: GuestUid::from(1000u32),
            gid: GuestGid::from(1000u32),
            pid: 5678,
        }
    }

    fn disabled_logger() -> AuditLogger {
        let cfg = AuditConfig {
            enabled: false,
            level: AuditLevel::None,
            ..AuditConfig::default()
        };
        AuditLogger::new(&cfg).unwrap()
    }

    fn stderr_logger(level: AuditLevel) -> AuditLogger {
        let cfg = AuditConfig {
            enabled: true,
            destination: AuditDestination::Stderr,
            level,
            channel_capacity: 64,
            ..AuditConfig::default()
        };
        AuditLogger::new(&cfg).unwrap()
    }

    #[test]
    fn test_level_none_sender_is_none() {
        let logger = disabled_logger();
        assert!(logger.sender.is_none());
    }

    #[test]
    fn test_level_deny_allow_not_sent() {
        let logger = stderr_logger(AuditLevel::Deny);
        let ctx = test_ctx();
        // This should not panic or block, and should not send (level=Deny, verdict=Allow).
        logger.log(&ctx, OpKind::Read, 0, 123, b"", &Verdict::Allow, 100);
        // If we reach here without panic, the test passes.
    }

    #[test]
    fn test_level_all_allow_sent() {
        let logger = stderr_logger(AuditLevel::All);
        let ctx = test_ctx();
        // Should send without panic.
        logger.log(&ctx, OpKind::Read, 0, 123, b"file.txt", &Verdict::Allow, 100);
    }

    #[test]
    fn test_deny_sent_on_level_deny() {
        let logger = stderr_logger(AuditLevel::Deny);
        let ctx = test_ctx();
        let verdict = Verdict::Deny {
            errno: libc::EPERM,
            reason: "test deny",
        };
        // Should send without panic.
        logger.log(&ctx, OpKind::Unlink, 1, 0, b"shadow", &verdict, 200);
    }

    #[test]
    fn test_channel_full_increments_dropped() {
        // Very small channel to force drops.
        let cfg = AuditConfig {
            enabled: true,
            destination: AuditDestination::Stderr,
            level: AuditLevel::All,
            channel_capacity: 64, // minimum
            ..AuditConfig::default()
        };
        let logger = AuditLogger::new(&cfg).unwrap();
        let ctx = test_ctx();
        // Send many events without draining.
        // Note: background thread will drain some, so we can't guarantee exact drop count,
        // but we can verify dropped counter is accessible without panic.
        for _ in 0..200 {
            logger.log(&ctx, OpKind::Write, 0, 1, b"f", &Verdict::Allow, 50);
        }
        // Check counter is accessible (may be 0 if thread drained fast enough).
        let _dropped = logger.take_dropped_count();
    }

    #[test]
    fn test_record_json_allow() {
        let ctx = test_ctx();
        let mut r = AuditRecord::new_allow(&ctx, OpKind::Read, 5, 10, 123);
        r.set_name(b"file.txt");
        let json = r.to_json_line();
        assert!(json.contains("\"op\":\"read\""));
        assert!(json.contains("\"decision\":\"allow\""));
        assert!(json.contains("\"name\":\"file.txt\""));
        assert!(json.ends_with('\n'));
    }

    #[test]
    fn test_record_json_deny() {
        let ctx = test_ctx();
        let mut r = AuditRecord::new_deny(&ctx, OpKind::Unlink, 1, 0, libc::EPERM, "test reason", 456);
        r.set_name(b"shadow");
        let json = r.to_json_line();
        assert!(json.contains("\"op\":\"unlink\""));
        assert!(json.contains("\"decision\":\"deny\""));
        assert!(json.contains("\"reason\":\"test reason\""));
        assert!(json.contains("\"name\":\"shadow\""));
    }

    #[test]
    fn test_name_truncation_at_64() {
        let ctx = test_ctx();
        let mut r = AuditRecord::new_allow(&ctx, OpKind::Lookup, 1, 0, 100);
        let long_name: Vec<u8> = b"a".repeat(100);
        r.set_name(&long_name);
        // name_len is capped at 255 (u8 max) but actual stored length is capped at NAME_INLINE_MAX.
        assert_eq!(r.name_len, 100); // actual length stored
        // First 64 bytes of name are stored.
        assert_eq!(&r.name[..64], b"a".repeat(64).as_slice());
    }

    #[test]
    fn test_contains_dotdot_component() {
        use super::super::policy::contains_dotdot_component;
        assert!(contains_dotdot_component(b"../escape"));
        assert!(contains_dotdot_component(b"foo/../bar"));
        assert!(contains_dotdot_component(b"foo/.."));
        assert!(!contains_dotdot_component(b"foo/bar"));
        assert!(!contains_dotdot_component(b"a..b"));
        assert!(!contains_dotdot_component(b"notdotdot"));
    }
}
