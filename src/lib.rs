#![doc = include_str!("../README.md")]
#![cfg(target_os = "linux")]

use std::{
    io::ErrorKind,
    os::fd::{AsFd as _, BorrowedFd, OwnedFd},
};

mod sockaddr;
mod sys;
mod syscall;
use log::{info, trace, warn};
use rustix::thread::Pid;
use sockaddr::SockAddr;
use syscall::Syscall;

/// Setup errors.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("Architecture {0:?} is not supported.")]
    UnsupportedArch(String),
}

/// A seccomp filter that selectively allows a process inside a network
/// namespace to `bind` and `connect` addresses that would normally not work.
pub struct NetnsFirewall {
    pub(crate) rules: Vec<Rule>,

    notif: sys::seccomp_notif,
    resp: sys::seccomp_notif_resp,
}

impl NetnsFirewall {
    /// Constructs a new NetnsFirewall with the given rules.
    pub fn new(rules: impl IntoIterator<Item = Rule>) -> Result<(Self, Filter), Error> {
        let this = Self {
            rules: rules.into_iter().collect(),
            // SAFETY: seccomp_notif and seccomp_notif_resp are repr(C) structs
            // composed of primitive types.
            notif: unsafe { std::mem::zeroed() },
            resp: unsafe { std::mem::zeroed() },
        };

        let arch = std::env::consts::ARCH
            .try_into()
            .map_err(|_| Error::UnsupportedArch(std::env::consts::ARCH.to_owned()))?;

        let seccomp_filter = {
            let rules: Vec<(i64, Vec<seccompiler::SeccompRule>)> =
                vec![(libc::SYS_bind, vec![]), (libc::SYS_connect, vec![])];

            match seccompiler::SeccompFilter::new(
                rules.into_iter().collect(),
                seccompiler::SeccompAction::Allow,  // mismatch
                seccompiler::SeccompAction::Notify, // match
                arch,
            ) {
                Ok(v) => v,
                Err(seccompiler::BackendError::InvalidTargetArch(arch)) => {
                    return Err(Error::UnsupportedArch(arch))
                }
                // Should never happen, since our rules are defined statically.
                Err(e) => panic!("failed to create seccomp filter: {e}"),
            }
        };

        let bpf = seccomp_filter
            .try_into()
            .expect("failed to compile seccomp filter");

        Ok((this, Filter(bpf)))
    }

    /// Monitor the child process(es) using the seccomp_unotify file descriptor
    /// returned from [Filter::install]. Blocks indefinitely.
    pub fn run(&mut self, fd: OwnedFd) -> std::io::Result<()> {
        loop {
            self.run_once(fd.as_fd())?;
        }
    }

    /// Handle a single syscall notification. This will block until a
    /// notification is received.
    ///
    /// This is probably only useful if you use poll/epoll/etc to monitor the
    /// FD you got from [Filter::install].
    pub fn run_once(&mut self, fd: BorrowedFd) -> std::io::Result<()> {
        sys::notif_recv(fd.as_fd(), &mut self.notif)?;

        let id = self.notif.id;
        let pid = Pid::from_raw(self.notif.pid as _).ok_or_else(|| {
            std::io::Error::new(
                ErrorKind::InvalidInput,
                "invalid PID returned by SECCOMP_IOCTL_NOTIF_RECV",
            )
        })?;

        let notif = self.notif.data;
        let syscall = Syscall::from_seccomp_data(id, pid, notif)?;

        // Check against our ruleset.
        if self.allow_syscall(&syscall) {
            info!("[{: >6}] ALLOW {:?}", pid.as_raw_nonzero(), syscall);

            let res = syscall.execute();
            sys::resp_return(fd.as_fd(), self.notif.id, res, &mut self.resp)?;
        } else {
            info!("[{: >6}]  DENY {:?}", pid.as_raw_nonzero(), syscall);

            // Tell seccomp to continue the process's syscall, where it will be
            // blocked or otherwise handled as normal by the network namespace.
            sys::resp_continue(fd.as_fd(), self.notif.id, &mut self.resp)?;
        }

        Ok(())
    }

    fn allow_syscall(&mut self, syscall: &Syscall) -> bool {
        if matches!(syscall, Syscall::Invalid) {
            return false;
        }

        let mut allows = 0;
        for rule in &self.rules {
            let matches = rule.matches(syscall);
            trace!(
                "applying rule: {:?} to syscall: {:?} with result: {}",
                rule,
                syscall,
                matches
            );

            if matches {
                match rule.action {
                    Action::Deny => return false,
                    Action::Allow => allows += 1,
                }
            }
        }

        if allows > 0 {
            if allows > 1 {
                warn!("multiple rules match syscall: {syscall:?}");
            }

            true
        } else {
            false
        }
    }
}

/// The filter portion of a NetnsFirewall.
pub struct Filter(seccompiler::BpfProgram);

impl Filter {
    /// Installs the filter in the current process, returning a FD which can be
    /// monitored elsewhere. This function should be called *after* `fork` or
    /// `clone`, and then the resulting fd passed back to the supervisor process
    /// using some sort of IPC mechanism. Note that the returned FD has CLOEXEC
    /// set on it.
    ///
    /// The calling thread must have already set PR_SET_NO_NEW_PRIVS, with the
    /// equivalent of:
    ///
    ///    prctl(PR_SET_NO_NEW_PRIVS, 1)
    ///
    /// Or the installation will fail.
    pub fn install(self) -> std::io::Result<OwnedFd> {
        match seccompiler::apply_filter_with_notify_fd(&self.0) {
            Ok(fd) => Ok(fd),
            Err(seccompiler::Error::Seccomp(e)) | Err(seccompiler::Error::Prctl(e)) => Err(e),
            Err(e) => Err(std::io::Error::other(e)),
        }
    }
}

/// A rule for a [NetnsFirewall] to follow.
///
/// Rules are collected into an ordered list for processing. When processing
/// rules, [NetnsFirewall] uses the following semantics:
///
///  - Rules match sockaddr_* structs. See [AddrMatcher] and [DirectionMatcher]
///    for details on matching.
///  - Rules have an action, which is one of [Action::Allow] or
///    [Action::Deny].
///  - Rules are processed sequentially until a rule with [Action::Deny] is
///    matched, in which case processing is short-circuited and the syscall is
///    denied (ignored).
///  - If no rules match, the syscall is denied (ignored).
#[derive(Debug, Clone)]
pub struct Rule {
    pub action: Action,
    pub direction: DirectionMatcher,
    pub addr: AddrMatcher,
}

impl Rule {
    /// A rule that matches everything and allows it.
    pub fn allow_everything() -> Self {
        Rule {
            action: Action::Allow,
            direction: DirectionMatcher::Both,
            addr: AddrMatcher::Everything,
        }
    }

    /// A rule that matches everything and denies it.
    pub fn deny_everything() -> Self {
        Rule {
            action: Action::Deny,
            direction: DirectionMatcher::Both,
            addr: AddrMatcher::Everything,
        }
    }

    fn matches(&self, syscall: &Syscall) -> bool {
        if !self.direction.matches(syscall) {
            return false;
        }

        let addr = match syscall {
            Syscall::Invalid => todo!(),
            Syscall::Bind(_, addr) | Syscall::Connect(_, addr) => addr,
        };

        self.addr.matches(addr)
    }
}

/// An action to perform on a match.
#[derive(Debug, Clone)]
pub enum Action {
    /// Perform the syscall on behalf of the process.
    Allow,
    /// Ignore the syscall.
    Deny,
}

/// A matcher for a syscall's "direction".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DirectionMatcher {
    /// Matches any syscall.
    Both,
    /// Matches `bind`, `recvfrom`, etc.
    Inbound,
    /// Matches `connect`, `sendto`, etc.
    Outbound,
}

impl DirectionMatcher {
    /// Attempt to match the given syscall.
    fn matches(&self, syscall: &Syscall) -> bool {
        if *self == Self::Both {
            return true;
        }

        let direction = match syscall {
            Syscall::Invalid => unreachable!(),
            Syscall::Bind(_, _) => Self::Inbound,
            Syscall::Connect(_, _) => Self::Outbound,
        };

        self.eq(&direction)
    }
}

/// A matcher for a sockaddr_* struct.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddrMatcher {
    /// Matches any valid sockaddr_* value.
    Everything,
}

impl AddrMatcher {
    /// Attempt to match the given sockaddr value.
    fn matches(&self, _addr: &SockAddr) -> bool {
        match self {
            Self::Everything => true,
        }
    }
}
