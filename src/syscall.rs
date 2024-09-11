use std::os::fd::{AsRawFd as _, OwnedFd};
use std::os::unix::fs::FileExt;

use log::warn;
use rustix::io::Errno;
use rustix::net::{bind, connect};
use rustix::process::{pidfd_getfd, PidfdGetfdFlags};
use rustix::{
    process::{pidfd_open, PidfdFlags},
    thread::Pid,
};

use crate::{sockaddr::SockAddr, sys};

/// A syscall being made by a supervised process.
pub(crate) enum Syscall {
    Invalid,
    Bind(OwnedFd, SockAddr),
    Connect(OwnedFd, SockAddr),
}

impl std::fmt::Debug for Syscall {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Syscall::Invalid => write!(f, "INVALID"),
            Syscall::Bind(fd, sa) => write!(f, "bind({}, {:?})", fd.as_raw_fd(), sa),
            Syscall::Connect(fd, sa) => write!(f, "connect({}, {:?})", fd.as_raw_fd(), sa),
        }
    }
}

impl Syscall {
    /// Determines the syscall and fetches args from the child process memory.
    pub(crate) fn from_seccomp_data(
        _id: u64,
        pid: Pid,
        data: sys::seccomp_data,
    ) -> std::io::Result<Self> {
        let nr = data.nr as _;
        let (fd_arg, off_arg, len_arg) = match nr {
            libc::SYS_connect | libc::SYS_bind if data.args.len() >= 3 => {
                (data.args[0], data.args[1], data.args[2])
            }
            _ => {
                warn!("unknown syscall number: {}", nr);
                return Ok(Self::Invalid);
            }
        };

        let Ok(fd) = fd_arg.try_into() else {
            return Ok(Self::Invalid);
        };

        let Ok(len) = len_arg.try_into() else {
            return Ok(Self::Invalid);
        };

        // ENOENT here means the process has terminated.
        // FIXME: we can potentially cache the pidfd and the fd itself.
        let child_pidfd = pidfd_open(pid, PidfdFlags::empty())?;
        let procmem = sys::open_procmem(pid)?;

        // TODO: Here, we're supposed to verify that the cookie is still
        // valid.
        // sys::verify_id(id)?;

        let syscall_fd = pidfd_getfd(child_pidfd, fd, PidfdGetfdFlags::empty())?;

        let mut sockaddr_buf = vec![0_u8; len];
        procmem.read_exact_at(&mut sockaddr_buf, off_arg)?;

        let Some(sa) = SockAddr::read(&sockaddr_buf) else {
            warn!("invalid sockaddr: {:?}", &sockaddr_buf);
            return Ok(Self::Invalid);
        };

        match nr {
            libc::SYS_connect => Ok(Self::Connect(syscall_fd, sa)),
            libc::SYS_bind => Ok(Self::Bind(syscall_fd, sa)),
            _ => unreachable!(),
        }
    }

    pub(crate) fn execute(self) -> Result<i64, Errno> {
        match self {
            Self::Invalid => unreachable!(),
            Self::Connect(fd, addr) => {
                let SockAddr::Inet(addr) = addr;
                connect(fd, &addr).map(|_| 0)
            }
            Self::Bind(fd, addr) => {
                let SockAddr::Inet(addr) = addr;
                bind(fd, &addr).map(|_| 0)
            }
        }
    }
}
