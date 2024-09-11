#![allow(non_camel_case_types, dead_code)]

use std::fs::OpenOptions;
use std::io::Result;
use std::os::fd::BorrowedFd;
use std::os::raw::c_void;

use rustix::io::Errno;
use rustix::ioctl;

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

// FIXME: we need to account for different sizes using SECCOMP_GET_NOTIF_SIZES.
// This would work given consts_refs_to_static.
//
// static SECCOMP_NOTIF_SIZES: LazyLock<seccomp_notif_sizes> = LazyLock::new(|| unsafe {
//     let mut sizes: seccomp_notif_sizes = std::mem::zeroed();
//     let rc = libc::syscall(
//         SYS_seccomp,
//         SECCOMP_GET_NOTIF_SIZES,
//         0,
//         &mut sizes as *mut seccomp_notif_sizes as *mut _,
//     );
//
//     if rc < 0 {
//         panic!("failed to call SECCOMP_GET_NOTIF_SIZES");
//     }
//
//     sizes
// });
//
// const SECCOMP_NOTIF_LEN: usize = SECCOMP_NOTIF_SIZES.seccomp_notif as usize;

struct NotifRecv<'a>(&'a mut seccomp_notif);

unsafe impl ioctl::Ioctl for NotifRecv<'_> {
    type Output = ();

    const IS_MUTATING: bool = true;
    const OPCODE: ioctl::Opcode = ioctl::Opcode::read_write::<seccomp_notif>(b'!', 0);

    fn as_ptr(&mut self) -> *mut c_void {
        self.0 as *mut _ as _
    }

    unsafe fn output_from_ptr(
        _: ioctl::IoctlOutput,
        _: *mut c_void,
    ) -> rustix::io::Result<Self::Output> {
        Ok(())
    }
}

struct NotifSend<'a>(&'a mut seccomp_notif_resp);

unsafe impl ioctl::Ioctl for NotifSend<'_> {
    type Output = ();

    const IS_MUTATING: bool = true;
    const OPCODE: ioctl::Opcode = ioctl::Opcode::read_write::<seccomp_notif_resp>(b'!', 1);

    fn as_ptr(&mut self) -> *mut c_void {
        self.0 as *mut _ as _
    }

    unsafe fn output_from_ptr(
        _: ioctl::IoctlOutput,
        _: *mut c_void,
    ) -> rustix::io::Result<Self::Output> {
        Ok(())
    }
}

/// Fetches a seccomp notification.
pub(crate) fn notif_recv(fd: BorrowedFd, notif: &mut seccomp_notif) -> Result<()> {
    notif.id = 0;
    notif.pid = 0;
    notif.flags = 0;
    notif.data = unsafe { std::mem::zeroed() };

    // SAFETY: our seccomp_notif is initialized (even if just with zeroes) and
    // we are using the ioctl as documented.
    unsafe { ioctl::ioctl(fd, NotifRecv(notif))? };

    Ok(())
}

pub(crate) fn resp_return(
    fd: BorrowedFd,
    id: u64,
    rc: std::result::Result<i64, Errno>,
    resp: &mut seccomp_notif_resp,
) -> Result<()> {
    resp.id = id;
    resp.flags = 0;

    match rc {
        Ok(v) => {
            resp.val = v;
            resp.error = 0;
        }
        Err(e) => {
            resp.val = 0;
            resp.error = e.raw_os_error();
        }
    }

    resp_send(fd, resp)
}

pub(crate) fn resp_continue(fd: BorrowedFd, id: u64, resp: &mut seccomp_notif_resp) -> Result<()> {
    resp.id = id;
    resp.val = 0;
    resp.error = 0;
    resp.flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;

    resp_send(fd, resp)
}

pub(crate) fn resp_send(fd: BorrowedFd, resp: &mut seccomp_notif_resp) -> Result<()> {
    // SAFETY: our seccomp_notif_resp is initialized (even if just with zeroes)
    // and we are using the ioctl as documented.
    match unsafe { ioctl::ioctl(fd, NotifSend(resp)) } {
        Ok(_) => Ok(()),
        // This means the process terminated, which is not our problem.
        Err(e) if e == Errno::NOENT => Ok(()),
        Err(e) => Err(e.into()),
    }
}

pub(crate) fn open_procmem(pid: rustix::thread::Pid) -> Result<std::fs::File> {
    let proc_mem_path = format!("/proc/{}/mem", pid.as_raw_nonzero());
    OpenOptions::new().read(true).open(&proc_mem_path)
}
