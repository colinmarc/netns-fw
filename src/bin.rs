#![cfg(target_os = "linux")]

use std::{
    io::{ErrorKind, Result},
    os::unix::{net::UnixDatagram, process::CommandExt as _},
    path::Path,
    process::Command,
};

use clap::Parser as _;
use log::info;
use rustix::{
    fd::{AsFd as _, AsRawFd as _, FromRawFd as _, OwnedFd},
    fs::{open, openat, Mode, OFlags},
    io::Errno,
    process::{wait, Pid, Signal, WaitOptions},
    thread::LinkNameSpaceType,
};
use uds::UnixDatagramExt as _;

/// A tool to allow selective network access for a network namespace.
#[derive(clap::Parser, Clone, Debug)]
#[command(version, about)]
struct Cli {
    /// The PID of the user/network namespace to enter.
    #[arg(short)]
    pid: i32,
    /// The command to execute.
    #[arg(trailing_var_arg = true, required = true)]
    cmd: Vec<String>,
}

fn main() -> Result<()> {
    let args = Cli::parse();

    let Some(pid) = libc::pid_t::try_from(args.pid).ok().and_then(Pid::from_raw) else {
        return Err(std::io::Error::new(
            ErrorKind::InvalidInput,
            format!("invalid PID: {}", args.pid),
        ));
    };

    env_logger::init();

    let (netns, userns) = get_ns(pid).map_err(|e| {
        std::io::Error::new(
            e.kind(),
            format!(
                "failed to enter namespace for PID: {}",
                pid.as_raw_nonzero()
            ),
        )
    })?;

    // Create a socketpair for handing the seccomp_unotify FD back to the parent.
    let (uds_parent, uds_child) = UnixDatagram::pair()?;

    // Create the firewall instance.
    let (nsfw, filter) = netns_fw::NetnsFirewall::new([netns_fw::Rule::allow_everything()])
        .map_err(|e| match e {
            netns_fw::Error::UnsupportedArch(arch) => {
                std::io::Error::new(ErrorKind::Unsupported, format!("unsupported arch: {arch}"))
            }
        })?;

    // Clone before exec'ing.
    let mut child_pidfd = -1;
    let mut clone_args = clone3::Clone3::default();
    clone_args.exit_signal(libc::SIGCHLD as _);
    clone_args.flag_pidfd(&mut child_pidfd);

    unsafe {
        match clone_args.call()? {
            0 => child_main(filter, netns, userns, args.cmd, uds_child),
            _child => parent_main(nsfw, uds_parent),
        }
    }
}

fn child_main(
    filter: netns_fw::Filter,
    netns: OwnedFd,
    userns: Option<OwnedFd>,
    cmd_args: Vec<String>,
    uds: UnixDatagram,
) -> Result<()> {
    rustix::process::set_parent_process_death_signal(Some(Signal::Kill))?;

    // Required by seccomp.
    rustix::thread::set_no_new_privs(true)?;

    // Install the seccomp filter.
    let fd = filter.install()?;

    // Send the fd number back to the parent.
    uds.send_fds(&[], &[fd.as_raw_fd()])?;

    // Enter the user namespace first.
    if let Some(fd) = userns.as_ref() {
        rustix::thread::move_into_link_name_space(fd.as_fd(), Some(LinkNameSpaceType::User))?;
    }

    // Enter the net namespace.
    rustix::thread::move_into_link_name_space(netns.as_fd(), Some(LinkNameSpaceType::Network))?;

    // Finally, we can exec.
    let (exe, cmd_args) = cmd_args.split_first().unwrap(); // Validated by clap parsing.
    let mut cmd = Command::new(exe);
    cmd.args(cmd_args);

    Err(cmd.exec())
}

fn parent_main(mut nsfw: netns_fw::NetnsFirewall, uds: UnixDatagram) -> Result<()> {
    // Wait for the notify PID.
    let mut buf = [];
    let mut fds = [0];

    let _ = uds.recv_fds(&mut buf, &mut fds)?;
    let fd = unsafe { OwnedFd::from_raw_fd(fds[0]) };

    // Spawn the monitor in another thread.
    std::thread::Builder::new()
        .name("netns-fw monitor".to_owned())
        .spawn(move || {
            if let Err(e) = nsfw.run(fd) {
                panic!("fatal error in supervisor: {e:?}");
            }
        })?;

    loop {
        match wait(WaitOptions::empty()) {
            Ok(Some(v)) => {
                info!("child {} died", v.0.as_raw_nonzero());
                continue;
            }
            Ok(None) | Err(Errno::CHILD) => break,
            Err(e) => return Err(e.into()),
        }
    }

    info!("all child processes died. exiting.");
    Ok(())
}

fn get_ns(pid: Pid) -> Result<(OwnedFd, Option<OwnedFd>)> {
    let flags = OFlags::RDONLY | OFlags::CLOEXEC;
    let dirfd = open(
        Path::new(&format!("/proc/{}/ns", pid.as_raw_nonzero())),
        flags,
        Mode::empty(),
    )?;

    let userns = match openat(&dirfd, "user", flags, Mode::empty()) {
        Ok(fd) => Some(fd),
        Err(e) if e.kind() == ErrorKind::NotFound => None,
        Err(e) => return Err(e.into()),
    };

    let netns = openat(&dirfd, "net", flags, Mode::empty())?;

    Ok((netns, userns))
}
