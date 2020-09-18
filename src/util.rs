use std::cmp::Ordering;
use std::fmt;
use std::process::exit;

use libc::{c_char, chdir, chroot, fork, getpwnam, getuid, setgid, setsid, setuid, umask};

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub enum DaemonizeError {
    Fork,
    SetSession,
    SetGroup,
    SetUser,
    Chroot,
    Chdir,
}

impl fmt::Display for DaemonizeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            DaemonizeError::Fork => "unable to fork",
            DaemonizeError::SetSession => "unable to create new process session",
            DaemonizeError::SetGroup => "unable to set group (drop privileges)",
            DaemonizeError::SetUser => "unable to set user (drop privileges)",
            DaemonizeError::Chroot => "unable to enter chroot jail",
            DaemonizeError::Chdir => "failed to change directory",
        }
        .fmt(f)
    }
}

fn fork_and_exit() -> Result<(), DaemonizeError> {
    let pid = unsafe { fork() };
    match pid.cmp(&0) {
        Ordering::Less => Err(DaemonizeError::Fork),
        Ordering::Equal => Ok(()),
        Ordering::Greater => exit(0),
    }
}

pub fn daemonize() -> Result<(), DaemonizeError> {
    // fork from the original parent
    fork_and_exit()?;

    // avoid killing the child when this parent dies
    if unsafe { setsid() } < 0 {
        return Err(DaemonizeError::SetSession);
    }

    // fork again to create orphan
    fork_and_exit()
}

pub fn drop_privileges() -> Result<(), DaemonizeError> {
    // retrieve nobody's uid & gid
    let usr = unsafe { getpwnam("nobody\x00".as_ptr() as *const c_char) };
    if usr.is_null() {
        return Err(DaemonizeError::SetGroup);
    }

    // change root directory
    let uid = unsafe { getuid() };
    if uid == 0 && unsafe { chroot("/tmp\x00".as_ptr() as *const c_char) } != 0 {
        return Err(DaemonizeError::Chroot);
    }

    // set umask for files
    unsafe { umask(0) };

    // change directory
    if unsafe { chdir("/\x00".as_ptr() as *const c_char) } != 0 {
        return Err(DaemonizeError::Chdir);
    }

    // set group id to nobody
    if unsafe { setgid((*usr).pw_gid) } != 0 {
        return Err(DaemonizeError::SetGroup);
    }

    // set user id to nobody
    if unsafe { setuid((*usr).pw_uid) } != 0 {
        Err(DaemonizeError::SetUser)
    } else {
        Ok(())
    }
}
