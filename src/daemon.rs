//! Process daemonization for background operation.
//!
//! Implements the classic Unix double-fork daemon pattern:
//! 1. First `fork()` — parent exits, child continues
//! 2. `setsid()` — become session leader, detach from terminal
//! 3. Second `fork()` — ensure the daemon can never reacquire a terminal
//! 4. Redirect stdin/stdout/stderr to `/dev/null`
//! 5. Write PID file for process management

use anyhow::{bail, Context, Result};
use std::fs;
use std::io;
use std::path::Path;

const DAEMON_READY: u8 = 0;
const DAEMON_FAILED: u8 = 1;

/// Daemonize the current process.
///
/// After this call, the original process has exited and the daemon
/// continues running in the background with no controlling terminal.
pub fn daemonize(pid_file: &Path) -> Result<()> {
    let mut ready_pipe = [-1; 2];
    if unsafe { libc::pipe(ready_pipe.as_mut_ptr()) } == -1 {
        bail!("pipe failed: {}", std::io::Error::last_os_error());
    }
    let read_fd = ready_pipe[0];
    let write_fd = ready_pipe[1];

    // First fork
    match unsafe { libc::fork() } {
        -1 => {
            close_fd(read_fd);
            close_fd(write_fd);
            bail!("First fork failed: {}", std::io::Error::last_os_error());
        }
        0 => {
            close_fd(read_fd);
        } // child continues
        child_pid => {
            close_fd(write_fd);
            let result = wait_for_daemon_status(read_fd);
            unsafe {
                libc::waitpid(child_pid, std::ptr::null_mut(), 0);
            }
            result?;
            std::process::exit(0);
        }
    }

    // Create new session
    if unsafe { libc::setsid() } == -1 {
        signal_daemon_status(write_fd, DAEMON_FAILED);
        bail!("setsid failed: {}", std::io::Error::last_os_error());
    }

    // Second fork (prevent reacquiring a terminal)
    match unsafe { libc::fork() } {
        -1 => {
            signal_daemon_status(write_fd, DAEMON_FAILED);
            bail!("Second fork failed: {}", std::io::Error::last_os_error());
        }
        0 => {} // grandchild continues as daemon
        _ => {
            close_fd(write_fd);
            std::process::exit(0);
        }
    }

    // Write PID file
    let pid = unsafe { libc::getpid() };
    if let Err(e) = fs::write(pid_file, format!("{}\n", pid))
        .with_context(|| format!("Failed to write PID file: {}", pid_file.display()))
    {
        signal_daemon_status(write_fd, DAEMON_FAILED);
        return Err(e);
    }

    // Redirect stdio to /dev/null
    unsafe {
        let devnull = libc::open(c"/dev/null".as_ptr(), libc::O_RDWR);
        if devnull >= 0 {
            libc::dup2(devnull, libc::STDIN_FILENO);
            libc::dup2(devnull, libc::STDOUT_FILENO);
            libc::dup2(devnull, libc::STDERR_FILENO);
            if devnull > 2 {
                libc::close(devnull);
            }
        }
    }

    signal_daemon_status(write_fd, DAEMON_READY);
    Ok(())
}

fn close_fd(fd: libc::c_int) {
    if fd >= 0 {
        unsafe {
            libc::close(fd);
        }
    }
}

fn signal_daemon_status(fd: libc::c_int, status: u8) {
    let status = [status];
    unsafe {
        let _ = libc::write(fd, status.as_ptr() as *const libc::c_void, status.len());
    }
    close_fd(fd);
}

fn wait_for_daemon_status(fd: libc::c_int) -> Result<()> {
    let mut status = [0u8; 1];
    loop {
        let n = unsafe { libc::read(fd, status.as_mut_ptr() as *mut libc::c_void, status.len()) };
        if n == 1 {
            close_fd(fd);
            return match status[0] {
                DAEMON_READY => Ok(()),
                DAEMON_FAILED => bail!("Daemon child failed during startup"),
                other => bail!("Daemon child reported unknown startup status {}", other),
            };
        }
        if n == 0 {
            close_fd(fd);
            bail!("Daemon child exited before reporting startup status");
        }
        let err = io::Error::last_os_error();
        if err.kind() != io::ErrorKind::Interrupted {
            close_fd(fd);
            return Err(err).context("Failed to read daemon startup status");
        }
    }
}

/// Remove the PID file on shutdown.
pub fn remove_pid_file(pid_file: &Path) {
    let _ = fs::remove_file(pid_file);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pipe_with_status(status: u8) -> libc::c_int {
        let mut fds = [-1; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        signal_daemon_status(fds[1], status);
        fds[0]
    }

    #[test]
    fn test_wait_for_daemon_status_ready() {
        let read_fd = pipe_with_status(DAEMON_READY);

        assert!(wait_for_daemon_status(read_fd).is_ok());
    }

    #[test]
    fn test_wait_for_daemon_status_failure() {
        let read_fd = pipe_with_status(DAEMON_FAILED);

        let err = wait_for_daemon_status(read_fd).unwrap_err();
        assert!(err.to_string().contains("failed during startup"));
    }
}
