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
use std::path::Path;

/// Daemonize the current process.
///
/// After this call, the original process has exited and the daemon
/// continues running in the background with no controlling terminal.
pub fn daemonize(pid_file: &Path) -> Result<()> {
    // First fork
    match unsafe { libc::fork() } {
        -1 => bail!("First fork failed: {}", std::io::Error::last_os_error()),
        0 => {}                     // child continues
        _ => std::process::exit(0), // parent exits
    }

    // Create new session
    if unsafe { libc::setsid() } == -1 {
        bail!("setsid failed: {}", std::io::Error::last_os_error());
    }

    // Second fork (prevent reacquiring a terminal)
    match unsafe { libc::fork() } {
        -1 => bail!("Second fork failed: {}", std::io::Error::last_os_error()),
        0 => {}                     // grandchild continues as daemon
        _ => std::process::exit(0), // first child exits
    }

    // Write PID file
    let pid = unsafe { libc::getpid() };
    fs::write(pid_file, format!("{}\n", pid))
        .with_context(|| format!("Failed to write PID file: {}", pid_file.display()))?;

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

    Ok(())
}

/// Remove the PID file on shutdown.
pub fn remove_pid_file(pid_file: &Path) {
    let _ = fs::remove_file(pid_file);
}
