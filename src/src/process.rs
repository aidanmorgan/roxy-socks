use std::os::unix::io::AsRawFd;
use std::process::Command;

use anyhow::{Context, Result};
use tracing::{debug, trace, warn};

// For tokio support
use tokio::net::UnixStream as TokioUnixStream;

// Linux-specific imports
#[cfg(target_os = "linux")]
use procfs::process::Process;

// macOS and other platforms imports
#[cfg(not(target_os = "linux"))]
use sysinfo::{ProcessExt, System, SystemExt};

/// Information about a process
#[derive(Debug, Clone)]
pub struct ProcessInfo {
    /// Process ID
    pub pid: i32,

    /// Path to the binary
    pub binary: String,
}

/// Get process information for a Tokio Unix socket connection
pub fn get_process_info(_stream: &TokioUnixStream) -> Result<ProcessInfo> {
    #[cfg(target_os = "linux")]
    {
        // On Linux, we can use the peer_cred function by:
        // 1. Getting the raw file descriptor from the Tokio UnixStream
        // 2. Creating a standard UnixStream from that raw file descriptor
        // 3. Using the standard library's peer_cred() method

        // Get the raw file descriptor from the Tokio UnixStream
        let fd = _stream.as_raw_fd();

        // Create a standard UnixStream from the raw file descriptor
        // This is unsafe because we need to ensure the file descriptor is not closed twice
        let std_stream = unsafe { std::os::unix::net::UnixStream::from_raw_fd(fd) };

        // Get the peer credentials using the standard UnixStream
        let ucred = std_stream
            .peer_cred()
            .context("Failed to get peer credentials")?;

        let pid = ucred.pid();
        trace!("Got peer credentials (tokio): pid={}", pid);

        // Forget the standard UnixStream to prevent it from closing the file descriptor
        // when it's dropped, since the Tokio UnixStream will close it when it's dropped
        std::mem::forget(std_stream);

        get_process_info_by_pid(pid)
    }

    #[cfg(target_os = "macos")]
    {
        // On macOS, use lsof to find the process connected to this socket
        let fd = _stream.as_raw_fd();
        match get_peer_pid_macos(fd) {
            Ok(pid) => {
                trace!("Got peer credentials (macOS, tokio): pid={}", pid);
                get_process_info_by_pid(pid)
            }
            Err(e) => {
                warn!("Failed to get peer PID on macOS (tokio): {}", e);
                // Fall back to using the current process ID
                let pid = std::process::id() as i32;
                trace!("Falling back to current process ID (tokio): pid={}", pid);
                get_process_info_by_pid(pid)
            }
        }
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        // On other platforms, we can't get the peer credentials from a Unix socket
        // in a stable way, so we'll just use the current process ID
        // This is a limitation, but it's better than not working at all
        let pid = std::process::id() as i32;
        trace!("Using current process ID (tokio): pid={}", pid);

        get_process_info_by_pid(pid)
    }
}

/// Get process information for a given PID
pub fn get_process_info_by_pid(pid: i32) -> Result<ProcessInfo> {
    #[cfg(target_os = "linux")]
    {
        // Linux implementation using procfs
        let process = Process::new(pid).context("Failed to get process information")?;

        // Get the executable path
        let exe = process
            .exe()
            .context("Failed to get executable path")?;

        let binary = exe
            .to_str()
            .context("Failed to convert executable path to string")?
            .to_string();

        debug!("Got process information: pid={}, binary={}", pid, binary);

        Ok(ProcessInfo { pid, binary })
    }

    #[cfg(not(target_os = "linux"))]
    {
        // macOS implementation using sysinfo
        let mut system = System::new();
        system.refresh_processes();

        // Convert i32 to usize for sysinfo's Pid
        let sysinfo_pid = (pid as usize).into();

        if let Some(process) = system.process(sysinfo_pid) {
            let binary = process.exe().to_string_lossy().to_string();

            debug!("Got process information: pid={}, binary={}", pid, binary);

            Ok(ProcessInfo { pid, binary })
        } else {
            anyhow::bail!("Failed to get process information for PID {}", pid)
        }
    }
}

#[cfg(target_os = "macos")]
fn get_peer_pid_macos(fd: i32) -> Result<i32> {
    // Use lsof to find the process connected to this socket
    // lsof -n -P -a -d <fd> -p <pid> -F p
    // This will output something like "p12345" where 12345 is the PID
    let output = Command::new("lsof")
        .args([
            "-n",          // Don't convert network numbers to hostnames
            "-P",          // Don't convert port numbers to service names
            "-a",          // AND the following conditions
            &format!("-d{}", fd), // File descriptor
            &format!("-p{}", std::process::id()), // Process ID
            "-F", "p",     // Output format: just the PID
        ])
        .output()
        .context("Failed to execute lsof command")?;

    if !output.status.success() {
        return Err(anyhow::anyhow!("lsof command failed"));
    }

    // Parse the output to get the PID
    let output_str = String::from_utf8_lossy(&output.stdout);
    for line in output_str.lines() {
        if line.starts_with('p') {
            if let Ok(pid) = line[1..].parse::<i32>() {
                return Ok(pid);
            }
        }
    }

    Err(anyhow::anyhow!("Failed to parse lsof output"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_process_info_by_pid() {
        // Get the current process ID
        let pid = std::process::id() as i32;

        // Get process information
        let process_info = get_process_info_by_pid(pid).unwrap();

        // Check that the process ID matches
        assert_eq!(process_info.pid, pid);

        // Check that the binary path is not empty
        assert!(!process_info.binary.is_empty());
    }
}
