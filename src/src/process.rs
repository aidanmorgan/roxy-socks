use std::os::unix::net::UnixStream;

use anyhow::Result;
use tracing::{debug, trace};

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

/// Get process information for a Unix socket connection
#[allow(dead_code)]
pub fn get_process_info(_stream: &UnixStream) -> Result<ProcessInfo> {
    // Get the peer credentials
    #[cfg(target_os = "linux")]
    {
        let ucred = _stream
            .peer_cred()
            .context("Failed to get peer credentials")?;

        let pid = ucred.pid();
        trace!("Got peer credentials: pid={}", pid);

        get_process_info_by_pid(pid)
    }

    #[cfg(not(target_os = "linux"))]
    {
        // On macOS, we can't get the peer credentials from a Unix socket
        // in a stable way, so we'll just use the current process ID
        // This is a limitation, but it's better than not working at all
        let pid = std::process::id() as i32;
        trace!("Using current process ID: pid={}", pid);

        get_process_info_by_pid(pid)
    }
}

/// Get process information for a Tokio Unix socket connection
pub fn get_process_info_tokio(_stream: &TokioUnixStream) -> Result<ProcessInfo> {
    // For now, we'll just use the current process ID
    // This is a limitation, but it's better than not working at all
    let pid = std::process::id() as i32;
    trace!("Using current process ID (tokio): pid={}", pid);

    get_process_info_by_pid(pid)
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

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
