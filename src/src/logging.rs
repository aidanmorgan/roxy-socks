use std::path::Path;

use anyhow::{anyhow, Context, Result};
use tracing::info;
use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::{
    fmt::{self, format::FmtSpan},
    prelude::*,
    EnvFilter,
};

/// Parse a rotation duration string into a Rotation enum value
pub fn parse_rotation(rotation: &str) -> Result<Rotation> {
    match rotation.to_lowercase().as_str() {
        "hourly" => Ok(Rotation::HOURLY),
        "daily" => Ok(Rotation::DAILY),
        "never" => Ok(Rotation::NEVER),
        _ => Err(anyhow!("Invalid rotation value: {}. Valid values are: hourly, daily, never", rotation)),
    }
}

/// Initialize logging with file rotation
/// 
/// # Arguments
/// 
/// * `log_dir` - Directory where log files will be stored
/// * `rotation` - Log rotation duration (HOURLY, DAILY, NEVER)
/// 
/// # Environment Variables
/// 
/// * `RUST_LOG` - Sets the log level (trace, debug, info, warn, error). Defaults to "info" if not set.
pub fn init<P: AsRef<Path>>(log_dir: P, rotation: Rotation) -> Result<()> {
    let log_dir = log_dir.as_ref();

    // Create the log directory if it doesn't exist
    std::fs::create_dir_all(log_dir)
        .with_context(|| format!("Failed to create log directory: {}", log_dir.display()))?;

    // Set up file appender with specified rotation
    let file_appender = RollingFileAppender::new(
        rotation,
        log_dir,
        "roxy.log",
    );

    // Set up a non-blocking writer
    let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);

    // Create a subscriber that logs to both stdout and the file
    let subscriber = tracing_subscriber::registry()
        .with(
            fmt::Layer::new()
                .with_writer(std::io::stdout)
                .with_span_events(FmtSpan::CLOSE)
                .with_filter(
                    EnvFilter::try_from_env("RUST_LOG")
                        .unwrap_or_else(|_| EnvFilter::new("info")),
                ),
        )
        .with(
            fmt::Layer::new()
                .with_writer(non_blocking)
                .with_span_events(FmtSpan::CLOSE)
                .with_filter(
                    EnvFilter::try_from_env("RUST_LOG")
                        .unwrap_or_else(|_| EnvFilter::new("info")),
                ),
        );

    // Set the subscriber as the global default
    tracing::subscriber::set_global_default(subscriber)
        .context("Failed to set global default subscriber")?;

    info!("Logging initialized to {}", log_dir.display());

    // Store the guard in a static to keep it alive for the program's duration
    // This is necessary to ensure logs are flushed properly
    Box::leak(Box::new(_guard));

    Ok(())
}

/// Log a request and its outcome
pub fn log_request(
    method: &str,
    path: &str,
    allowed: bool,
    reason: Option<&str>,
    process_info: &crate::process::ProcessInfo,
) {
    if allowed {
        info!(
            target: "request",
            method = %method,
            path = %path,
            pid = %process_info.pid,
            binary = %process_info.binary,
            "Request allowed"
        );
    } else {
        info!(
            target: "request",
            method = %method,
            path = %path,
            pid = %process_info.pid,
            binary = %process_info.binary,
            reason = %reason.unwrap_or("No matching allow rule"),
            "Request denied"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_init_logging() {
        let temp_dir = TempDir::new().unwrap();
        let result = init(temp_dir.path(), Rotation::DAILY);
        assert!(result.is_ok());
    }
}
