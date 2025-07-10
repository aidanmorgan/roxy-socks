use std::path::PathBuf;
use std::process as std_process;

use anyhow::{Context, Result};
use clap::Parser;
use tracing::{error, info};

mod buffered_request;
mod config;
mod file_watcher;
mod logging;
mod process;
mod proxy;
mod rules;
mod shared_config;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to the socket to create
    #[arg(short, long, default_value = "/var/run/roxy")]
    socket_path: PathBuf,

    /// Path to the Docker socket
    #[arg(short, long, default_value = "/var/run/docker.sock")]
    docker_socket: PathBuf,

    /// Path to the rules configuration file
    #[arg(short, long, default_value = "/etc/roxy/config.yml")]
    config_path: PathBuf,

    /// Path to the log directory
    #[arg(short, long, default_value = "/var/log/roxy")]
    log_dir: PathBuf,

    /// Timeout in seconds for network operations
    #[arg(short, long, default_value = "5")]
    timeout: u64,

    /// Log rotation duration (hourly, daily, never)
    #[arg(short = 'r', long, default_value = "daily")]
    log_rotation: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Parse command line arguments
    let args = Args::parse();

    // Parse log rotation setting
    let rotation = logging::parse_rotation(&args.log_rotation)
        .context("Failed to parse log rotation setting")?;

    // Initialize logging
    logging::init(&args.log_dir, rotation).context("Failed to initialize logging")?;
    info!("Starting Roxy Docker Socket Proxy");

    // Load configuration
    let mut config = config::load_config(&args.config_path)
        .context("Failed to load configuration")?;

    // Override timeout with command line argument if provided
    config.timeout = args.timeout;

    // Start the proxy server
    match proxy::start_proxy(args.socket_path, args.docker_socket, config, args.config_path.clone()).await {
        Ok(_) => {
            info!("Proxy server stopped gracefully");
            Ok(())
        }
        Err(e) => {
            error!("Proxy server error: {}", e);
            std_process::exit(1);
        }
    }
}
