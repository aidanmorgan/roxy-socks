use std::path::PathBuf;
use std::process as std_process;

use anyhow::{Context, Result};
use clap::Parser;
use tracing::{error, info, warn};
use crate::config::Config;
use crate::rules::{add_default_rules, QueryParamMatch, Rule};
use crate::shared_config::SharedConfig;

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
    #[arg(short, long, default_value = "/var/run/roxy.sock")]
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
    #[arg(short, long, default_value = "30")]
    timeout: u64,

    /// Log rotation duration (hourly, daily, never)
    #[arg(short = 'r', long, default_value = "daily")]
    log_rotation: String,

    /// Disable the default rule that allows GET requests to the /version endpoint
    #[arg(long, action = clap::ArgAction::SetTrue)]
    no_default_rules: bool,
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
        .unwrap_or(Config {
            rules: vec![],
            timeout: args.timeout,
        });

    if !args.no_default_rules {
        add_default_rules(&mut config.rules);
        warn!("Default rule allowing GET requests to /version endpoint is enabled. Use --no-default-rules to disable this behavior.");
    }

    // Override timeout with command line argument if provided
    config.timeout = args.timeout;
    info!("Configuration: {:?}", config);

    // Create a shared configuration that can be updated
    let shared_config = SharedConfig::new(config);

    // Set up the configuration file watcher
    let watcher_config = shared_config.clone();
    let config_path_for_watcher = args.config_path.clone();

    tokio::spawn(async move {
        if let Err(e) = file_watcher::watch_config_with_shared(config_path_for_watcher, watcher_config, !args.no_default_rules).await {
            error!("Config watcher error: {}", e);
        }
    });

    info!("Watching configuration file for changes: {}", args.config_path.display());

    // Start the proxy server
    match proxy::start_proxy(
        args.socket_path, 
        args.docker_socket, 
        &shared_config
    ).await {
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
