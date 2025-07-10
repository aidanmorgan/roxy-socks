use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use notify::{Config as NotifyConfig, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use tokio::sync::mpsc::{self, Receiver, Sender};
use tokio::time::sleep;
use tracing::{debug, error, info, warn};

use crate::config::{self, Config};
use crate::shared_config::SharedConfig;

/// Struct to manage file watching and configuration reloading
#[allow(dead_code)]
pub struct ConfigWatcher {
    config_path: PathBuf,
    tx: Sender<Arc<Config>>,
    rx: Option<Receiver<Arc<Config>>>,
}

impl ConfigWatcher {
    /// Create a new ConfigWatcher
    #[allow(dead_code)]
    pub fn new(config_path: impl AsRef<Path>) -> Self {
        let (tx, rx) = mpsc::channel(1);
        Self {
            config_path: config_path.as_ref().to_path_buf(),
            tx,
            rx: Some(rx),
        }
    }

    /// Start watching the configuration file for changes
    #[allow(dead_code)]
    pub async fn start_watching(
        &mut self,
        initial_config: Arc<Config>,
    ) -> Result<Receiver<Arc<Config>>> {
        // Return the receiver for the updated configurations
        let rx = self.rx.take().context("Watcher already started")?;

        // Clone values for the async task
        let config_path = self.config_path.clone();
        let tx = self.tx.clone();

        // Send the initial configuration
        if tx.send(Arc::clone(&initial_config)).await.is_err() {
            error!("Failed to send initial configuration");
        }

        // Spawn a task to watch for file changes
        tokio::spawn(async move {
            if let Err(e) = watch_config_file(config_path, tx, initial_config).await {
                error!("Config watcher error: {}", e);
            }
        });

        Ok(rx)
    }
}

/// Watch the configuration file for changes and send updated configurations
#[allow(dead_code)]
#[allow(unused_assignments)]
async fn watch_config_file(
    config_path: PathBuf,
    tx: Sender<Arc<Config>>,
    initial_config: Arc<Config>,
) -> Result<()> {
    // Create a channel to receive file system events
    let (watcher_tx, mut watcher_rx) = mpsc::channel(100);

    // Create a watcher with the recommended implementation for the current platform
    let mut watcher = RecommendedWatcher::new(
        move |res: Result<Event, notify::Error>| {
            if let Ok(event) = res {
                let _ = watcher_tx.blocking_send(event);
            }
        },
        NotifyConfig::default(),
    )?;

    // Start watching the config file
    let watch_path = if config_path.is_file() {
        config_path.parent().unwrap_or(Path::new(".")).to_path_buf()
    } else {
        config_path.clone()
    };

    watcher.watch(&watch_path, RecursiveMode::NonRecursive)?;
    info!("Watching for changes to configuration file: {}", config_path.display());

    // Keep track of the current configuration
    let mut current_config = initial_config;

    // Process file system events
    while let Some(event) = watcher_rx.recv().await {
        if is_relevant_event(&event, &config_path) {
            debug!("Detected change to configuration file: {}", config_path.display());

            // Add a small delay to ensure the file is fully written
            sleep(Duration::from_millis(100)).await;

            // Try to load the new configuration
            match config::load_config(&config_path) {
                Ok(new_config) => {
                    info!(
                        "Reloaded configuration with {} rules",
                        new_config.rules.len()
                    );

                    // Update the current configuration
                    current_config = Arc::new(new_config);

                    // Send the updated configuration
                    if tx.send(Arc::clone(&current_config)).await.is_err() {
                        error!("Failed to send updated configuration");
                        break;
                    }
                }
                Err(e) => {
                    warn!("Failed to reload configuration: {}", e);
                }
            }
        }
    }

    Ok(())
}

/// Check if an event is relevant to the configuration file
fn is_relevant_event(event: &Event, config_path: &Path) -> bool {
    if let EventKind::Modify(_) | EventKind::Create(_) = event.kind {
        for path in &event.paths {
            if path == config_path {
                return true;
            }
        }
    }
    false
}

/// Watch a configuration file and update a SharedConfig when changes are detected
pub async fn watch_config_with_shared(
    config_path: impl AsRef<Path>,
    shared_config: SharedConfig,
) -> Result<()> {
    let config_path = config_path.as_ref().to_path_buf();

    // Create a channel to receive file system events
    let (watcher_tx, mut watcher_rx) = mpsc::channel(100);

    // Create a watcher with the recommended implementation for the current platform
    let mut watcher = RecommendedWatcher::new(
        move |res: Result<Event, notify::Error>| {
            if let Ok(event) = res {
                let _ = watcher_tx.blocking_send(event);
            }
        },
        NotifyConfig::default(),
    )?;

    // Start watching the config file
    let watch_path = if config_path.is_file() {
        config_path.parent().unwrap_or(Path::new(".")).to_path_buf()
    } else {
        config_path.clone()
    };

    watcher.watch(&watch_path, RecursiveMode::NonRecursive)?;
    info!("Watching for changes to configuration file: {}", config_path.display());

    // Process file system events
    while let Some(event) = watcher_rx.recv().await {
        if is_relevant_event(&event, &config_path) {
            debug!("Detected change to configuration file: {}", config_path.display());

            // Add a small delay to ensure the file is fully written
            sleep(Duration::from_millis(100)).await;

            // Try to load the new configuration
            match config::load_config(&config_path) {
                Ok(new_config) => {
                    info!(
                        "Reloaded configuration with {} rules",
                        new_config.rules.len()
                    );

                    // Update the shared configuration
                    shared_config.update(new_config);
                }
                Err(e) => {
                    warn!("Failed to reload configuration: {}", e);
                }
            }
        }
    }

    Ok(())
}
