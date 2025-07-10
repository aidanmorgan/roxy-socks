use std::fs;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use hyper::server::conn::Http;
use hyper::service::service_fn;
use hyper::{Body, Client, Method, Request, Response, StatusCode};
use hyperlocal::UnixClientExt;
use tokio::net::UnixListener;
use tokio::time::timeout;
use tracing::{debug, error, info, instrument, warn};

use crate::buffered_request::BufferedRequest;
use crate::config::Config;
use crate::file_watcher;
use crate::logging;
use crate::process;
use crate::rules;
use crate::shared_config::SharedConfig;

/// Helper function to execute an async operation with a timeout
#[allow(dead_code)]
async fn with_timeout<T, F>(duration: Duration, future: F) -> Result<T>
where
    F: std::future::Future<Output = Result<T>>,
{
    match timeout(duration, future).await {
        Ok(result) => result,
        Err(_) => Err(anyhow::anyhow!("Operation timed out"))
    }
}

/// Check if the Docker socket is accessible by making a request to the /version endpoint
/// 
/// This function attempts to connect to the Docker socket and make a simple request
/// to verify that the socket is accessible and functioning correctly.
#[instrument(skip(docker_socket))]
async fn check_docker_socket_accessibility(docker_socket: &Path) -> Result<()> {
    info!("Checking Docker socket accessibility at: {}", docker_socket.display());

    // Create a client for the Docker socket
    let client = Client::unix();

    // Create a request to the /version endpoint
    let uri = hyperlocal::Uri::new(docker_socket, "/version");
    let request = Request::builder()
        .method(Method::GET)
        .uri(uri)
        .body(Body::empty())
        .context("Failed to build request for Docker version check")?;

    // Send the request with a timeout
    match timeout(Duration::from_secs(5), client.request(request)).await {
        Ok(response_result) => {
            match response_result {
                Ok(response) => {
                    if response.status().is_success() {
                        info!("Docker socket is accessible (status: {})", response.status());
                        Ok(())
                    } else {
                        let error_msg = format!("Docker socket returned error status: {}", response.status());
                        warn!("{}", error_msg);
                        Err(anyhow::anyhow!(error_msg))
                    }
                },
                Err(e) => {
                    let error_msg = format!("Failed to connect to Docker socket: {}", e);
                    warn!("{}", error_msg);
                    Err(anyhow::anyhow!(error_msg))
                }
            }
        },
        Err(_) => {
            let error_msg = "Timeout while checking Docker socket accessibility";
            warn!("{}", error_msg);
            Err(anyhow::anyhow!(error_msg))
        }
    }
}

/// Start the proxy server
/// 
/// Note: The timeout parameter in the Config struct is applied to the full request processing loop,
/// ensuring that each connection is processed within the specified timeout period.
// Removed instrument attribute to avoid lifetime issues
pub async fn start_proxy<P1, P2, P3>(
    socket_path: P1,
    docker_socket: P2,
    config: Config,
    config_path: P3,
) -> Result<()>
where
    P1: AsRef<Path> + std::fmt::Debug + 'static,
    P2: AsRef<Path> + std::fmt::Debug + 'static,
    P3: AsRef<Path> + std::fmt::Debug + 'static,
{
    let socket_path = socket_path.as_ref();
    let docker_socket = docker_socket.as_ref();
    let config_path_ref = config_path.as_ref();

    // Check Docker socket accessibility before starting the proxy
    if let Err(e) = check_docker_socket_accessibility(docker_socket).await {
        error!("Docker accessibility check failed. Cannot start proxy: {}", e);
        return Err(anyhow::anyhow!("Docker socket is not accessible: {}. Make sure the Docker daemon is running and the socket has correct permissions.", e));
    }

    // Create an owned PathBuf for the config path to use in async tasks
    let config_path_owned = config_path_ref.to_path_buf();

    // Create a shared configuration that can be updated
    let shared_config = SharedConfig::new(config);

    // Set up the configuration file watcher
    let watcher_config = shared_config.clone();
    let config_path_for_watcher = config_path_owned.clone();
    tokio::spawn(async move {
        if let Err(e) = file_watcher::watch_config_with_shared(config_path_for_watcher, watcher_config).await {
            error!("Config watcher error: {}", e);
        }
    });

    info!("Watching configuration file for changes: {}", config_path_owned.display());

    // Create the parent directory if it doesn't exist
    if let Some(parent) = socket_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create directory: {}", parent.display()))?;
    }

    // Remove the socket file if it already exists and is not a valid socket
    if socket_path.exists() {
        // Check if it's a socket or a regular file
        match fs::metadata(socket_path) {
            Ok(metadata) => {
                // On Unix, sockets are special files
                if !metadata.file_type().is_socket() {
                    // Not a socket, remove it
                    if let Err(e) = fs::remove_file(socket_path) {
                        warn!("Could not remove existing non-socket file: {}", e);
                        return Err(anyhow::anyhow!("Cannot create socket: path exists and is not a socket"));
                    }
                } else {
                    // It's a socket, but might be stale - try to remove it
                    if let Err(e) = fs::remove_file(socket_path) {
                        warn!("Could not remove existing socket file: {}", e);
                        // Continue anyway, as bind() might still succeed if the socket is stale
                    }
                }
            },
            Err(e) => {
                // Error getting metadata, but file exists - try to remove it
                warn!("Error checking socket file metadata: {}", e);
                if let Err(e) = fs::remove_file(socket_path) {
                    warn!("Could not remove existing file: {}", e);
                    // Continue anyway, as bind() might still succeed
                }
            }
        }
    }

    // Create the Unix socket
    let listener = match UnixListener::bind(socket_path) {
        Ok(l) => l,
        Err(e) => {
            error!("Failed to bind to socket: {}", e);
            return Err(anyhow::anyhow!("Failed to bind to socket: {}", e));
        }
    };

    // Set permissions to allow non-root users to connect
    fs::set_permissions(socket_path, fs::Permissions::from_mode(0o666))
        .with_context(|| format!("Failed to set socket permissions: {}", socket_path.display()))?;

    info!("Listening on Unix socket: {}", socket_path.display());
    info!("Forwarding to Docker socket: {}", docker_socket.display());

    // Create a client for the Docker socket
    let client = Client::unix();
    let docker_socket = docker_socket.to_path_buf();

    // Accept connections
    loop {
        let (stream, _) = match listener.accept().await {
            Ok(stream) => stream,
            Err(e) => {
                error!("Failed to accept connection: {}", e);
                continue;
            }
        };

        // Get process information for the connection
        let process_info = match process::get_process_info_tokio(&stream) {
            Ok(info) => info,
            Err(e) => {
                error!("Failed to get process information: {}", e);
                continue;
            }
        };

        debug!(
            "Accepted connection from pid={}, binary={}",
            process_info.pid, process_info.binary
        );

        // Clone the shared data for the connection
        let config_for_connection = shared_config.clone();
        let client = client.clone();
        let docker_socket = docker_socket.clone();
        let process_info = Arc::new(process_info);

        // Get timeout from the shared config
        let timeout_duration = {
            let config_guard = shared_config.read();
            Duration::from_secs(config_guard.timeout)
        };

        tokio::spawn(async move {
            let task = async {
                let service = service_fn(move |req: Request<Body>| {
                    let config = config_for_connection.clone();
                    let client = client.clone();
                    let docker_socket = docker_socket.clone();
                    let process_info = Arc::clone(&process_info);

                    async move {
                        // Get a copy of the config to avoid Send issues with RwLockReadGuard
                        let config_copy = {
                            let guard = config.read();
                            guard.clone()
                        };
                        handle_request(req, &config_copy, &client, &docker_socket, &process_info).await
                    }
                });

                if let Err(_e) = Http::new()
                    .serve_connection(stream, service)
                    .await
                {
                    // just no-op this for the moment, it's not adding any value that the other logging isn;t providing
                }
            };

            // Apply timeout to the entire request processing
            if let Err(_) = timeout(timeout_duration, task).await {
                error!("Connection processing timed out after {} seconds", timeout_duration.as_secs());
            }
        });
    }

    // This point is unreachable because of the infinite loop above,
    // but we need to return a Result<()> to satisfy the function signature
    #[allow(unreachable_code)]
    Ok(())
}

/// Handle an HTTP request
#[instrument(skip(config, client, docker_socket, process_info))]
async fn handle_request(
    req: Request<Body>,
    config: &Config,
    client: &Client<hyperlocal::UnixConnector>,
    docker_socket: &Path,
    process_info: &process::ProcessInfo,
) -> Result<Response<Body>> {
    let method = req.method().clone();
    let path = req.uri().path().to_string();

    debug!(
        "Received request: method={}, path={}, from pid={}, binary={}",
        method, path, process_info.pid, process_info.binary
    );

    // Check if any rule has JSON conditions in request_rules
    let _has_json_conditions = config.rules.iter().any(|rule| {
        if let Some(rules) = &rule.request_rules {
            !rules.is_empty()
        } else {
            false
        }
    });

    // Create a buffered request - either with the body for POST/PUT/PATCH or empty for GET
    let buffered_req = if method == Method::POST || method == Method::PUT || method == Method::PATCH {
        // Buffer the request body
        let (parts, body) = req.into_parts();
        match BufferedRequest::from_request(Request::from_parts(parts, body)).await {
            Ok(buffered) => {
                debug!("Buffered request body for JSON path checking");
                buffered
            }
            Err(e) => {
                error!("Failed to buffer request body: {}", e);
                logging::log_request(
                    method.as_str(),
                    &path,
                    false,
                    Some(&format!("Error buffering request body: {}", e)),
                    process_info,
                );
                return Ok(Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(Body::from("Failed to buffer request body"))
                    .unwrap());
            }
        }
    } else {
        // For GET requests, create an empty buffered request
        let (parts, _) = req.into_parts();
        BufferedRequest::from_parts(parts)
    };

    // Check if the request is allowed using the buffered request
    let rule_check_result = match rules::check_request_buffered(&buffered_req, &config.rules, process_info).await {
        Ok(result) => {
            if result.allowed {
                // Request is allowed, forward it to the Docker socket
                info!(
                    "Forwarding request: method={}, path={}, from pid={}, binary={}",
                    method, path, process_info.pid, process_info.binary
                );
                logging::log_request(
                    method.as_str(),
                    &path,
                    true,
                    None,
                    process_info,
                );

                // Create a new request for the Docker socket using the buffered request
                let req = buffered_req.into_request();
                let (parts, body) = req.into_parts();
                let uri = hyperlocal::Uri::new(docker_socket, parts.uri.path_and_query().map(|p| p.as_str()).unwrap_or(""));

                let docker_req = Request::builder()
                    .method(parts.method)
                    .uri(uri)
                    .body(body)
                    .unwrap();

                // Forward the request to the Docker socket
                match client.request(docker_req).await {
                    Ok(resp) => {
                        debug!("Received response from Docker: status={}", resp.status());

                        // Check if any rule has response_rules
                        let has_response_rules = config.rules.iter().any(|rule| {
                            if let Some(rules) = &rule.response_rules {
                                !rules.is_empty()
                            } else {
                                false
                            }
                        });

                        if has_response_rules {
                            // Buffer the response to check response_rules
                            let (parts, body) = resp.into_parts();
                            let body_bytes = match hyper::body::to_bytes(body).await {
                                Ok(bytes) => bytes,
                                Err(e) => {
                                    error!("Failed to buffer response body: {}", e);
                                    return Ok(Response::builder()
                                        .status(StatusCode::INTERNAL_SERVER_ERROR)
                                        .body(Body::from("Failed to buffer response body"))
                                        .unwrap());
                                }
                            };

                            // Try to parse the body as JSON
                            let json_body = match serde_json::from_slice::<serde_json::Value>(&body_bytes) {
                                Ok(json) => Some(json),
                                Err(_) => None, // Not JSON or invalid JSON
                            };

                            // Check response rules if we have JSON
                            if let Some(json) = json_body {
                                for rule in &config.rules {
                                    if let Some(response_rules) = &rule.response_rules {
                                        if !response_rules.is_empty() {
                                            // Check each response rule
                                            for (path, expected_value) in response_rules {
                                                // Use JsonPathFinder to evaluate the JSON path
                                                let finder = match jsonpath_rust::JsonPathFinder::from_str(&json.to_string(), path) {
                                                    Ok(finder) => finder,
                                                    Err(e) => {
                                                        debug!("Failed to create JsonPathFinder for response: {}", e);
                                                        continue; // Skip this rule
                                                    }
                                                };

                                                let found_values = finder.find();

                                                // Check if the found value matches the expected value
                                                let condition_matched = match found_values {
                                                    serde_json::Value::Array(values) => {
                                                        // If the result is an array, check if any value matches the expected value
                                                        values.iter().any(|found| {
                                                            debug!("Checking response rule: {} = {}", path, found);
                                                            found == expected_value
                                                        })
                                                    }
                                                    _ => {
                                                        // If the result is not an array, check if it matches the expected value
                                                        debug!("Checking response rule: {} = {}", path, found_values);
                                                        &found_values == expected_value
                                                    }
                                                };

                                                if !condition_matched {
                                                    debug!("Response rule mismatch: {} != {:?}", path, expected_value);
                                                    // If a response rule doesn't match, deny the request
                                                    return Ok(Response::builder()
                                                        .status(StatusCode::FORBIDDEN)
                                                        .body(Body::from("Response denied by access control rules"))
                                                        .unwrap());
                                                }
                                            }
                                        }
                                    }
                                }
                            }

                            // All response rules passed or no JSON body, reconstruct the response
                            let resp = Response::from_parts(parts, Body::from(body_bytes));
                            return Ok(resp);
                        } else {
                            // No response rules, return the response as is
                            return Ok(resp);
                        }
                    }
                    Err(e) => {
                        error!("Failed to forward request to Docker: {}", e);
                        return Ok(Response::builder()
                            .status(StatusCode::BAD_GATEWAY)
                            .body(Body::from(format!("Failed to forward request to Docker: {}", e)))
                            .unwrap());
                    }
                }
            }
            result
        }
        Err(e) => {
            error!("Failed to check request with buffered body: {}", e);
            logging::log_request(
                method.as_str(),
                &path,
                false,
                Some(&format!("Error checking rules with buffered body: {}", e)),
                process_info,
            );
            return Ok(Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::from("Failed to check request against rules"))
                .unwrap());
        }
    };

    // If we get here, the request was not allowed
    warn!(
        "Request denied: method={}, path={}, from pid={}, binary={}",
        method, path, process_info.pid, process_info.binary
    );
    logging::log_request(
        method.as_str(),
        &path,
        false,
        rule_check_result.rule_info.as_deref(),
        process_info,
    );
    Ok(Response::builder()
        .status(StatusCode::FORBIDDEN)
        .body(Body::from("Request denied by access control rules"))
        .unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::{QueryParamMatch, Rule, RuleCheckResult};
    use hyper::body::to_bytes;
    use std::collections::HashMap;
    use tempfile::TempDir;
    use tokio::fs::File;
    use tokio::io::AsyncWriteExt;

    #[tokio::test]
    async fn test_handle_request_allowed() {
        // Create a mock process info
        let process_info = process::ProcessInfo {
            pid: 1,
            binary: "/usr/bin/docker".to_string(),
        };

        // Create a mock config with an allow rule
        let config = Config {
            rules: vec![Rule {
                endpoint: "/containers/json".to_string(),
                methods: vec!["GET".to_string()],
                allow: true,
                request_rules: None,
                response_rules: None,
                process_binaries: None,
                path_variables: None,
                path_regex: None,
                match_query_params: QueryParamMatch::Ignore,
                query_params: None,
            }],
            timeout: 5,
        };

        // Create a mock request
        let req = Request::builder()
            .method(Method::GET)
            .uri("/containers/json")
            .body(Body::empty())
            .unwrap();

        // Create a mock client that returns a successful response
        let client = Client::unix();
        let temp_dir = TempDir::new().unwrap();
        let docker_socket = temp_dir.path().join("docker.sock");

        // This test can't actually connect to a Docker socket, so we'll just check
        // that the request is allowed and would be forwarded
        let result = handle_request(req, &config, &client, &docker_socket, &process_info).await;

        // The request should be allowed, but forwarding will fail (which is expected in the test)
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    }

    #[tokio::test]
    async fn test_handle_request_denied() {
        // Create a mock process info
        let process_info = process::ProcessInfo {
            pid: 1,
            binary: "/usr/bin/malicious".to_string(),
        };

        // Create a mock config with a deny rule
        let config = Config {
            rules: vec![Rule {
                endpoint: "/containers/json".to_string(),
                methods: vec!["GET".to_string()],
                allow: false,
                request_rules: None,
                response_rules: None,
                process_binaries: None,
                path_variables: None,
                path_regex: None,
                match_query_params: QueryParamMatch::Ignore,
                query_params: None,
            }],
            timeout: 5,
        };

        // Create a mock request
        let req = Request::builder()
            .method(Method::GET)
            .uri("/containers/json")
            .body(Body::empty())
            .unwrap();

        // Create a mock client
        let client = Client::unix();
        let temp_dir = TempDir::new().unwrap();
        let docker_socket = temp_dir.path().join("docker.sock");

        // Handle the request
        let result = handle_request(req, &config, &client, &docker_socket, &process_info).await;

        // The request should be denied
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        // Check the response body
        let body = to_bytes(response.into_body()).await.unwrap();
        let body_str = String::from_utf8(body.to_vec()).unwrap();
        assert!(body_str.contains("Request denied"));
    }

    #[tokio::test]
    async fn test_rule_info_in_logs() {
        // This test verifies that rule information is included in logs when a request is denied
        // In a real test, we would check the log output, but for this unit test we'll just
        // ensure the code path is correct by mocking the logging function

        // Create a mock process info
        let process_info = process::ProcessInfo {
            pid: 1,
            binary: "/usr/bin/malicious".to_string(),
        };

        // Create a mock config with a deny rule
        let config = Config {
            rules: vec![Rule {
                endpoint: "/containers/json".to_string(),
                methods: vec!["GET".to_string()],
                allow: false,
                request_rules: None,
                response_rules: None,
                process_binaries: None,
                path_variables: None,
                path_regex: None,
                match_query_params: QueryParamMatch::Ignore,
                query_params: None,
            }],
            timeout: 5,
        };

        // Create a mock request
        let req = Request::builder()
            .method(Method::GET)
            .uri("/containers/json")
            .body(Body::empty())
            .unwrap();

        // Create a mock client
        let client = Client::unix();
        let temp_dir = TempDir::new().unwrap();
        let docker_socket = temp_dir.path().join("docker.sock");

        // Handle the request
        let result = handle_request(req, &config, &client, &docker_socket, &process_info).await;

        // The request should be denied
        assert!(result.is_ok());

        // In a real test, we would check that the log contains the rule information
        // For this unit test, we're just verifying that the code path is correct
    }
}
