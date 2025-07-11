# Roxy - Docker Socket Proxy

A secure proxy for the Docker socket (`/var/run/docker.sock`) that allows non-root users to access the Docker API with fine-grained access control.

## Features

- Runs as root but exposes a socket accessible to non-root users
- Rule-based access control via YAML configuration
- Filtering by endpoint, HTTP method, and request content (using JSON path)
- Process-based access control (restrict access to specific binaries)
- Comprehensive logging of all requests with pass/fail status
- Configurable paths for socket, rules, and logs

## Installation

### Building from Source

```bash
cd src
cargo build --release
```

The binary will be available at `src/target/release/roxy-socks`.

### Running as a Service

Create a systemd service file at `/etc/systemd/system/roxy.service`:

```
[Unit]
Description=Roxy Docker Socket Proxy
After=docker.service
Requires=docker.service

[Service]
ExecStart=/usr/local/bin/roxy-socks
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Enable and start the service:

```bash
sudo systemctl enable roxy
sudo systemctl start roxy
```

## Usage

```
roxy-socks [OPTIONS]
```

### Options

- `-s, --socket-path <PATH>`: Path to the socket to create (default: `/var/run/roxy`)
- `-d, --docker-socket <PATH>`: Path to the Docker socket (default: `/var/run/docker.sock`)
- `-c, --config-path <PATH>`: Path to the rules configuration file (default: `/etc/roxy/config.yml`)
- `-l, --log-dir <PATH>`: Path to the log directory (default: `/var/log/roxy`)
- `-t, --timeout <SECONDS>`: Timeout in seconds for network operations (default: `5`)
- `-r, --log-rotation <ROTATION>`: Log rotation duration (hourly, daily, never) (default: `daily`)
- `--no-default-rules`: Disable the default rules that allow GET requests to the /version endpoint

## Configuration

The configuration file uses YAML format and defines access control rules. By default, all requests are denied unless explicitly allowed by a rule.

Roxy automatically watches the configuration file for changes and reloads the rules when the file is modified, without requiring a restart of the proxy. This allows you to update the access control rules on the fly.

### Default Rules

By default, Roxy adds the following rules to allow basic Docker version checking:
- Allow GET requests to the `/version` endpoint
- Allow GET requests to the `/v1.*/version` endpoint (using regex pattern)

These default rules can be disabled using the `--no-default-rules` command-line option.

### Example Configurations

Below are examples of different rule configurations for various use cases.

#### Basic Endpoint and Method Matching

```yaml
# Allow listing containers from specific binaries
- endpoint: /containers/json
  methods: [GET]
  allow: true
  process_binaries: ["/usr/bin/docker", "/usr/local/bin/docker-compose"]
```

#### Path Variables

```yaml
# Allow inspecting containers using path variables
- endpoint: /containers/{container_id}/json
  methods: [GET]
  allow: true
  process_binaries: ["/usr/bin/docker", "/usr/local/bin/docker-compose"]
  path_variables:
    container_id: ".*"  # Match any container ID
  # Example of response_rules to ensure container is not privileged
  response_rules:
    "$.HostConfig.Privileged": false
```

#### Multiple Path Variables

```yaml
# Allow accessing container logs with multiple path variables
- endpoint: /containers/{container_id}/logs/{log_type}
  methods: [GET]
  allow: true
  process_binaries: ["/usr/bin/docker", "/usr/local/bin/docker-compose"]
  path_variables:
    container_id: "[a-f0-9]+"  # Match container IDs with hexadecimal characters
    log_type: "stdout|stderr"  # Match only stdout or stderr
```

#### Regex Path Matching

```yaml
# Allow inspecting containers using regex pattern
- endpoint: "^/containers/[a-f0-9]+/json$"  # Match container IDs with hexadecimal characters
  methods: [GET]
  allow: true
  process_binaries: ["/usr/bin/docker", "/usr/local/bin/docker-compose"]
```

#### Request Body Validation

```yaml
# Allow creating containers but restrict options
- endpoint: /containers/create
  methods: [POST]
  allow: true
  process_binaries: ["/usr/bin/docker"]
  request_rules:
    "$.HostConfig.Privileged": false
    "$.HostConfig.PidMode": null
```

#### Response Body Validation

```yaml
# Allow listing images with response validation
- endpoint: /images/json
  methods: [GET]
  allow: true
  process_binaries: ["/usr/bin/docker", "/usr/local/bin/docker-compose"]
  response_rules:
    "$[0].RepoTags": ["*"]  # Ensure images have tags
```

#### Combined Request and Response Rules

```yaml
# Example of using both request_rules and response_rules
- endpoint: /images/json
  methods: [GET]
  allow: true
  process_binaries: ["/usr/bin/docker", "/usr/local/bin/docker-compose"]
  request_rules:
    "$.filters.reference": null  # No specific reference filter
  response_rules:
    "$[0].RepoTags": ["*"]  # Ensure images have tags
```

#### Query Parameter Matching

```yaml
# Allow listing containers with specific query parameters
- endpoint: /containers/json
  methods: [GET]
  allow: true
  process_binaries: ["/usr/bin/docker", "/usr/local/bin/docker-compose"]
  match_query_params: required  # Query parameters must match the specified patterns
  query_params:
    limit: "^\\d+$"  # Only digits
    all: "^(true|false)$"  # Only true or false
```

```yaml
# Allow listing containers with optional query parameters
- endpoint: /containers/json
  methods: [GET]
  allow: true
  process_binaries: ["/usr/bin/docker", "/usr/local/bin/docker-compose"]
  match_query_params: optional  # Query parameters must match if present, but can be missing
  query_params:
    limit: "^\\d+$"  # Only digits
    all: "^(true|false)$"  # Only true or false
```

```yaml
# Allow listing containers with regex patterns for query parameter names
- endpoint: /containers/json
  methods: [GET]
  allow: true
  process_binaries: ["/usr/bin/docker", "/usr/local/bin/docker-compose"]
  match_query_params: required  # Query parameters must match the specified patterns
  query_params:
    "^lim\\w+$": "^\\d+$"  # Parameter names starting with "lim" must have digit values
    "^a\\w+$": "^(true|false)$"  # Parameter names starting with "a" must be true or false
```

#### Deny Rules

```yaml
# Deny all other requests to the containers endpoint
- endpoint: /containers
  allow: false
```

### Rule Properties

- `endpoint`: The API endpoint to match (e.g., `/containers/json`)
- `methods`: HTTP methods to match (e.g., `[GET, POST]`)
- `allow`: Whether to allow or deny the request if it matches
- `request_rules`: JSON path conditions to match in the request body
- `response_rules`: JSON path conditions to match in the response body
- `process_binaries`: Process binary paths to match
- `path_variables`: Variables to use in endpoint matching (e.g., `{container_id}`)
- `match_query_params`: How to match query parameters when matching the endpoint (values: `ignore`, `required`, `optional`)
- `query_params`: Regex patterns to match query parameters (keys are parameter names, values are regex patterns)

## Security Considerations

- The proxy should run as root to access the Docker socket
- The proxy creates a socket with 0666 permissions to allow non-root access

## Logs

Logs are stored in the specified log directory (default: `/var/log/roxy`) and include:
- Request details (method, path)
- Process information (PID, binary)
- Access decision (allowed/denied)
- Reason for denial if applicable

Logs are rotated based on the specified rotation period (default: daily) to prevent excessive disk usage.

### Log Level

The log level can be set using the `RUST_LOG` environment variable. Valid values are:
- `trace`: Most verbose, includes all log messages
- `debug`: Includes debug information useful for development
- `info`: Default level, includes informational messages
- `warn`: Only includes warnings and errors
- `error`: Only includes errors

Example:
```bash
RUST_LOG=debug /usr/local/bin/roxy-socks
```

Or in the systemd service file:
```
[Service]
Environment="RUST_LOG=debug"
ExecStart=/usr/local/bin/roxy-socks
```

## Releases

The project uses GitHub Actions to automate the release process. When a new version is ready to be released, follow these steps:

1. Ensure all changes are committed and pushed to the main branch
2. Create a new tag with a version number prefixed with 'v' (e.g., `v1.0.0`)
   ```bash
   git tag v1.0.0
   git push origin v1.0.0
   ```
3. The GitHub Actions workflow will automatically:
   - Use GitVersion to determine the semantic version based on the tag
   - Update the version in Cargo.toml
   - Build the release binary
   - Run the Rust unit tests
   - Create a GitHub release
   - Upload the binary as a release asset

### Version Bumping

You can control version bumping through commit messages using the following format:
- `+semver: major` or `+semver: breaking` - Bump major version
- `+semver: minor` or `+semver: feature` - Bump minor version
- `+semver: patch` or `+semver: fix` - Bump patch version
- `+semver: none` or `+semver: skip` - Don't bump version

## Testing

The project includes integration tests written in Python that verify the functionality of the Roxy Docker Socket Proxy.

### Running Tests with CMake

The tests can be run using CMake, which will build the Rust binary and then run the Python tests:

```bash
# Navigate to the test directory
cd test

# Configure CMake (only needed once)
cmake .

# Run the tests
cmake --build . --target run-tests
```

Alternatively, you can use the make command directly:

```bash
cd test
make run-tests
```

This will:
1. Build the Rust binary in release mode
2. Install the test dependencies using uv
3. Run the pytest tests and output the results to test_output.log

### Test Requirements

The tests require:
- Python 3.12 or higher
- Docker
- CMake 3.10 or higher
- uv (Python package manager)
