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

## Configuration

The configuration file uses YAML format and defines access control rules. By default, all requests are denied unless explicitly allowed by a rule.

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
- endpoint: /containers/
  methods: [GET]
  allow: true
  process_binaries: ["/usr/bin/docker", "/usr/local/bin/docker-compose"]
  path_regex: "^/containers/[a-f0-9]+/json$"  # Match container IDs with hexadecimal characters
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
- `path_regex`: Regular expression pattern for path matching

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
