import os
import time
import socket
import subprocess
import tempfile
import logging
import inspect
from pathlib import Path
from typing import Callable, Optional, Union, Any, Generator

import docker
import pytest
from _pytest.fixtures import FixtureRequest
from _pytest.config import Config

from config_model import RoxyConfig, Rule

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('test_fixtures.log')
    ]
)
logger = logging.getLogger("pytest_fixtures")


def pytest_configure(config: Config) -> None:
    """Add custom attributes to the pytest config object."""
    config.addinivalue_line("markers", "roxy: mark test as using roxy-socks proxy")
    # Add the custom attribute to avoid linter errors
    setattr(config, 'roxy_config_path', None)


@pytest.fixture(scope="session")
def docker_client() -> docker.DockerClient:
    """Create a Docker client for the tests."""
    client = docker.from_env()
    logger.info(f"Created docker client: {client}")
    return client


@pytest.fixture(scope="session")
def roxy_binary() -> Path:
    # Get the project root directory
    project_root = Path(__file__).parent.parent
    src_dir = project_root / "src"

    # Return the path to the binary
    binary_path = src_dir / "target" / "debug" / "roxy-socks"
    assert binary_path.exists(), f"Binary not found at {binary_path}"
    logger.info(f"Using roxy binary at: {binary_path}")
    return binary_path


@pytest.fixture(scope="function")
def with_roxy_config(request: FixtureRequest) -> Generator[Callable[[RoxyConfig | None], str], Any, None]:
    """
    Create a temporary configuration file for roxy-socks.

    This fixture returns a callback function that tests can call to save their specific configuration.
    Each test should define its own rules for testing by calling this callback with their RoxyConfig instance.

    Example usage in a test:
        def test_something(self, with_roxy_config):
            # Create a config model with specific rules for this test
            config_model = RoxyConfig(rules=[...])

            # Save the configuration and get the path to the config file
            config_path = with_roxy_config(config_model)

            # Use config_path in the test...
    """

    # Define the callback function that tests will call to save their configuration
    def _save_config(config_model: Optional[RoxyConfig] = None) -> str:
        if config_model is not None:
            # Use the provided configuration
            current_config = config_model
        else:
            # Use an empty configuration (default rules will be added by the application)
            current_config = RoxyConfig()

        config_path = request.config.roxy_config_path  # type: ignore
        logger.info(f"Updating config file for test: {config_path}")

        # Write the configuration to the file
        with open(config_path, 'w') as f:
            yaml_content = f"# Test configuration for Roxy Docker Socket Proxy\n{current_config.to_yaml()}"
            logger.info(f"Config YAML content: {yaml_content}")
            f.write(yaml_content)

        # Allow the file watcher time to reload the configuration
        time.sleep(0.2)

        return config_path

    # Return the callback function
    yield _save_config


    config_path = request.config.roxy_config_path  # type: ignore
    # Clean up
    logger.info(f"Cleaning up config file: {config_path}")
    os.unlink(config_path)


@pytest.fixture(scope="function")
def roxy_socket() -> Generator[Path, None, None]:
    """Create a temporary socket path for roxy-socks."""
    with tempfile.TemporaryDirectory() as temp_dir:
        socket_path = Path(temp_dir) / "roxy.sock"
        logger.info(f"Created socket path: {socket_path}")
        yield socket_path
        logger.info(f"Cleaning up socket path: {socket_path}")


@pytest.fixture(scope="function")
def roxy_log_dir() -> Generator[Path, None, None]:
    """Create a temporary log directory for roxy-socks."""
    with tempfile.TemporaryDirectory() as temp_dir:
        log_dir = Path(temp_dir)
        logger.info(f"Created log directory: {log_dir}")
        yield log_dir
        logger.info(f"Cleaning up log directory: {log_dir}")


@pytest.fixture(scope="function")
def roxy_process(
    roxy_binary: Path, 
    roxy_socket: Path,
    roxy_log_dir: Path, 
    request: FixtureRequest
) -> Generator[subprocess.Popen, None, None]:
    """Start the roxy-socks process and yield the process object."""
    # Create a temporary file that will be used for the configuration
    temp_file = tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False)
    config_path = temp_file.name
    temp_file.close()  # Close the file but keep it for later use

    # set the config file here, we will be able to trust the file-watcher to resync the configuration
    # once the with_roxy_config fixture runs
    request.config.roxy_config_path = config_path  # type: ignore

    # Create a minimal valid configuration to start with, this prevents the "missing field rules" error
    # it also makes sure that the docker client can be created properly as it requires the ability to call the
    # /version endpoint to make it work
    minimal_config = RoxyConfig(rules=[
        Rule(
            endpoint="/version",
            methods=["GET"],
            allow=True,
        ),
        Rule(
            endpoint="/v1.*/version",
            methods=["GET"],
            allow=True,
        )
    ])
    
    # Write the minimal config to the file initially
    with open(config_path, 'w') as f:
        yaml_content = f"# Minimal test configuration for Roxy Docker Socket Proxy\n{minimal_config.to_yaml()}"
        f.write(yaml_content)

    logger.info(f"Using config file: {config_path}")

    # Start the roxy-socks process
    user_docker = Path.home() / ".docker/run/docker.sock"
    logger.info(f"Using user docker socket at: {user_docker}")

    cmd = [
        str(roxy_binary),
        "--socket-path", str(roxy_socket),
        "--docker-socket", str(user_docker),
        "--config-path", request.config.roxy_config_path,  # type: ignore
        "--log-dir", str(roxy_log_dir),
        "--log-rotation", "never",
    ]

    new_env = os.environ.copy()
    new_env["RUST_LOG"] = "debug"

    logger.info(f"Starting roxy process with command: {cmd}")
    process = subprocess.Popen(cmd, env=new_env)
    logger.info(f"Started roxy process with PID: {process.pid}")

    # Wait for the socket to be created
    for i in range(10):
        if roxy_socket.exists():
            logger.info(f"Socket created after {i*0.5} seconds")
            break
        time.sleep(0.5)
    else:
        process.terminate()
        stdout, stderr = process.communicate()
        error_msg = f"Socket not created after 5 seconds. stdout: {stdout.decode() if stdout else 'None'}, stderr: {stderr.decode() if stderr else 'None'}"
        logger.error(error_msg)
        raise RuntimeError(error_msg)

    # Wait for the socket to be ready
    for i in range(10):
        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.connect(str(roxy_socket))
            sock.close()
            logger.info(f"Socket ready after {i*0.5} seconds")
            break
        except (socket.error, ConnectionRefusedError) as e:
            logger.debug(f"Socket not ready yet: {e}")
            time.sleep(0.5)
    else:
        process.terminate()
        stdout, stderr = process.communicate()
        error_msg = f"Socket not ready after 5 seconds. stdout: {stdout.decode() if stdout else 'None'}, stderr: {stderr.decode() if stderr else 'None'}"
        logger.error(error_msg)
        raise RuntimeError(error_msg)

    # Yield the process
    logger.info(f"Roxy process ready with PID: {process.pid}")
    yield process

    # Clean up
    logger.info(f"Terminating roxy process with PID: {process.pid}")
    process.terminate()
    process.wait()
    logger.info(f"Roxy process terminated with return code: {process.returncode}")


@pytest.fixture(scope="function")
def docker_client_with_roxy(roxy_socket: Path, roxy_process: subprocess.Popen, request: FixtureRequest) -> Generator[docker.DockerClient, None, None]:
    """Create a Docker client that uses the roxy-socks proxy."""
    base_url = f"unix://{roxy_socket}"
    logger.info(f"Creating Docker client with base_url: {base_url}")
    client = docker.DockerClient(base_url=base_url)
    logger.info(f"Created Docker client: {client}")
    yield client
    logger.info(f"Closing Docker client: {client}")
    client.close()

    client.close()
