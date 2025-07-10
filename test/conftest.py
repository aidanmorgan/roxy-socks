import os
import time
import socket
import subprocess
import tempfile
import logging
import inspect
from pathlib import Path

import docker
import pytest

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


@pytest.fixture(scope="session")
def docker_client():
    """Create a Docker client for the tests."""
    client = docker.from_env()
    logger.info(f"Created docker client: {client}")
    return client


@pytest.fixture(scope="session")
def roxy_binary():
    # Get the project root directory
    project_root = Path(__file__).parent.parent
    src_dir = project_root / "src"

    # Return the path to the binary
    binary_path = src_dir / "target" / "release" / "roxy-socks"
    assert binary_path.exists(), f"Binary not found at {binary_path}"
    logger.info(f"Using roxy binary at: {binary_path}")
    return binary_path


@pytest.fixture(scope="function")
def roxy_config(request):
    """Create a temporary configuration file for roxy-socks."""
    # Get the test function
    test_function = request.function
    test_class = request.instance.__class__
    test_name = test_function.__name__

    # Create a default config model with an empty rule set
    from config_model import RoxyConfig, Rule
    default_config = RoxyConfig(rules=[])

    # Try to get the config model from the test instance
    config_model = getattr(request.instance, 'config_model', None)

    # If not found, try to create it from the test method
    if config_model is None:
        # Find the test method in the class
        test_method = getattr(test_class, test_name)

        # Create the config model by executing the first few lines of the test method
        # that set self.config_model
        try:
            # Create a temporary instance to execute the method
            temp_instance = test_class()

            # Execute just the part of the method that sets self.config_model
            method_source = test_method.__code__.co_consts[0]  # Get the docstring
            method_lines = inspect.getsource(test_method).split('\n')

            # Find the lines that set self.config_model
            config_lines = []
            for i, line in enumerate(method_lines):
                if 'self.config_model' in line:
                    # Get this line and all indented lines that follow
                    j = i
                    indent_level = len(line) - len(line.lstrip())
                    while j < len(method_lines) and (j == i or len(method_lines[j]) - len(method_lines[j].lstrip()) >= indent_level):
                        config_lines.append(method_lines[j])
                        j += 1
                    break

            if config_lines:
                try:
                    # Dedent the code to avoid indentation errors
                    import textwrap
                    config_code = textwrap.dedent('\n'.join(config_lines))
                    # Execute these lines to set config_model on the temporary instance
                    exec(config_code, globals(), {'self': temp_instance})
                    config_model = temp_instance.config_model
                except Exception as e:
                    logger.warning(f"Failed to execute extracted config code: {e}")
                    logger.warning(f"Extracted code was: {config_code}")
                    # Use the default config
                    config_model = default_config

        except Exception as e:
            logger.warning(f"Failed to extract config_model from test method: {e}")
            # Use the default config
            config_model = default_config

    logger.info(f"Creating config file with model: {config_model}")

    with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False) as f:
        # Convert the configuration model to YAML and write it to the file
        yaml_content = f"# Test configuration for Roxy Docker Socket Proxy\n{config_model.to_yaml()}"
        logger.info(f"Config YAML content: {yaml_content}")
        f.write(yaml_content)

    config_path = f.name
    logger.info(f"Created config file at: {config_path}")
    yield config_path

    # Clean up
    logger.info(f"Cleaning up config file: {config_path}")
    os.unlink(config_path)


@pytest.fixture(scope="function")
def roxy_socket():
    """Create a temporary socket path for roxy-socks."""
    with tempfile.TemporaryDirectory() as temp_dir:
        socket_path = Path(temp_dir) / "roxy.sock"
        logger.info(f"Created socket path: {socket_path}")
        yield socket_path
        logger.info(f"Cleaning up socket path: {socket_path}")


@pytest.fixture(scope="function")
def roxy_log_dir():
    """Create a temporary log directory for roxy-socks."""
    with tempfile.TemporaryDirectory() as temp_dir:
        log_dir = Path(temp_dir)
        logger.info(f"Created log directory: {log_dir}")
        yield log_dir
        logger.info(f"Cleaning up log directory: {log_dir}")


@pytest.fixture(scope="function")
def roxy_process(roxy_binary, roxy_config, roxy_socket, roxy_log_dir):
    """Start the roxy-socks process and yield the process object."""
    # Start the roxy-socks process

    user_docker = Path.home() / ".docker/run/docker.sock"
    logger.info(f"Using user docker socket at: {user_docker}")

    cmd = [
        str(roxy_binary),
        "--socket-path", str(roxy_socket),
        "--docker-socket", str(user_docker),
        "--config-path", roxy_config,
        "--log-dir", str(roxy_log_dir),
        "--log-rotation", "never",
    ]

    logger.info(f"Starting roxy process with command: {cmd}")
    process = subprocess.Popen(cmd)
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
def docker_client_with_roxy(roxy_socket, roxy_process):
    """Create a Docker client that uses the roxy-socks proxy."""
    base_url = f"unix://{roxy_socket}"
    logger.info(f"Creating Docker client with base_url: {base_url}")
    client = docker.DockerClient(base_url=base_url)
    logger.info(f"Created Docker client: {client}")
    yield client
    logger.info(f"Closing Docker client: {client}")
    client.close()
