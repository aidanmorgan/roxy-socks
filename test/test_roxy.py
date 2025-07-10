import pytest
import docker
from docker.errors import APIError

from config_model import RoxyConfig, Rule


class TestRoxyIntegration:
    """Integration tests for the roxy-socks application."""

    def test_list_containers(self, docker_client_with_roxy):
        """Test listing containers."""
        # Create the model within the test
        self.config_model = RoxyConfig(rules=[
            Rule(
                endpoint="/v1.*/containers/json",
                methods=["GET"],
                allow=True
            )
        ])

        containers = docker_client_with_roxy.containers.list(all=True)
        # Just verify that the request succeeds, we don't care about the actual containers

    def test_list_containers_with_filters(self, docker_client_with_roxy):
        """Test listing containers with filters."""
        # Create the model within the test
        self.config_model = RoxyConfig(rules=[
            Rule(
                endpoint="/v1.*/containers/json",
                methods=["GET"],
                allow=True,
                request_rules={
                    "$.filters": {"status": ["running"]}  # Only allow filtering by running status
                }
            )
        ])

        # List only running containers
        containers = docker_client_with_roxy.containers.list(filters={"status": ["running"]})
        # Just verify that the request succeeds

    def test_list_containers_with_response_rules(self, docker_client_with_roxy):
        """Test listing containers with response rules."""
        # Create the model within the test
        self.config_model = RoxyConfig(rules=[
            # List containers rule with response_rules
            Rule(
                endpoint="/v1.*/containers/json",
                methods=["GET"],
                allow=True,
                response_rules={
                    "$[*].State": {"Running": True, "Paused": False}  # Only allow running, non-paused containers
                }
            ),
            # Create container rule
            Rule(
                endpoint="/v1.*/containers/create",
                methods=["POST"],
                allow=True
            ),
            # Start container rule
            Rule(
                endpoint="/v1.*/containers/{container_id}/start",
                methods=["POST"],
                allow=True,
                path_variables={"container_id": ".*"}
            ),
            # Stop container rule
            Rule(
                endpoint="/v1.*/containers/{container_id}/stop",
                methods=["POST"],
                allow=True,
                path_variables={"container_id": ".*"}
            ),
            # Remove container rule
            Rule(
                endpoint="/v1.*/containers/{container_id}",
                methods=["DELETE"],
                allow=True,
                path_variables={"container_id": ".*"}
            )
        ])

        try:
            # Create and start a container
            container = docker_client_with_roxy.containers.create(
                "alpine:latest",
                command="sleep 300",
                name="roxy-test-response-rules-positive",
            )
            container.start()

            # List running containers, which should succeed
            running_containers = docker_client_with_roxy.containers.list(all=False)
            # Verify that our container is in the list
            container_ids = [c.id for c in running_containers]
            assert container.id in container_ids

        finally:
            # Clean up
            try:
                container = docker_client_with_roxy.containers.get("roxy-test-response-rules-positive")
                if container.status == "running":
                    container.stop()
                container.remove()
            except docker.errors.NotFound:
                pass

    def test_container_lifecycle(self, docker_client_with_roxy):
        """Test the full container lifecycle: create, start, inspect, stop, remove."""
        # Create the model within the test
        self.config_model = RoxyConfig(rules=[
            # List containers rule
            Rule(
                endpoint="/v1.*/containers/json",
                methods=["GET"],
                allow=True
            ),
            # Inspect container rule
            Rule(
                endpoint="/v1.*/containers/{container_id}/json",
                methods=["GET"],
                allow=True,
                path_variables={"container_id": ".*"}
            ),
            # Create container rule
            Rule(
                endpoint="/v1.*/containers/create",
                methods=["POST"],
                allow=True
            ),
            # Start container rule
            Rule(
                endpoint="/v1.*/containers/{container_id}/start",
                methods=["POST"],
                allow=True,
                path_variables={"container_id": ".*"}
            ),
            # Stop container rule
            Rule(
                endpoint="/v1.*/containers/{container_id}/stop",
                methods=["POST"],
                allow=True,
                path_variables={"container_id": ".*"}
            ),
            # Remove container rule
            Rule(
                endpoint="/v1.*/containers/{container_id}",
                methods=["DELETE"],
                allow=True,
                path_variables={"container_id": ".*"}
            )
        ])
        try:
            # Create a container
            container = docker_client_with_roxy.containers.create(
                "alpine:latest",
                command="sleep 300",
                name="roxy-test-container",
            )

            # Start the container
            container.start()

            # Inspect the container
            container.reload()
            assert container.status == "running"

            # Stop the container
            container.stop()
            container.reload()
            assert container.status == "exited"

            # Remove the container
            container.remove()

            # Verify that the container is gone
            with pytest.raises(docker.errors.NotFound):
                docker_client_with_roxy.containers.get("roxy-test-container")

        finally:
            # Clean up in case of test failure
            try:
                container = docker_client_with_roxy.containers.get("roxy-test-container")
                if container.status == "running":
                    container.stop()
                container.remove()
            except docker.errors.NotFound:
                pass

    def test_privileged_container_denied(self, docker_client_with_roxy):
        """Test that creating a privileged container is denied."""
        # Create the model within the test
        self.config_model = RoxyConfig(rules=[
            # Create container rule with privileged=False
            Rule(
                endpoint="/v1.*/containers/create",
                methods=["POST"],
                allow=True,
                request_rules={"$.HostConfig.Privileged": False}
            )
        ])
        with pytest.raises(APIError) as excinfo:
            docker_client_with_roxy.containers.create(
                "alpine:latest",
                command="sleep 300",
                name="roxy-test-privileged",
                privileged=True,
            )

        # Verify that the error is due to the request being denied
        assert "403 Forbidden" in str(excinfo.value)

    def test_list_images(self, docker_client_with_roxy):
        """Test listing images."""
        # Create the model within the test
        self.config_model = RoxyConfig(rules=[
            # List images rule
            Rule(
                endpoint="/v1.*/images/json",
                methods=["GET"],
                allow=True
            )
        ])

        images = docker_client_with_roxy.images.list()
        # Just verify that the request succeeds, we don't care about the actual images

    def test_path_variables(self, docker_client_with_roxy):
        """Test rules with path variables."""
        # Create the model within the test
        self.config_model = RoxyConfig(rules=[
            # Create container rule
            Rule(
                endpoint="/v1.*/containers/create",
                methods=["POST"],
                allow=True
            ),
            # Inspect container rule
            Rule(
                endpoint="/v1.*/containers/{container_id}/json",
                methods=["GET"],
                allow=True,
                path_variables={"container_id": ".*"}
            ),
            # Start container rule
            Rule(
                endpoint="/v1.*/containers/{container_id}/start",
                methods=["POST"],
                allow=True,
                path_variables={"container_id": ".*"}
            ),
            # Stop container rule
            Rule(
                endpoint="/v1.*/containers/{container_id}/stop",
                methods=["POST"],
                allow=True,
                path_variables={"container_id": ".*"}
            ),
            # Remove container rule
            Rule(
                endpoint="/v1.*/containers/{container_id}",
                methods=["DELETE"],
                allow=True,
                path_variables={"container_id": ".*"}
            )
        ])
        try:
            # Create a container
            container = docker_client_with_roxy.containers.create(
                "alpine:latest",
                command="sleep 300",
                name="roxy-test-path-vars",
            )

            # Test inspecting the container (uses path variables)
            container_info = docker_client_with_roxy.api.inspect_container(container.id)
            assert container_info["Id"] == container.id

            # Test starting the container (uses path variables)
            docker_client_with_roxy.api.start_container(container.id)
            container.reload()
            assert container.status == "running"

            # Test stopping the container (uses path variables)
            docker_client_with_roxy.api.stop_container(container.id)
            container.reload()
            assert container.status == "exited"

            # Test removing the container (uses path variables)
            docker_client_with_roxy.api.remove_container(container.id)
            with pytest.raises(docker.errors.NotFound):
                docker_client_with_roxy.containers.get("roxy-test-path-vars")

        finally:
            # Clean up in case of test failure
            try:
                container = docker_client_with_roxy.containers.get("roxy-test-path-vars")
                if container.status == "running":
                    container.stop()
                container.remove()
            except docker.errors.NotFound:
                pass

    def test_specific_path_variable_regex(self, docker_client_with_roxy):
        """Test rules with specific path variable regex patterns."""
        # Create the model within the test
        self.config_model = RoxyConfig(rules=[
            # Create container rule
            Rule(
                endpoint="/v1.*/containers/create",
                methods=["POST"],
                allow=True
            ),
            # Inspect container rule with specific regex for container_id
            # This regex matches the full 64-character hex ID format
            Rule(
                endpoint="/v1.*/containers/{container_id}/json",
                methods=["GET"],
                allow=True,
                path_variables={"container_id": "^[a-f0-9]{64}$"}
            ),
            # Start container rule with specific regex for container_id
            # This regex matches either the full 64-character hex ID or the short 12-character prefix
            Rule(
                endpoint="/v1.*/containers/{container_id}/start",
                methods=["POST"],
                allow=True,
                path_variables={"container_id": "^[a-f0-9]{12}([a-f0-9]{52})?$"}
            ),
            # Stop container rule with specific regex for container_id
            Rule(
                endpoint="/v1.*/containers/{container_id}/stop",
                methods=["POST"],
                allow=True,
                path_variables={"container_id": "^[a-f0-9]{12}([a-f0-9]{52})?$"}
            ),
            # Remove container rule with specific regex for container_id
            Rule(
                endpoint="/v1.*/containers/{container_id}",
                methods=["DELETE"],
                allow=True,
                path_variables={"container_id": "^[a-f0-9]{12}([a-f0-9]{52})?$"}
            )
        ])
        try:
            # Create a container
            container = docker_client_with_roxy.containers.create(
                "alpine:latest",
                command="sleep 300",
                name="roxy-test-specific-path-vars",
            )

            # Test inspecting the container (uses path variables)
            # This should work with the full 64-character ID
            container_info = docker_client_with_roxy.api.inspect_container(container.id)
            assert container_info["Id"] == container.id

            # Test starting the container (uses path variables)
            # This should work with either the full ID or the short ID
            docker_client_with_roxy.api.start_container(container.id)
            container.reload()
            assert container.status == "running"

            # Test stopping the container (uses path variables)
            docker_client_with_roxy.api.stop_container(container.id)
            container.reload()
            assert container.status == "exited"

            # Test removing the container (uses path variables)
            docker_client_with_roxy.api.remove_container(container.id)
            with pytest.raises(docker.errors.NotFound):
                docker_client_with_roxy.containers.get("roxy-test-specific-path-vars")

        finally:
            # Clean up in case of test failure
            try:
                container = docker_client_with_roxy.containers.get("roxy-test-specific-path-vars")
                if container.status == "running":
                    container.stop()
                container.remove()
            except docker.errors.NotFound:
                pass

    def test_path_regex_with_query_params(self, docker_client_with_roxy):
        """Test rules with path_regex including query parameters."""
        # Create the model within the test
        self.config_model = RoxyConfig(rules=[
            # List containers rule with path_regex for specific query parameters
            Rule(
                endpoint="/v1.*/containers/json",
                methods=["GET"],
                allow=True,
                path_regex="^/v1\\.[0-9]+/containers/json\\?all=true&limit=\\d+$"  # Only allow with all=true and limit=<number>
            ),
            # Create container rule
            Rule(
                endpoint="/v1.*/containers/create",
                methods=["POST"],
                allow=True
            ),
            # Start container rule
            Rule(
                endpoint="/v1.*/containers/{container_id}/start",
                methods=["POST"],
                allow=True,
                path_variables={"container_id": ".*"}
            ),
            # Stop container rule
            Rule(
                endpoint="/v1.*/containers/{container_id}/stop",
                methods=["POST"],
                allow=True,
                path_variables={"container_id": ".*"}
            ),
            # Remove container rule
            Rule(
                endpoint="/v1.*/containers/{container_id}",
                methods=["DELETE"],
                allow=True,
                path_variables={"container_id": ".*"}
            )
        ])

        try:
            # Create a container to ensure we have at least one container
            container = docker_client_with_roxy.containers.create(
                "alpine:latest",
                command="sleep 300",
                name="roxy-test-path-regex-query",
            )

            # List containers with all=true and limit=10, which should be allowed
            containers = docker_client_with_roxy.containers.list(all=True, limit=10)
            # Just verify that the request succeeds

            # Try to list containers with all=true but no limit, which should be denied
            with pytest.raises(APIError) as excinfo:
                docker_client_with_roxy.containers.list(all=True)

            # Verify that the error is due to the request being denied
            assert "403 Forbidden" in str(excinfo.value)

        finally:
            # Clean up
            try:
                container = docker_client_with_roxy.containers.get("roxy-test-path-regex-query")
                container.remove()
            except docker.errors.NotFound:
                pass

    def test_combined_rules(self, docker_client_with_roxy):
        """Test combining path_variables, request_rules, and response_rules."""
        # Create the model within the test
        self.config_model = RoxyConfig(rules=[
            # Create container rule with request_rules
            Rule(
                endpoint="/v1.*/containers/create",
                methods=["POST"],
                allow=True,
                request_rules={
                    "$.Image": "alpine:latest",  # Only allow alpine:latest image
                    "$.Cmd": ["echo", "hello"]   # Command must be exactly ["echo", "hello"]
                }
            ),
            # Inspect container rule with path_variables and response_rules
            Rule(
                endpoint="/v1.*/containers/{container_id}/json",
                methods=["GET"],
                allow=True,
                path_variables={"container_id": "^[a-f0-9]{12}([a-f0-9]{52})?$"},  # Must be a valid hex ID
                response_rules={
                    "$.Config.Image": "alpine:latest",  # Must be alpine:latest image
                    "$.Config.Cmd": ["echo", "hello"]   # Command must be exactly ["echo", "hello"]
                }
            ),
            # Start container rule
            Rule(
                endpoint="/v1.*/containers/{container_id}/start",
                methods=["POST"],
                allow=True,
                path_variables={"container_id": "^[a-f0-9]{12}([a-f0-9]{52})?$"}
            ),
            # Stop container rule
            Rule(
                endpoint="/v1.*/containers/{container_id}/stop",
                methods=["POST"],
                allow=True,
                path_variables={"container_id": "^[a-f0-9]{12}([a-f0-9]{52})?$"}
            ),
            # Remove container rule
            Rule(
                endpoint="/v1.*/containers/{container_id}",
                methods=["DELETE"],
                allow=True,
                path_variables={"container_id": "^[a-f0-9]{12}([a-f0-9]{52})?$"}
            )
        ])

        try:
            # Create a container with the required image and command
            container = docker_client_with_roxy.containers.create(
                "alpine:latest",
                command=["echo", "hello"],  # Must match the request_rules
                name="roxy-test-combined-rules",
            )

            # Inspect the container, which should pass the response_rules
            container_info = docker_client_with_roxy.api.inspect_container(container.id)
            assert container_info["Config"]["Image"] == "alpine:latest"
            assert container_info["Config"]["Cmd"] == ["echo", "hello"]

            # Try to create a container with a different command, which should be denied
            with pytest.raises(APIError) as excinfo:
                docker_client_with_roxy.containers.create(
                    "alpine:latest",
                    command=["echo", "world"],  # This doesn't match the required ["echo", "hello"]
                    name="roxy-test-combined-rules-invalid",
                )

            # Verify that the error is due to the request being denied
            assert "403 Forbidden" in str(excinfo.value)

        finally:
            # Clean up
            try:
                container = docker_client_with_roxy.containers.get("roxy-test-combined-rules")
                container.remove()
            except docker.errors.NotFound:
                pass
            try:
                container = docker_client_with_roxy.containers.get("roxy-test-combined-rules-invalid")
                container.remove()
            except docker.errors.NotFound:
                pass


class TestRoxyNegative:
    """Negative tests for the roxy-socks application."""

    def test_direct_docker_access(self, docker_client, roxy_process):
        """Test that direct access to the Docker socket still works."""
        # Create the model within the test
        self.config_model = RoxyConfig(rules=[
            # List containers rule
            Rule(
                endpoint="/v1.*/containers/json",
                methods=["GET"],
                allow=True
            ),
            # List images rule
            Rule(
                endpoint="/v1.*/images/json",
                methods=["GET"],
                allow=True
            )
        ])

        # This test verifies that the proxy doesn't interfere with direct Docker access
        containers = docker_client.containers.list(all=True)
        # Just verify that the request succeeds

    def test_proxy_restart(self, docker_client_with_roxy, roxy_process, roxy_binary, roxy_config, roxy_socket, roxy_log_dir):
        """Test that the proxy can be restarted and still works."""
        # Create the model within the test
        self.config_model = RoxyConfig(rules=[
            # List containers rule
            Rule(
                endpoint="/v1.*/containers/json",
                methods=["GET"],
                allow=True
            )
        ])

        # First, verify that the proxy is working
        docker_client_with_roxy.containers.list(all=True)

        # Restart the proxy
        roxy_process.terminate()
        roxy_process.wait()

        # Manually restart the proxy
        import subprocess
        import time
        import socket

        new_process = subprocess.Popen(
            [
                str(roxy_binary),
                "--socket-path", str(roxy_socket),
                "--config-path", roxy_config,
                "--log-dir", str(roxy_log_dir),
                "--log-rotation", "never",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        # Wait for the socket to be created
        for _ in range(10):
            if roxy_socket.exists():
                break
            time.sleep(0.5)
        else:
            new_process.terminate()
            stdout, stderr = new_process.communicate()
            raise RuntimeError(
                f"Socket not created after 5 seconds. "
                f"stdout: {stdout.decode()}, stderr: {stderr.decode()}"
            )

        # Wait for the socket to be ready
        for _ in range(10):
            try:
                sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                sock.connect(str(roxy_socket))
                sock.close()
                break
            except (socket.error, ConnectionRefusedError):
                time.sleep(0.5)
        else:
            new_process.terminate()
            stdout, stderr = new_process.communicate()
            raise RuntimeError(
                f"Socket not ready after 5 seconds. "
                f"stdout: {stdout.decode()}, stderr: {stderr.decode()}"
            )

        try:
            # Verify that it's still working
            docker_client_with_roxy.containers.list(all=True)
        finally:
            # Clean up the new process
            new_process.terminate()
            new_process.wait()

    def test_operation_not_allowed(self, docker_client_with_roxy):
        """Test that operations not explicitly allowed are denied."""
        # Create the model within the test with no rules
        self.config_model = RoxyConfig(rules=[])

        # Try to list containers, which should be denied
        with pytest.raises(APIError) as excinfo:
            docker_client_with_roxy.containers.list(all=True)

        # Verify that the error is due to the request being denied
        assert "403 Forbidden" in str(excinfo.value)

    def test_method_not_allowed(self, docker_client_with_roxy):
        """Test that methods not explicitly allowed are denied."""
        # Create the model within the test with only GET allowed
        self.config_model = RoxyConfig(rules=[
            # Create container rule with only GET allowed
            Rule(
                endpoint="/v1.*/containers/create",
                methods=["GET"],  # POST is required for container creation
                allow=True
            )
        ])

        # Try to create a container, which should be denied because POST is not allowed
        with pytest.raises(APIError) as excinfo:
            docker_client_with_roxy.containers.create(
                "alpine:latest",
                command="sleep 300",
                name="roxy-test-method-not-allowed",
            )

        # Verify that the error is due to the request being denied
        assert "403 Forbidden" in str(excinfo.value)

    def test_path_variable_regex_restriction(self, docker_client_with_roxy):
        """Test that path variables with regex restrictions work correctly."""
        # Create the model within the test with a specific regex for container_id
        self.config_model = RoxyConfig(rules=[
            # Create container rule
            Rule(
                endpoint="/v1.*/containers/create",
                methods=["POST"],
                allow=True
            ),
            # Start container rule with regex restriction
            Rule(
                endpoint="/v1.*/containers/{container_id}/start",
                methods=["POST"],
                allow=True,
                path_variables={"container_id": "^[a-f0-9]{12}$"}  # Only allow 12-character hex IDs
            )
        ])

        try:
            # Create a container
            container = docker_client_with_roxy.containers.create(
                "alpine:latest",
                command="sleep 300",
                name="roxy-test-path-regex",
            )

            # Try to start the container, which should be denied due to regex mismatch
            # Container IDs are typically longer than 12 characters
            with pytest.raises(APIError) as excinfo:
                docker_client_with_roxy.api.start_container(container.id)

            # Verify that the error is due to the request being denied
            assert "403 Forbidden" in str(excinfo.value)

        finally:
            # Clean up in case of test failure
            try:
                container = docker_client_with_roxy.containers.get("roxy-test-path-regex")
                if container.status == "running":
                    container.stop()
                container.remove()
            except docker.errors.NotFound:
                pass

    def test_request_rules_validation(self, docker_client_with_roxy):
        """Test that request_rules validation works correctly."""
        # Create the model within the test with request_rules
        self.config_model = RoxyConfig(rules=[
            # Create container rule with request_rules
            Rule(
                endpoint="/v1.*/containers/create",
                methods=["POST"],
                allow=True,
                request_rules={
                    "$.Image": "alpine:latest",  # Only allow alpine:latest image
                    "$.Cmd[0]": "echo"  # First command must be 'echo'
                }
            )
        ])

        # Try to create a container with a different command, which should be denied
        with pytest.raises(APIError) as excinfo:
            docker_client_with_roxy.containers.create(
                "alpine:latest",
                command="sleep 300",  # This doesn't match the required 'echo'
                name="roxy-test-request-rules",
            )

        # Verify that the error is due to the request being denied
        assert "403 Forbidden" in str(excinfo.value)

        # Now try with a valid command
        try:
            container = docker_client_with_roxy.containers.create(
                "alpine:latest",
                command="echo hello",
                name="roxy-test-request-rules-valid",
            )
            # This should succeed
            assert container.name == "roxy-test-request-rules-valid"

        finally:
            # Clean up
            try:
                container = docker_client_with_roxy.containers.get("roxy-test-request-rules-valid")
                container.remove()
            except docker.errors.NotFound:
                pass

    def test_response_rules_validation(self, docker_client_with_roxy):
        """Test that response_rules validation works correctly."""
        # Create the model within the test with response_rules
        self.config_model = RoxyConfig(rules=[
            # List containers rule with response_rules
            Rule(
                endpoint="/v1.*/containers/json",
                methods=["GET"],
                allow=True,
                response_rules={
                    "$[*].Image": "alpine:latest"  # Only allow containers with alpine:latest image
                }
            ),
            # Create container rule
            Rule(
                endpoint="/v1.*/containers/create",
                methods=["POST"],
                allow=True
            ),
            # Start container rule
            Rule(
                endpoint="/v1.*/containers/{container_id}/start",
                methods=["POST"],
                allow=True,
                path_variables={"container_id": ".*"}
            )
        ])

        try:
            # Create and start a container with a different image
            container = docker_client_with_roxy.containers.create(
                "ubuntu:latest",  # This doesn't match the required alpine:latest
                command="sleep 300",
                name="roxy-test-response-rules",
            )
            container.start()

            # Try to list containers, which should be denied due to response_rules
            with pytest.raises(APIError) as excinfo:
                docker_client_with_roxy.containers.list(all=False)  # Only running containers

            # Verify that the error is due to the response being denied
            assert "403 Forbidden" in str(excinfo.value)

        finally:
            # Clean up
            try:
                container = docker_client_with_roxy.containers.get("roxy-test-response-rules")
                if container.status == "running":
                    container.stop()
                container.remove()
            except docker.errors.NotFound:
                pass

    def test_complex_path_regex(self, docker_client_with_roxy):
        """Test that path_regex works correctly for complex paths."""
        # Create the model within the test with path_regex
        self.config_model = RoxyConfig(rules=[
            # Rule with path_regex
            Rule(
                endpoint="/v1.*/containers/json",
                methods=["GET"],
                allow=True,
                path_regex="^/v1\\.[0-9]+/containers/json\\?all=true$"  # Only allow with all=true query param
            )
        ])

        # Try to list all containers, which should be allowed
        containers_all = docker_client_with_roxy.containers.list(all=True)
        # Just verify that the request succeeds

        # Try to list only running containers, which should be denied
        with pytest.raises(APIError) as excinfo:
            docker_client_with_roxy.containers.list(all=False)

        # Verify that the error is due to the request being denied
        assert "403 Forbidden" in str(excinfo.value)
