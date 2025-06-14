"""
Shared pytest fixtures and configuration for all tests.
"""
import os
import tempfile
import shutil
from pathlib import Path
from typing import Generator, Dict, Any
import pytest
import yaml
import json


@pytest.fixture
def temp_dir() -> Generator[Path, None, None]:
    """
    Create a temporary directory for test files.
    
    Yields:
        Path: Path to the temporary directory
    """
    temp_path = tempfile.mkdtemp()
    yield Path(temp_path)
    shutil.rmtree(temp_path)


@pytest.fixture
def mock_config() -> Dict[str, Any]:
    """
    Provide a mock configuration dictionary for testing.
    
    Returns:
        Dict[str, Any]: Mock configuration data
    """
    return {
        "kubernetes": {
            "api_endpoint": "https://test.k8s.local",
            "namespace": "default",
            "timeout": 30,
        },
        "security": {
            "enable_ssl_verification": True,
            "scan_depth": "medium",
        },
        "output": {
            "format": "json",
            "verbose": False,
        }
    }


@pytest.fixture
def mock_kubeconfig(temp_dir: Path) -> Path:
    """
    Create a mock kubeconfig file for testing.
    
    Args:
        temp_dir: Temporary directory fixture
        
    Returns:
        Path: Path to the mock kubeconfig file
    """
    kubeconfig_data = {
        "apiVersion": "v1",
        "kind": "Config",
        "clusters": [{
            "cluster": {
                "server": "https://test.k8s.local",
                "certificate-authority-data": "mock-ca-data"
            },
            "name": "test-cluster"
        }],
        "contexts": [{
            "context": {
                "cluster": "test-cluster",
                "user": "test-user"
            },
            "name": "test-context"
        }],
        "current-context": "test-context",
        "users": [{
            "name": "test-user",
            "user": {
                "token": "mock-token"
            }
        }]
    }
    
    kubeconfig_path = temp_dir / "kubeconfig"
    with open(kubeconfig_path, "w") as f:
        yaml.dump(kubeconfig_data, f)
    
    return kubeconfig_path


@pytest.fixture
def mock_k8s_response() -> Dict[str, Any]:
    """
    Provide a mock Kubernetes API response for testing.
    
    Returns:
        Dict[str, Any]: Mock API response data
    """
    return {
        "apiVersion": "v1",
        "items": [
            {
                "metadata": {
                    "name": "test-pod",
                    "namespace": "default",
                    "uid": "12345-67890"
                },
                "spec": {
                    "containers": [{
                        "name": "test-container",
                        "image": "test:latest"
                    }]
                },
                "status": {
                    "phase": "Running"
                }
            }
        ]
    }


@pytest.fixture
def mock_vulnerability_data() -> Dict[str, Any]:
    """
    Provide mock vulnerability scan data for testing.
    
    Returns:
        Dict[str, Any]: Mock vulnerability data
    """
    return {
        "scan_id": "test-scan-001",
        "timestamp": "2024-01-01T00:00:00Z",
        "vulnerabilities": [
            {
                "id": "CVE-2024-0001",
                "severity": "HIGH",
                "description": "Test vulnerability",
                "affected_resources": ["test-pod"]
            }
        ],
        "summary": {
            "total": 1,
            "high": 1,
            "medium": 0,
            "low": 0
        }
    }


@pytest.fixture
def clean_env() -> Generator[None, None, None]:
    """
    Provide a clean environment for tests by backing up and restoring env vars.
    """
    original_env = os.environ.copy()
    yield
    os.environ.clear()
    os.environ.update(original_env)


@pytest.fixture
def mock_requests_response(mocker):
    """
    Create a mock requests.Response object.
    
    Args:
        mocker: pytest-mock fixture
        
    Returns:
        Mock response object with configurable attributes
    """
    mock_response = mocker.Mock()
    mock_response.status_code = 200
    mock_response.headers = {"Content-Type": "application/json"}
    mock_response.json.return_value = {"status": "ok"}
    mock_response.text = '{"status": "ok"}'
    mock_response.content = b'{"status": "ok"}'
    mock_response.raise_for_status.return_value = None
    
    return mock_response


@pytest.fixture
def capture_logs(caplog):
    """
    Helper fixture to capture and assert on log messages.
    
    Args:
        caplog: pytest's log capture fixture
        
    Returns:
        The caplog fixture configured for testing
    """
    caplog.set_level("DEBUG")
    return caplog


@pytest.fixture(autouse=True)
def reset_singletons():
    """
    Reset any singleton instances between tests to ensure test isolation.
    """
    # This would be implemented based on actual singleton patterns in the code
    yield
    # Cleanup code here if needed


@pytest.fixture
def mock_websocket_client(mocker):
    """
    Create a mock websocket client for testing.
    
    Args:
        mocker: pytest-mock fixture
        
    Returns:
        Mock websocket client
    """
    mock_ws = mocker.Mock()
    mock_ws.connected = True
    mock_ws.send.return_value = None
    mock_ws.recv.return_value = '{"type": "message", "data": "test"}'
    mock_ws.close.return_value = None
    
    return mock_ws


# Pytest configuration hooks

def pytest_configure(config):
    """
    Configure pytest with custom settings.
    """
    config.addinivalue_line(
        "markers", "requires_k8s: mark test as requiring Kubernetes cluster access"
    )
    config.addinivalue_line(
        "markers", "network: mark test as requiring network access"
    )


def pytest_collection_modifyitems(config, items):
    """
    Modify test collection to add markers based on test location.
    """
    for item in items:
        # Add unit marker to tests in unit directory
        if "unit" in str(item.fspath):
            item.add_marker(pytest.mark.unit)
        # Add integration marker to tests in integration directory
        elif "integration" in str(item.fspath):
            item.add_marker(pytest.mark.integration)