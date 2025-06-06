"""
Shared pytest fixtures and configuration for kubestriker tests.
"""

import pytest
import tempfile
import os
from unittest.mock import Mock, patch


@pytest.fixture
def temp_dir():
    """Create a temporary directory for test files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield tmpdir


@pytest.fixture
def mock_kubernetes_config():
    """Mock Kubernetes configuration."""
    return {
        'apiVersion': 'v1',
        'clusters': [{
            'cluster': {
                'certificate-authority-data': 'fake-cert-data',
                'server': 'https://kubernetes.example.com:6443'
            },
            'name': 'test-cluster'
        }],
        'contexts': [{
            'context': {
                'cluster': 'test-cluster',
                'user': 'test-user'
            },
            'name': 'test-context'
        }],
        'current-context': 'test-context',
        'kind': 'Config',
        'users': [{
            'name': 'test-user',
            'user': {
                'token': 'fake-token'
            }
        }]
    }


@pytest.fixture
def mock_requests_response():
    """Mock requests.Response object."""
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {}
    mock_response.text = ""
    mock_response.headers = {}
    return mock_response


@pytest.fixture
def sample_target_host():
    """Sample target host for testing."""
    return "192.168.1.100"


@pytest.fixture
def sample_port():
    """Sample port for testing."""
    return 6443


@pytest.fixture
def mock_socket():
    """Mock socket for network testing."""
    with patch('socket.socket') as mock_sock:
        yield mock_sock


@pytest.fixture(autouse=True)
def clean_environment():
    """Clean environment variables before each test."""
    env_vars_to_clean = [
        'KUBECONFIG',
        'KUBERNETES_SERVICE_HOST',
        'KUBERNETES_SERVICE_PORT'
    ]
    
    original_values = {}
    for var in env_vars_to_clean:
        original_values[var] = os.environ.get(var)
        if var in os.environ:
            del os.environ[var]
    
    yield
    
    # Restore original values
    for var, value in original_values.items():
        if value is not None:
            os.environ[var] = value
        elif var in os.environ:
            del os.environ[var]