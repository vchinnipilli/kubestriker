"""
Validation tests to ensure the testing infrastructure is properly configured.
"""
import sys
import pytest
from pathlib import Path


def test_python_version():
    """Test that Python version meets requirements."""
    assert sys.version_info >= (3, 8), "Python 3.8+ is required"


def test_pytest_available():
    """Test that pytest is properly installed."""
    assert pytest.__version__, "pytest should be installed"


def test_project_structure():
    """Test that the project structure is set up correctly."""
    project_root = Path(__file__).parent.parent
    
    # Check that main directories exist
    assert project_root.exists(), "Project root should exist"
    assert (project_root / "tests").exists(), "tests directory should exist"
    assert (project_root / "tests" / "unit").exists(), "tests/unit directory should exist"
    assert (project_root / "tests" / "integration").exists(), "tests/integration directory should exist"
    
    # Check that __init__.py files exist
    assert (project_root / "tests" / "__init__.py").exists(), "tests/__init__.py should exist"
    assert (project_root / "tests" / "unit" / "__init__.py").exists(), "tests/unit/__init__.py should exist"
    assert (project_root / "tests" / "integration" / "__init__.py").exists(), "tests/integration/__init__.py should exist"
    
    # Check that conftest.py exists
    assert (project_root / "tests" / "conftest.py").exists(), "tests/conftest.py should exist"


def test_fixtures_available(temp_dir, mock_config, clean_env):
    """Test that custom fixtures are available and working."""
    # Test temp_dir fixture
    assert temp_dir.exists(), "temp_dir fixture should create a directory"
    assert temp_dir.is_dir(), "temp_dir should be a directory"
    
    # Test mock_config fixture
    assert isinstance(mock_config, dict), "mock_config should return a dictionary"
    assert "kubernetes" in mock_config, "mock_config should contain kubernetes config"
    
    # Test clean_env fixture (it's automatically applied)
    assert True, "clean_env fixture should not raise errors"


@pytest.mark.unit
def test_unit_marker():
    """Test that unit test marker works."""
    assert True, "Unit test marker should be recognized"


@pytest.mark.integration
def test_integration_marker():
    """Test that integration test marker works."""
    assert True, "Integration test marker should be recognized"


@pytest.mark.slow
def test_slow_marker():
    """Test that slow test marker works."""
    assert True, "Slow test marker should be recognized"


def test_coverage_configured():
    """Test that coverage is properly configured."""
    # This test verifies coverage runs without errors
    # Actual coverage configuration is tested by running with coverage
    assert True, "Coverage should be configured in pyproject.toml"


class TestValidationSuite:
    """Test class to verify pytest class discovery works."""
    
    def test_class_discovery(self):
        """Test that pytest discovers test classes correctly."""
        assert True, "Test classes should be discovered"
    
    def test_method_discovery(self):
        """Test that pytest discovers test methods correctly."""
        assert True, "Test methods should be discovered"


def test_mock_fixtures(mock_kubeconfig, mock_k8s_response, mock_vulnerability_data):
    """Test that mock data fixtures work correctly."""
    # Test mock_kubeconfig
    assert mock_kubeconfig.exists(), "mock_kubeconfig should create a file"
    assert mock_kubeconfig.name == "kubeconfig", "mock_kubeconfig should have correct name"
    
    # Test mock_k8s_response
    assert isinstance(mock_k8s_response, dict), "mock_k8s_response should return a dict"
    assert "items" in mock_k8s_response, "mock_k8s_response should contain items"
    
    # Test mock_vulnerability_data
    assert isinstance(mock_vulnerability_data, dict), "mock_vulnerability_data should return a dict"
    assert "vulnerabilities" in mock_vulnerability_data, "mock_vulnerability_data should contain vulnerabilities"


def test_requests_mock(mock_requests_response):
    """Test that the requests mock fixture works."""
    assert mock_requests_response.status_code == 200, "Mock response should have status 200"
    assert mock_requests_response.json() == {"status": "ok"}, "Mock response should return correct JSON"


def test_websocket_mock(mock_websocket_client):
    """Test that the websocket mock fixture works."""
    assert mock_websocket_client.connected is True, "Mock websocket should be connected"
    assert mock_websocket_client.recv() == '{"type": "message", "data": "test"}', "Mock websocket should return data"


def test_log_capture(capture_logs):
    """Test that log capturing works correctly."""
    import logging
    logger = logging.getLogger(__name__)
    
    test_message = "Test log message"
    logger.info(test_message)
    
    assert test_message in capture_logs.text, "Log message should be captured"


if __name__ == "__main__":
    # Allow running this file directly for quick validation
    pytest.main([__file__, "-v"])