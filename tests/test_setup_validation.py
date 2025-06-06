"""
Simple validation test to ensure testing infrastructure is working.
This file can be removed once real tests are written.
"""

import pytest
import sys
import os

# Add the kubestriker package to the path for testing
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

def test_python_version():
    """Test that we're running on a supported Python version."""
    assert sys.version_info >= (3, 8), "Python 3.8+ is required"


def test_pytest_working():
    """Simple test to verify pytest is working."""
    assert True


def test_import_kubestriker():
    """Test that we can import the kubestriker package."""
    try:
        import kubestriker
        assert True
    except ImportError:
        pytest.fail("Could not import kubestriker package")


@pytest.mark.unit
def test_unit_marker():
    """Test that unit test marker works."""
    assert True


@pytest.mark.integration
def test_integration_marker():
    """Test that integration test marker works."""
    assert True


@pytest.mark.slow
def test_slow_marker():
    """Test that slow test marker works."""
    assert True


def test_mock_fixture_available(mock_requests_response):
    """Test that pytest-mock and custom fixtures are available."""
    assert mock_requests_response.status_code == 200


def test_temp_dir_fixture(temp_dir):
    """Test that temp_dir fixture works."""
    assert os.path.exists(temp_dir)
    assert os.path.isdir(temp_dir)