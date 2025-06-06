#!/bin/bash

# Test script for kubestriker
# Provides convenient commands for running tests with different options

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Help function
show_help() {
    echo "Usage: $0 [OPTION]"
    echo "Run tests for kubestriker"
    echo ""
    echo "Options:"
    echo "  all           Run all tests with coverage (default)"
    echo "  unit          Run only unit tests"
    echo "  integration   Run only integration tests"
    echo "  fast          Run tests without slow tests"
    echo "  coverage      Run tests and generate coverage report"
    echo "  clean         Clean test artifacts and coverage files"
    echo "  help          Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 all        # Run all tests"
    echo "  $0 unit       # Run only unit tests"
    echo "  $0 fast       # Skip slow tests"
}

# Clean function
clean_artifacts() {
    echo -e "${YELLOW}Cleaning test artifacts...${NC}"
    rm -rf .pytest_cache/
    rm -rf htmlcov/
    rm -f .coverage
    rm -f coverage.xml
    echo -e "${GREEN}Clean complete.${NC}"
}

# Main test function
run_tests() {
    local test_type="$1"
    
    case "$test_type" in
        "unit")
            echo -e "${GREEN}Running unit tests...${NC}"
            poetry run pytest tests/unit/ -v -m "unit"
            ;;
        "integration")
            echo -e "${GREEN}Running integration tests...${NC}"
            poetry run pytest tests/integration/ -v -m "integration"
            ;;
        "fast")
            echo -e "${GREEN}Running fast tests (excluding slow tests)...${NC}"
            poetry run pytest -v -m "not slow"
            ;;
        "coverage")
            echo -e "${GREEN}Running tests with coverage report...${NC}"
            poetry run pytest --cov=kubestriker --cov-report=html --cov-report=term-missing
            echo -e "${YELLOW}Coverage report generated in htmlcov/index.html${NC}"
            ;;
        "all"|"")
            echo -e "${GREEN}Running all tests...${NC}"
            poetry run pytest -v
            ;;
        "clean")
            clean_artifacts
            exit 0
            ;;
        "help"|"-h"|"--help")
            show_help
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $test_type${NC}"
            show_help
            exit 1
            ;;
    esac
}

# Check if poetry is available
if ! command -v poetry &> /dev/null; then
    echo -e "${RED}Poetry is not installed. Please install Poetry first.${NC}"
    exit 1
fi

# Check if we're in the right directory
if [[ ! -f "pyproject.toml" ]]; then
    echo -e "${RED}pyproject.toml not found. Please run this script from the project root.${NC}"
    exit 1
fi

# Run the specified test type
run_tests "$1"