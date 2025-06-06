# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Kubestriker is a Kubernetes security auditing tool designed to identify misconfigurations and security vulnerabilities in Kubernetes clusters across multiple platforms (self-hosted, EKS, AKS, GKE). It provides both CLI and web application interfaces for comprehensive security scanning.

## Core Architecture

The tool is structured around several key components:

- **Service Discovery** (`service_discovery.py`): Port scanning and service identification for Kubernetes endpoints (API server, kubelet, etcd, etc.)
- **Service Hunt** (`service_hunt.py`): Core security scanning logic that performs authenticated/unauthenticated scans against discovered services
- **API Modules**: Separate modules for different Kubernetes API versions (core_v1api, apps_v1api, rbac_authorization_v1api, etc.)
- **Specialized Scanners**: Dedicated modules for kubelet (RO/RW), PSP validation, container privilege scanning
- **Command Execution** (`cmd_exec.py`): Remote command execution capabilities on discovered containers

### Scanning Workflow

1. **Input Validation** (`validate_input.py`): Processes target input (single host, IP range/CIDR, or kubeconfig)
2. **Service Discovery**: Scans for common Kubernetes services (ports 6443, 8080, 10250, 10255, etc.)
3. **Security Analysis**: Based on discovered services, performs specific security checks:
   - API server insecure/secure endpoint analysis
   - RBAC misconfigurations
   - Pod Security Policy violations
   - Container privilege escalations
   - Network policy misconfigurations
4. **Interactive Command Execution**: Allows remote command execution on accessible containers
5. **Report Generation**: Creates detailed security reports with findings

## Development Commands

### Installation and Setup
```bash
# Install dependencies
pip install -r requirements.txt

# Install package in development mode
pip install -e .
```

### Running the Tool
```bash
# CLI version
python -m kubestriker

# Direct execution
python kubestriker/__main__.py
```

### Web Application Deployment
```bash
# Deploy to Kubernetes cluster
kubectl apply -f webapp/kubestriker_webapp.yaml
```

## Key Dependencies

- **kubernetes client libraries**: For API interactions
- **requests**: HTTP/HTTPS communications with Kubernetes endpoints
- **websocket-client**: For kubectl exec-like functionality
- **pyyaml**: Kubernetes configuration parsing
- **selectmenu**: Interactive CLI menu system
- **colored/colorama**: Terminal output formatting

## Security Considerations

- Uses bearer token authentication for Kubernetes API access
- Supports both authenticated and unauthenticated scanning modes
- Implements SSL verification controls for different environments
- JWT token decoding for namespace extraction and authorization context