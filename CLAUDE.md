# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Development Commands

### Python Development (Horizon FastAPI Service)
```bash
# Install development dependencies
pip install ".[dev]"

# Run locally for development (requires API key)
PDP_API_KEY=<YOUR_API_KEY> uvicorn horizon.main:app --reload --port=7000

# Run against custom control plane
PDP_CONTROL_PLANE=https://api.permit.io PDP_API_KEY=<YOUR_API_KEY> uvicorn horizon.main:app --reload --port=7000

# Lint Python code
ruff check horizon/
ruff format horizon/

# Type checking
mypy horizon/

# Run Python tests
pytest horizon/tests/
```

### Rust Development (PDP Server)
```bash
# Build Rust components
cd pdp-server && cargo build

# Run Rust tests
cd pdp-server && cargo test

# Build watchdog
cd watchdog && cargo build && cargo test
```

### Docker Development
```bash
# Build custom Docker image (requires VERSION env var)
VERSION=dev make build-amd64  # For AMD64
VERSION=dev make build-arm64  # For ARM64

# Run Docker image locally (requires API_KEY env var)
VERSION=dev API_KEY=<YOUR_API_KEY> make run
```

## Architecture Overview

The PDP (Policy Decision Point) is a hybrid Rust/Python microservice with three main components:

### Core Components
1. **Rust API Server** (`/pdp-server`) - Port 7000
   - High-performance HTTP API using Axum
   - Handles `/allowed`, `/allowed/bulk`, `/user-permissions`, `/authorized_users` endpoints
   - Optional decision caching (memory/Redis)
   - Proxies to Horizon for endpoints not yet ported

2. **Horizon Python Service** (`/horizon`) - Port 7001
   - FastAPI application
   - OPAL client for real-time policy/data synchronization
   - Legacy endpoints and admin/debug routes
   - Main entry point: `horizon/main.py` → `horizon/pdp.py`

3. **Watchdog Supervisor** (`/watchdog`)
   - Process supervisor in Rust
   - Health checking and automatic restart of components
   - Ensures system resilience

### Key Architectural Patterns
- **OPAL Integration**: Real-time policy and data sync via WebSocket to Permit control plane
- **OPA Embedding**: Local Open Policy Agent instance (port 8181) with ReBAC plugin
- **Cache Layer**: Optional memory or Redis caching for decision results
- **Fallback Pattern**: Rust server transparently proxies to Horizon for unported endpoints

### Module Organization
- `horizon/facts/` - Fact-related functionality and OPAL client
- `horizon/enforcer/` - Policy enforcement logic
- `horizon/startup/` - Application initialization
- `horizon/system/` - System-level functionality  
- `horizon/proxy/` - API proxying utilities
- `horizon/local/` - Local caching implementation

### Request Flow
1. Client → Rust API (port 7000)
2. Cache check (if enabled)
3. OPA evaluation (local HTTP to port 8181)
4. Response (typically <10ms)
5. Background: OPAL client keeps OPA data fresh

## Configuration
Key environment variables:
- `PDP_API_KEY` - Required Permit environment API key
- `PDP_CONTROL_PLANE` - Permit API endpoint (default: https://api.permit.io)
- `PDP_CACHE_STORE` - Cache backend: none/memory/redis
- `PDP_DEBUG` - Enable debug logging
- `OPAL_INLINE_OPA_ENABLED=true` - Use embedded OPA process

## OAuth 2.0 Authorization Server

The PDP includes a complete OAuth 2.0 Authorization Server that integrates with Permit.io's Fine-Grained Authorization system:

### OAuth 2.0 Endpoints
- `GET /authorize` - Authorization endpoint for user authentication (RFC 6749 Section 4.1.1)
- `POST /oauth/authenticate` - User authentication handler (internal)
- `POST /token` - Token endpoint supporting both Authorization Code and Client Credentials flows
- `POST /introspect` - Token Introspection with real-time authorization checks (RFC 7662)

### Supported OAuth 2.0 Flows

#### 1. Authorization Code Flow (RFC 6749 Section 4.1)
For user authentication and API protection:
```bash
# 1. Direct user to authorization endpoint
https://pdp.example.com/authorize?response_type=code&client_id=myapp&redirect_uri=https://myapp.com/callback&scope=documents:read+cars:write&state=xyz123

# 2. User authenticates via built-in login form
# 3. User gets redirected back with authorization code
# 4. Exchange code for token
curl -X POST http://localhost:7766/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code&client_id=myapp&client_secret=secret&code=AUTH_CODE&redirect_uri=https://myapp.com/callback"
```

#### 2. Client Credentials Flow (RFC 6749 Section 4.4)
For service-to-service authentication:
```bash
curl -X POST http://localhost:7766/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=service_account_123&client_secret=secret"
```

### OAuth Configuration
Key environment variables:
- `PDP_OAUTH_ENABLED` - Enable/disable OAuth endpoints (default: true)
- `PDP_OAUTH_TOKEN_TTL` - Token TTL in seconds (default: 3600)
- `PDP_OAUTH_PERMIT_API_URL` - Permit API URL (default: https://api.permit.io)
- `PDP_OAUTH_RESOURCE_TYPES` - Resource types for scope generation (default: documents,cars)
- `PDP_OAUTH_ISSUER` - OAuth issuer identifier (default: permit-pdp)

### Data Model Integration
- **OAuth clients**: Any Permit user (for Authorization Code flow) or users with `client_type: service_account` (for Client Credentials)
- **User authentication**: Simple form-based auth (demo) - can be extended to integrate with external IdPs
- **OAuth scopes**: Follow `resource:action` format (e.g., `documents:read`, `cars:write`)
- **Token structure**: Contains user identity for real-time authorization checks
- **Real-time authorization**: Token introspection performs live permission checks using user identity from token

### API Protection Pattern

#### Simple Authorization Check
```bash
# Form-encoded request (OAuth 2.0 standard)
curl -X POST http://localhost:7766/introspect \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "token=ACCESS_TOKEN&resource=documents:doc_123&action=read"
```

#### Advanced Authorization with JSON Context
```bash
# JSON request with additional context for complex authorization
curl -X POST http://localhost:7766/introspect \
  -H "Content-Type: application/json" \
  -d '{
    "token": "ACCESS_TOKEN",
    "resource": "documents:doc_123", 
    "action": "read",
    "context": {
      "department": "engineering",
      "classification": "confidential",
      "time_of_day": "business_hours"
    }
  }'

# Response includes both token validity and real-time authorization result:
{
  "active": true,
  "client_id": "myapp", 
  "scope": "documents:read documents:write",
  "exp": 1234567890,
  "allowed": true  // Real-time permission check with context
}
```

### PKCE Support
Authorization Code flow supports PKCE (RFC 7636) for enhanced security:
```bash
# Include PKCE parameters in authorization request
https://pdp.example.com/authorize?response_type=code&client_id=myapp&redirect_uri=https://myapp.com/callback&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256

# Include code_verifier in token exchange
curl -X POST http://localhost:7766/token \
  -d "grant_type=authorization_code&client_id=myapp&code=AUTH_CODE&redirect_uri=https://myapp.com/callback&code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
```

## Testing
- Python tests: `pytest horizon/tests/`
- Rust tests: `cargo test` (in respective directories)
- Integration testing with offline mode in `/test_offline_mode/`
- OAuth endpoints available at `/scalar` for API documentation