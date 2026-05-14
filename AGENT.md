# Agent Guide: goidc-proxy

This guide provides a comprehensive overview of the `goidc-proxy` project for AI agents and developers.

## Project Overview

`goidc-proxy` is a lightweight OIDC-aware reverse proxy written in Go. It acts as an authentication layer in front of upstream services, ensuring all requests are authenticated via an OpenID Connect provider.

### Core Capabilities
- **OIDC Authentication**: Implements Authorization Code Grant flow.
- **Reverse Proxy**: Dynamic routing based on path prefixes with optional prefix stripping.
- **Session Management**: Cookie-based sessions with in-memory storage (Redis support planned).
- **Identity Propagation**: Passes OIDC tokens to upstream services via fixed headers.
- **Discovery**: Automatic metadata loading from OIDC `.well-known` endpoints.

## Architecture

### Package Structure
- `cmd/`: CLI implementation using Cobra.
- `config/`: Configuration loading (YAML + Env) and metadata discovery.
- `oidc/`: 
    - `http_server.go`: Main server logic and route registration.
    - `proxy.go`: `httputil.ReverseProxy` implementation with identity propagation.
    - `http_server_handlers.go`: OIDC callback and userinfo handlers.
    - `http_server_helpers.go`: OAuth exchange logic and redirection helpers.
- `session/`:
    - `manager.go`: Orchestrates session lifecycle and context injection.
    - `cookie.go`: Secure cookie handling.
    - `memory.go`: Thread-safe in-memory session store.
- `types/`: Shared OIDC and Metadata structures.

### Authentication Flow
1. Incoming request matches a route with `authRequired: true`.
2. `GetSessionWrapperHandler` checks for a valid session cookie.
3. If no session:
    - User is redirected to the OIDC Authorization Endpoint.
    - Original request path is saved in a temporary session.
4. After IdP authentication:
    - User redirected to `/oidc/authorization-code/callback`.
    - Proxy exchanges `code` for tokens (`access_token`, `id_token`).
    - Session is upgraded with tokens and appropriate expiry.
    - User redirected back to the original request path.
5. If session exists:
    - Session object is injected into the request context.
    - Request is forwarded to the Reverse Proxy.

### Identity Propagation (to Upstream)
When a request is proxied, the following headers are injected based on the `propagationPolicy` (configured in `oidc.propagationPolicy`):

#### Default Policy (`default`)
- `X-Auth-Access-Token`: The OIDC access token.
- `X-Auth-Id-Token`: The OIDC ID token (if available).

#### AWS ALB Compatible Policy (`aws`)
Simulates AWS Application Load Balancer (ALB) OIDC authentication headers:
- `x-amzn-oidc-accesstoken`: The OIDC access token.
- `x-amzn-oidc-identity`: The `sub` claim extracted from the ID token.
- `x-amzn-oidc-data`: The ID token (simulating user claims JWT).

Standard `X-Forwarded-*` headers are injected in all modes via `r.SetXForwarded()`.

## Known Gaps & Roadmap

### Incomplete Features
- **Redis Store**: Configurable but not yet implemented in `session/manager.go`.
- **Client Credentials Grant**: Planned but not implemented.
- **Refresh Tokens**: Token refresh logic is missing; sessions currently expire with the access token.
- **ALB JWT Signing**: In `aws` mode, the ID token is passed as `x-amzn-oidc-data` instead of a proxy-signed JWT.
- **Request Restoration**: The callback handler redirects to the original path but does not currently restore POST bodies or complex query parameters (see TODO in `authCodeCallbackHandler`).

### Security Considerations
- **TLS Termination**: The proxy does not handle TLS. It MUST be deployed behind a load balancer that terminates TLS.
- **State Integrity**: While a `state` parameter is used, more rigorous validation against the session store could be added.
- **Config Exposure**: The `/oidc/info` endpoint (if enabled) currently dumps the entire configuration, which may include sensitive data if not properly overridden by environment variables.

## Development Workflows

- **Build**: `make build`
- **Test**: `make test`
- **Lint**: `make lint`
- **Run**: `./goidc-proxy --config resources/proxy.yml --log-level debug`
