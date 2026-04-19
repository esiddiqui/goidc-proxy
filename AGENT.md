# Agent Guide: goidc-proxy

This guide is intended for AI agents and developers working on the `goidc-proxy` codebase. It provides a high-level overview of the project's architecture, key components, and development workflows.

## Project Overview

`goidc-proxy` is a lightweight OIDC-aware reverse proxy written in Go. It sits in front of upstream applications and ensures that incoming requests are authenticated via an OpenID Connect provider (like Google, Okta, Keycloak, etc.) before they are forwarded.

### Key Features
- **OIDC Authentication**: Implements the OIDC Authorization Code Grant flow.
- **Reverse Proxy**: Forwards requests to one or more upstream services based on path prefixes.
- **Session Management**: Manages user sessions using cookies, with support for in-memory and Redis (upcoming) storage.
- **User Information**: Exposes a `/userinfo` endpoint that provides user identity data from the OIDC provider.
- **Configurable**: Driven by a YAML configuration file with environment variable overrides for sensitive data.

## Architecture

The application is structured into several key packages:

- `cmd/`: Contains the CLI entry point using the [Cobra](https://github.com/spf13/cobra) library.
- `config/`: Handles configuration loading from `proxy.yml` and environment variables.
- `oidc/`: The core package containing the OIDC client logic, HTTP server, and reverse proxy implementation.
  - `http_server.go`: Orchestrates the HTTP server, routing, and middleware.
  - `proxy.go`: Implements the reverse proxy logic.
  - `funcs.go`: Helper functions for OIDC flow (e.g., token exchange).
- `session/`: Provides session management abstractions.
  - `manager.go`: Orchestrates session creation, retrieval, and validation.
  - `cookie.go`: Handles cookie-based session tracking.
- `types/`: Defines shared data structures used across the project.

## Technology Stack

- **Language**: Go (1.21+)
- **CLI**: [spf13/cobra](https://github.com/spf13/cobra)
- **Logging**: [sirupsen/logrus](https://github.com/sirupsen/logrus)
- **OIDC/JWT**: [lestrrat-go/jwx](https://github.com/lestrrat-go/jwx)
- **YAML**: [gopkg.in/yaml.v2](https://gopkg.in/yaml.v2)

## Development Workflow

### Building the Project

Use the provided `Makefile` to build the binary:

```bash
make build
```

### Running Tests

```bash
make test
```

### Linting

```bash
make lint
```

### Running the Proxy

The proxy requires a configuration file (default: `./resources/proxy.yml`).

```bash
./goidc-proxy --config path/to/your/proxy.yml
```

You can also set the log level:

```bash
./goidc-proxy --log-level debug
```

## Key Configuration

The proxy is primarily configured via `proxy.yml`. Sensitive information like `clientID` and `clientSecret` should be provided via environment variables:

- `GOIDC_CLIENT_ID`
- `GOIDC_CLIENT_SECRET`

## Common Tasks for Agents

- **Adding a new route**: Update the `routes` section in `proxy.yml`. If the route requires authentication, set `authRequired: true`.
- **Modifying OIDC flow**: Look into `oidc/funcs.go` and `oidc/http_server_handlers.go`.
- **Updating session logic**: Check `session/manager.go`.
- **Adding new CLI flags**: Modify `cmd/root.go`.
