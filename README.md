# Fayda MCP Bridge

A high-assurance identity bridge connecting Ethiopian National ID (Fayda eSignet) with AI agents over the Model Context Protocol (MCP).

## Overview

- **Stack**: Python 3.12+, FastAPI, standalone FastMCP, Neon PostgreSQL, Redis, Fayda eSignet OIDC.
- **Protocol**: Streamable HTTP MCP exposed at `/mcp`.
- **Security Boundaries**: Agents call standardized verification tools with OAuth-scoped tokens. Citizens authenticate and consent directly via Fayda eSignet. Private keys and citizen raw identifiers are strictly isolated from agents.

## Quickstart

### Prerequisites
- Python 3.12+ and `uv`
- Docker and Docker Compose (for local Redis & containerization)

### Local Development

1. Setup environment:
```bash
cp .env.example .env
```

2. Start local Redis:
```bash
docker compose up -d redis
```

3. Install dependencies and run the server:
```bash
uv sync
uvicorn app.main:app --reload --port 8000
```

4. Verify endpoints:
- Liveness: `GET http://localhost:8000/health/live`
- Readiness: `GET http://localhost:8000/health/ready`
- MCP Streamable endpoint: `http://localhost:8000/mcp`
- OAuth Resource Metadata: `GET http://localhost:8000/.well-known/oauth-protected-resource`

### Docker Compose

Run the complete local stack:
```bash
docker compose up --build
```
