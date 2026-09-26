# Agentic SOC Data Fabric Orchestrator

Production-oriented Agentic SOC control plane that lets independently deployed agents work directly against a governed Security Data Fabric. Agents register through a versioned protocol and can execute over HTTP, gRPC, or MCP without changing orchestrator code. The default stack includes PostgreSQL, Redis Streams, distributed workers, a reference external agent, and an enterprise operator console.

## Demo In Two Commands

```bash
docker compose up --build -d
open http://127.0.0.1:8000
```

Sign in with `demo-admin-key`. The stack exposes the control plane on port `8000` and the reference external agent on port `8100`. PostgreSQL and Redis data survive restarts.

To stop the harness without deleting its database:

```bash
docker compose down
```

## Target Flow

```text
Security Data Sources
  SIEM | EDR/XDR | IAM | Cloud | Network | TI | CMDB | Vulnerability
        |
        v
Security Data Fabric
        |
        v
Security Context API
        |
        v
Redis Streams -> Distributed Workers -> Agentic SOC Orchestrator
        |              |
        |              +--> Agent Registry and Router
        |                    +--> HTTP Agent
        |                    +--> gRPC Agent
        |                    +--> MCP Agent
        |                    +--> Built-in Fallback Agents
        v
Cases | Evidence | Approvals | SIEM Writeback | SOAR Package | Audit | Metrics
```

## What Is Coded

- PostgreSQL persistence in Docker, with SQLite retained only as a zero-dependency local/test option.
- Agent registration, discovery, enablement, health, invocation, credential rotation, and capability-routing APIs.
- Agent Protocol `1.x` execution and callback schemas with major-version compatibility enforcement.
- HTTP, generic gRPC, and MCP JSON-RPC remote execution adapters.
- Dynamic hashed agent credentials and per-agent scopes with callback ownership enforcement.
- Timeouts, bounded concurrency, health probes, circuit breakers, durable invocation history, and built-in fallback routing.
- Redis Streams event bus and independently scalable worker service; durable local broker fallback for development.
- A responsive operator console for agents, routes, invocation latency, scenarios, cases, approvals, workflows, integrations, and writeback delivery.
- API-key authentication and authorization on every route.
- Per-agent data access scopes enforced by the policy engine.
- Field-level masking for sensitive user and identity context.
- Security Data Fabric reference adapter.
- Configurable REST clients for EDR, IAM, cloud, CMDB, vulnerability, and threat intelligence gateways.
- Security Context API for entity context and timeline retrieval.
- Durable event execution with idempotency keys, Redis consumer groups, retry state, dead-letter streams, and workflow resume.
- Triage, Investigation, Threat Intelligence, Correlation, and Response Recommendation agents.
- Configurable HTTP SIEM and SOAR clients behind a durable writeback queue.
- Prompt-injection sanitization for log-derived text.
- OpenAI-compatible model gateway, prompt registry, deterministic offline fallback, and prompt-injection controls.
- OpenTelemetry instrumentation, local telemetry spans, and structured JSON request/audit logs.
- Dashboard endpoint for MTTA, false positive rate, analyst override rate, and escalation accuracy.
- Agent SDK and runnable reference external triage agent.
- Docker Compose and Kubernetes HA deployment assets, Alembic migrations, backup job, and disaster-recovery runbook.
- Contract, compatibility, circuit-breaker, callback ownership, load, API, and orchestration tests.
- Production PRD and architecture docs.

## Demo API Keys

```text
admin:   demo-admin-key
analyst: demo-analyst-key
agent:   demo-agent-key
```

Every route requires `X-API-Key`. User and identity context is masked unless the caller has `sensitive:read`.

## Local Development

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -e ".[dev]"
uvicorn agentic_soc.main:app --reload --port 8000
# second terminal
uvicorn agentic_soc.reference_agent:app --reload --port 8100
```

Open:

```text
http://127.0.0.1:8000/docs
```

The non-Docker development defaults are `dev-admin-key`, `dev-analyst-key`, and `dev-agent-key`, and the database defaults to `sqlite:///agentic_soc.sqlite3`.

## Plug In An Existing Agent

An agent implements `POST /execute` using `AgentExecutionRequest` and returns `AgentExecutionResult`. Registering it returns a one-time callback credential:

```bash
curl -X POST http://127.0.0.1:8000/agents \
  -H 'x-api-key: dev-admin-key' \
  -H 'content-type: application/json' \
  -d '{
    "name": "my-triage-agent",
    "version": "1.0.0",
    "protocol_version": "1.0",
    "capabilities": ["triage"],
    "transport": "http",
    "endpoint": "http://127.0.0.1:8100/execute",
    "health_endpoint": "http://127.0.0.1:8100/health",
    "scopes": ["fabric:read", "cases:write"]
  }'
```

For Docker Compose, use `http://reference-agent:8100/execute` and `http://reference-agent:8100/health`. Select **Agent registry** in the console, register the endpoint, run its health probe, and route the `triage` capability to it. The next alert uses the external agent; failures open its circuit and fall back to the built-in implementation.

The SDK is available from `agentic_soc.sdk`:

```python
from agentic_soc.sdk import AgentApplication

agent = AgentApplication("my-agent", "1.0.0")

@agent.capability("triage")
def triage(request):
    return {"status": "completed", "decisions": [...]}

app = agent.app
```

Agent authentication supports bearer secrets, OAuth2 client credentials, and mTLS. In production, secret references must use `env://NAME` or `file:///run/secrets/name`; literal secrets are rejected.

## Connect Real SIEM And SOAR Endpoints

Copy the environment template and configure one or both delivery targets:

```bash
cp .env.example .env
docker compose up --build -d
```

```text
SIEM_WEBHOOK_URL=https://siem.example/api/agentic-soc/writeback
SIEM_API_TOKEN=replace-me
SOAR_WEBHOOK_URL=https://soar.example/api/investigations
SOAR_API_TOKEN=replace-me
```

`POST /writebacks/dispatch` sends queued payloads over HTTP with a bearer token. Successful responses are marked `delivered`; failures move through `retry` to `dead_lettered`. With no URL configured, the demo uses a local harness sink and marks delivery `harness_delivered` so the complete workflow remains demonstrable offline.

Run checks:

```bash
pytest
ruff check .
```

Run the sustained broker/API load profile with [k6](https://k6.io/):

```bash
k6 run tests/load/k6-agent-platform.js
```

Run with Docker:

```bash
docker compose up --build
```

## Main Endpoints

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/health` | Authenticated health check |
| `GET` | `/ready` | Container/database readiness probe |
| `POST` | `/events` | Enqueue durable async workflow |
| `POST` | `/events/sync` | Run workflow immediately |
| `GET` | `/workflows` | List workflow runs |
| `POST` | `/workflows/{workflow_id}/resume` | Resume queued, failed, or dead-lettered workflow |
| `POST` | `/context/entity` | Get governed entity context with field masking |
| `PUT` | `/context/entity` | Ingest or update live entity context |
| `POST` | `/timeline` | Get entity timeline evidence |
| `GET` | `/cases` | List generated cases |
| `GET` | `/cases/{case_id}` | Get one case |
| `GET` | `/approvals` | List approval requests |
| `POST` | `/approvals/{approval_id}/decision` | Approve or reject an action |
| `POST` | `/feedback` | Submit analyst feedback |
| `GET` | `/audit` | List audit records |
| `GET` | `/connectors` | Show configured connector modes |
| `GET` | `/writebacks` | Show queued SIEM/SOAR writebacks |
| `POST` | `/writebacks/dispatch` | Deliver pending SIEM/SOAR payloads |
| `GET` | `/harness/scenarios` | List runnable SOC demo scenarios |
| `POST` | `/harness/scenarios/{id}/run` | Execute and persist a scenario |
| `GET` | `/metrics` | Show operational metrics |
| `GET` | `/dashboard` | Show SOC dashboard metrics |
| `GET` | `/telemetry/spans` | Show local telemetry spans |
| `GET` | `/prompts` | List prompt templates |
| `POST` | `/model/complete` | Invoke model gateway |
| `POST` | `/agents` | Register an agent and issue a one-time credential |
| `GET` | `/agents` | Discover agents, optionally by capability |
| `PATCH` | `/agents/{id}` | Enable, disable, or reconfigure an agent |
| `POST` | `/agents/{id}/health` | Probe agent health |
| `POST` | `/agents/{id}/credentials` | Rotate agent callback credentials |
| `GET` | `/agent-routes` | Read capability routing |
| `PUT` | `/agent-routes/{capability}` | Configure capability routing |
| `GET` | `/agent-invocations` | Inspect execution and circuit outcomes |
| `POST` | `/agent-invocations/{id}/callback` | Submit an owned asynchronous result |

## Example: Durable Async Workflow

```bash
curl -X POST http://127.0.0.1:8000/events \
  -H 'x-api-key: dev-admin-key' \
  -H 'idempotency-key: alert-123' \
  -H 'content-type: application/json' \
  -d '{
    "source": "siem",
    "name": "Known Malicious IP",
    "category": "network_ioc",
    "severity": "high",
    "entities": [{"type": "ip", "id": "185.199.108.153"}]
  }'
```

Inspect or resume workflows:

```bash
curl -H 'x-api-key: dev-admin-key' http://127.0.0.1:8000/workflows
curl -X POST -H 'x-api-key: dev-admin-key' http://127.0.0.1:8000/workflows/{workflow_id}/resume
```

## Example: Synchronous Triage

```bash
curl -X POST http://127.0.0.1:8000/events/sync \
  -H 'x-api-key: dev-admin-key' \
  -H 'content-type: application/json' \
  -d '{
    "source": "siem",
    "name": "Impossible Travel",
    "category": "identity_anomaly",
    "severity": "medium",
    "entities": [
      {"type": "user", "id": "user:maya"},
      {"type": "ip", "id": "185.199.108.153"}
    ],
    "description": "Successful login from a new country shortly after normal login."
  }'
```

## Example: Approve A Response Action

```bash
curl -X POST http://127.0.0.1:8000/approvals/{approval_id}/decision \
  -H 'x-api-key: dev-admin-key' \
  -H 'content-type: application/json' \
  -d '{
    "approved": true,
    "decided_by": "analyst-1",
    "notes": "Evidence reviewed and action approved."
  }'
```

## Example: Masked Analyst Context

```bash
curl -X POST http://127.0.0.1:8000/context/entity \
  -H 'x-api-key: dev-analyst-key' \
  -H 'content-type: application/json' \
  -d '{"type": "user", "id": "user:maya"}'
```

The analyst key can read context, but sensitive user identity and business context are masked.

## Production Configuration Map

| Reference Piece | Production Replacement |
| --- | --- |
| Docker PostgreSQL | Managed PostgreSQL or enterprise case store |
| Generic SIEM HTTP client | Vendor-specific Splunk, Sentinel, QRadar, Chronicle, Elastic, or internal client |
| Generic SOAR HTTP client | Cortex XSOAR, Splunk SOAR, Tines, Torq, ServiceNow SecOps, or internal client |
| Generic EDR/IAM/cloud/CMDB/vuln/TI clients | Configure vendor gateway base URLs and tokens |
| Agent callback identity | Hashed credentials, OAuth2 client credentials, workload identity, or mTLS |
| Local broker fallback | Redis Streams with consumer groups and independent workers |
| Stub model mode | OpenAI-compatible model endpoint through `MODEL_BASE_URL` |
| Simple policy threshold | RBAC/ABAC policy service with per-action approval rules |
| Local structured logs | Central log platform and SIEM ingestion |
| Local telemetry spans | OpenTelemetry collector and tracing backend |

## Workflow Behavior

1. The request is authenticated and authorized.
2. Prompt-injection patterns in event text are sanitized.
3. The event is durably saved into PostgreSQL in the demo stack.
4. The workflow is enqueued with an idempotency key and published to Redis Streams.
5. The event router writes an audit record.
6. The registry routes each capability to a healthy external HTTP, gRPC, or MCP agent; built-ins are controlled fallbacks.
7. High-risk or suspicious outputs trigger Investigation and Response Recommendation agents.
8. The policy engine applies approval requirements based on action risk.
9. A case is created with evidence and agent decisions.
10. Approval requests are created for risky actions.
11. SIEM writeback is queued.
12. SOAR package is queued when approvals exist.
13. Metrics, dashboard data, audit records, and telemetry spans are available through API endpoints.

## Docs

- [Production PRD](docs/PRD.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Production operations and disaster recovery](docs/OPERATIONS.md)
- [Agent Protocol JSON Schema](schemas/agent-protocol-1.0.schema.json)
