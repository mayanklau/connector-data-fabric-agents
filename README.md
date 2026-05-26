# Agentic SOC Data Fabric Orchestrator

Reference implementation for an Agentic SOC orchestration layer that lets agents work directly against a governed Security Data Fabric. SIEM remains supported as a signal source and writeback target, but it is no longer the mandatory orchestration layer.

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
Durable Event Bus -> Agentic SOC Orchestrator
        |              |
        |              +--> Triage Agent
        |              +--> Investigation Agent
        |              +--> Threat Intel Agent
        |              +--> Correlation Agent
        |              +--> Response Recommendation Agent
        v
Cases | Evidence | Approvals | SIEM Writeback | SOAR Package | Audit | Metrics
```

## What Is Coded

- Durable SQLite persistence for events, cases, approvals, feedback, audit records, writebacks, workflow runs, prompt templates, and telemetry spans.
- API-key authentication and authorization on every route.
- Per-agent data access scopes enforced by the policy engine.
- Field-level masking for sensitive user and identity context.
- Security Data Fabric reference adapter.
- EDR, IAM, cloud, CMDB, vulnerability, and threat intelligence adapter boundaries.
- Security Context API for entity context and timeline retrieval.
- Durable event bus with idempotency keys, async background processing, retry state, dead-letter status, and workflow resume.
- Triage, Investigation, Threat Intelligence, Correlation, and Response Recommendation agents.
- SIEM writeback client boundary behind a writeback queue.
- SOAR investigation package client boundary behind a writeback queue.
- Prompt-injection sanitization for log-derived text.
- Model gateway and prompt registry for future LLM-backed agents.
- OpenTelemetry instrumentation, local telemetry spans, and structured JSON request/audit logs.
- Dashboard endpoint for MTTA, false positive rate, analyst override rate, and escalation accuracy.
- Docker and docker-compose support.
- Unit tests.
- Production PRD and architecture docs.

## Local API Keys

```text
admin:   dev-admin-key
analyst: dev-analyst-key
agent:   dev-agent-key
```

Every route requires `X-API-Key`. User and identity context is masked unless the caller has `sensitive:read`.

## Quick Start

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -e ".[dev]"
uvicorn agentic_soc.main:app --reload
```

Open:

```text
http://127.0.0.1:8000/docs
```

Run checks:

```bash
pytest
ruff check .
```

Run with Docker:

```bash
docker compose up --build
```

## Main Endpoints

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/health` | Authenticated health check |
| `POST` | `/events` | Enqueue durable async workflow |
| `POST` | `/events/sync` | Run workflow immediately |
| `GET` | `/workflows` | List workflow runs |
| `POST` | `/workflows/{workflow_id}/resume` | Resume queued, failed, or dead-lettered workflow |
| `POST` | `/context/entity` | Get governed entity context with field masking |
| `POST` | `/timeline` | Get entity timeline evidence |
| `GET` | `/cases` | List generated cases |
| `GET` | `/cases/{case_id}` | Get one case |
| `GET` | `/approvals` | List approval requests |
| `POST` | `/approvals/{approval_id}/decision` | Approve or reject an action |
| `POST` | `/feedback` | Submit analyst feedback |
| `GET` | `/audit` | List audit records |
| `GET` | `/connectors` | Show configured connector modes |
| `GET` | `/writebacks` | Show queued SIEM/SOAR writebacks |
| `GET` | `/metrics` | Show operational metrics |
| `GET` | `/dashboard` | Show SOC dashboard metrics |
| `GET` | `/telemetry/spans` | Show local telemetry spans |
| `GET` | `/prompts` | List prompt templates |
| `POST` | `/model/complete` | Invoke model gateway |

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

## Production Replacement Map

| Reference Piece | Production Replacement |
| --- | --- |
| SQLite repository | Managed PostgreSQL, cloud SQL, or enterprise case store |
| Stub SIEM client | Splunk, Sentinel, QRadar, Chronicle, Elastic, or internal SIEM API |
| Stub SOAR client | Cortex XSOAR, Splunk SOAR, Tines, Torq, ServiceNow SecOps, or internal SOAR |
| Stub EDR/IAM/cloud/CMDB/vuln/TI adapters | Real enterprise connector clients |
| API-key auth | Enterprise IdP, OAuth2, mTLS, or workload identity |
| Simple policy threshold | RBAC/ABAC policy service with per-action approval rules |
| Local structured logs | Central log platform and SIEM ingestion |
| Local telemetry spans | OpenTelemetry collector and tracing backend |

## Workflow Behavior

1. The request is authenticated and authorized.
2. Prompt-injection patterns in event text are sanitized.
3. The event is durably saved into SQLite.
4. The workflow is enqueued with an idempotency key.
5. The event router writes an audit record.
6. Triage, Threat Intelligence, and Correlation agents run with policy-scoped access.
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
