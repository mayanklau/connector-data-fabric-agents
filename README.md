# Agentic SOC Data Fabric Orchestrator

Reference implementation for an Agentic SOC orchestration layer that lets agents work directly against a governed Security Data Fabric. SIEM is still supported, but it is a source and writeback target instead of the mandatory orchestration layer.

## Current Build Status

The full coded MVP/reference implementation is in draft PR [#1](https://github.com/mayanklau/connector-data-fabric-agents/pull/1). This homepage README describes the target repository experience and the implementation included in that PR.

The build provides the contracts, workflows, guardrails, endpoints, seeded data, and integration stubs needed to replace in-memory adapters with production connectors.

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
Agentic SOC Orchestrator
        |
        +--> Triage Agent
        +--> Investigation Agent
        +--> Threat Intel Agent
        +--> Correlation Agent
        +--> Response Recommendation Agent
        |
        v
Cases | Evidence | Approvals | SIEM Writeback | SOAR Package | Audit | Metrics
```

## What Is Coded In The MVP

- FastAPI service with OpenAPI docs.
- Security Data Fabric reference adapter.
- Security Context API for entity context and timeline retrieval.
- Event ingestion and workflow orchestration.
- Triage Agent for disposition, severity, confidence, evidence, and recommendations.
- Investigation Agent for timelines and similar case context.
- Threat Intelligence Agent for indicator reputation.
- Correlation Agent for related alert patterns.
- Response Recommendation Agent for SOAR-ready actions.
- Policy engine for action risk and approval requirements.
- Case, evidence, approval, feedback, writeback, audit, and metrics models.
- SIEM writeback queue stub.
- SOAR investigation package queue stub.
- Connector status endpoint.
- Approval decision endpoint.
- Metrics endpoint.
- Docker and docker-compose support.
- Unit tests.
- Production PRD and architecture docs.

## What Must Be Replaced For Production

| Reference Piece | Production Replacement |
| --- | --- |
| `InMemorySecurityDataFabric` | Enterprise data fabric, lakehouse, search, or graph API |
| Seeded entity context | Live IAM, EDR, cloud, network, CMDB, vuln, TI, and case data |
| SIEM writeback stub | Splunk, Sentinel, QRadar, Chronicle, Elastic, or internal SIEM API |
| SOAR package stub | Cortex XSOAR, Splunk SOAR, Tines, Torq, ServiceNow SecOps, or internal SOAR |
| In-memory `CaseStore` | Durable DB or enterprise case platform |
| In-memory `AuditLog` | Immutable audit store and SIEM audit sink |
| Simple policy threshold | RBAC/ABAC policy service with per-action approval rules |

## Quick Start After PR Merge

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
| `GET` | `/health` | Health check |
| `POST` | `/events` | Ingest event and run agent workflow |
| `POST` | `/context/entity` | Get governed entity context |
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

## Example: Triage An Impossible Travel Alert

```bash
curl -X POST http://127.0.0.1:8000/events \
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

The response includes the original event, generated case, agent decisions, evidence references, recommended response actions, and approval requests.

## Example: Approve A Response Action

```bash
curl -X POST http://127.0.0.1:8000/approvals/{approval_id}/decision \
  -H 'content-type: application/json' \
  -d '{
    "approved": true,
    "decided_by": "analyst-1",
    "notes": "Evidence reviewed and action approved."
  }'
```

## Example: Inspect Queued Writebacks

```bash
curl http://127.0.0.1:8000/writebacks
```

The reference build queues SIEM enrichment writebacks and SOAR investigation packages.

## Agent Workflow

When `/events` receives an alert:

1. The event is saved into the data fabric adapter.
2. The event router writes an audit record.
3. Triage, Threat Intelligence, and Correlation agents run.
4. High-risk or suspicious outputs trigger Investigation and Response Recommendation agents.
5. The policy engine applies approval requirements based on action risk.
6. A case is created with evidence and agent decisions.
7. Approval requests are created for risky actions.
8. SIEM writeback is queued.
9. SOAR package is queued when approvals exist.
10. Metrics and audit records are available through API endpoints.

## Production Hardening Checklist

- Replace in-memory stores with durable persistence.
- Add authentication and authorization to every route.
- Add per-agent data access scopes.
- Add field-level masking for sensitive data.
- Add real SIEM and SOAR clients behind the writeback queue.
- Add EDR, IAM, cloud, CMDB, vulnerability, and threat intel adapters.
- Add an event bus for asynchronous workflow execution.
- Add retry, dead-letter, idempotency, and workflow resume support.
- Add model gateway and prompt/version registry if LLM-backed agents are introduced.
- Add prompt-injection handling for log-derived text.
- Add OpenTelemetry traces and structured logs.
- Add dashboarding on MTTA, false positives, override rate, and escalation accuracy.
