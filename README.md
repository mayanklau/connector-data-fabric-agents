# Agentic SOC Data Fabric Orchestrator

Production reference build for an Agentic SOC orchestration layer that lets security agents work directly against a governed Security Data Fabric instead of depending on SIEM as the orchestration path.

## What This Builds

```text
Security Data Fabric -> Security Context API -> Agentic SOC Orchestrator
                                             -> Triage / Investigation / TI / Response Agents
                                             -> Cases / Evidence / SIEM Writeback / SOAR Approval
```

The SIEM remains supported as an alert source and writeback target, but agents interact with the data fabric through governed APIs.

## Included

- Production PRD: `docs/PRD.md`
- Architecture and operating model: `docs/ARCHITECTURE.md`
- FastAPI service with OpenAPI docs
- Security Context API
- Event ingestion and routing
- Triage, investigation, threat intel, correlation, and response recommendation agents
- Case, evidence, approval, feedback, and audit models
- In-memory reference data fabric for local development
- Policy guardrails for action risk levels
- Dockerfile and docker-compose
- Unit tests for workflows and guardrails

## Quick Start

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
uvicorn agentic_soc.main:app --reload
```

Then open `http://127.0.0.1:8000/docs`.

Run tests:

```bash
pytest
```

Run with Docker:

```bash
docker compose up --build
```

## Example

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

The service returns the event, generated case, agent decisions, evidence, recommended actions, approval requests, and audit-ready metadata.
