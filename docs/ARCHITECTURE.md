# Architecture

## Target State

```text
Security Data Sources
  SIEM | EDR/XDR | IAM | Cloud | Network | Email | TI | CMDB | Vulnerability
        |
        v
Security Data Fabric
  Normalization | Entity Resolution | Knowledge Graph | Indexing | Streaming
        |
        v
Security Context API
  Entity Context | Timeline | Risk | Similar Cases | Threat Intel | Evidence
        |
        v
Agentic SOC Orchestrator
  Routing | Agent Selection | Policy | Tool Control | Audit | Case State
        |
        v
Agents
  Triage | Investigation | Threat Intel | Correlation | Response Recommendation
        |
        v
Analyst UI | Case Store | SIEM Writeback | SOAR Approval | Reporting
```

## Key Decisions

1. Agents do not query raw logs directly. They use the Security Context API.
2. SIEM remains a signal source and writeback target, not the mandatory orchestrator.
3. Every agent decision must include evidence references.
4. High-impact actions are recommendation-only until approved.
5. Agent runs, tool calls, data access, decisions, approvals, and analyst feedback are audited.

## Production Component Mapping

| Reference Component | Production Replacement |
| --- | --- |
| `InMemorySecurityDataFabric` | Enterprise data fabric, lakehouse, SIEM search, graph store |
| `CaseStore` | Postgres or enterprise case system |
| `AuditLog` | Immutable audit log, SIEM, or compliance ledger |
| FastAPI service | Kubernetes service behind API gateway |
| Pydantic models | Contract-first OpenAPI schemas |
| Policy engine | RBAC/ABAC and approval policy service |

## Action Risk Levels

| Level | Meaning | Approval |
| --- | --- | --- |
| 0 | Read-only | Automatic |
| 1 | Case write | Automatic |
| 2 | Enrichment | Automatic |
| 3 | Reversible response | Policy approval |
| 4 | High-impact containment | Mandatory human approval |
| 5 | Destructive | Mandatory human approval |

## Production Hardening Checklist

- Replace in-memory adapter with authenticated data fabric adapters.
- Add RBAC/ABAC on every API route and context function.
- Add field-level masking for sensitive identity and HR data.
- Add durable workflow execution with retries and dead-letter queues.
- Add model gateway with provider abstraction and prompt versioning.
- Add prompt-injection filtering for log-derived content.
- Add immutable evidence preservation with object-store hashes.
- Add SIEM, SOAR, ticketing, and case-management connectors.
- Add dashboards for agent accuracy, latency, override rate, and false positives.
