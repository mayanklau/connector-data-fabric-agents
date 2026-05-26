# Product Requirements Document: Agentic SOC Data Fabric Orchestrator

## 1. Executive Summary

Build a production-grade Agentic SOC Orchestration Layer that sits on top of the Security Data Fabric and lets security agents perform detection enrichment, triage, investigation, correlation, threat intelligence enrichment, response recommendation, case creation, and audit logging without requiring SIEM to be the mandatory orchestration layer.

Current state:

```text
Security Data Fabric -> SIEM -> Agents -> Analyst / SOAR
```

Target state:

```text
Security Data Fabric -> Agentic SOC Orchestrator -> Agents -> Analyst / SOAR / SIEM
```

The SIEM remains a source of alerts, dashboarding layer, compliance evidence store, and writeback destination. It is no longer the only gateway between data and agents.

## 2. Problem Statement

The SIEM-centric operating model creates bottlenecks:

- Agents only see alerts and fields that SIEM receives or forwards.
- Alert triage lacks full context from EDR, IAM, cloud, asset inventory, vulnerabilities, and case history.
- Analysts pivot manually across tools.
- Correlation logic is duplicated across SIEM rules, SOAR playbooks, notebooks, and prompts.
- SOC work is entity-oriented, while SIEM alerts are usually event-oriented.
- Analyst feedback is not consistently fed back into detection and triage workflows.

## 3. Vision

Security agents should operate directly against normalized security context in the data fabric. They should produce evidence-backed conclusions, consistent triage, investigation timelines, recommended actions, and governed writebacks to SIEM, SOAR, ticketing, and case management systems.

## 4. Goals

- Reduce mean time to triage by at least 50%.
- Reduce false-positive analyst workload by at least 30%.
- Enrich at least 90% of onboarded alert types.
- Require evidence references for 100% of agent findings.
- Prevent high-risk actions from executing without approval.
- Preserve full audit trails of agent data access, decisions, recommendations, approvals, and analyst overrides.

## 5. Non-Goals

- Replace SIEM in the first release.
- Replace SOAR in the first release.
- Allow destructive or high-impact actions without human approval.
- Give agents unrestricted raw-log access.
- Depend on a single LLM provider.
- Build a new data lake from scratch.

## 6. Users

- Tier 1 SOC analyst: needs rapid triage and clear evidence.
- Tier 2 SOC analyst: needs timelines, entity correlation, and escalation context.
- Incident responder: needs blast-radius analysis and recommended containment.
- Detection engineer: needs feedback and tuning insights.
- SOC manager: needs operational metrics and quality reporting.
- Security architect: needs governance, integration, and control-plane clarity.
- Compliance team: needs auditability and evidence preservation.

## 7. MVP Scope

The MVP delivers autonomous alert enrichment and triage directly from the Security Data Fabric.

Included:

- Security Context API v1.
- Event ingestion and routing.
- Triage Agent.
- Investigation Agent lite.
- Threat Intelligence Agent.
- Correlation Agent.
- Response Recommendation Agent.
- Case and evidence model.
- Approval generation for risky actions.
- Analyst feedback model.
- Audit log.
- SIEM writeback-ready output model.
- OpenAPI documentation.

Initial use cases:

- Impossible travel.
- Suspicious PowerShell or script execution.
- Known malicious IP communication.
- Privileged login from a new device.
- Multiple failed logins followed by success.
- Cloud IAM privilege escalation.
- Endpoint isolation recommendation.

## 8. Functional Requirements

### Event Ingestion

The system shall accept alerts and events from SIEM, data fabric streams, EDR, IAM, cloud logs, and analyst-created investigations.

Acceptance criteria:

- Every event has a unique ID.
- Every event preserves source metadata.
- Events can include normalized entities.
- Events can trigger an agent workflow.
- Events are saved to the data fabric adapter.

### Security Context API

The system shall expose governed context functions: entity context, entity timeline, related alerts, threat intelligence, similar cases, risk score drivers, and evidence references. Agents must use these APIs instead of arbitrary raw queries.

### Agent Orchestration

The orchestrator shall receive events, select agents, pass scoped context, execute policies, create cases, generate approvals, write audit records, and return a complete orchestration result.

### Agents

- Triage Agent: scores disposition, severity, confidence, evidence, and next steps.
- Investigation Agent: builds timelines, finds similar cases, and attaches evidence.
- Threat Intelligence Agent: enriches indicators and preserves reputation evidence.
- Correlation Agent: links related alerts across normalized entities.
- Response Recommendation Agent: proposes SOAR-ready actions with risk levels.

### Approval Workflow

Approval is required for session revocation, user disablement, endpoint isolation, process termination, global blocking, credential reset, firewall or detection rule changes, and any destructive action.

### Feedback And Audit

Analysts can mark decisions as correct, incorrect, missing evidence, wrong severity, duplicate, false positive, or escalation needed. The system logs event receipt, agent runs, case creation, approval requests, workflow completion, and feedback.

## 9. Non-Functional Requirements

- Availability: 99.9% orchestration service availability in production.
- Performance: simple triage under 60 seconds; standard enrichment under 2 minutes; deep investigation under 10 minutes.
- Scalability: 100,000+ events/day; 10,000+ alerts/day; 1,000+ agent workflows/hour; 100+ concurrent analysts.
- Security: RBAC, ABAC, least privilege, encryption, secrets management, field-level masking, full audit logging.
- Reliability: idempotent workflows, retries, dead-letter queues, circuit breakers, workflow resume, model fallback.
- Explainability: every decision includes summary, evidence, confidence, rationale, data sources, next steps, and uncertainty where relevant. Hidden chain-of-thought is not exposed.

## 10. Data Model

Core objects: AlertEvent, EntityRef, ContextBundle, Evidence, AgentDecision, RecommendedAction, Case, Approval, Feedback, and AuditRecord.

## 11. API Requirements

Required endpoints:

- `GET /health`
- `POST /events`
- `POST /context/entity`
- `POST /timeline`
- `GET /cases`
- `GET /cases/{case_id}`
- `GET /approvals`
- `POST /feedback`
- `GET /audit`

## 12. Governance

Governance must cover agent permissions, data access, tool access, prompt and model versioning, approval policy, audit evidence, analyst override tracking, evaluation, and regression testing.

## 13. Success Metrics

Operational: MTTA reduction 50%, false-positive workload reduction 30%, triage adoption 80%, escalation accuracy 85%+, analyst override under 20% after tuning.

Technical: triage success 99%, cached context API p95 under 2 seconds, triage workflow p95 under 2 minutes, failed agent runs under 1%, audit completeness 100%.

Quality: evidence-backed conclusions 100%, unsupported critical claims zero, hallucinated source references zero, high-risk action without approval zero.

## 14. Release Plan

Phase 0: discovery, source inventory, SOC workflow mapping, SIEM/SOAR assessment, policy model, security architecture, success baseline.

Phase 1: MVP pilot with Context API v1, event router, Triage Agent, case store, audit logs, and dashboard-ready metrics.

Phase 2: investigation and correlation with timelines, similar incident search, and entity risk scoring.

Phase 3: response recommendation with SOAR integration, approval workflow, and action simulation.

Phase 4: SOC-wide production with enterprise scale, multi-team workflows, detection engineering feedback, advanced reporting, model evaluation, and full governance.

## 15. Production Acceptance Criteria

The product is production-ready when agents can triage selected alerts directly from the data fabric; SIEM is not required as the orchestration path; every decision includes evidence; all data access is logged; analysts can approve, reject, or correct findings; SIEM and case management receive writebacks; high-risk actions require approval; dashboards show agent performance and SOC impact; security, reliability, and MVP accuracy thresholds pass.
