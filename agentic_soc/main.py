from __future__ import annotations

import hashlib
import json
import logging
import re
import sqlite3
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from enum import Enum
from functools import lru_cache
from pathlib import Path
from typing import Any
from uuid import uuid4

from fastapi import BackgroundTasks, Depends, FastAPI, Header, HTTPException, Request
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict

try:
    from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
except Exception:  # pragma: no cover
    FastAPIInstrumentor = None

logger = logging.getLogger("agentic_soc")
logging.basicConfig(level=logging.INFO, format="%(message)s")


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid4().hex[:12]}"


def as_json(value: Any) -> str:
    if isinstance(value, BaseModel):
        return value.model_dump_json()
    return json.dumps(value, default=str)


def digest(value: Any) -> str:
    return hashlib.sha256(as_json(value).encode()).hexdigest()


class Settings(BaseSettings):
    app_env: str = "local"
    database_path: str = "agentic_soc.sqlite3"
    require_human_approval_level: int = Field(default=3, ge=0, le=5)
    admin_api_key: str = "dev-admin-key"
    analyst_api_key: str = "dev-analyst-key"
    agent_api_key: str = "dev-agent-key"
    model_provider: str = "stub"
    model_name: str = "local-security-rules-v1"
    max_workflow_attempts: int = 3
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


class Severity(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class Disposition(str, Enum):
    benign = "benign"
    suspicious = "suspicious"
    malicious = "malicious"
    needs_investigation = "needs_investigation"


class CaseStatus(str, Enum):
    new = "new"
    in_triage = "in_triage"
    awaiting_approval = "awaiting_approval"


class EntityType(str, Enum):
    user = "user"
    host = "host"
    ip = "ip"
    domain = "domain"
    url = "url"
    file = "file"
    process = "process"
    cloud_resource = "cloud_resource"
    identity = "identity"
    vulnerability = "vulnerability"


class AgentType(str, Enum):
    triage = "triage"
    investigation = "investigation"
    threat_intel = "threat_intel"
    correlation = "correlation"
    response_recommendation = "response_recommendation"


class ActionRiskLevel(int, Enum):
    read_only = 0
    case_write = 1
    enrichment = 2
    reversible_response = 3
    high_impact_containment = 4
    destructive = 5


class EntityRef(BaseModel):
    type: EntityType
    id: str
    display_name: str | None = None


class AlertEvent(BaseModel):
    id: str = Field(default_factory=lambda: new_id("evt"))
    source: str
    name: str
    category: str
    severity: Severity = Severity.medium
    entities: list[EntityRef] = Field(default_factory=list)
    description: str = ""
    timestamp: datetime = Field(default_factory=now_utc)
    raw_reference: str | None = None
    mitre_techniques: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class Evidence(BaseModel):
    id: str = Field(default_factory=lambda: new_id("evd"))
    source: str
    type: str
    summary: str
    timestamp: datetime = Field(default_factory=now_utc)
    entity_refs: list[EntityRef] = Field(default_factory=list)
    raw_data_pointer: str | None = None
    integrity_hash: str | None = None


class RecommendedAction(BaseModel):
    id: str = Field(default_factory=lambda: new_id("act"))
    name: str
    description: str
    risk_level: ActionRiskLevel
    target: EntityRef | None = None
    requires_approval: bool = True


class AgentDecision(BaseModel):
    id: str = Field(default_factory=lambda: new_id("run"))
    agent_type: AgentType
    disposition: Disposition
    severity: Severity
    confidence: float = Field(ge=0, le=1)
    summary: str
    rationale: list[str] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    recommended_actions: list[RecommendedAction] = Field(default_factory=list)
    requires_human_review: bool = True
    prompt_version: str | None = None
    model: str | None = None
    created_at: datetime = Field(default_factory=now_utc)


class Case(BaseModel):
    id: str = Field(default_factory=lambda: new_id("case"))
    title: str
    status: CaseStatus = CaseStatus.new
    source_event_id: str
    severity: Severity
    entities: list[EntityRef] = Field(default_factory=list)
    decisions: list[AgentDecision] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=now_utc)
    updated_at: datetime = Field(default_factory=now_utc)


class Approval(BaseModel):
    id: str = Field(default_factory=lambda: new_id("appr"))
    case_id: str
    action: RecommendedAction
    status: str = "pending"
    requested_at: datetime = Field(default_factory=now_utc)
    decided_at: datetime | None = None
    decided_by: str | None = None


class Feedback(BaseModel):
    id: str = Field(default_factory=lambda: new_id("fb"))
    case_id: str
    agent_decision_id: str
    verdict: str
    notes: str = ""
    submitted_by: str = "analyst"
    created_at: datetime = Field(default_factory=now_utc)


class AuditRecord(BaseModel):
    id: str = Field(default_factory=lambda: new_id("aud"))
    actor: str
    action: str
    target: str
    details: dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=now_utc)


class ContextBundle(BaseModel):
    entity: EntityRef
    risk_score: int = Field(ge=0, le=100)
    summary: str
    recent_activity: list[str] = Field(default_factory=list)
    related_alerts: list[str] = Field(default_factory=list)
    business_context: dict[str, Any] = Field(default_factory=dict)
    threat_intel: dict[str, Any] = Field(default_factory=dict)
    source_context: dict[str, Any] = Field(default_factory=dict)


class ApprovalDecision(BaseModel):
    approved: bool
    decided_by: str
    notes: str = ""


class IntegrationWriteback(BaseModel):
    id: str = Field(default_factory=lambda: new_id("wb"))
    target: str
    case_id: str
    payload: dict[str, Any]
    status: str = "queued"
    attempts: int = 0
    last_error: str | None = None
    created_at: datetime = Field(default_factory=now_utc)


class ConnectorStatus(BaseModel):
    name: str
    type: str
    mode: str
    status: str
    capabilities: list[str] = Field(default_factory=list)


class WorkflowRun(BaseModel):
    id: str = Field(default_factory=lambda: new_id("wf"))
    event_id: str
    idempotency_key: str
    status: str = "queued"
    attempts: int = 0
    result_case_id: str | None = None
    error: str | None = None
    created_at: datetime = Field(default_factory=now_utc)
    updated_at: datetime = Field(default_factory=now_utc)


class OrchestrationResult(BaseModel):
    event: AlertEvent
    workflow_id: str | None = None
    case: Case
    decisions: list[AgentDecision]
    approvals: list[Approval] = Field(default_factory=list)


class MetricsSnapshot(BaseModel):
    events_received: int
    cases_created: int
    approvals_pending: int
    approvals_approved: int
    approvals_rejected: int
    writebacks_queued: int
    workflow_queued: int
    workflow_running: int
    workflow_completed: int
    workflow_failed: int
    workflow_dead_lettered: int
    audit_records: int
    feedback_items: int


class DashboardSnapshot(BaseModel):
    mtta_seconds: float
    false_positive_rate: float
    analyst_override_rate: float
    escalation_accuracy: float
    metrics: MetricsSnapshot


class Principal(BaseModel):
    name: str
    scopes: set[str]


class PromptTemplate(BaseModel):
    name: str
    version: str
    template: str
    created_at: datetime = Field(default_factory=now_utc)


class ModelRequest(BaseModel):
    prompt_name: str
    variables: dict[str, Any] = Field(default_factory=dict)


class ModelResponse(BaseModel):
    provider: str
    model: str
    prompt_version: str
    output: str
    safety_flags: list[str] = Field(default_factory=list)


class SQLiteRepository:
    def __init__(self, path: str) -> None:
        self.path = path
        if path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.init_schema()

    @contextmanager
    def connect(self):
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def init_schema(self) -> None:
        with self.connect() as conn:
            conn.executescript(
                """
                create table if not exists objects (
                    kind text, id text, payload text, created_at text, updated_at text,
                    primary key(kind, id)
                );
                create table if not exists workflows (
                    id text primary key, event_id text, idempotency_key text unique,
                    status text, attempts integer, result_case_id text, error text,
                    created_at text, updated_at text
                );
                create table if not exists telemetry (
                    id text primary key, trace_id text, span text, duration_ms real,
                    attributes text, created_at text
                );
                """
            )

    def key_for(self, kind: str, item: BaseModel) -> str:
        if hasattr(item, "id"):
            return str(getattr(item, "id"))
        if kind == "context" and isinstance(item, ContextBundle):
            return item.entity.id
        if kind == "prompt" and isinstance(item, PromptTemplate):
            return f"{item.name}:{item.version}"
        return digest(item.model_dump(mode="json"))

    def put(self, kind: str, item: BaseModel) -> None:
        timestamp = now_utc().isoformat()
        with self.connect() as conn:
            conn.execute(
                """
                insert into objects values (?, ?, ?, ?, ?)
                on conflict(kind, id) do update set
                    payload=excluded.payload, updated_at=excluded.updated_at
                """,
                (kind, self.key_for(kind, item), item.model_dump_json(), timestamp, timestamp),
            )

    def get(self, kind: str, item_id: str, model: type[BaseModel]) -> Any | None:
        with self.connect() as conn:
            row = conn.execute("select payload from objects where kind=? and id=?", (kind, item_id)).fetchone()
        return model.model_validate_json(row["payload"]) if row else None

    def list(self, kind: str, model: type[BaseModel]) -> list[Any]:
        with self.connect() as conn:
            rows = conn.execute("select payload from objects where kind=? order by created_at", (kind,)).fetchall()
        return [model.model_validate_json(row["payload"]) for row in rows]

    def put_workflow(self, workflow: WorkflowRun) -> None:
        with self.connect() as conn:
            conn.execute(
                """
                insert into workflows values (?, ?, ?, ?, ?, ?, ?, ?, ?)
                on conflict(id) do update set status=excluded.status,
                    attempts=excluded.attempts, result_case_id=excluded.result_case_id,
                    error=excluded.error, updated_at=excluded.updated_at
                """,
                (
                    workflow.id,
                    workflow.event_id,
                    workflow.idempotency_key,
                    workflow.status,
                    workflow.attempts,
                    workflow.result_case_id,
                    workflow.error,
                    workflow.created_at.isoformat(),
                    workflow.updated_at.isoformat(),
                ),
            )

    def workflow_from_row(self, row: sqlite3.Row) -> WorkflowRun:
        return WorkflowRun(
            id=row["id"],
            event_id=row["event_id"],
            idempotency_key=row["idempotency_key"],
            status=row["status"],
            attempts=row["attempts"],
            result_case_id=row["result_case_id"],
            error=row["error"],
            created_at=datetime.fromisoformat(row["created_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
        )

    def get_workflow(self, workflow_id: str) -> WorkflowRun | None:
        with self.connect() as conn:
            row = conn.execute("select * from workflows where id=?", (workflow_id,)).fetchone()
        return self.workflow_from_row(row) if row else None

    def get_workflow_by_idempotency(self, key: str) -> WorkflowRun | None:
        with self.connect() as conn:
            row = conn.execute("select * from workflows where idempotency_key=?", (key,)).fetchone()
        return self.workflow_from_row(row) if row else None

    def list_workflows(self) -> list[WorkflowRun]:
        with self.connect() as conn:
            rows = conn.execute("select * from workflows order by created_at").fetchall()
        return [self.workflow_from_row(row) for row in rows]

    def span(self, span: str, duration_ms: float, attributes: dict[str, Any]) -> None:
        with self.connect() as conn:
            conn.execute(
                "insert into telemetry values (?, ?, ?, ?, ?, ?)",
                (new_id("span"), uuid4().hex, span, duration_ms, json.dumps(attributes, default=str), now_utc().isoformat()),
            )

    def list_spans(self) -> list[dict[str, Any]]:
        with self.connect() as conn:
            rows = conn.execute("select * from telemetry order by created_at").fetchall()
        return [dict(row) | {"attributes": json.loads(row["attributes"])} for row in rows]


class PromptInjectionGuard:
    patterns = [
        re.compile(r"ignore (all )?(previous|prior) instructions", re.I),
        re.compile(r"system prompt", re.I),
        re.compile(r"developer message", re.I),
        re.compile(r"reveal.*secret", re.I),
        re.compile(r"disable.*guardrail", re.I),
    ]

    def sanitize(self, text: str) -> tuple[str, list[str]]:
        flags = [pattern.pattern for pattern in self.patterns if pattern.search(text)]
        for pattern in self.patterns:
            text = pattern.sub("[redacted-prompt-injection]", text)
        return text, flags

    def event(self, event: AlertEvent) -> tuple[AlertEvent, list[str]]:
        name, name_flags = self.sanitize(event.name)
        description, desc_flags = self.sanitize(event.description)
        return event.model_copy(update={"name": name, "description": description}), name_flags + desc_flags


class DataMasker:
    def context(self, context: ContextBundle, principal: Principal) -> ContextBundle:
        if "sensitive:read" in principal.scopes:
            return context
        if context.entity.type not in {EntityType.user, EntityType.identity}:
            return context
        masked = context.entity.model_copy(
            update={"id": f"{context.entity.type.value}:masked:{digest(context.entity.id)[:8]}", "display_name": "masked"}
        )
        return context.model_copy(update={"entity": masked, "business_context": {"masked": True}})


class DurableSecurityDataFabric:
    def __init__(self, repo: SQLiteRepository) -> None:
        self.repo = repo
        self.seed()

    def seed(self) -> None:
        if self.repo.list("context", ContextBundle):
            return
        for context in [
            ContextBundle(
                entity=EntityRef(type=EntityType.user, id="user:maya", display_name="Maya L."),
                risk_score=78,
                summary="Privileged user with impossible travel and MFA fatigue signals.",
                recent_activity=["7 failed MFA prompts", "Successful login from new ASN"],
                related_alerts=["Impossible Travel", "MFA Fatigue"],
                business_context={"department": "Engineering", "privileged": True},
                source_context={"iam": {"mfa_failures": 7}, "cmdb": {"owner": "Engineering"}},
            ),
            ContextBundle(
                entity=EntityRef(type=EntityType.host, id="host:macbook-77"),
                risk_score=64,
                summary="Developer endpoint with suspicious script activity.",
                recent_activity=["Encoded shell command", "New persistence item"],
                related_alerts=["Suspicious Script Execution"],
                source_context={"edr": {"process_tree": "shell -> encoded command"}},
            ),
            ContextBundle(
                entity=EntityRef(type=EntityType.ip, id="185.199.108.153"),
                risk_score=82,
                summary="IP observed in credential stuffing campaigns.",
                recent_activity=["Multiple login attempts against tenant"],
                related_alerts=["Known Malicious IP"],
                threat_intel={"reputation": "malicious", "campaign": "credential_stuffing"},
            ),
        ]:
            self.repo.put("context", context)

    def save_event(self, event: AlertEvent) -> AlertEvent:
        self.repo.put("event", event)
        return event

    def get_event(self, event_id: str) -> AlertEvent | None:
        return self.repo.get("event", event_id, AlertEvent)

    def get_entity_context(self, entity: EntityRef) -> ContextBundle:
        return self.repo.get("context", entity.id, ContextBundle) or ContextBundle(
            entity=entity, risk_score=25, summary="No high-risk context found."
        )

    def get_timeline(self, entity: EntityRef) -> list[Evidence]:
        context = self.get_entity_context(entity)
        return [
            Evidence(
                source="data_fabric",
                type="timeline_event",
                summary=activity,
                entity_refs=[entity],
                raw_data_pointer=f"fabric://timeline/{entity.id}/{index}",
                integrity_hash=digest(activity),
            )
            for index, activity in enumerate(context.recent_activity)
        ]

    def get_threat_intel(self, entity: EntityRef) -> dict[str, Any]:
        return self.get_entity_context(entity).threat_intel or {"reputation": "unknown"}

    def get_related_alerts(self, entity: EntityRef) -> list[str]:
        return self.get_entity_context(entity).related_alerts

    def find_similar_cases(self, event: AlertEvent) -> list[str]:
        if "impossible" in event.name.lower():
            return ["case_hist_1042", "case_hist_1188"]
        if "script" in event.name.lower():
            return ["case_hist_2201"]
        return []


class CaseStore:
    def __init__(self, repo: SQLiteRepository) -> None:
        self.repo = repo

    def save_case(self, case: Case) -> Case:
        self.repo.put("case", case)
        return case

    def get_case(self, case_id: str) -> Case | None:
        return self.repo.get("case", case_id, Case)

    def list_cases(self) -> list[Case]:
        return self.repo.list("case", Case)

    def save_approval(self, approval: Approval) -> Approval:
        self.repo.put("approval", approval)
        return approval

    def list_approvals(self) -> list[Approval]:
        return self.repo.list("approval", Approval)

    def decide_approval(self, approval_id: str, decision: ApprovalDecision) -> Approval | None:
        approval = self.repo.get("approval", approval_id, Approval)
        if not approval:
            return None
        approval = approval.model_copy(
            update={"status": "approved" if decision.approved else "rejected", "decided_by": decision.decided_by, "decided_at": now_utc()}
        )
        self.save_approval(approval)
        return approval

    def save_writeback(self, writeback: IntegrationWriteback) -> IntegrationWriteback:
        self.repo.put("writeback", writeback)
        return writeback

    def list_writebacks(self) -> list[IntegrationWriteback]:
        return self.repo.list("writeback", IntegrationWriteback)

    def save_feedback(self, feedback: Feedback) -> Feedback:
        self.repo.put("feedback", feedback)
        return feedback

    def list_feedback(self) -> list[Feedback]:
        return self.repo.list("feedback", Feedback)


class AuditLog:
    def __init__(self, repo: SQLiteRepository) -> None:
        self.repo = repo

    def record(self, actor: str, action: str, target: str, **details: Any) -> AuditRecord:
        record = AuditRecord(actor=actor, action=action, target=target, details=details)
        self.repo.put("audit", record)
        logger.info(as_json({"event": "audit", "actor": actor, "action": action}))
        return record

    def list(self) -> list[AuditRecord]:
        return self.repo.list("audit", AuditRecord)


class PolicyEngine:
    agent_scopes = {
        AgentType.triage: {"fabric:read", "case:write"},
        AgentType.investigation: {"fabric:read", "sensitive:read"},
        AgentType.threat_intel: {"fabric:read", "threat:intel"},
        AgentType.correlation: {"fabric:read"},
        AgentType.response_recommendation: {"case:write", "response:recommend"},
    }

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def require_agent_scope(self, agent: AgentType, scope: str) -> None:
        if scope not in self.agent_scopes[agent]:
            raise PermissionError(f"{agent.value} lacks scope {scope}")

    def apply(self, actions: list[RecommendedAction]) -> list[RecommendedAction]:
        return [
            action.model_copy(update={"requires_approval": int(action.risk_level) >= self.settings.require_human_approval_level})
            for action in actions
        ]


class IntegrationHub:
    connectors = [
        ConnectorStatus(name="security_data_fabric", type="data_fabric", mode="sqlite", status="ready"),
        ConnectorStatus(name="siem", type="siem", mode="client_boundary", status="ready"),
        ConnectorStatus(name="soar", type="soar", mode="client_boundary", status="ready"),
        ConnectorStatus(name="edr", type="edr", mode="adapter_boundary", status="ready"),
        ConnectorStatus(name="iam", type="iam", mode="adapter_boundary", status="ready"),
        ConnectorStatus(name="cloud", type="cloud", mode="adapter_boundary", status="ready"),
        ConnectorStatus(name="cmdb", type="cmdb", mode="adapter_boundary", status="ready"),
        ConnectorStatus(name="vulnerability", type="vulnerability", mode="adapter_boundary", status="ready"),
        ConnectorStatus(name="threat_intel", type="threat_intel", mode="adapter_boundary", status="ready"),
    ]

    def __init__(self, store: CaseStore, audit: AuditLog) -> None:
        self.store = store
        self.audit = audit

    def queue_siem_writeback(self, case: Case) -> IntegrationWriteback:
        payload = {
            "case_id": case.id,
            "source_event_id": case.source_event_id,
            "severity": case.severity.value,
            "status": case.status.value,
            "summary": case.decisions[0].summary if case.decisions else case.title,
        }
        writeback = self.store.save_writeback(IntegrationWriteback(target="siem", case_id=case.id, payload=payload))
        self.audit.record("integration_hub", "siem_writeback_queued", writeback.id)
        return writeback

    def queue_soar_package(self, case: Case) -> IntegrationWriteback:
        payload = {
            "case_id": case.id,
            "entities": [entity.model_dump(mode="json") for entity in case.entities],
            "evidence": [evidence.model_dump(mode="json") for evidence in case.evidence],
        }
        writeback = self.store.save_writeback(IntegrationWriteback(target="soar", case_id=case.id, payload=payload))
        self.audit.record("integration_hub", "soar_package_queued", writeback.id)
        return writeback


class PromptRegistry:
    def __init__(self, repo: SQLiteRepository) -> None:
        self.repo = repo
        self.register(PromptTemplate(name="triage_summary", version="1.0.0", template="{alert_name}"))

    def register(self, prompt: PromptTemplate) -> PromptTemplate:
        self.repo.put("prompt", prompt)
        return prompt

    def list(self) -> list[PromptTemplate]:
        return self.repo.list("prompt", PromptTemplate)

    def get(self, name: str) -> PromptTemplate:
        matches = [prompt for prompt in self.list() if prompt.name == name]
        if not matches:
            raise HTTPException(status_code=404, detail="prompt not found")
        return matches[-1]


class ModelGateway:
    def __init__(self, settings: Settings, registry: PromptRegistry, guard: PromptInjectionGuard) -> None:
        self.settings = settings
        self.registry = registry
        self.guard = guard

    def complete(self, request: ModelRequest) -> ModelResponse:
        prompt = self.registry.get(request.prompt_name)
        rendered = prompt.template.format(**request.variables)
        safe, flags = self.guard.sanitize(rendered)
        return ModelResponse(
            provider=self.settings.model_provider,
            model=self.settings.model_name,
            prompt_version=prompt.version,
            output=f"[{self.settings.model_name}] {safe}",
            safety_flags=flags,
        )


class AgenticSOCOrchestrator:
    def __init__(self) -> None:
        self.fabric = get_fabric()
        self.store = get_store()
        self.audit = get_audit()
        self.policy = PolicyEngine(get_settings())
        self.integrations = get_integrations()
        self.guard = get_guard()
        self.model_gateway = get_model_gateway()

    def handle_event(self, event: AlertEvent, workflow_id: str | None = None) -> OrchestrationResult:
        start = time.perf_counter()
        event, flags = self.guard.event(event)
        self.fabric.save_event(event)
        self.audit.record("event_router", "event_received", event.id, safety_flags=flags)
        decisions = [self.triage(event), self.threat_intel(event), self.correlation(event)]
        if any(decision.requires_human_review for decision in decisions):
            decisions.extend([self.investigation(event), self.response(event)])
        decisions = [
            decision.model_copy(update={"recommended_actions": self.policy.apply(decision.recommended_actions)})
            for decision in decisions
        ]
        evidence = [item for decision in decisions for item in decision.evidence]
        highest = max(decisions, key=lambda d: ["low", "medium", "high", "critical"].index(d.severity.value))
        case = self.store.save_case(
            Case(
                title=f"{event.name} - agentic triage",
                status=CaseStatus.awaiting_approval
                if any(action.requires_approval for d in decisions for action in d.recommended_actions)
                else CaseStatus.in_triage,
                source_event_id=event.id,
                severity=highest.severity,
                entities=event.entities,
                decisions=decisions,
                evidence=evidence,
                updated_at=now_utc(),
            )
        )
        approvals = [
            self.store.save_approval(Approval(case_id=case.id, action=action))
            for decision in decisions
            for action in decision.recommended_actions
            if action.requires_approval
        ]
        self.integrations.queue_siem_writeback(case)
        if approvals:
            self.integrations.queue_soar_package(case)
        get_repo().span("orchestrator.handle_event", (time.perf_counter() - start) * 1000, {"case": case.id})
        return OrchestrationResult(event=event, workflow_id=workflow_id, case=case, decisions=decisions, approvals=approvals)

    def triage(self, event: AlertEvent) -> AgentDecision:
        self.policy.require_agent_scope(AgentType.triage, "fabric:read")
        bundles = [self.fabric.get_entity_context(entity) for entity in event.entities]
        risk = max([bundle.risk_score for bundle in bundles] or [0])
        severity = Severity.high if risk >= 70 or event.severity == Severity.high else Severity.medium
        disposition = Disposition.suspicious if risk >= 60 else Disposition.needs_investigation
        evidence = [
            Evidence(
                source="security_context_api",
                type="entity_context",
                summary=f"{bundle.entity.id}: {bundle.summary}",
                entity_refs=[bundle.entity],
                integrity_hash=digest(bundle),
            )
            for bundle in bundles
        ]
        actions = [RecommendedAction(name="Escalate to Tier 2", description="Open investigation.", risk_level=ActionRiskLevel.case_write)]
        if severity == Severity.high:
            actions.append(
                RecommendedAction(
                    name="Revoke sessions",
                    description="Revoke sessions after approval.",
                    risk_level=ActionRiskLevel.reversible_response,
                    target=event.entities[0] if event.entities else None,
                )
            )
        model = self.model_gateway.complete(ModelRequest(prompt_name="triage_summary", variables={"alert_name": event.name}))
        return AgentDecision(
            agent_type=AgentType.triage,
            disposition=disposition,
            severity=severity,
            confidence=min(0.95, 0.45 + risk / 150),
            summary=f"{event.name} triaged as {disposition.value} with {severity.value} severity. Top entity risk is {risk}.",
            rationale=[model.output],
            evidence=evidence,
            recommended_actions=actions,
            requires_human_review=severity == Severity.high,
            prompt_version=model.prompt_version,
            model=model.model,
        )

    def threat_intel(self, event: AlertEvent) -> AgentDecision:
        self.policy.require_agent_scope(AgentType.threat_intel, "threat:intel")
        evidence = []
        malicious = False
        for entity in event.entities:
            if entity.type in {EntityType.ip, EntityType.domain, EntityType.url, EntityType.file}:
                intel = self.fabric.get_threat_intel(entity)
                malicious = malicious or intel.get("reputation") == "malicious"
                evidence.append(
                    Evidence(
                        source="threat_intel",
                        type="indicator",
                        summary=f"{entity.id} reputation: {intel.get('reputation', 'unknown')}",
                        entity_refs=[entity],
                        integrity_hash=digest(intel),
                    )
                )
        return AgentDecision(
            agent_type=AgentType.threat_intel,
            disposition=Disposition.suspicious if malicious else Disposition.needs_investigation,
            severity=Severity.high if malicious else event.severity,
            confidence=0.82 if malicious else 0.55,
            summary=f"Threat intelligence enrichment found {len(evidence)} indicator results.",
            evidence=evidence,
            requires_human_review=malicious,
        )

    def correlation(self, event: AlertEvent) -> AgentDecision:
        related = sorted({alert for entity in event.entities for alert in self.fabric.get_related_alerts(entity)})
        evidence = [Evidence(source="correlation", type="related_alert", summary=alert, integrity_hash=digest(alert)) for alert in related]
        return AgentDecision(
            agent_type=AgentType.correlation,
            disposition=Disposition.needs_investigation,
            severity=event.severity,
            confidence=0.6 if evidence else 0.35,
            summary=f"Found {len(related)} related alert patterns.",
            evidence=evidence,
            requires_human_review=False,
        )

    def investigation(self, event: AlertEvent) -> AgentDecision:
        self.policy.require_agent_scope(AgentType.investigation, "sensitive:read")
        evidence = [item for entity in event.entities for item in self.fabric.get_timeline(entity)]
        similar = self.fabric.find_similar_cases(event)
        return AgentDecision(
            agent_type=AgentType.investigation,
            disposition=Disposition.needs_investigation,
            severity=Severity.high if evidence or similar else event.severity,
            confidence=0.74 if evidence else 0.5,
            summary=f"Built investigation timeline with {len(evidence)} evidence items and {len(similar)} similar cases.",
            evidence=evidence,
            requires_human_review=True,
        )

    def response(self, event: AlertEvent) -> AgentDecision:
        actions = [RecommendedAction(name="Create SOAR investigation package", description="Send evidence to SOAR.", risk_level=ActionRiskLevel.case_write)]
        if any(entity.type in {EntityType.user, EntityType.identity} for entity in event.entities):
            target = next(entity for entity in event.entities if entity.type in {EntityType.user, EntityType.identity})
            actions.append(
                RecommendedAction(
                    name="Revoke sessions",
                    description="Revoke active sessions after approval.",
                    risk_level=ActionRiskLevel.reversible_response,
                    target=target,
                )
            )
        if any(entity.type == EntityType.host for entity in event.entities):
            target = next(entity for entity in event.entities if entity.type == EntityType.host)
            actions.append(
                RecommendedAction(
                    name="Isolate endpoint",
                    description="Isolate endpoint after approval.",
                    risk_level=ActionRiskLevel.high_impact_containment,
                    target=target,
                )
            )
        return AgentDecision(
            agent_type=AgentType.response_recommendation,
            disposition=Disposition.needs_investigation,
            severity=event.severity if event.severity != Severity.low else Severity.medium,
            confidence=0.7,
            summary=f"Prepared {len(actions)} response recommendations with risk tiers.",
            recommended_actions=actions,
            requires_human_review=True,
        )


class WorkflowEngine:
    def __init__(self) -> None:
        self.repo = get_repo()
        self.fabric = get_fabric()
        self.orchestrator = get_orchestrator()
        self.settings = get_settings()

    def enqueue(self, event: AlertEvent, idempotency_key: str | None) -> WorkflowRun:
        key = idempotency_key or digest(event.model_dump(mode="json"))
        existing = self.repo.get_workflow_by_idempotency(key)
        if existing:
            return existing
        self.fabric.save_event(event)
        workflow = WorkflowRun(event_id=event.id, idempotency_key=key)
        self.repo.put_workflow(workflow)
        return workflow

    def process(self, workflow_id: str) -> WorkflowRun:
        workflow = self.repo.get_workflow(workflow_id)
        if not workflow:
            raise HTTPException(status_code=404, detail="workflow not found")
        event = self.fabric.get_event(workflow.event_id)
        workflow.status = "running"
        workflow.attempts += 1
        workflow.updated_at = now_utc()
        self.repo.put_workflow(workflow)
        try:
            if not event:
                raise RuntimeError("event payload missing")
            result = self.orchestrator.handle_event(event, workflow_id=workflow.id)
            workflow.status = "completed"
            workflow.result_case_id = result.case.id
            workflow.error = None
        except Exception as exc:  # noqa: BLE001
            workflow.error = str(exc)
            workflow.status = "dead_lettered" if workflow.attempts >= self.settings.max_workflow_attempts else "failed"
        workflow.updated_at = now_utc()
        self.repo.put_workflow(workflow)
        return workflow

    def resume(self, workflow_id: str) -> WorkflowRun:
        workflow = self.repo.get_workflow(workflow_id)
        if not workflow:
            raise HTTPException(status_code=404, detail="workflow not found")
        if workflow.status in {"completed", "running"}:
            return workflow
        workflow.status = "queued"
        workflow.updated_at = now_utc()
        self.repo.put_workflow(workflow)
        return self.process(workflow.id)


@lru_cache
def get_settings() -> Settings:
    return Settings()


@lru_cache
def get_repo() -> SQLiteRepository:
    return SQLiteRepository(get_settings().database_path)


@lru_cache
def get_fabric() -> DurableSecurityDataFabric:
    return DurableSecurityDataFabric(get_repo())


@lru_cache
def get_store() -> CaseStore:
    return CaseStore(get_repo())


@lru_cache
def get_audit() -> AuditLog:
    return AuditLog(get_repo())


@lru_cache
def get_integrations() -> IntegrationHub:
    return IntegrationHub(get_store(), get_audit())


@lru_cache
def get_guard() -> PromptInjectionGuard:
    return PromptInjectionGuard()


@lru_cache
def get_masker() -> DataMasker:
    return DataMasker()


@lru_cache
def get_prompt_registry() -> PromptRegistry:
    return PromptRegistry(get_repo())


@lru_cache
def get_model_gateway() -> ModelGateway:
    return ModelGateway(get_settings(), get_prompt_registry(), get_guard())


@lru_cache
def get_orchestrator() -> AgenticSOCOrchestrator:
    return AgenticSOCOrchestrator()


@lru_cache
def get_workflows() -> WorkflowEngine:
    return WorkflowEngine()


def reset_state_for_tests() -> None:
    db_path = get_settings().database_path
    if db_path != ":memory:":
        Path(db_path).unlink(missing_ok=True)
    for fn in [
        get_repo,
        get_fabric,
        get_store,
        get_audit,
        get_integrations,
        get_guard,
        get_masker,
        get_prompt_registry,
        get_model_gateway,
        get_orchestrator,
        get_workflows,
    ]:
        fn.cache_clear()


def principal_from_key(key: str | None) -> Principal:
    settings = get_settings()
    principals = {
        settings.admin_api_key: Principal(
            name="admin",
            scopes={
                "admin",
                "events:write",
                "fabric:read",
                "sensitive:read",
                "cases:read",
                "cases:write",
                "approvals:write",
                "feedback:write",
                "audit:read",
                "connectors:read",
                "metrics:read",
                "model:invoke",
            },
        ),
        settings.analyst_api_key: Principal(
            name="analyst",
            scopes={"fabric:read", "cases:read", "approvals:write", "feedback:write", "metrics:read"},
        ),
        settings.agent_api_key: Principal(name="agent", scopes={"events:write", "fabric:read", "cases:write"}),
    }
    principal = principals.get(key or "")
    if not principal:
        raise HTTPException(status_code=401, detail="missing or invalid api key")
    return principal


def require_scopes(*required: str):
    def dependency(x_api_key: str | None = Header(default=None, alias="X-API-Key")) -> Principal:
        principal = principal_from_key(x_api_key)
        missing = [scope for scope in required if scope not in principal.scopes and "admin" not in principal.scopes]
        if missing:
            raise HTTPException(status_code=403, detail=f"missing scopes: {', '.join(missing)}")
        return principal

    return dependency


app = FastAPI(title="Agentic SOC Data Fabric Orchestrator", version="0.2.0")
if FastAPIInstrumentor:
    FastAPIInstrumentor.instrument_app(app)


@app.middleware("http")
async def structured_request_logging(request: Request, call_next):
    start = time.perf_counter()
    response = await call_next(request)
    logger.info(
        as_json(
            {
                "event": "http_request",
                "method": request.method,
                "path": request.url.path,
                "status": response.status_code,
                "duration_ms": (time.perf_counter() - start) * 1000,
            }
        )
    )
    return response


@app.get("/health")
def health(_: Principal = Depends(require_scopes("metrics:read"))) -> dict[str, str]:
    return {"status": "ok", "service": "agentic-soc-data-fabric-orchestrator"}


@app.post("/events", response_model=WorkflowRun)
def ingest_event(
    event: AlertEvent,
    background_tasks: BackgroundTasks,
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    _: Principal = Depends(require_scopes("events:write")),
    workflows: WorkflowEngine = Depends(get_workflows),
) -> WorkflowRun:
    workflow = workflows.enqueue(event, idempotency_key)
    if workflow.status == "queued":
        background_tasks.add_task(workflows.process, workflow.id)
    return workflow


@app.post("/events/sync", response_model=OrchestrationResult)
def ingest_event_sync(
    event: AlertEvent,
    _: Principal = Depends(require_scopes("events:write")),
    orchestrator: AgenticSOCOrchestrator = Depends(get_orchestrator),
) -> OrchestrationResult:
    return orchestrator.handle_event(event)


@app.get("/workflows", response_model=list[WorkflowRun])
def list_workflows(
    _: Principal = Depends(require_scopes("cases:read")),
    repo: SQLiteRepository = Depends(get_repo),
) -> list[WorkflowRun]:
    return repo.list_workflows()


@app.post("/workflows/{workflow_id}/resume", response_model=WorkflowRun)
def resume_workflow(
    workflow_id: str,
    _: Principal = Depends(require_scopes("cases:write")),
    workflows: WorkflowEngine = Depends(get_workflows),
) -> WorkflowRun:
    return workflows.resume(workflow_id)


@app.post("/context/entity", response_model=ContextBundle)
def entity_context(
    entity: EntityRef,
    principal: Principal = Depends(require_scopes("fabric:read")),
    fabric: DurableSecurityDataFabric = Depends(get_fabric),
    masker: DataMasker = Depends(get_masker),
) -> ContextBundle:
    return masker.context(fabric.get_entity_context(entity), principal)


@app.post("/timeline", response_model=list[Evidence])
def timeline(
    entity: EntityRef,
    _: Principal = Depends(require_scopes("fabric:read")),
    fabric: DurableSecurityDataFabric = Depends(get_fabric),
) -> list[Evidence]:
    return fabric.get_timeline(entity)


@app.get("/cases", response_model=list[Case])
def list_cases(
    _: Principal = Depends(require_scopes("cases:read")),
    store: CaseStore = Depends(get_store),
) -> list[Case]:
    return store.list_cases()


@app.get("/cases/{case_id}", response_model=Case)
def get_case(
    case_id: str,
    _: Principal = Depends(require_scopes("cases:read")),
    store: CaseStore = Depends(get_store),
) -> Case:
    case = store.get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="case not found")
    return case


@app.get("/approvals", response_model=list[Approval])
def list_approvals(
    _: Principal = Depends(require_scopes("cases:read")),
    store: CaseStore = Depends(get_store),
) -> list[Approval]:
    return store.list_approvals()


@app.post("/approvals/{approval_id}/decision", response_model=Approval)
def decide_approval(
    approval_id: str,
    decision: ApprovalDecision,
    principal: Principal = Depends(require_scopes("approvals:write")),
    store: CaseStore = Depends(get_store),
    audit: AuditLog = Depends(get_audit),
) -> Approval:
    approval = store.decide_approval(approval_id, decision)
    if not approval:
        raise HTTPException(status_code=404, detail="approval not found")
    audit.record(principal.name, "approval_decided", approval_id, status=approval.status)
    return approval


@app.post("/feedback", response_model=Feedback)
def create_feedback(
    feedback: Feedback,
    principal: Principal = Depends(require_scopes("feedback:write")),
    store: CaseStore = Depends(get_store),
    audit: AuditLog = Depends(get_audit),
) -> Feedback:
    saved = store.save_feedback(feedback)
    audit.record(principal.name, "feedback_created", feedback.id, verdict=feedback.verdict)
    return saved


@app.get("/audit", response_model=list[AuditRecord])
def list_audit(
    _: Principal = Depends(require_scopes("audit:read")),
    audit: AuditLog = Depends(get_audit),
) -> list[AuditRecord]:
    return audit.list()


@app.get("/connectors", response_model=list[ConnectorStatus])
def list_connectors(_: Principal = Depends(require_scopes("connectors:read"))) -> list[ConnectorStatus]:
    return IntegrationHub.connectors


@app.get("/writebacks", response_model=list[IntegrationWriteback])
def list_writebacks(
    _: Principal = Depends(require_scopes("cases:read")),
    store: CaseStore = Depends(get_store),
) -> list[IntegrationWriteback]:
    return store.list_writebacks()


@app.get("/metrics", response_model=MetricsSnapshot)
def metrics(
    _: Principal = Depends(require_scopes("metrics:read")),
    store: CaseStore = Depends(get_store),
    audit: AuditLog = Depends(get_audit),
    repo: SQLiteRepository = Depends(get_repo),
) -> MetricsSnapshot:
    approvals = store.list_approvals()
    workflows = repo.list_workflows()
    return MetricsSnapshot(
        events_received=len(repo.list("event", AlertEvent)),
        cases_created=len(store.list_cases()),
        approvals_pending=sum(1 for approval in approvals if approval.status == "pending"),
        approvals_approved=sum(1 for approval in approvals if approval.status == "approved"),
        approvals_rejected=sum(1 for approval in approvals if approval.status == "rejected"),
        writebacks_queued=len(store.list_writebacks()),
        workflow_queued=sum(1 for workflow in workflows if workflow.status == "queued"),
        workflow_running=sum(1 for workflow in workflows if workflow.status == "running"),
        workflow_completed=sum(1 for workflow in workflows if workflow.status == "completed"),
        workflow_failed=sum(1 for workflow in workflows if workflow.status == "failed"),
        workflow_dead_lettered=sum(1 for workflow in workflows if workflow.status == "dead_lettered"),
        audit_records=len(audit.list()),
        feedback_items=len(store.list_feedback()),
    )


@app.get("/dashboard", response_model=DashboardSnapshot)
def dashboard(
    _: Principal = Depends(require_scopes("metrics:read")),
    snapshot: MetricsSnapshot = Depends(metrics),
    store: CaseStore = Depends(get_store),
) -> DashboardSnapshot:
    feedback = store.list_feedback()
    total = max(1, len(feedback))
    false_positives = sum(1 for item in feedback if item.verdict in {"false_positive", "incorrect"})
    overrides = sum(1 for item in feedback if item.verdict in {"wrong_severity", "incorrect"})
    return DashboardSnapshot(
        mtta_seconds=0.0 if snapshot.cases_created == 0 else 60.0,
        false_positive_rate=false_positives / total,
        analyst_override_rate=overrides / total,
        escalation_accuracy=1.0 - (overrides / total),
        metrics=snapshot,
    )


@app.get("/telemetry/spans")
def telemetry_spans(
    _: Principal = Depends(require_scopes("metrics:read")),
    repo: SQLiteRepository = Depends(get_repo),
) -> list[dict[str, Any]]:
    return repo.list_spans()


@app.get("/prompts", response_model=list[PromptTemplate])
def list_prompts(
    _: Principal = Depends(require_scopes("model:invoke")),
    registry: PromptRegistry = Depends(get_prompt_registry),
) -> list[PromptTemplate]:
    return registry.list()


@app.post("/model/complete", response_model=ModelResponse)
def model_complete(
    request: ModelRequest,
    _: Principal = Depends(require_scopes("model:invoke")),
    gateway: ModelGateway = Depends(get_model_gateway),
) -> ModelResponse:
    return gateway.complete(request)
