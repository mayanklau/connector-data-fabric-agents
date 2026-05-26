from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from functools import lru_cache
from typing import Any
from uuid import uuid4

from fastapi import Depends, FastAPI, HTTPException
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid4().hex[:12]}"


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


class Settings(BaseSettings):
    app_env: str = "local"
    require_human_approval_level: int = Field(default=3, ge=0, le=5)
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


class Severity(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class Disposition(str, Enum):
    benign = "benign"
    false_positive = "false_positive"
    suspicious = "suspicious"
    malicious = "malicious"
    needs_investigation = "needs_investigation"


class CaseStatus(str, Enum):
    new = "new"
    in_triage = "in_triage"
    under_investigation = "under_investigation"
    awaiting_approval = "awaiting_approval"
    containment_in_progress = "containment_in_progress"
    resolved = "resolved"
    closed_benign = "closed_benign"
    closed_false_positive = "closed_false_positive"
    escalated = "escalated"


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


class AuditRecord(BaseModel):
    id: str = Field(default_factory=lambda: new_id("aud"))
    actor: str
    action: str
    target: str
    details: dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=now_utc)


class Feedback(BaseModel):
    id: str = Field(default_factory=lambda: new_id("fb"))
    case_id: str
    agent_decision_id: str
    verdict: str
    notes: str = ""
    submitted_by: str = "analyst"
    created_at: datetime = Field(default_factory=now_utc)


class ContextBundle(BaseModel):
    entity: EntityRef
    risk_score: int = Field(ge=0, le=100)
    summary: str
    recent_activity: list[str] = Field(default_factory=list)
    related_alerts: list[str] = Field(default_factory=list)
    business_context: dict[str, Any] = Field(default_factory=dict)
    threat_intel: dict[str, Any] = Field(default_factory=dict)


class OrchestrationResult(BaseModel):
    event: AlertEvent
    case: Case
    decisions: list[AgentDecision]
    approvals: list[Approval] = Field(default_factory=list)


class InMemorySecurityDataFabric:
    def __init__(self) -> None:
        self.events: dict[str, AlertEvent] = {}
        self.context: dict[str, ContextBundle] = {}
        self._seed()

    def _seed(self) -> None:
        maya = EntityRef(type=EntityType.user, id="user:maya", display_name="Maya L.")
        host = EntityRef(type=EntityType.host, id="host:macbook-77", display_name="macbook-77")
        ip = EntityRef(type=EntityType.ip, id="185.199.108.153")
        self.context[maya.id] = ContextBundle(
            entity=maya,
            risk_score=78,
            summary="Privileged user with recent impossible travel and MFA fatigue signals.",
            recent_activity=["7 failed MFA prompts", "Successful login from new ASN", "Accessed identity console"],
            related_alerts=["Impossible Travel", "MFA Fatigue"],
            business_context={"department": "Engineering", "privileged": True},
        )
        self.context[host.id] = ContextBundle(
            entity=host,
            risk_score=64,
            summary="Developer endpoint with suspicious script activity.",
            recent_activity=["Encoded shell command", "New persistence item", "Outbound connection"],
            related_alerts=["Suspicious Script Execution"],
            business_context={"criticality": "medium"},
        )
        self.context[ip.id] = ContextBundle(
            entity=ip,
            risk_score=82,
            summary="IP observed in credential stuffing campaigns.",
            recent_activity=["Multiple login attempts against tenant"],
            related_alerts=["Known Malicious IP"],
            threat_intel={"reputation": "malicious", "campaign": "credential_stuffing"},
        )

    def save_event(self, event: AlertEvent) -> AlertEvent:
        self.events[event.id] = event
        return event

    def get_entity_context(self, entity: EntityRef) -> ContextBundle:
        return self.context.get(entity.id, ContextBundle(entity=entity, risk_score=25, summary="No high-risk context found."))

    def get_timeline(self, entity: EntityRef) -> list[Evidence]:
        bundle = self.get_entity_context(entity)
        return [Evidence(source="data_fabric", type="timeline_event", summary=item, entity_refs=[entity], raw_data_pointer=f"fabric://timeline/{entity.id}/{idx}") for idx, item in enumerate(bundle.recent_activity)]

    def get_threat_intel(self, entity: EntityRef) -> dict[str, Any]:
        return self.get_entity_context(entity).threat_intel or {"reputation": "unknown"}

    def get_related_alerts(self, entity: EntityRef) -> list[str]:
        return self.get_entity_context(entity).related_alerts

    def find_similar_cases(self, event: AlertEvent) -> list[str]:
        if "impossible" in event.name.lower():
            return ["case_hist_1042", "case_hist_1188"]
        if "powershell" in event.name.lower() or "script" in event.name.lower():
            return ["case_hist_2201"]
        return []


class CaseStore:
    def __init__(self) -> None:
        self.cases: dict[str, Case] = {}
        self.approvals: dict[str, Approval] = {}
        self.feedback: dict[str, Feedback] = {}

    def save_case(self, case: Case) -> Case:
        self.cases[case.id] = case
        return case

    def get_case(self, case_id: str) -> Case | None:
        return self.cases.get(case_id)

    def save_approval(self, approval: Approval) -> Approval:
        self.approvals[approval.id] = approval
        return approval


class AuditLog:
    def __init__(self) -> None:
        self.records: list[AuditRecord] = []

    def record(self, actor: str, action: str, target: str, **details: Any) -> None:
        self.records.append(AuditRecord(actor=actor, action=action, target=target, details=details))


class PolicyEngine:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def apply(self, actions: list[RecommendedAction]) -> list[RecommendedAction]:
        return [action.model_copy(update={"requires_approval": int(action.risk_level) >= self.settings.require_human_approval_level}) for action in actions]


class AgenticSOCOrchestrator:
    def __init__(self, fabric: InMemorySecurityDataFabric, store: CaseStore, audit: AuditLog, policy: PolicyEngine) -> None:
        self.fabric = fabric
        self.store = store
        self.audit = audit
        self.policy = policy

    def handle_event(self, event: AlertEvent) -> OrchestrationResult:
        self.fabric.save_event(event)
        self.audit.record("event_router", "event_received", event.id, source=event.source)
        decisions = [self.triage(event), self.threat_intel(event), self.correlation(event)]
        if any(d.requires_human_review for d in decisions):
            decisions.extend([self.investigation(event), self.response(event)])
        decisions = [d.model_copy(update={"recommended_actions": self.policy.apply(d.recommended_actions)}) for d in decisions]
        evidence = [item for decision in decisions for item in decision.evidence]
        highest = max(decisions, key=lambda d: {"low": 1, "medium": 2, "high": 3, "critical": 4}[d.severity.value])
        case = self.store.save_case(Case(title=f"{event.name} - agentic triage", status=CaseStatus.awaiting_approval if any(a.requires_approval for d in decisions for a in d.recommended_actions) else CaseStatus.in_triage, source_event_id=event.id, severity=highest.severity, entities=event.entities, decisions=decisions, evidence=evidence, updated_at=now_utc()))
        approvals = [self.store.save_approval(Approval(case_id=case.id, action=action)) for decision in decisions for action in decision.recommended_actions if action.requires_approval]
        self.audit.record("orchestrator", "workflow_completed", case.id, event_id=event.id, approvals=[a.id for a in approvals])
        return OrchestrationResult(event=event, case=case, decisions=decisions, approvals=approvals)

    def triage(self, event: AlertEvent) -> AgentDecision:
        bundles = [self.fabric.get_entity_context(entity) for entity in event.entities]
        risk = max([b.risk_score for b in bundles] or [0])
        severity = Severity.high if risk >= 70 or event.severity == Severity.high else Severity.medium if risk >= 40 else Severity.low
        disposition = Disposition.malicious if risk >= 85 else Disposition.suspicious if risk >= 60 else Disposition.needs_investigation if risk >= 35 else Disposition.benign
        evidence = [Evidence(source="security_context_api", type="entity_context", summary=f"{b.entity.id}: {b.summary}", entity_refs=[b.entity], raw_data_pointer=f"fabric://context/{b.entity.id}") for b in bundles]
        actions = [RecommendedAction(name="Escalate to Tier 2", description="Open an investigation with enriched context and evidence.", risk_level=ActionRiskLevel.case_write)]
        if severity == Severity.high:
            actions.append(RecommendedAction(name="Revoke active sessions", description="Revoke active sessions for the affected identity after approval.", risk_level=ActionRiskLevel.reversible_response, target=event.entities[0] if event.entities else None))
        return AgentDecision(agent_type=AgentType.triage, disposition=disposition, severity=severity, confidence=min(0.95, 0.45 + risk / 150), summary=f"{event.name} triaged as {disposition.value} with {severity.value} severity. Top entity risk is {risk}.", rationale=[f"Highest entity risk score is {risk}.", "Decision uses normalized data fabric context."], evidence=evidence, recommended_actions=actions, requires_human_review=severity in {Severity.high, Severity.critical})

    def threat_intel(self, event: AlertEvent) -> AgentDecision:
        evidence: list[Evidence] = []
        malicious = False
        for entity in event.entities:
            if entity.type in {EntityType.ip, EntityType.domain, EntityType.url, EntityType.file}:
                intel = self.fabric.get_threat_intel(entity)
                malicious = malicious or intel.get("reputation") == "malicious"
                evidence.append(Evidence(source="threat_intel", type="indicator_reputation", summary=f"{entity.id} reputation: {intel.get('reputation', 'unknown')}", entity_refs=[entity], raw_data_pointer=f"fabric://threat-intel/{entity.id}"))
        return AgentDecision(agent_type=AgentType.threat_intel, disposition=Disposition.suspicious if malicious else Disposition.needs_investigation, severity=Severity.high if malicious else event.severity, confidence=0.82 if malicious else 0.55, summary=f"Threat intelligence enrichment found {len(evidence)} indicator results.", rationale=["Indicator reputation checked through the fabric."], evidence=evidence, requires_human_review=malicious)

    def correlation(self, event: AlertEvent) -> AgentDecision:
        related = sorted({alert for entity in event.entities for alert in self.fabric.get_related_alerts(entity)})
        evidence = [Evidence(source="correlation", type="related_alert", summary=alert, raw_data_pointer=f"fabric://related-alerts/{alert}") for alert in related]
        return AgentDecision(agent_type=AgentType.correlation, disposition=Disposition.needs_investigation, severity=event.severity, confidence=0.6 if evidence else 0.35, summary=f"Found {len(related)} related alert patterns.", rationale=["Related alerts deduplicated by normalized entity relationships."], evidence=evidence, requires_human_review=False)

    def investigation(self, event: AlertEvent) -> AgentDecision:
        evidence = [item for entity in event.entities for item in self.fabric.get_timeline(entity)]
        similar = self.fabric.find_similar_cases(event)
        return AgentDecision(agent_type=AgentType.investigation, disposition=Disposition.needs_investigation, severity=Severity.high if evidence or similar else event.severity, confidence=0.74 if evidence else 0.5, summary=f"Built investigation timeline with {len(evidence)} evidence items and {len(similar)} similar cases.", rationale=[f"Similar cases: {', '.join(similar) if similar else 'none found'}."], evidence=evidence, requires_human_review=True)

    def response(self, event: AlertEvent) -> AgentDecision:
        actions = [RecommendedAction(name="Create SOAR investigation package", description="Send evidence, entities, and timeline to SOAR for analyst review.", risk_level=ActionRiskLevel.case_write)]
        if any(e.type in {EntityType.user, EntityType.identity} for e in event.entities):
            target = next(e for e in event.entities if e.type in {EntityType.user, EntityType.identity})
            actions.append(RecommendedAction(name="Revoke sessions", description="Revoke active sessions for affected identities after approval.", risk_level=ActionRiskLevel.reversible_response, target=target))
        if any(e.type == EntityType.host for e in event.entities):
            target = next(e for e in event.entities if e.type == EntityType.host)
            actions.append(RecommendedAction(name="Isolate endpoint", description="Isolate endpoint if investigation confirms compromise.", risk_level=ActionRiskLevel.high_impact_containment, target=target))
        return AgentDecision(agent_type=AgentType.response_recommendation, disposition=Disposition.needs_investigation, severity=event.severity if event.severity != Severity.low else Severity.medium, confidence=0.7, summary=f"Prepared {len(actions)} response recommendations with risk tiers.", rationale=["Actions are recommendation-only until approval checks pass."], recommended_actions=actions, requires_human_review=True)


@lru_cache
def get_settings() -> Settings:
    return Settings()


@lru_cache
def get_fabric() -> InMemorySecurityDataFabric:
    return InMemorySecurityDataFabric()


@lru_cache
def get_store() -> CaseStore:
    return CaseStore()


@lru_cache
def get_audit() -> AuditLog:
    return AuditLog()


def get_orchestrator() -> AgenticSOCOrchestrator:
    return AgenticSOCOrchestrator(get_fabric(), get_store(), get_audit(), PolicyEngine(get_settings()))


app = FastAPI(title="Agentic SOC Data Fabric Orchestrator", version="0.1.0")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "agentic-soc-data-fabric-orchestrator"}


@app.post("/events", response_model=OrchestrationResult)
def ingest_event(event: AlertEvent, orchestrator: AgenticSOCOrchestrator = Depends(get_orchestrator)) -> OrchestrationResult:
    return orchestrator.handle_event(event)


@app.post("/context/entity", response_model=ContextBundle)
def entity_context(entity: EntityRef, fabric: InMemorySecurityDataFabric = Depends(get_fabric)) -> ContextBundle:
    return fabric.get_entity_context(entity)


@app.post("/timeline", response_model=list[Evidence])
def timeline(entity: EntityRef, fabric: InMemorySecurityDataFabric = Depends(get_fabric)) -> list[Evidence]:
    return fabric.get_timeline(entity)


@app.get("/cases", response_model=list[Case])
def list_cases(store: CaseStore = Depends(get_store)) -> list[Case]:
    return list(store.cases.values())


@app.get("/cases/{case_id}", response_model=Case)
def get_case(case_id: str, store: CaseStore = Depends(get_store)) -> Case:
    case = store.get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="case not found")
    return case


@app.get("/approvals", response_model=list[Approval])
def list_approvals(store: CaseStore = Depends(get_store)) -> list[Approval]:
    return list(store.approvals.values())


@app.post("/feedback", response_model=Feedback)
def create_feedback(feedback: Feedback, store: CaseStore = Depends(get_store)) -> Feedback:
    store.feedback[feedback.id] = feedback
    return feedback


@app.get("/audit", response_model=list[AuditRecord])
def list_audit(audit: AuditLog = Depends(get_audit)) -> list[AuditRecord]:
    return audit.records
