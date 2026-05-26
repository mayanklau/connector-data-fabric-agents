from agentic_soc.main import AlertEvent, EntityRef, EntityType, Severity, get_audit, get_fabric, get_orchestrator, get_store


def setup_function() -> None:
    get_fabric.cache_clear()
    get_store.cache_clear()
    get_audit.cache_clear()


def test_high_risk_identity_alert_creates_case_and_approval() -> None:
    event = AlertEvent(
        source="siem",
        name="Impossible Travel",
        category="identity_anomaly",
        severity=Severity.medium,
        entities=[
            EntityRef(type=EntityType.user, id="user:maya"),
            EntityRef(type=EntityType.ip, id="185.199.108.153"),
        ],
    )
    result = get_orchestrator().handle_event(event)
    assert result.case.severity == Severity.high
    assert result.case.evidence
    assert result.approvals
    assert any(decision.agent_type.value == "triage" for decision in result.decisions)
    assert {writeback.target for writeback in get_store().writebacks.values()} == {"siem", "soar"}


def test_low_context_event_stays_low_or_medium_without_response_approval() -> None:
    event = AlertEvent(
        source="data_fabric",
        name="Unusual SaaS Login",
        category="identity_activity",
        severity=Severity.low,
        entities=[EntityRef(type=EntityType.user, id="user:unknown")],
    )
    result = get_orchestrator().handle_event(event)
    assert result.case.severity in {Severity.low, Severity.medium}
    assert all(approval.action.risk_level.value >= 3 for approval in result.approvals)
