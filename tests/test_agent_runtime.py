from __future__ import annotations

from fastapi.testclient import TestClient

from agentic_soc.main import (
    AgentDecision,
    AgentType,
    Case,
    Disposition,
    Severity,
    WorkflowRun,
    app,
    get_agent_runtime,
    get_repo,
    get_store,
    reset_state_for_tests,
)
from agentic_soc.plugin_runtime import (
    AgentExecutionResult,
    AgentInvocation,
    AgentRegistrationRequest,
    AgentRoute,
    decode_protobuf_json_envelope,
    protobuf_json_envelope,
)
from agentic_soc.reference_agent import app as reference_app


ADMIN = {"X-API-Key": "dev-admin-key"}


def setup_function() -> None:
    reset_state_for_tests()


def registration_payload(**overrides):
    payload = {
        "name": "remote-triage",
        "version": "1.2.0",
        "protocol_version": "1.0",
        "capabilities": ["triage"],
        "transport": "http",
        "endpoint": "http://agent.example/execute",
        "health_endpoint": "http://agent.example/health",
        "scopes": ["fabric:read", "cases:write"],
        "limits": {
            "timeout_seconds": 1,
            "max_concurrency": 2,
            "failure_threshold": 1,
            "recovery_seconds": 60,
        },
    }
    payload.update(overrides)
    return payload


def test_agent_registration_discovery_routing_and_owned_callback() -> None:
    client = TestClient(app)
    created = client.post("/agents", headers=ADMIN, json=registration_payload())
    assert created.status_code == 201
    result = created.json()
    agent_id = result["agent"]["id"]
    assert result["api_key"].startswith("soc_agent_")
    assert client.get("/agents?capability=triage", headers=ADMIN).json()[0]["id"] == agent_id

    route = {"capability": "triage", "agent_ids": [agent_id], "strategy": "priority"}
    assert client.put("/agent-routes/triage", headers=ADMIN, json=route).status_code == 200

    invocation = AgentInvocation(id="inv_callback", agent_id=agent_id, capability="triage", status="accepted")
    get_repo().put("agent_invocation", invocation)
    callback = client.post(
        "/agent-invocations/inv_callback/callback",
        headers={"X-API-Key": result["api_key"]},
        json={"protocol_version": "1.0", "status": "completed", "decisions": []},
    )
    assert callback.status_code == 200
    assert callback.json()["status"] == "completed"


def test_incompatible_protocol_is_rejected() -> None:
    response = TestClient(app).post(
        "/agents",
        headers=ADMIN,
        json=registration_payload(protocol_version="2.0"),
    )
    assert response.status_code == 422


def test_external_decision_replaces_builtin_without_code_change(monkeypatch) -> None:
    runtime = get_agent_runtime()
    agent, _ = runtime.registry.register(AgentRegistrationRequest.model_validate(registration_payload()))

    def completed(_agent, request):
        return AgentExecutionResult(
            invocation_id=request.invocation_id,
            decisions=[
                {
                    "agent_type": "triage",
                    "disposition": "suspicious",
                    "severity": "high",
                    "confidence": 0.91,
                    "summary": "Decision produced by registered external agent.",
                    "requires_human_review": True,
                }
            ],
        )

    monkeypatch.setattr(runtime, "_http", completed)
    runtime.registry.save_route(AgentRoute(capability="triage", agent_ids=[agent.id], strategy="priority"))
    response = TestClient(app).post(
        "/events/sync",
        headers=ADMIN,
        json={"source": "iam", "name": "External agent contract", "category": "identity", "severity": "high"},
    )
    assert response.status_code == 200
    assert response.json()["decisions"][0]["summary"] == "Decision produced by registered external agent."


def test_failure_opens_circuit_and_builtin_can_continue() -> None:
    runtime = get_agent_runtime()
    runtime.registry.register(AgentRegistrationRequest.model_validate(registration_payload(endpoint="http://127.0.0.1:1/execute")))
    assert runtime.execute("triage", {"name": "failure injection"}) == []
    first_count = len(runtime.invocations())
    assert runtime.execute("triage", {"name": "circuit should be open"}) == []
    assert len(runtime.invocations()) == first_count


def test_reference_sdk_agent_contract() -> None:
    client = TestClient(reference_app)
    response = client.post(
        "/execute",
        json={
            "protocol_version": "1.0",
            "invocation_id": "inv_sdk",
            "capability": "triage",
            "event": {"name": "SDK contract", "severity": "high"},
        },
    )
    assert response.status_code == 200
    assert response.json()["invocation_id"] == "inv_sdk"
    assert response.json()["decisions"][0]["agent_type"] == "triage"


def test_asynchronous_callback_replaces_fallback_decision() -> None:
    runtime = get_agent_runtime()
    agent, api_key = runtime.registry.register(AgentRegistrationRequest.model_validate(registration_payload()))
    fallback = AgentDecision(
        agent_type=AgentType.triage,
        disposition=Disposition.needs_investigation,
        severity=Severity.medium,
        confidence=0.5,
        summary="Built-in fallback",
    )
    case = get_store().save_case(Case(title="Async case", source_event_id="evt_async", severity=Severity.medium, decisions=[fallback]))
    workflow = WorkflowRun(event_id="evt_async", idempotency_key="async-test", status="completed", result_case_id=case.id)
    get_repo().put_workflow(workflow)
    get_repo().put("agent_invocation", AgentInvocation(id="inv_async", agent_id=agent.id, capability="triage", workflow_id=workflow.id, status="accepted"))
    response = TestClient(app).post(
        "/agent-invocations/inv_async/callback",
        headers={"X-API-Key": api_key},
        json={
            "status": "completed",
            "decisions": [{"agent_type": "triage", "disposition": "suspicious", "severity": "high", "confidence": 0.9, "summary": "Asynchronous external decision"}],
        },
    )
    assert response.status_code == 200
    assert get_store().get_case(case.id).decisions[0].summary == "Asynchronous external decision"


def test_grpc_json_envelope_contract() -> None:
    payload = b'{"protocol_version":"1.0"}' * 10
    assert decode_protobuf_json_envelope(protobuf_json_envelope(payload)) == payload


def test_registry_handles_large_discovery_set() -> None:
    runtime = get_agent_runtime()
    for index in range(100):
        runtime.registry.register(
            AgentRegistrationRequest.model_validate(
                registration_payload(name=f"load-agent-{index}", endpoint=f"http://agent-{index}.example/execute")
            )
        )
    assert len(runtime.registry.list()) == 100
