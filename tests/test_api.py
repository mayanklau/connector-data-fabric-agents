from fastapi.testclient import TestClient

from agentic_soc.main import app, get_audit, get_fabric, get_store


def setup_function() -> None:
    get_fabric.cache_clear()
    get_store.cache_clear()
    get_audit.cache_clear()


def test_event_ingestion_api_returns_orchestration_result() -> None:
    client = TestClient(app)
    response = client.post(
        "/events",
        json={
            "source": "siem",
            "name": "Impossible Travel",
            "category": "identity_anomaly",
            "severity": "medium",
            "entities": [
                {"type": "user", "id": "user:maya"},
                {"type": "ip", "id": "185.199.108.153"},
            ],
            "description": "Successful login from a new country.",
        },
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["case"]["status"] == "awaiting_approval"
    assert payload["decisions"]
    assert payload["approvals"]


def test_health() -> None:
    client = TestClient(app)
    assert client.get("/health").json()["status"] == "ok"


def test_connectors_metrics_writebacks_and_approval_decision() -> None:
    client = TestClient(app)
    response = client.post(
        "/events",
        json={
            "source": "siem",
            "name": "Impossible Travel",
            "category": "identity_anomaly",
            "severity": "medium",
            "entities": [
                {"type": "user", "id": "user:maya"},
                {"type": "ip", "id": "185.199.108.153"},
            ],
        },
    )
    payload = response.json()
    approval_id = payload["approvals"][0]["id"]

    connectors = client.get("/connectors").json()
    assert {connector["type"] for connector in connectors} == {"data_fabric", "siem", "soar"}

    writebacks = client.get("/writebacks").json()
    assert {writeback["target"] for writeback in writebacks} == {"siem", "soar"}

    approval_response = client.post(
        f"/approvals/{approval_id}/decision",
        json={"approved": True, "decided_by": "analyst-1", "notes": "Validated evidence."},
    )
    assert approval_response.status_code == 200
    assert approval_response.json()["status"] == "approved"

    metrics = client.get("/metrics").json()
    assert metrics["cases_created"] == 1
    assert metrics["approvals_approved"] == 1
    assert metrics["writebacks_queued"] == 2
