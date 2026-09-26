from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import httpx


@dataclass
class ConnectorConfig:
    name: str
    base_url: str
    token: str
    timeout: float


class SecurityProductClient:
    """Vendor-neutral REST boundary for enterprise security products."""

    def __init__(self, config: ConnectorConfig) -> None:
        self.config = config

    @property
    def configured(self) -> bool:
        return bool(self.config.base_url)

    def request(self, operation: str, payload: dict[str, Any]) -> dict[str, Any]:
        if not self.config.base_url:
            return {}
        headers = {"authorization": f"Bearer {self.config.token}"} if self.config.token else {}
        response = httpx.post(
            f"{self.config.base_url.rstrip('/')}/{operation.lstrip('/')}",
            json=payload,
            headers=headers,
            timeout=self.config.timeout,
        )
        response.raise_for_status()
        return response.json()

    def health(self) -> bool:
        if not self.config.base_url:
            return False
        try:
            response = httpx.get(
                f"{self.config.base_url.rstrip('/')}/health",
                headers={"authorization": f"Bearer {self.config.token}"} if self.config.token else {},
                timeout=min(5, self.config.timeout),
            )
            return response.is_success
        except httpx.HTTPError:
            return False


class EDRClient(SecurityProductClient):
    def telemetry(self, entity_id: str) -> dict[str, Any]:
        return self.request("telemetry/search", {"entity_id": entity_id})


class IAMClient(SecurityProductClient):
    def identity(self, entity_id: str) -> dict[str, Any]:
        return self.request("identities/context", {"entity_id": entity_id})


class CloudClient(SecurityProductClient):
    def resource(self, entity_id: str) -> dict[str, Any]:
        return self.request("resources/context", {"entity_id": entity_id})


class CMDBClient(SecurityProductClient):
    def asset(self, entity_id: str) -> dict[str, Any]:
        return self.request("assets/context", {"entity_id": entity_id})


class VulnerabilityClient(SecurityProductClient):
    def findings(self, entity_id: str) -> dict[str, Any]:
        return self.request("findings/search", {"entity_id": entity_id})


class ThreatIntelClient(SecurityProductClient):
    def lookup(self, indicator: str) -> dict[str, Any]:
        return self.request("indicators/lookup", {"indicator": indicator})


class EnterpriseConnectorHub:
    def __init__(self, settings: Any) -> None:
        timeout = settings.connector_timeout_seconds
        self.clients = {
            "edr": EDRClient(ConnectorConfig("edr", settings.edr_url, settings.edr_token, timeout)),
            "iam": IAMClient(ConnectorConfig("iam", settings.iam_url, settings.iam_token, timeout)),
            "cloud": CloudClient(ConnectorConfig("cloud", settings.cloud_url, settings.cloud_token, timeout)),
            "cmdb": CMDBClient(ConnectorConfig("cmdb", settings.cmdb_url, settings.cmdb_token, timeout)),
            "vulnerability": VulnerabilityClient(ConnectorConfig("vulnerability", settings.vulnerability_url, settings.vulnerability_token, timeout)),
            "threat_intel": ThreatIntelClient(ConnectorConfig("threat_intel", settings.threat_intel_url, settings.threat_intel_token, timeout)),
        }

    def status(self, name: str) -> tuple[str, str]:
        client = self.clients[name]
        if not client.configured:
            return "fabric_fallback", "ready"
        return "enterprise_rest", "connected" if client.health() else "degraded"

    def enrich(self, entity_type: str, entity_id: str) -> dict[str, Any]:
        operations = {
            "host": ("edr", "telemetry"),
            "user": ("iam", "identity"),
            "identity": ("iam", "identity"),
            "cloud_resource": ("cloud", "resource"),
            "vulnerability": ("vulnerability", "findings"),
        }
        if entity_type not in operations:
            return {}
        name, method = operations[entity_type]
        client = self.clients[name]
        return getattr(client, method)(entity_id) if client.configured else {}

    def threat_intel(self, indicator: str) -> dict[str, Any]:
        client = self.clients["threat_intel"]
        return client.lookup(indicator) if client.configured else {}
