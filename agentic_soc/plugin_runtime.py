from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import threading
import time
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any
from uuid import uuid4

import httpx
from pydantic import BaseModel, Field, field_validator


PROTOCOL_VERSION = "1.0"


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def identifier(prefix: str) -> str:
    return f"{prefix}_{uuid4().hex[:16]}"


def protobuf_json_envelope(payload: bytes) -> bytes:
    length = len(payload)
    encoded_length = bytearray()
    while True:
        byte = length & 0x7F
        length >>= 7
        encoded_length.append(byte | (0x80 if length else 0))
        if not length:
            return b"\x0a" + bytes(encoded_length) + payload


def decode_protobuf_json_envelope(payload: bytes) -> bytes:
    if not payload or payload[0] != 0x0A:
        raise ValueError("invalid gRPC JSON envelope")
    length = 0
    shift = 0
    index = 1
    while index < len(payload):
        byte = payload[index]
        index += 1
        length |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return payload[index:index + length]
        shift += 7
    raise ValueError("truncated gRPC JSON envelope")


class AgentTransport(str, Enum):
    http = "http"
    grpc = "grpc"
    mcp = "mcp"


class AgentStatus(str, Enum):
    unknown = "unknown"
    healthy = "healthy"
    degraded = "degraded"
    unavailable = "unavailable"
    disabled = "disabled"


class AgentAuth(BaseModel):
    type: str = "none"
    secret_ref: str | None = None
    token_url: str | None = None
    client_id: str | None = None
    audience: str | None = None
    ca_cert_ref: str | None = None
    client_cert_ref: str | None = None
    client_key_ref: str | None = None


class AgentLimits(BaseModel):
    timeout_seconds: float = Field(default=15, ge=0.1, le=300)
    max_concurrency: int = Field(default=4, ge=1, le=100)
    failure_threshold: int = Field(default=3, ge=1, le=20)
    recovery_seconds: int = Field(default=30, ge=1, le=3600)


class AgentRegistration(BaseModel):
    id: str = Field(default_factory=lambda: identifier("agent"))
    name: str
    version: str
    protocol_version: str = PROTOCOL_VERSION
    description: str = ""
    capabilities: list[str]
    transport: AgentTransport = AgentTransport.http
    endpoint: str
    health_endpoint: str | None = None
    enabled: bool = True
    scopes: set[str] = Field(default_factory=lambda: {"fabric:read"})
    auth: AgentAuth = Field(default_factory=AgentAuth)
    limits: AgentLimits = Field(default_factory=AgentLimits)
    metadata: dict[str, Any] = Field(default_factory=dict)
    status: AgentStatus = AgentStatus.unknown
    last_health_check: datetime | None = None
    last_error: str | None = None
    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)

    @field_validator("protocol_version")
    @classmethod
    def supported_protocol(cls, value: str) -> str:
        if value.split(".", 1)[0] != PROTOCOL_VERSION.split(".", 1)[0]:
            raise ValueError(f"unsupported protocol version {value}")
        return value


class AgentRegistrationRequest(BaseModel):
    name: str
    version: str
    protocol_version: str = PROTOCOL_VERSION
    description: str = ""
    capabilities: list[str]
    transport: AgentTransport = AgentTransport.http
    endpoint: str
    health_endpoint: str | None = None
    enabled: bool = True
    scopes: set[str] = Field(default_factory=lambda: {"fabric:read"})
    auth: AgentAuth = Field(default_factory=AgentAuth)
    limits: AgentLimits = Field(default_factory=AgentLimits)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("protocol_version")
    @classmethod
    def supported_protocol(cls, value: str) -> str:
        if value.split(".", 1)[0] != PROTOCOL_VERSION.split(".", 1)[0]:
            raise ValueError(f"unsupported protocol version {value}")
        return value


class AgentRegistrationResult(BaseModel):
    agent: AgentRegistration
    api_key: str
    warning: str = "Store this credential now. It cannot be recovered."


class AgentPatch(BaseModel):
    enabled: bool | None = None
    endpoint: str | None = None
    health_endpoint: str | None = None
    capabilities: list[str] | None = None
    scopes: set[str] | None = None
    limits: AgentLimits | None = None
    auth: AgentAuth | None = None


class AgentRoute(BaseModel):
    capability: str
    agent_ids: list[str]
    strategy: str = "priority"
    enabled: bool = True
    updated_at: datetime = Field(default_factory=utcnow)


class AgentExecutionRequest(BaseModel):
    protocol_version: str = PROTOCOL_VERSION
    invocation_id: str = Field(default_factory=lambda: identifier("inv"))
    workflow_id: str | None = None
    capability: str
    event: dict[str, Any]
    context: dict[str, Any] = Field(default_factory=dict)
    callback_url: str | None = None
    deadline: datetime | None = None
    trace_context: dict[str, str] = Field(default_factory=dict)

    @field_validator("protocol_version")
    @classmethod
    def supported_protocol(cls, value: str) -> str:
        if value.split(".", 1)[0] != PROTOCOL_VERSION.split(".", 1)[0]:
            raise ValueError(f"unsupported protocol version {value}")
        return value


class AgentExecutionResult(BaseModel):
    protocol_version: str = PROTOCOL_VERSION
    invocation_id: str
    status: str = "completed"
    decisions: list[dict[str, Any]] = Field(default_factory=list)
    error: str | None = None
    metrics: dict[str, float] = Field(default_factory=dict)

    @field_validator("protocol_version")
    @classmethod
    def supported_protocol(cls, value: str) -> str:
        if value.split(".", 1)[0] != PROTOCOL_VERSION.split(".", 1)[0]:
            raise ValueError(f"unsupported protocol version {value}")
        return value


class AgentCallback(BaseModel):
    protocol_version: str = PROTOCOL_VERSION
    status: str
    decisions: list[dict[str, Any]] = Field(default_factory=list)
    error: str | None = None
    metrics: dict[str, float] = Field(default_factory=dict)

    @field_validator("protocol_version")
    @classmethod
    def supported_protocol(cls, value: str) -> str:
        if value.split(".", 1)[0] != PROTOCOL_VERSION.split(".", 1)[0]:
            raise ValueError(f"unsupported protocol version {value}")
        return value


class AgentInvocation(BaseModel):
    id: str
    agent_id: str
    capability: str
    workflow_id: str | None = None
    status: str = "running"
    attempts: int = 1
    duration_ms: float | None = None
    error: str | None = None
    result: AgentExecutionResult | None = None
    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)


class AgentCredential(BaseModel):
    id: str
    agent_id: str
    key_hash: str
    scopes: set[str]
    enabled: bool = True
    created_at: datetime = Field(default_factory=utcnow)


class SecretResolver:
    def __init__(self, secrets_dir: str = "/run/secrets", allow_literal: bool = False) -> None:
        self.secrets_dir = Path(secrets_dir)
        self.allow_literal = allow_literal

    def resolve(self, reference: str | None) -> str | None:
        if not reference:
            return None
        if reference.startswith("env://"):
            return os.environ.get(reference[6:])
        if reference.startswith("file://"):
            path = Path(reference[7:]).resolve()
            allowed = self.secrets_dir.resolve()
            if allowed not in path.parents and path != allowed:
                raise ValueError("secret file must be inside the configured secrets directory")
            return path.read_text().strip()
        if self.allow_literal:
            return reference
        raise ValueError("production secrets must use env:// or file:// references")

    def path(self, reference: str | None) -> str | None:
        if not reference:
            return None
        value = os.environ.get(reference[6:]) if reference.startswith("env://") else reference[7:] if reference.startswith("file://") else reference
        path = Path(value).resolve()
        if reference.startswith("file://"):
            allowed = self.secrets_dir.resolve()
            if allowed not in path.parents and path != allowed:
                raise ValueError("TLS material must be inside the configured secrets directory")
        elif not self.allow_literal:
            raise ValueError("production TLS paths must use env:// or file:// references")
        return str(path)


class CircuitState:
    def __init__(self) -> None:
        self.failures = 0
        self.open_until = 0.0


class AgentRegistry:
    def __init__(self, repo: Any) -> None:
        self.repo = repo

    def register(self, request: AgentRegistrationRequest) -> tuple[AgentRegistration, str]:
        registration = AgentRegistration(**request.model_dump())
        self.repo.put("agent_registration", registration)
        return registration, self.issue_credential(registration)

    def issue_credential(self, agent: AgentRegistration) -> str:
        token = f"soc_agent_{secrets.token_urlsafe(32)}"
        credential = AgentCredential(
            id=hashlib.sha256(token.encode()).hexdigest()[:20],
            agent_id=agent.id,
            key_hash=hashlib.sha256(token.encode()).hexdigest(),
            scopes=set(agent.scopes) | {"agent:callback", "agent:self"},
        )
        self.repo.put("agent_credential", credential)
        return token

    def authenticate(self, token: str) -> AgentCredential | None:
        candidate = hashlib.sha256(token.encode()).hexdigest()
        for credential in self.repo.list("agent_credential", AgentCredential):
            if credential.enabled and hmac.compare_digest(candidate, credential.key_hash):
                return credential
        return None

    def list(self) -> list[AgentRegistration]:
        return self.repo.list("agent_registration", AgentRegistration)

    def get(self, agent_id: str) -> AgentRegistration | None:
        return self.repo.get("agent_registration", agent_id, AgentRegistration)

    def patch(self, agent_id: str, patch: AgentPatch) -> AgentRegistration | None:
        agent = self.get(agent_id)
        if not agent:
            return None
        values = {key: getattr(patch, key) for key in patch.model_fields_set if getattr(patch, key) is not None}
        values["updated_at"] = utcnow()
        agent = agent.model_copy(update=values)
        if not agent.enabled:
            agent.status = AgentStatus.disabled
        self.repo.put("agent_registration", agent)
        return agent

    def routes(self) -> list[AgentRoute]:
        return self.repo.list("agent_route", AgentRoute)

    def save_route(self, route: AgentRoute) -> AgentRoute:
        for agent_id in route.agent_ids:
            if not self.get(agent_id):
                raise ValueError(f"unknown agent {agent_id}")
        self.repo.put("agent_route", route)
        return route

    def candidates(self, capability: str) -> list[AgentRegistration]:
        agents = {agent.id: agent for agent in self.list() if agent.enabled and capability in agent.capabilities}
        route = next((item for item in self.routes() if item.capability == capability and item.enabled), None)
        if route:
            return [agents[agent_id] for agent_id in route.agent_ids if agent_id in agents]
        return sorted(agents.values(), key=lambda item: item.created_at)


class ExternalAgentRuntime:
    def __init__(self, repo: Any, settings: Any) -> None:
        self.repo = repo
        self.settings = settings
        self.registry = AgentRegistry(repo)
        self.secrets = SecretResolver(
            settings.secrets_dir,
            allow_literal=settings.app_env in {"local", "demo", "test"},
        )
        self._circuits: dict[str, CircuitState] = {}
        self._semaphores: dict[str, threading.BoundedSemaphore] = {}

    def invocations(self) -> list[AgentInvocation]:
        return self.repo.list("agent_invocation", AgentInvocation)

    def get_invocation(self, invocation_id: str) -> AgentInvocation | None:
        return self.repo.get("agent_invocation", invocation_id, AgentInvocation)

    def _headers(self, agent: AgentRegistration) -> dict[str, str]:
        headers = {"content-type": "application/json", "x-agent-protocol": PROTOCOL_VERSION}
        if agent.auth.type == "bearer":
            token = self.secrets.resolve(agent.auth.secret_ref)
            if token:
                headers["authorization"] = f"Bearer {token}"
        elif agent.auth.type == "oauth2_client_credentials":
            secret = self.secrets.resolve(agent.auth.secret_ref)
            if not agent.auth.token_url or not agent.auth.client_id or not secret:
                raise ValueError("OAuth2 agent authentication is incomplete")
            response = httpx.post(
                agent.auth.token_url,
                data={
                    "grant_type": "client_credentials",
                    "client_id": agent.auth.client_id,
                    "client_secret": secret,
                    "audience": agent.auth.audience or "",
                },
                timeout=agent.limits.timeout_seconds,
            )
            response.raise_for_status()
            headers["authorization"] = f"Bearer {response.json()['access_token']}"
        elif agent.auth.type == "workload_identity":
            token_ref = agent.auth.secret_ref or f"file://{os.getenv('WORKLOAD_IDENTITY_TOKEN_FILE', '/var/run/secrets/tokens/identity-token')}"
            token = self.secrets.resolve(token_ref)
            if not token:
                raise ValueError("workload identity token is unavailable")
            headers["authorization"] = f"Bearer {token}"
        return headers

    def _tls(self, agent: AgentRegistration) -> tuple[str | bool, tuple[str, str] | None]:
        verify: str | bool = self.secrets.path(agent.auth.ca_cert_ref) or True
        cert_path = self.secrets.path(agent.auth.client_cert_ref)
        key_path = self.secrets.path(agent.auth.client_key_ref)
        return verify, (cert_path, key_path) if cert_path and key_path else None

    def _http(self, agent: AgentRegistration, request: AgentExecutionRequest) -> AgentExecutionResult:
        verify, cert = self._tls(agent)
        with httpx.Client(verify=verify, cert=cert, timeout=agent.limits.timeout_seconds) as client:
            response = client.post(agent.endpoint, json=request.model_dump(mode="json"), headers=self._headers(agent))
            response.raise_for_status()
            return AgentExecutionResult.model_validate(response.json())

    def _mcp(self, agent: AgentRegistration, request: AgentExecutionRequest) -> AgentExecutionResult:
        verify, cert = self._tls(agent)
        payload = {
            "jsonrpc": "2.0",
            "id": request.invocation_id,
            "method": "tools/call",
            "params": {"name": "execute_security_agent", "arguments": request.model_dump(mode="json")},
        }
        with httpx.Client(verify=verify, cert=cert, timeout=agent.limits.timeout_seconds) as client:
            response = client.post(agent.endpoint, json=payload, headers=self._headers(agent))
            response.raise_for_status()
            body = response.json()
            if "error" in body:
                raise RuntimeError(str(body["error"]))
            result = body.get("result", body)
            if isinstance(result, dict) and "structuredContent" in result:
                result = result["structuredContent"]
            return AgentExecutionResult.model_validate(result)

    def _grpc(self, agent: AgentRegistration, request: AgentExecutionRequest) -> AgentExecutionResult:
        try:
            import grpc
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError("install the grpc optional dependency to use gRPC agents") from exc
        channel = grpc.secure_channel(agent.endpoint, grpc.ssl_channel_credentials()) if agent.endpoint.endswith(":443") else grpc.insecure_channel(agent.endpoint)
        call = channel.unary_unary(
            "/agentic.soc.v1.AgentService/Execute",
            request_serializer=lambda value: protobuf_json_envelope(value.model_dump_json().encode()),
            response_deserializer=lambda value: AgentExecutionResult.model_validate_json(decode_protobuf_json_envelope(value)),
        )
        return call(request, timeout=agent.limits.timeout_seconds)

    def execute(
        self,
        capability: str,
        event: dict[str, Any],
        workflow_id: str | None = None,
        context: dict[str, Any] | None = None,
    ) -> list[AgentExecutionResult]:
        results = []
        for agent in self.registry.candidates(capability):
            circuit = self._circuits.setdefault(agent.id, CircuitState())
            if circuit.open_until > time.monotonic():
                continue
            semaphore = self._semaphores.setdefault(agent.id, threading.BoundedSemaphore(agent.limits.max_concurrency))
            if not semaphore.acquire(blocking=False):
                continue
            request = AgentExecutionRequest(
                workflow_id=workflow_id,
                capability=capability,
                event=event,
                context=context or {},
                callback_url=f"{self.settings.public_base_url}/agent-invocations/{{invocation_id}}/callback",
                deadline=utcnow() + timedelta(seconds=agent.limits.timeout_seconds),
            )
            request.callback_url = request.callback_url.replace("{invocation_id}", request.invocation_id)
            invocation = AgentInvocation(id=request.invocation_id, agent_id=agent.id, capability=capability, workflow_id=workflow_id)
            self.repo.put("agent_invocation", invocation)
            started = time.perf_counter()
            try:
                handlers = {AgentTransport.http: self._http, AgentTransport.grpc: self._grpc, AgentTransport.mcp: self._mcp}
                result = handlers[agent.transport](agent, request)
                invocation.status = result.status
                invocation.result = result
                circuit.failures = 0
                results.append(result)
            except Exception as exc:  # noqa: BLE001
                circuit.failures += 1
                if circuit.failures >= agent.limits.failure_threshold:
                    circuit.open_until = time.monotonic() + agent.limits.recovery_seconds
                invocation.status = "failed"
                invocation.error = str(exc)
            finally:
                invocation.duration_ms = (time.perf_counter() - started) * 1000
                invocation.updated_at = utcnow()
                self.repo.put("agent_invocation", invocation)
                semaphore.release()
            if results and self.registry.routes() and next((route for route in self.registry.routes() if route.capability == capability and route.strategy == "priority"), None):
                break
        return results

    def callback(self, invocation_id: str, callback: AgentCallback, agent_id: str) -> AgentInvocation:
        invocation = self.get_invocation(invocation_id)
        if not invocation:
            raise KeyError("invocation not found")
        if invocation.agent_id != agent_id:
            raise PermissionError("credential does not own this invocation")
        result = AgentExecutionResult(invocation_id=invocation_id, **callback.model_dump())
        invocation.status = callback.status
        invocation.error = callback.error
        invocation.result = result
        invocation.updated_at = utcnow()
        self.repo.put("agent_invocation", invocation)
        return invocation

    def health(self, agent_id: str) -> AgentRegistration:
        agent = self.registry.get(agent_id)
        if not agent:
            raise KeyError("agent not found")
        if not agent.enabled:
            return agent
        endpoint = agent.health_endpoint or agent.endpoint
        try:
            if agent.transport == AgentTransport.grpc:
                raise RuntimeError("gRPC health requires the standard grpc.health.v1 service")
            verify, cert = self._tls(agent)
            with httpx.Client(verify=verify, cert=cert, timeout=min(5, agent.limits.timeout_seconds)) as client:
                response = client.get(endpoint, headers=self._headers(agent))
                response.raise_for_status()
            agent.status = AgentStatus.healthy
            agent.last_error = None
        except Exception as exc:  # noqa: BLE001
            agent.status = AgentStatus.unavailable
            agent.last_error = str(exc)
        agent.last_health_check = utcnow()
        agent.updated_at = utcnow()
        self.repo.put("agent_registration", agent)
        return agent
