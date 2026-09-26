from __future__ import annotations

from collections.abc import Callable
from typing import Any, Union

import httpx
from fastapi import FastAPI, Header, HTTPException

from agentic_soc.plugin_runtime import AgentExecutionRequest, AgentExecutionResult


Handler = Callable[[AgentExecutionRequest], Union[AgentExecutionResult, dict[str, Any]]]


class AgentApplication:
    """Small SDK for implementing protocol-compatible external agents."""

    def __init__(self, name: str, version: str, api_key: str = "") -> None:
        self.name = name
        self.version = version
        self.api_key = api_key
        self.handlers: dict[str, Handler] = {}
        self.app = FastAPI(title=name, version=version)
        self.app.add_api_route("/health", self.health, methods=["GET"])
        self.app.add_api_route("/execute", self.execute, methods=["POST"], response_model=AgentExecutionResult)
        self.app.add_api_route("/mcp", self.mcp, methods=["POST"])

    def capability(self, name: str):
        def decorator(handler: Handler) -> Handler:
            self.handlers[name] = handler
            return handler

        return decorator

    def health(self) -> dict[str, Any]:
        return {"status": "healthy", "agent": self.name, "version": self.version, "capabilities": sorted(self.handlers)}

    def execute(self, request: AgentExecutionRequest, authorization: str | None = Header(default=None)) -> AgentExecutionResult:
        if self.api_key and authorization != f"Bearer {self.api_key}":
            raise HTTPException(status_code=401, detail="invalid agent runtime credential")
        handler = self.handlers.get(request.capability)
        if not handler:
            raise HTTPException(status_code=422, detail=f"unsupported capability {request.capability}")
        result = handler(request)
        if isinstance(result, AgentExecutionResult):
            return result
        return AgentExecutionResult(invocation_id=request.invocation_id, **result)

    def mcp(self, payload: dict[str, Any]) -> dict[str, Any]:
        if payload.get("method") != "tools/call" or payload.get("params", {}).get("name") != "execute_security_agent":
            return {"jsonrpc": "2.0", "id": payload.get("id"), "error": {"code": -32601, "message": "method not found"}}
        request = AgentExecutionRequest.model_validate(payload["params"]["arguments"])
        result = self.execute(request)
        return {"jsonrpc": "2.0", "id": payload.get("id"), "result": {"structuredContent": result.model_dump(mode="json")}}


class ControlPlaneClient:
    def __init__(self, base_url: str, api_key: str) -> None:
        self.base_url = base_url.rstrip("/")
        self.headers = {"x-api-key": api_key}

    def callback(self, invocation_id: str, result: AgentExecutionResult) -> dict[str, Any]:
        response = httpx.post(
            f"{self.base_url}/agent-invocations/{invocation_id}/callback",
            headers=self.headers,
            json={
                "protocol_version": result.protocol_version,
                "status": result.status,
                "decisions": result.decisions,
                "error": result.error,
                "metrics": result.metrics,
            },
            timeout=15,
        )
        response.raise_for_status()
        return response.json()
