from __future__ import annotations

import os

from agentic_soc.plugin_runtime import AgentExecutionRequest, AgentExecutionResult
from agentic_soc.sdk import AgentApplication


agent = AgentApplication("reference-triage-agent", "1.0.0", os.getenv("REFERENCE_AGENT_SECRET", ""))


@agent.capability("triage")
def triage(request: AgentExecutionRequest) -> AgentExecutionResult:
    event = request.event
    severity = event.get("severity", "medium")
    high = severity in {"high", "critical"}
    decision = {
        "agent_type": "triage",
        "disposition": "suspicious" if high else "needs_investigation",
        "severity": severity,
        "confidence": 0.88,
        "summary": f"Reference external agent triaged {event.get('name', 'event')}.",
        "rationale": ["Executed through Agent Protocol 1.0 over the remote agent runtime."],
        "evidence": [],
        "recommended_actions": [],
        "requires_human_review": high,
        "model": "reference-agent-rules-v1",
    }
    return AgentExecutionResult(invocation_id=request.invocation_id, decisions=[decision])


app = agent.app
