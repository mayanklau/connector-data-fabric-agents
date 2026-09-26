from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field


class BrokerMessage(BaseModel):
    id: str = Field(default_factory=lambda: f"msg_{uuid4().hex[:16]}")
    topic: str
    payload: dict[str, Any]
    status: str = "queued"
    attempts: int = 0
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class DatabaseBroker:
    """Durable local fallback. Production deployments use Redis Streams."""

    distributed = False

    def __init__(self, repo: Any) -> None:
        self.repo = repo

    def publish(self, topic: str, payload: dict[str, Any]) -> str:
        message = BrokerMessage(topic=topic, payload=payload)
        self.repo.put("broker_message", message)
        return message.id


class RedisStreamBroker:
    distributed = True

    def __init__(self, url: str, stream: str = "agentic-soc:workflows") -> None:
        try:
            import redis
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError("Redis broker selected but redis dependency is not installed") from exc
        self.client = redis.Redis.from_url(url, decode_responses=True)
        self.stream = stream

    def publish(self, topic: str, payload: dict[str, Any]) -> str:
        return str(self.client.xadd(self.stream, {"topic": topic, "payload": json.dumps(payload)}))

    def ensure_group(self, group: str) -> None:
        try:
            self.client.xgroup_create(self.stream, group, id="0", mkstream=True)
        except Exception as exc:  # BUSYGROUP is expected after first worker
            if "BUSYGROUP" not in str(exc):
                raise

    def consume(self, group: str, consumer: str, block_ms: int = 5000):
        self.ensure_group(group)
        records = self.client.xreadgroup(group, consumer, {self.stream: ">"}, count=1, block=block_ms)
        for _, messages in records:
            for message_id, fields in messages:
                yield message_id, fields["topic"], json.loads(fields["payload"])

    def acknowledge(self, group: str, message_id: str) -> None:
        self.client.xack(self.stream, group, message_id)

    def dead_letter(self, message_id: str, payload: dict[str, Any], error: str) -> None:
        self.client.xadd(f"{self.stream}:dead-letter", {"source_id": message_id, "payload": json.dumps(payload), "error": error})


def create_broker(settings: Any, repo: Any):
    if settings.broker_url:
        return RedisStreamBroker(settings.broker_url)
    return DatabaseBroker(repo)
