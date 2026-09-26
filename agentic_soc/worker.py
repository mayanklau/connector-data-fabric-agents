from __future__ import annotations

import logging
import os
import socket

from agentic_soc.main import get_broker, get_workflows


logger = logging.getLogger("agentic_soc.worker")


def run() -> None:
    broker = get_broker()
    if not getattr(broker, "distributed", False):
        raise RuntimeError("workers require BROKER_URL to point to Redis")
    group = os.getenv("WORKER_GROUP", "agentic-soc-workers")
    consumer = os.getenv("WORKER_NAME", socket.gethostname())
    for message_id, topic, payload in broker.consume(group, consumer):
        try:
            if topic == "workflow.execute":
                get_workflows().process(payload["workflow_id"])
            broker.acknowledge(group, message_id)
        except Exception as exc:  # noqa: BLE001
            logger.exception("workflow message failed")
            broker.dead_letter(message_id, payload, str(exc))


if __name__ == "__main__":
    run()
