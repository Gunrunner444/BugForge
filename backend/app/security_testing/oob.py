"""Out-of-band callback correlation.

No network client is included. A missing collaborator is UNAVAILABLE.
A missing callback is ABSENT. A callback never verifies a finding by itself,
and it attaches only to the session and payload that minted its id.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field


@dataclass
class OobEvent:
    correlation_id: str
    session_id: str
    payload_id: str
    body: str = ""
    state: str = "ABSENT"


@dataclass
class OobLedger:
    available: bool = False
    events: dict[str, OobEvent] = field(default_factory=dict)

    def mint(self, session_id: str, payload_id: str) -> OobEvent:
        if not self.available:
            return OobEvent("", session_id, payload_id, state="UNAVAILABLE")
        digest = hashlib.sha256(f"{session_id}:{payload_id}".encode()).hexdigest()[:16]
        event = OobEvent(digest, session_id, payload_id, state="WAITING")
        self.events[digest] = event
        return event

    def receive(self, correlation_id: str, session_id: str, payload_id: str, body: str) -> OobEvent:
        event = self.events.get(correlation_id)
        if event is None or event.session_id != session_id or event.payload_id != payload_id:
            raise ValueError("callback does not belong to this session and payload")
        event.body = body[:200]
        event.state = "CALLBACK"
        return event

    def status(self, correlation_id: str) -> str:
        event = self.events.get(correlation_id)
        if event is None:
            return "UNAVAILABLE" if not self.available else "ABSENT"
        return event.state
