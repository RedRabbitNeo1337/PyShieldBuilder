import json
from pathlib import Path
from datetime import datetime, UTC


def write_audit_event(log_path: Path, event: str, payload: dict) -> None:
    record = {
        "timestamp": datetime.now(UTC).isoformat(),
        "event": event,
        "payload": payload,
    }
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record) + "\n")
