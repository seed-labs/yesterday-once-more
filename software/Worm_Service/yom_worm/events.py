"""One line per thing the worm does, in JSON, so that people and maps can read it."""

import json
import time
from pathlib import Path


def make_logger(home: Path):
    """A log() that prints and appends to events.jsonl in the worm's folder."""
    path = Path(home) / "events.jsonl"

    def log(event, **fields):
        record = {"time": time.strftime("%Y-%m-%dT%H:%M:%S"), "event": event}
        record.update(fields)
        line = json.dumps(record)
        print(line, flush=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")

    return log
