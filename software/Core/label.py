"""The label of a payload.

A payload is a folder plus a label. The label is all the worm ever needs to
know about a payload, so the worm and the piece that made the payload never
depend on each other. It holds four things:

    name      what the payload is called (it shows up in the worm's log)
    start     the command that does the payload's own work on a machine the
              worm just arrived on; it ends when that work is done
    settings  whatever the payload needs to know; only the payload reads them
    needs     what a machine needs before the start command can run there:
              "software" (packages) and "build" (commands run while the
              machine's image is built)

The piece that provides the payload (the writer) and the worm (the reader)
both import this file and nothing of each other. It uses only the standard
library, so the same file can travel inside the worm's bundle.

The label is a file called `label.json` inside the payload's folder, where
the start command can read its settings.
"""

import json
from pathlib import Path

LABEL_FILE = "label.json"

REQUIRED = ("name", "start")


class Payload:
    """A payload: the folder that holds its code, and its label."""

    def __init__(self, folder, label: dict):
        self.folder = Path(folder).resolve()
        self.label = label


def new_label(name: str, start: str, settings: dict = None, needs: dict = None) -> dict:
    """A label as plain data, ready to be written."""
    return {"name": name, "start": start, "settings": settings or {}, "needs": needs or {}}


def label_text(label: dict) -> str:
    """A label as the text of its file.

    Whoever places a payload on a machine at build time writes this text
    there; whoever writes one on a machine at run time uses `write_label`.
    """
    for key in REQUIRED:
        if not label.get(key):
            raise ValueError(f"a label needs a {key}")
    return json.dumps(label, indent=2) + "\n"


def write_label(folder, label: dict) -> Path:
    """Write a label into a payload's folder."""
    path = Path(folder) / LABEL_FILE
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(label_text(label), encoding="utf-8")
    return path


def read_label(folder) -> dict:
    """Read the label of the payload whose folder this is."""
    path = Path(folder) / LABEL_FILE
    try:
        label = json.loads(path.read_text(encoding="utf-8"))
    except OSError as error:
        raise ValueError(f"no payload in {Path(folder)}: {LABEL_FILE} is missing") from error
    for key in REQUIRED:
        if not label.get(key):
            raise ValueError(f"the payload in {Path(folder)} has no {key} in its label")
    label.setdefault("settings", {})
    label.setdefault("needs", {})
    return label
