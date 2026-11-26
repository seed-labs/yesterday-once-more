"""Rebuild the three parts on a new machine from the settings file."""

import importlib
import sys
from pathlib import Path

from .spec import SLOTS

#: The module that holds the parts shipping with the worm itself.
BUILTIN = "yom_worm.builtin"


def load(home: Path, packages) -> dict:
    """Import the worm's own parts and the extra packages the bundle carries.

    Returns {(slot, class name): class}.
    """
    if str(home) not in sys.path:
        sys.path.insert(0, str(home))
    found = {}
    for name in [BUILTIN] + list(packages):
        for obj in vars(importlib.import_module(name)).values():
            if isinstance(obj, type) and getattr(obj, "SLOT", None) in SLOTS:
                found[(obj.SLOT, obj.__name__)] = obj
    return found


def build(registry: dict, slot: str, spec) -> object:
    """Make one part from what the settings file says about it."""
    key = (slot, spec["type"])
    if key not in registry:
        raise LookupError("no {} named {} was shipped inside the bundle".format(slot, spec["type"]))
    return registry[key](**spec["settings"])
