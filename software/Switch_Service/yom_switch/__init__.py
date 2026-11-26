"""The switch's run-time half. Its reader travels inside the worm's bundle.

`reader.py` is what a worm is given for its control slot. `__main__.py` is
the instructor's tool, which runs on the switch's own machine. Both ask the
switch machine by its address (`dnsquery.py`), never through the system
resolver.
"""

from .reader import RUN, PAUSE, STOP, MODES, SwitchReader, SwitchUnreachable

__all__ = ["MODES", "PAUSE", "RUN", "STOP", "SwitchReader", "SwitchUnreachable"]
