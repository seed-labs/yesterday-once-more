"""What a worm is made of: three slots and a pace. Plain data, no seedemu.

A slot is filled by any class that follows three rules:

  - a class attribute SLOT naming the slot it fills;
  - a constructor whose arguments are plain data (strings, numbers, lists),
    each kept in an attribute of the same name;
  - the method of its slot.

That is all the worm needs to write a part into its settings file and build
it again on the next machine. Nothing has to be registered anywhere.
"""

import inspect

RUN, PAUSE, STOP = "run", "pause", "stop"

#: slot -> the method it must have
SLOTS = {
    "scanner": "next_target",
    "exploit": "break_in",
    "control": "answer",
}


class Pace:
    """Small settings of the loop itself."""

    def __init__(self, attempt_delay=2.0, announce_wait=8.0, body_wait=8.0,
                 max_seconds=1800, startup_wait=60, pause_seconds=5, announce_port=9998):
        self.attempt_delay = attempt_delay    # seconds between two attempts
        self.announce_wait = announce_wait    # how long to wait for a machine to answer
        self.body_wait = body_wait            # how long to wait for a machine to take the bundle
        self.max_seconds = max_seconds        # the worm always stops after this (a safety limit)
        self.startup_wait = startup_wait      # how long to wait for the switch machine at start
        self.pause_seconds = pause_seconds    # how long a pause lasts before asking again
        self.announce_port = announce_port    # UDP port that machines answer on


def describe(part) -> dict:
    """Write one part as plain data: its class name and its constructor arguments.

    Only the constructor's arguments are written. Anything else a part keeps
    (its running state, private helpers) stays behind, because the next
    machine builds the part by calling its constructor again.
    """
    kind = type(part)
    slot = getattr(kind, "SLOT", None)
    if slot not in SLOTS:
        raise TypeError("{} is not a worm part: give the class a SLOT of {}".format(
            kind.__name__, list(SLOTS)))
    method = SLOTS[slot]
    if not callable(getattr(part, method, None)):
        raise TypeError("{} fills the '{}' slot but has no {}()".format(kind.__name__, slot, method))
    settings = {}
    for name, parameter in inspect.signature(kind.__init__).parameters.items():
        if name == "self" or parameter.kind in (parameter.VAR_POSITIONAL, parameter.VAR_KEYWORD):
            continue
        if not hasattr(part, name):
            raise TypeError("{} must keep its argument '{}' in an attribute of the same name, "
                            "or the next machine cannot rebuild it".format(kind.__name__, name))
        settings[name] = getattr(part, name)
    return {"type": kind.__name__, "settings": settings}
