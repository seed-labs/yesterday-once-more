"""The instructor's tool. Run it on the switch's own machine.

What it can do depends on the mode of the switch:

    killswitch (the kill switch of the real WannaCry)
        switch register        the domain answers from now on: every worm stops
        switch unregister      it is gone again: worms may spread again
        switch status          is the domain registered, and what would a worm do?

    control (the Morris worm's encoding)
        switch run | pause | stop
        switch status

It changes the DNS record with nsupdate, the same tool the Morris worm
example (control_worm.sh) uses.
"""

import json
import subprocess
import sys
from pathlib import Path

from .dnsquery import query
from .reader import PAUSE, RUN, STOP, SwitchUnreachable, conclude

SETTINGS = Path("/opt/yom/switch.json")
TTL = 5

#: The Morris worm's addresses (control_worm.sh), one per command.
ADDRESSES = {RUN: "0.0.0.0", STOP: "1.0.0.0", PAUSE: "2.0.0.0"}
VERBS = {"killswitch": ("register", "unregister", "status"),
         "control": (RUN, PAUSE, STOP, "status")}


def update(settings, value=None) -> int:
    """Set the switch's record to `value`, or delete it when `value` is None.

    The record is deleted before it is set, so setting it also replaces it.
    """
    lines = ["server {}".format(settings["server"]), "zone {}".format(settings["zone"]),
             "update delete {} A".format(settings["domain"])]
    if value:
        lines.append("update add {} {} A {}".format(settings["domain"], TTL, value))
    result = subprocess.run(["nsupdate"], input="\n".join(lines + ["send"]) + "\n",
                            text=True, capture_output=True)
    sys.stdout.write(result.stdout)
    sys.stderr.write(result.stderr)
    return result.returncode


def describe(settings) -> str:
    """The state of the record, and what a worm would conclude from it."""
    state, address = query(settings["server"], settings["domain"], port=settings["port"])
    if state is None:
        record = "the switch machine did not answer"
    elif state == "refused":
        record = "the switch machine refused to answer for this name"
    elif address is None:
        record = "not registered, so nothing answers"
    else:
        record = "registered at {}".format(address)
    try:
        verdict = "the worm " + {RUN: "runs", PAUSE: "pauses", STOP: "stops"}[
            conclude(settings["mode"], state, address)]
    except SwitchUnreachable as error:
        verdict = "the worm stops ({})".format(error)
    return "{}: {}; {}".format(settings["domain"], record, verdict)


def main(argv) -> int:
    verb = argv[0] if argv else ""
    try:
        settings = json.loads(SETTINGS.read_text(encoding="utf-8"))
    except OSError:
        print("this is not the switch machine: {} is missing".format(SETTINGS))
        return 2
    verbs = VERBS[settings["mode"]]
    if len(argv) != 1 or verb not in verbs:
        print("usage: switch " + " | ".join(verbs))
        return 2
    if verb == "status":
        print(describe(settings))
        return 0
    if verb == "unregister":
        value = None                           # the record goes away
    elif verb == "register":
        value = settings["server"]             # the domain points at the switch machine
    else:
        value = ADDRESSES[verb]                # the Morris worm's encoding
    return update(settings, value)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
