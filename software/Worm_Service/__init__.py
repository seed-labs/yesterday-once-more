"""Worm_Service: the spread loop with three slots the case fills in.

    from software.Worm_Service import Worm

    worm = Worm(exploit=bof.exploit(),          # how to get in: from the vulnerability
                payload=ransom.payload(),       # what to carry: a folder plus a label
                control=switch.reader())        # when to stop: run, pause or stop
    emu.addLayer(worm)
    worm.launchFrom("patient-zero")

A case may leave `payload` and `control` out: the worm then carries nothing,
and only the time limit can stop it. Who to attack is filled in by the
installer: every machine marked with the exploit's vulnerability.
"""

from .service import ShuffleScanner, Worm
from .yom_worm.spec import PAUSE, RUN, STOP, Pace

__all__ = ["PAUSE", "Pace", "RUN", "STOP", "ShuffleScanner", "Worm"]
