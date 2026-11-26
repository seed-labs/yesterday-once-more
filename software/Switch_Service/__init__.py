"""Switch_Service: one machine that holds one DNS record, and a worm that obeys it.

    from software.Switch_Service import DnsSwitch

    switch = DnsSwitch(domain, mode="killswitch")     one machine, one record
    switch.install("switch")                          the machine that holds it
    emu.addLayer(switch)

    worm = Worm(..., control=switch.reader())         the worm asks it: run, pause or stop?

Two modes. In "killswitch" the record is the kill switch of the real WannaCry:
absent, the worm runs; registered, every worm stops. In "control" the record
carries Prof. Du's encoding and the instructor flips it by hand.
"""

from .service import DnsSwitch
from .yom_switch import MODES, SwitchReader, SwitchUnreachable

__all__ = ["MODES", "DnsSwitch", "SwitchReader", "SwitchUnreachable"]
