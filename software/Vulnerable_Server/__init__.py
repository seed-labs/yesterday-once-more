"""Vulnerable_Server: put a vulnerability on machines.

    from software.Vulnerable_Server import MorrisBof, VulnerableServer, vulnerable_hosts

    bof = MorrisBof()                    # pick one vulnerability
    vulns = VulnerableServer(bof)        # the service that installs it
    for victim in VICTIMS:
        vulns.install(victim)            # one virtual node per machine
    emu.addLayer(vulns)

    vulnerable_hosts(emu, bof.name)      # the machines that got it

A vulnerability is useful on its own. Its exploit is optional, and a worm
takes it from the same object: `bof.exploit()`.
"""

from .service import VulnerableServer, vulnerable_hosts
from .vulnerability import Vulnerability
from .morris_bof import MorrisBof, MorrisBofExploit

__all__ = ["MorrisBof", "MorrisBofExploit", "VulnerableServer",
           "Vulnerability", "vulnerable_hosts"]
