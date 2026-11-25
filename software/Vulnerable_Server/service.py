"""Vulnerable_Server: the installer (build time).

    bof = MorrisBof()                 one vulnerability
    vulns = VulnerableServer(bof)     puts it on machines
    emu.addLayer(vulns)
    vulns.install("victim1")          one virtual node per machine
    vulns.install("victim2").setVulnerability(other)     a different one there

The service marks every machine it is installed on with the name of its
vulnerability. `vulnerable_hosts` finds machines by that mark, so other
pieces never have to look inside this service. The service itself knows
nothing about individual vulnerabilities: adding one never changes it.
"""

from seedemu.core import Server, Service

from .vulnerability import Vulnerability

#: The mark a machine carries: the name of its vulnerability.
MARK = "yom_vulnerability"


def vulnerable_hosts(emu, name: str) -> list:
    """The machines that have the vulnerability called `name`.

    They are found by their mark alone. The marks are set while the emulation
    renders, so ask after `emu.render()` (or from a service's own rendering).
    """
    return [node for (_, kind, _), node in emu.getRegistry().getAll().items()
            if kind == "hnode" and node.getAttribute(MARK) == name]


class VulnerableHost(Server):
    """One installation, on ONE machine."""

    def __init__(self, vulnerability: Vulnerability):
        super().__init__()
        self.vulnerability = vulnerability

    def setVulnerability(self, vulnerability: Vulnerability) -> "VulnerableHost":
        """Give this one machine a different vulnerability than the others."""
        self.vulnerability = vulnerability
        return self

    def install(self, node):
        self.vulnerability.install(node)

    def print(self, indent: int) -> str:
        return " " * indent + "Vulnerable host ({})\n".format(self.vulnerability.name)


class VulnerableServer(Service):
    """A seedemu service: installs a vulnerability on machines."""

    def __init__(self, default_vulnerability: Vulnerability):
        super().__init__()
        if not getattr(default_vulnerability, "name", "") or \
                not callable(getattr(default_vulnerability, "install", None)):
            raise TypeError("choose a vulnerability, for example VulnerableServer(MorrisBof())")
        self.default_vulnerability = default_vulnerability
        self.addDependency("Base", False, False)

    def _createServer(self) -> Server:
        return VulnerableHost(self.default_vulnerability)

    def _doConfigure(self, node, server):
        # Mark the machine now, while the emulation is configured, so that every
        # piece can find it later, the way seedemu's BotnetService publishes
        # its server.
        node.setAttribute(MARK, server.vulnerability.name)

    def render(self, emulator):
        # What a vulnerability needs from the Docker host can only be warned
        # about: the server on the machine waits until it is there.
        seen = []
        for server in self._pending_targets.values():
            if server.vulnerability not in seen:
                seen.append(server.vulnerability)
        for vulnerability in seen:
            for problem in vulnerability.check_host():
                print("WARNING: " + problem)
        super().render(emulator)

    def getName(self) -> str:
        return "VulnerableServer"
