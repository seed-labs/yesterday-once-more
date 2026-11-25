"""Vulnerable_Server: the installer (build time).

    bof = MorrisBof()                 one vulnerability
    vulns = VulnerableServer(bof)     puts it on machines
    emu.addLayer(vulns)
    vulns.install("victim1")          one virtual node per machine
    vulns.install("victim2").setVulnerability(other)     a different one there

The service marks every machine it is installed on with the name of its
vulnerability. Any piece can find machines by that mark through Core
(`marked_hosts`), so no piece has to look inside this service. The service
itself knows nothing about individual vulnerabilities: adding one never
changes it.

A machine gets one vulnerability. Core lets a machine carry several marks;
this rule is the service's own.
"""

from seedemu.core import Server, Service

from software.Core.marks import mark, marked_hosts

from .vulnerability import Vulnerability


def vulnerable_hosts(emu, name: str) -> list:
    """The machines that have the vulnerability called `name`.

    The marks are made while the emulation is configured, so ask from a
    service's own rendering, or after `emu.render()`.
    """
    return marked_hosts(emu, name)


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
        self._vulnerability_of = {}            # machine -> the vulnerability installed on it
        self.addDependency("Base", False, False)

    def _createServer(self) -> Server:
        return VulnerableHost(self.default_vulnerability)

    def _doConfigure(self, node, server):
        name = server.vulnerability.name
        installed = self._vulnerability_of.setdefault(node, name)
        if installed != name:
            raise ValueError(
                "as{}/{} cannot have '{}' as well as '{}': a machine gets one vulnerability. "
                "Put it on another machine, or choose one for this one.".format(
                    node.getAsn(), node.getName(), name, installed))
        # Mark the machine now, while the emulation is configured, so that every
        # piece can find it later.
        mark(node, name)

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
