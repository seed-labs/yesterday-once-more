"""Switch_Service: the installer (build time).

    switch = DnsSwitch(domain, mode="killswitch")     one machine, one DNS record
    switch.install("switch")                          the machine that holds it
    emu.addLayer(switch)

    worm = Worm(..., control=switch.reader())         the worm asks it: run, pause or stop?

One machine plays the internet for one name. It runs a real BIND server
(seedemu's own DNS server) for the zone the name lives in. Nothing else in
the emulation needs to know about DNS: the worm asks this machine by its
address.
"""

import json
from pathlib import Path

from seedemu.core import Service
from seedemu.services import DomainNameServer, DomainNameService

from software.Core.files import HOME, add_command, place_files

from .yom_switch import MODES, SwitchReader

RUNTIME_DIR = Path(__file__).resolve().parent / "yom_switch"

#: The port the switch machine answers DNS questions on.
DNS_PORT = 53


class DnsSwitch(Service):
    """A switch machine: one machine that holds one DNS record, changed by a command."""

    def __init__(self, domain: str, mode: str = "killswitch", lab_nameserver: bool = False):
        super().__init__()
        domain = domain.strip().rstrip(".")
        if "." not in domain:
            raise ValueError("DnsSwitch needs a name with at least two parts, like 'www.example.com'")
        if mode not in MODES:
            raise ValueError("DnsSwitch needs a mode of {}; not '{}'".format(" or ".join(MODES), mode))
        self.domain = domain                            # the one name the record is about
        self.mode = mode
        self.lab_nameserver = lab_nameserver            # every machine asks this one for names
        self.zone = domain.split(".", 1)[1] + "."       # the zone that name lives in
        self.address = None                             # the switch machine; known once the emulation renders
        # seedemu's DNS server does the real work; this object only holds the zone.
        self._zones = DomainNameService(autoNameServer=False)
        self._readers = []
        self.addDependency("Base", False, False)

    def install(self, vnode: str):
        """Put the switch on one machine. There is never more than one."""
        if self._pending_targets and vnode not in self._pending_targets:
            raise ValueError("the switch runs on one machine; it is already on '{}'".format(
                next(iter(self._pending_targets))))
        return super().install(vnode)

    def reader(self) -> SwitchReader:
        """What a worm's control slot is given: it answers run, pause or stop.

        The reader is made before the switch machine has an address. The
        switch fills the address in by itself when the emulation renders, so
        nobody types it and no piece has to ask for it.
        """
        reader = SwitchReader(domain=self.domain, mode=self.mode, server=self.address, port=DNS_PORT)
        self._readers.append(reader)
        return reader

    def _createServer(self):
        return DomainNameServer().addZone(self.zone)

    def _doConfigure(self, node, server):
        server.configure(node, self._zones)
        self.address = str(node.getInterfaces()[0].getAddress())
        for reader in self._readers:
            reader.server = self.address

    def _doInstall(self, node, server):
        server.install(node, self._zones)           # BIND, its config and its start command
        place_files(node, RUNTIME_DIR, "{}/yom_switch".format(HOME))
        node.setFile("{}/switch.json".format(HOME), json.dumps({
            "mode": self.mode,
            "domain": self.domain,                  # the name the worm asks for, www and all
            "zone": self.zone,
            "server": self.address,
            "port": DNS_PORT,
        }, indent=2) + "\n")
        add_command(node, "switch", "yom_switch")
        verbs = "register | unregister | status" if self.mode == "killswitch" else "run | pause | stop | status"
        print("DnsSwitch: {} is served by as{}/{} ({}). On that machine:  switch {}".format(
            self.domain, node.getAsn(), node.getName(), self.address, verbs))

    def render(self, emulator):
        if len(self._pending_targets) != 1:
            raise ValueError("the switch needs its one machine: call switch.install(<name of the machine>)")
        super().render(emulator)
        if not self.lab_nameserver:
            return        # nothing changes any machine's resolver: the reader asks the switch directly
        # Make every machine in the lab ask this one for names, as machines ask their
        # network's DNS server. Then a student can look the domain up on any machine
        # and see it appear when the instructor registers it. These are the two start
        # commands seedemu writes for a node's name servers. They are added here, at
        # the very end, because seedemu writes its own while it prepares the machines
        # and they would overwrite these.
        mine = emulator.getBindingFor(next(iter(self._pending_targets)))
        scope, kind, _ = mine.getRegistryInfo()
        for node in [mine] + list(emulator.getRegistry().getByType(scope, kind)):
            server = "127.0.0.1" if node is mine else self.address
            node.insertStartCommand(0, ": > /etc/resolv.conf")
            node.insertStartCommand(1, 'echo "nameserver {}" >> /etc/resolv.conf'.format(server))

    def getName(self) -> str:
        return "DnsSwitch"

    def getConflicts(self) -> list:
        return ["DomainNameService", "DomainNameCachingService"]
