"""Worm: the installer (build time).

    worm = Worm(exploit=bof.exploit(), payload=ransom.payload(),
                control=switch.reader())
    emu.addLayer(worm)
    worm.launchFrom("patient-zero")

This half looks at the rest of the emulation and fills in what a case
should not have to type:

  - who to attack: every machine that is marked with the exploit's
    vulnerability (the marks are read through Core);
  - what every reached machine needs to run the bundle and the payload.

It then puts the worm on patient zero only: its own code, the code of the
parts, the payload's folder with its label, the settings file, and the
one-word `worm` command. Nothing is put on the victims; the worm reaches
them by itself.

The worm never imports another piece. It is handed three small objects (the
exploit, the payload, the control) and it writes each one into its settings
file by looking at it: the class's name and what its constructor took.
"""

import inspect
import json
from pathlib import Path

from seedemu.core import Server, Service

from software.Core import label
from software.Core.files import HOME, add_command, place_files
from software.Core.marks import marked_hosts

from .yom_worm.builtin import ShuffleScanner
from .yom_worm.spec import Pace, SLOTS, describe

RUNTIME_DIR = Path(__file__).resolve().parent / "yom_worm"

#: What any machine needs before the bundle can run there. The installer adds
#: it to every machine the worm can reach, so a victim is never missing it.
BODY_NEEDS = ("python3",)

SLOT_NAMES = {"scanner": "who to attack", "exploit": "how to get in", "control": "when to stop"}


def runtime_dir(part) -> Path:
    """The folder of a part's code: what has to travel inside the bundle."""
    return Path(inspect.getfile(type(part))).resolve().parent


def address_of(node) -> str:
    return str(node.getInterfaces()[0].getAddress())


class Launcher(Server):
    """The worm on the machine where the outbreak starts."""

    def __init__(self, service):
        super().__init__()
        self.service = service

    def install(self, node):
        self.service._install(node)

    def print(self, indent: int) -> str:
        return " " * indent + "Worm launcher\n"


class Worm(Service):
    """The worm as a seedemu service: three slots, started from one machine, carrying a payload."""

    def __init__(self, exploit=None, payload=None, control=None, scanner=None,
                 autostart=False, pace=None):
        super().__init__()
        if exploit is None:
            raise ValueError("a worm needs an exploit: how it gets in (for example bof.exploit())")
        self.scanner = scanner if scanner is not None else ShuffleScanner()
        self.exploit = exploit
        self.payload = payload              # a folder plus a label (Core's Payload), or nothing
        self.control = control              # None: only the time limit can stop it
        self.pace = pace if pace is not None else Pace()
        self.autostart = autostart          # False: a person runs `worm launch`
        for slot in SLOTS:
            if getattr(self, slot) is not None:
                describe(getattr(self, slot))   # complain now, while the case is being written
        if payload is not None and not (hasattr(payload, "folder") and hasattr(payload, "label")):
            raise TypeError("a payload is a folder plus a label (Core's Payload)")
        self.addDependency("Base", False, False)

    def launchFrom(self, vnode):
        """The machine where the outbreak starts (patient zero)."""
        return self.install(vnode)

    def getName(self) -> str:
        return "Worm"

    def print(self, indent: int) -> str:
        out = " " * indent + "Worm:\n"
        for slot in SLOTS:
            part = getattr(self, slot)
            out += " " * (indent + 4) + "{}: {}\n".format(
                slot, type(part).__name__ if part is not None else "none")
        out += " " * (indent + 4) + "payload: {}\n".format(
            self.payload.label.get("name", "?") if self.payload is not None else "none")
        return out

    def _createServer(self) -> Server:
        return Launcher(self)

    def render(self, emulator):
        self._aim(emulator)
        super().render(emulator)

    def _aim(self, emulator):
        """Aim the worm at every machine marked with the exploit's vulnerability."""
        wanted = getattr(type(self.exploit), "vulnerability", None)
        if wanted is None:
            return                 # this exploit is not tied to a mark: the case says who to attack
        targets = marked_hosts(emulator, wanted)
        if not targets:
            raise ValueError(
                "the worm's exploit fits the vulnerability '{}', but no machine is marked with it. "
                "Install that vulnerability on machines first.".format(wanted))
        for node in targets:
            self._provide(node)
        if isinstance(self.scanner, ShuffleScanner) and not self.scanner.targets:
            self.scanner.targets = [address_of(node) for node in targets]

    def _provide(self, node):
        """Give a machine what the bundle and the payload need to run there.

        The bundle is Python. A payload may need more, and says so in its
        label; that is put on every machine the worm can reach as ordinary
        machine software. The payload itself is not.
        """
        software, build = list(BODY_NEEDS), []
        if self.payload is not None:
            needs = self.payload.label.get("needs", {})
            software += [name for name in needs.get("software", []) if name not in software]
            build += [command for command in needs.get("build", []) if command not in build]
        for name in software:
            node.addSoftware(name)
        for command in build:
            node.addBuildCommand(command)

    def _install(self, node):
        packages = []
        for slot in ("exploit", "control"):
            part = getattr(self, slot)
            if part is None:
                continue
            folder = runtime_dir(part)
            if folder != RUNTIME_DIR and folder.name not in packages:
                packages.append(folder.name)
                place_files(node, folder, "{}/{}".format(HOME, folder.name))
            stage = getattr(part, "stage", None)
            if stage:
                stage(node)            # what the part needs on patient zero (a probe program...)
        if self.payload is not None:
            name = self.payload.folder.name
            place_files(node, self.payload.folder, "{}/{}".format(HOME, name))
            node.setFile("{}/{}/{}".format(HOME, name, label.LABEL_FILE),
                         label.label_text(self.payload.label))
        place_files(node, Path(label.__file__), "{}/label.py".format(HOME))
        place_files(node, RUNTIME_DIR, "{}/yom_worm".format(HOME))
        self._provide(node)
        node.setFile("{}/worm.json".format(HOME),
                     json.dumps(self.manifest(packages), indent=2) + "\n")
        add_command(node, "worm", "yom_worm")
        if self.autostart:
            node.appendStartCommand("worm launch", fork=True)

    def manifest(self, packages=()) -> dict:
        """The settings file of the worm, as plain data."""
        manifest = {}
        for slot in SLOTS:
            part = getattr(self, slot)
            if part is not None:
                manifest[slot] = describe(part)
        manifest["payload"] = ({"folder": self.payload.folder.name}
                               if self.payload is not None else None)
        manifest["pace"] = vars(self.pace)
        manifest["packages"] = list(packages)      # the parts' folders; the payload's is carried, not imported
        return manifest
