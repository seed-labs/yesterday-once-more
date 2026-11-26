"""Ransomware: the installer (build time).

    ransom = Ransomware(documents="/home/seed/Documents", suffix=".WNCRY",
                        note=NOTE, price_eth=1)
    ransom.paymentIn(lab, "net0", emu=emu)          brings its payment chain
    ransom.operatorTools("patient-zero", network=lab)   the operator's tools
    emu.addLayer(ransom)

    worm = Worm(..., payload=ransom.payload())      the worm carries it

What this puts into the emulation:

  - at build time, the payment machines where the case says: three chain
    nodes, a faucet, and a utility server that deploys the RansomExchange
    contract (see payment/);
  - at build time, the operator's tools on the machine the case names. The
    operator's key pair is created when that machine boots, and a command
    answers paid requests;
  - nothing at all on the victims. The ransomware is what the worm carries:
    `payload()` hands its folder and its label to the worm.

The payload carries the operator's public key only. The private key never
leaves the operator's machine.
"""

import json
from pathlib import Path

from software.Core import label
from software.Core.files import HOME, add_command, place_files
from software.Core.label import Payload, new_label

from .payment import PaymentChain

# Only the light module of the payload's half is used here: where it keeps
# its files. The payload's own code needs libraries that exist on machines,
# not on the one that builds the emulation.
from .yom_ransomware import paths

RUNTIME_DIR = Path(__file__).resolve().parent / "yom_ransomware"

#: The folder a victim's files live in, unless a case says otherwise.
DOCUMENTS = "/home/seed/Documents"

#: What every machine needs before the payload's code can run there.
NEEDS = {
    "software": ["python3-cryptography", "python3-pip"],
    "build": ["pip3 install --break-system-packages eth-account==0.13.7"],
}

#: The price the shipped contract is built for: its price is a constant in
#: the contract, because chain-seed's deployment cannot pass arguments.
CONTRACT_PRICE_ETH = 1


class Ransomware(PaymentChain):
    """The ransomware as a seedemu service: its payment chain, its operator's tools, and its payload."""

    def __init__(self, documents: str = DOCUMENTS, suffix: str = ".WNCRY",
                 note: str = None, price_eth: int = CONTRACT_PRICE_ETH):
        super().__init__()
        if not suffix.startswith("."):
            raise ValueError(f"'{suffix}' is not a file suffix like '.WNCRY'")
        if price_eth != CONTRACT_PRICE_ETH:
            raise ValueError(
                "the shipped RansomExchange contract is built for a price of {} ETH (its price is "
                "a constant in the contract), so price_eth={} would make every payment revert".format(
                    CONTRACT_PRICE_ETH, price_eth))
        self._operator = None
        self._payload = Payload(RUNTIME_DIR, new_label(
            name="ransomware",
            start="python3 -m yom_ransomware detonate",
            settings={
                "documents": documents,
                "suffix": suffix,
                "note": note,                # None: the payload's own note is used
                "price_eth": price_eth,
                "payment": None,            # filled in by paymentIn, once addresses exist
            },
            needs={name: list(wanted) for name, wanted in NEEDS.items()},
        ))

    def payload(self) -> Payload:
        """What the worm carries: the ransomware's folder and its label."""
        return self._payload

    def paymentIn(self, asn, network: str = "net0", emu=None) -> None:
        """Bring the payment chain: three chain nodes, a faucet and the utility server."""
        super().installIn(asn, network, emu)

    def operatorTools(self, machine, network=None) -> None:
        """Put the operator's tools on a machine, named as the case named it.

        The key pair is created when the machine boots (`ransom init`), which
        also puts the public half into the payload's label: the worm is
        launched from this machine and packs that folder.
        """
        node = machine
        if not hasattr(node, "getFiles"):
            if network is None:
                raise ValueError("'{}' is a name: pass the network that holds it (network=...)".format(machine))
            try:
                node = network.getHost(machine)
            except (KeyError, TypeError) as error:
                raise ValueError("no machine named '{}' in that network".format(machine)) from error
        place_files(node, RUNTIME_DIR, "{}/yom_ransomware".format(HOME))
        place_files(node, Path(label.__file__), "{}/label.py".format(HOME))
        add_command(node, "ransom", "yom_ransomware")
        for package in NEEDS["software"]:
            node.addSoftware(package)
        for command in NEEDS["build"]:
            node.addBuildCommand(command)
        # The account that deployed the contract is the contract's "attacker".
        node.setFile(str(paths.CHAIN_KEY), json.dumps(self.chain_key, indent=2) + "\n")
        node.appendStartCommand("ransom init")
        self._operator = node

    def configure(self, emulator):
        super().configure(emulator)
        if self.chain:
            settings = self._payload.label["settings"]
            settings["payment"] = dict(self.chain, ransom_wei=settings["price_eth"] * 10**18)

    def render(self, emulator):
        super().render(emulator)                # the payment machines, if any
        if self._operator is not None and self.chain:
            self._operator.setFile(str(paths.OPERATOR_CHAIN),
                                   json.dumps(self._payload.label["settings"]["payment"], indent=2) + "\n")

    def getName(self) -> str:
        return "Ransomware"
