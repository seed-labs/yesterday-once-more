#!/usr/bin/env python3
"""Y51 WannaCry (2017): a worm that carries ransomware.

The whole picture in one case. Three victims have documents. The worm breaks
in through a buffer overflow, carries the ransomware with it, and locks them.
A victim pays on a private chain and gets its documents back. The instructor
can stop every worm with the kill switch of the real WannaCry.

Needs Docker, and ASLR switched off on the host while the lab runs (the
Morris worm lab needs the same). Restore it afterwards with =2:

    sudo sysctl -w kernel.randomize_va_space=0

Build and start, from this folder:

    ../../.venv/bin/python emulator.py                 build ./output
    cd output
    docker compose up -d --build                      the first build takes a while
    docker compose logs hnode_180_ransom-utility      wait for "Contract deployed"
    curl -X POST -H "Content-Type: application/json" -d '{"name": "submit_event"}' \
         http://10.180.0.250:7071/api/v1/install      once: infected machines can show
                                                      themselves on the map
                                                      (the map's page: http://localhost:8082)

Run:

    docker compose exec -d hnode_180_patient-zero sh -c 'worm launch > /tmp/worm.out 2>&1'
    docker compose logs hnode_180_victim1             watch it arrive and lock

On a victim, open the menu the worm left behind and follow it (wallet,
exchange, pay, receive the key, decrypt):

    docker compose exec -it hnode_180_victim1 ransom

The instructor stops every worm:

    docker compose exec hnode_180_switch switch register

Stop the lab, and switch ASLR back on:

    docker compose down
    sudo sysctl -w kernel.randomize_va_space=2
"""

import argparse
from pathlib import Path
import shutil
import subprocess
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1]))             # the repository root, for `software`

from seedemu.compiler import Docker, Platform  # noqa: E402
from seedemu.containerBundle import InternetMap  # noqa: E402
from seedemu.core import Binding, Emulator, Filter  # noqa: E402
from seedemu.layers import Base, Routing  # noqa: E402

from software.Core.files import place_files  # noqa: E402
from software.Ransomware_Service import Ransomware  # noqa: E402
from software.Switch_Service import DnsSwitch  # noqa: E402
from software.Vulnerable_Server import MorrisBof, VulnerableServer  # noqa: E402
from software.Worm_Service import Worm  # noqa: E402

ASN = 180                       # the lab's autonomous system
VICTIMS = ["victim1", "victim2", "victim3"]
DOCUMENTS = "/home/seed/Documents"

#: The kill switch of the real WannaCry: the long nonsense domain it looked for.
KILL_DOMAIN = "www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com"
NOTE = (HERE / "note.txt").read_text(encoding="utf-8")

MAP_PORTS = list(range(8081, 8089))          # the map's defaults; its page is on 8082
#: Where the map's server also stands inside the lab's network. The map's own
#: containers live on a network of their own, which no machine can reach; a
#: machine tells the map about itself at this address.
MAP_ADDRESS = "10.180.0.250"
BASE_IMAGE = "handsonsecurity/seedemu-base:2.0"


def build() -> Emulator:
    """The machines, the story, and the lines that connect the pieces."""
    emu, lab = lab_network()

    # The story: the documents each victim has before anything happens.
    place_files(VICTIMS, HERE / "documents", DOCUMENTS, network=lab)

    # The vulnerability: one program with a weakness, on as many machines as we like.
    bof = MorrisBof()
    vulns = VulnerableServer(bof)
    for victim in VICTIMS:
        vulns.install(victim)

    # The switch: one machine plays the internet for the kill-switch domain.
    switch = DnsSwitch(domain=KILL_DOMAIN, mode="killswitch")
    switch.install("switch")

    # The ransomware: its payment chain comes with it, and the operator's tools
    # go on the machine the worm is launched from.
    ransom = Ransomware(documents=DOCUMENTS, suffix=".WNCRY", note=NOTE, price_eth=1)
    ransom.paymentIn(lab, "net0", emu=emu)
    ransom.operatorTools("patient-zero", network=lab)

    # The worm: its exploit comes from the vulnerability, and it carries the ransomware.
    worm = Worm(exploit=bof.exploit(), payload=ransom.payload(),
                control=switch.reader())
    worm.launchFrom("patient-zero")

    for piece in (vulns, switch, ransom, worm):
        emu.addLayer(piece)
    return emu


def lab_network():
    """The network: one small network with a router.

    Every machine is also known by its name, so the recipe can name them.
    """
    emu, base = Emulator(), Base()
    lab = base.createAutonomousSystem(ASN)
    lab.createNetwork("net0", prefix="10.180.0.0/24")
    lab.createRouter("router0").joinNetwork("net0")
    for name in VICTIMS + ["patient-zero", "switch"]:
        lab.createHost(name).joinNetwork("net0")
        emu.addBinding(Binding(name, filter=Filter(asn=ASN, nodeName=name)))
    emu.addLayer(base)
    emu.addLayer(Routing())
    return emu, lab


def add_internet_map(emu, compiler):
    """The Internet Map, with the add-on that lets an infected machine flash on it.

    The add-on (map/submit_event, unchanged from SEED-Emulator) is put into
    the map's server when the lab is built. It still has to be switched on
    once the lab is up; see the command at the top.

    The map's server is also given an address in the lab's own network
    (MAP_ADDRESS). Without it, a machine's message "I am infected, flash me"
    could not reach the map: the map's containers sit on a network of their
    own. The add-on is therefore switched on through that address: the map
    writes "the address your request came in on" into every machine's copy
    of it. Asked through localhost:8082, it would write an address that no
    machine can reach.
    """
    map_bundle = InternetMap(emu, ".map.seed")
    map_bundle.setPorts(MAP_PORTS)
    map_bundle.addInternalNetwork(asn=str(ASN), network_name="net0", ip_addresses=[MAP_ADDRESS])
    add_on = HERE / "map" / "submit_event"
    server = map_bundle.getContainer("emulator_api_server")
    for name in ("plugin.json", "submit_event.sh"):
        server.setFile("/usr/src/app/plugin/submit_event/" + name,
                       (add_on / name).read_text(encoding="utf-8"))
    compiler.addContainerBundle(map_bundle)


def reset_output(output: Path) -> None:
    """Remove a previous output folder, so that the lab can be built again.

    The Internet Map's traffic observer runs as root and leaves root-owned
    files in that folder after a run, so a plain removal fails with
    "Permission denied". Those are removed through a throwaway container.
    """
    output = Path(output)
    if not output.exists():
        return
    running = subprocess.run(["docker", "compose", "ps", "-q"], cwd=output,
                             capture_output=True, text=True)
    if running.returncode == 0 and running.stdout.strip():
        raise SystemExit(
            f"{output.name} is still running. Stop it first with `docker compose down` in that folder."
        )
    try:
        shutil.rmtree(output)
    except PermissionError:
        subprocess.run(
            ["docker", "run", "--rm", "-v", "{}:/w".format(output.resolve()), BASE_IMAGE,
             "sh", "-c", "rm -rf /w/* /w/.[!.]*"],
            check=True, stdout=subprocess.DEVNULL,
        )
        shutil.rmtree(output)


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--platform", choices=["amd", "arm"], default="amd")
    parser.add_argument("--output", type=Path, default=HERE / "output")
    args = parser.parse_args()

    emu = build()
    emu.render()
    compiler = Docker(
        platform=Platform.AMD64 if args.platform == "amd" else Platform.ARM64)
    add_internet_map(emu, compiler)
    output = args.output.expanduser().resolve()
    reset_output(output)
    emu.compile(compiler, str(output), override=True)
    print(f"Docker configuration written to {output}")


if __name__ == "__main__":
    main()
