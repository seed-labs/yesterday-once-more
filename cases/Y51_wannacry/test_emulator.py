"""The WannaCry case builds from the pieces in software/ and compiles. No Docker daemon.

seedemu and chainseed are real here. The lab is even compiled into a
temporary folder, with the Internet Map, and the files the compiler writes
are read back.
"""

import importlib.util
import io
import json
import tarfile
from pathlib import Path

from seedemu.compiler import Docker, Platform

from software.Core.marks import marked_hosts

HERE = Path(__file__).resolve().parent
SERVICES = ["hnode_180_victim1", "hnode_180_victim2", "hnode_180_victim3",
            "hnode_180_patient-zero", "hnode_180_switch", "hnode_180_ransom-utility"]


def load(name):
    spec = importlib.util.spec_from_file_location("y51_" + name, HERE / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def texts(node):
    """{path on the machine: what stands there}: the text of a written file, the source of an imported one."""
    return {**{item.get()[0]: item.get()[1] for item in node.getFiles()},
            **dict(node.getImportedFiles())}


def address(node):
    return str(node.getInterfaces()[0].getAddress())


# ---- the recipe ----

def test_the_case_builds_from_the_pieces():
    case = load("emulator")
    emu = case.build()
    emu.render()

    victims = [node.getName() for node in marked_hosts(emu, "morris-bof")]
    assert victims == case.VICTIMS
    worm, switch = emu.getLayer("Worm"), emu.getLayer("DnsSwitch")

    # The worm attacks exactly the victims, and obeys exactly this switch.
    assert sorted(worm.scanner.targets) == sorted(
        address(node) for node in marked_hosts(emu, "morris-bof"))
    assert worm.control.domain == case.KILL_DOMAIN
    assert worm.control.mode == "killswitch"
    assert worm.control.server == switch.address

    # Every victim has the story's documents, and what the bundle needs.
    for node in marked_hosts(emu, "morris-bof"):
        for name in ("notes.txt", "budget.csv", "report.md", "contacts.csv", "minutes.txt"):
            # Copied as real files, so a victim's document is byte for byte the case's.
            assert Path(node.getImportedFiles()["{}/{}".format(case.DOCUMENTS, name)]).read_bytes() == (
                HERE / "documents" / name).read_bytes()
        for software in ("python3", "python3-cryptography"):
            assert software in node.getSoftware()

    # Patient zero has the worm and the operator's tools.
    zero = emu.getBindingFor("patient-zero")
    on_zero = texts(zero)
    assert {"/usr/local/bin/worm", "/usr/local/bin/ransom"} <= set(on_zero)
    assert json.loads(on_zero["/opt/yom/yom_ransomware/label.json"])["settings"]["note"] == case.NOTE
    assert "/opt/yom/yom_ransomware/keys.py" in on_zero
    assert not any("ransom" in path for path in texts(emu.getBindingFor("victim1")))   # not on a victim


def test_the_recipe_is_short():
    """The case is a recipe: its build() is a few lines that connect the pieces."""
    source = (HERE / "emulator.py").read_text(encoding="utf-8")
    build = source[source.index("def build()"):source.index("def lab_network")]
    code = [line for line in build.splitlines()
            if line.strip() and not line.strip().startswith(("#", '"""'))]
    assert len(code) <= 26, "\n".join(code)
    for piece in ("MorrisBof()", "VulnerableServer(bof)", "DnsSwitch(", "Ransomware(",
                  "Worm(", "worm.launchFrom(", "ransom.paymentIn(", "ransom.operatorTools("):
        assert piece in build, piece


# ---- the lab, compiled ----

def compiled(tmp_path):
    case = load("emulator")
    emu = case.build()
    emu.render()
    compiler = Docker(platform=Platform.AMD64)
    case.add_internet_map(emu, compiler)
    out = tmp_path / "lab"
    emu.compile(compiler, str(out), override=True)
    return case, out


def test_the_lab_compiles_with_the_internet_map(tmp_path):
    case, out = compiled(tmp_path)
    compose = (out / "docker-compose.yml").read_text(encoding="utf-8")
    for service in SERVICES + ["hnode_180_ransom-chain-2", "hnode_180_ransom-faucet",
                               "emulator_api_server.map.seed"]:
        assert "    {}:".format(service) in compose, service            # one service per machine
    assert "8082:80" in compose                                          # the map's page
    # The add-on that lets an infected machine flash is already in the map's server.
    dockerfile = (out / "emulator_api_server.map.seed" / "Dockerfile").read_text(encoding="utf-8")
    assert "/usr/src/app/plugin/submit_event/submit_event.sh" in dockerfile
    # The map's server also stands in the lab's own network, or a machine could
    # not tell the map about itself (a live run showed "Couldn't connect").
    server = compose[compose.index("    emulator_api_server.map.seed:"):]
    server = server[:server.index("\n    net_180_net0:")] if "\n    net_180_net0:" in server else server
    assert "ipv4_address: {}".format(case.MAP_ADDRESS) in server


def test_a_victim_is_staged_the_way_the_story_needs(tmp_path):
    """Read back what a victim and patient zero are built from."""
    _, out = compiled(tmp_path)

    def copied(node, path):
        dockerfile = (out / node / "Dockerfile").read_text(encoding="utf-8")
        line = next(l for l in dockerfile.splitlines() if l.startswith("COPY ") and l.endswith(" " + path))
        return (out / node / line.split()[1]).read_text(encoding="utf-8")

    victim = "hnode_180_victim1"
    assert copied(victim, "/home/seed/Documents/notes.txt") == (HERE / "documents" / "notes.txt").read_text()
    dockerfile = (out / victim / "Dockerfile").read_text(encoding="utf-8")
    assert "eth-account" in dockerfile                       # what the payload needs, as machine software
    assert "worm" not in dockerfile.lower() and "ransom" not in dockerfile.lower()   # nothing of either

    zero = "hnode_180_patient-zero"
    settings = json.loads(copied(zero, "/opt/yom/worm.json"))
    assert settings["payload"] == {"folder": "yom_ransomware"}
    assert settings["control"]["settings"]["mode"] == "killswitch"
    start = copied(zero, "/start.sh")
    assert start.index("chmod +x /usr/local/bin/ransom") < start.index("ransom init")
    assert "worm launch" not in start                          # a person launches it


# ---- check_state.py, on listings instead of machines ----

def listing(folder: dict) -> bytes:
    """What `tar -C <folder> -cf - .` prints, for the files of a dict."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        for name, data in folder.items():
            info = tarfile.TarInfo("./" + name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


ORIGINALS = {"notes.txt": b"Team handover notes\n", "budget.csv": b"department,allocated,spent\n"}


def test_check_state_reads_a_listing_the_way_tar_prints_it():
    check = load("check_state")
    assert check.unpack(listing({"notes.txt": b"hello", "sub/b.txt": b"x", "a.WNCRY": b"\x00\x01"})) == {
        "notes.txt": b"hello", "sub/b.txt": b"x", "a.WNCRY": b"\x00\x01"}


def test_check_state_tells_how_far_the_story_is():
    check = load("check_state")
    untouched = dict(ORIGINALS)
    locked = {name + ".WNCRY": b"cipher" for name in ORIGINALS}
    locked[check.NOTE] = b"Pay up."
    restored = {**ORIGINALS, check.NOTE: b"Pay up."}
    partly = {**dict(ORIGINALS), "budget.csv": b"tampered", check.NOTE: b"Pay up."}
    del partly["notes.txt"]
    partly["notes.txt.WNCRY"] = b"cipher"

    assert check.compare(untouched, ORIGINALS)["state"] == "NOT ATTACKED"
    done = check.compare(restored, ORIGINALS)
    assert (done["state"], done["restored"], done["note"]) == ("RESTORED", ["budget.csv", "notes.txt"], True)
    caught = check.compare(locked, ORIGINALS)
    assert (caught["state"], caught["locked"]) == ("LOCKED", ["budget.csv", "notes.txt"])
    half = check.compare(partly, ORIGINALS)
    assert (half["state"], half["restored"], half["locked"], half["changed"]) == (
        "PARTLY", [], ["notes.txt"], ["budget.csv"])
    assert check.report("victim1", caught, 2) == (
        "victim1: 0 of 2 documents identical to the originals. "
        "2 still locked (.WNCRY), their originals gone; the ransom note is there  [LOCKED]")
    assert check.report("victim2", done, 2) == (
        "victim2: 2 of 2 documents identical to the originals. the ransom note is there  [RESTORED]")


def test_check_state_names_the_machines_as_docker_compose_does():
    check = load("check_state")
    assert [check.service_of(victim) for victim in check.VICTIMS] == SERVICES[:3]


def test_check_state_says_when_there_is_no_lab(tmp_path, capsys):
    check = load("check_state")
    assert check.main(["--output", str(tmp_path / "nowhere")]) == 2
    assert "no lab in" in capsys.readouterr().out
