"""Core's build-time helpers, on real seedemu nodes. No Docker daemon."""

from pathlib import Path

import pytest
from seedemu.compiler import Docker, Platform
from seedemu.core import Binding, Emulator, Filter
from seedemu.layers import Base, Routing

from software.Core.files import HOME, add_command, place_files


def lab(names):
    """A tiny emulation: one network with the named machines, each bound by its name."""
    emu, base = Emulator(), Base()
    asn = base.createAutonomousSystem(170)
    asn.createNetwork("net0")
    asn.createRouter("router0").joinNetwork("net0")
    hosts = {name: asn.createHost(name).joinNetwork("net0") for name in names}
    emu.addLayer(base)
    for name in names:
        emu.addBinding(Binding(name, filter=Filter(asn=170, nodeName=name)))
    return emu, asn, hosts


def imported(node):
    """{path on the machine: path it was copied from}."""
    return dict(node.getImportedFiles())


def story(tmp_path):
    """A folder as a case has it: documents, one of them in a subfolder."""
    folder = tmp_path / "documents"
    (folder / "last-year").mkdir(parents=True)
    (folder / "notes.txt").write_text("Team handover notes\n")
    (folder / "budget.csv").write_text("department,allocated,spent\n")
    (folder / "last-year" / "report.md").write_text("# Last year\n")
    return folder


def test_a_folder_is_copied_as_it_is(tmp_path):
    folder = story(tmp_path)
    _, _, hosts = lab(["victim1"])
    count = place_files(hosts["victim1"], folder, "/home/seed/Documents")
    assert count == 3
    assert imported(hosts["victim1"]) == {
        "/home/seed/Documents/notes.txt": str(folder / "notes.txt"),
        "/home/seed/Documents/budget.csv": str(folder / "budget.csv"),
        "/home/seed/Documents/last-year/report.md": str(folder / "last-year" / "report.md"),
    }


def test_several_machines_get_the_same_files(tmp_path):
    folder = story(tmp_path)
    _, _, hosts = lab(["victim1", "victim2", "router"])
    place_files([hosts["victim1"], hosts["victim2"]], folder, "/home/seed/Documents")
    assert imported(hosts["victim1"]) == imported(hosts["victim2"])
    assert len(imported(hosts["victim1"])) == 3
    assert imported(hosts["router"]) == {}                  # only the machines that were named


def test_a_case_can_name_the_machines(tmp_path):
    """The way a case writes it: the names it gave its machines, and its network.

    seedemu only knows a machine by name once the emulation renders, so the
    names are looked up where they were made: in the network itself."""
    folder = story(tmp_path)
    _, network, hosts = lab(["victim1", "victim2", "router"])
    place_files(["victim1", "victim2"], folder, "/home/seed/Documents", network=network)
    assert len(imported(hosts["victim1"])) == 3 and len(imported(hosts["victim2"])) == 3
    assert imported(hosts["router"]) == {}


def test_a_name_needs_the_network_and_must_exist(tmp_path):
    folder = story(tmp_path)
    _, network, hosts = lab(["victim1"])
    with pytest.raises(ValueError, match="pass the network"):
        place_files(["victim1"], folder, "/home/seed/Documents")
    with pytest.raises(ValueError, match="no machine named 'nobody'"):
        place_files(["nobody"], folder, "/home/seed/Documents", network=network)
    assert imported(hosts["victim1"]) == {}                # a failed call places nothing


def test_one_file_goes_to_its_full_new_path(tmp_path):
    _, _, hosts = lab(["victim1"])
    program = tmp_path / "stack"
    program.write_bytes(b"\x7fELF\x00\x00\x00binary")
    assert place_files(hosts["victim1"], program, "/bof/stack") == 1
    assert imported(hosts["victim1"]) == {"/bof/stack": str(program)}


def test_leftover_python_cache_is_not_copied(tmp_path):
    _, _, hosts = lab(["victim1"])
    folder = tmp_path / "piece"
    (folder / "__pycache__").mkdir(parents=True)
    (folder / "__main__.py").write_text("")
    (folder / "__pycache__" / "__main__.cpython-310.pyc").write_bytes(b"\x00")
    (folder / "old.pyc").write_bytes(b"\x00")
    assert place_files(hosts["victim1"], folder, HOME + "/piece") == 1
    assert list(imported(hosts["victim1"])) == [HOME + "/piece/__main__.py"]


def test_nothing_is_written_as_text(tmp_path):
    """A file written as text gets an extra empty line; a program cannot be written as text at all."""
    folder = tmp_path / "piece"
    (folder / "bin").mkdir(parents=True)
    (folder / "bin" / "with-zero").write_bytes(b"abc\x00def")
    (folder / "run.py").write_text("print('hi')\n")
    node = type("Node", (), {"files": [], "imports": [], "getFiles": lambda self: []})()
    node.importFile = lambda host, container: node.imports.append(container)
    node.setFile = lambda path, content: node.files.append(path)
    place_files(node, folder, HOME + "/piece")
    assert node.imports == [HOME + "/piece/bin/with-zero", HOME + "/piece/run.py"]
    assert node.files == []                                 # never setFile


def test_a_document_stays_identical_to_its_original_through_the_compiler(tmp_path):
    """The proof, with the real compiler: what a machine is built from equals the file in the case.

    Written as text, the document would gain an empty line, and after the
    ransomware restored it, it would no longer match its original.
    """
    emu, _, hosts = lab(["victim1"])
    folder = story(tmp_path)
    original = (folder / "notes.txt").read_bytes()
    place_files(hosts["victim1"], folder, "/home/seed/Documents")
    emu.render()
    out = tmp_path / "lab"
    emu.compile(Docker(platform=Platform.AMD64), str(out), override=True)

    dockerfile = (out / "hnode_170_victim1" / "Dockerfile").read_text(encoding="utf-8")
    line = next(l for l in dockerfile.splitlines()
                if l.startswith("COPY ") and l.endswith(" /home/seed/Documents/notes.txt"))
    staged = (out / "hnode_170_victim1" / line.split()[1]).read_bytes()
    assert staged == original and staged.endswith(b"notes\n")


def test_a_command_runs_its_package_and_needs_no_reminder():
    _, _, hosts = lab(["attacker"])
    node = hosts["attacker"]
    add_command(node, "worm", "yom_worm")
    assert node.getFile("/usr/local/bin/worm").get()[1] == (
        '#!/bin/bash\nPYTHONPATH={} exec python3 -m yom_worm "$@"\n'.format(HOME))
    assert "python3" in node.getSoftware()
    assert node.getStartCommands() == [("chmod +x /usr/local/bin/worm", False)]   # before anything uses it
