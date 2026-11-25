"""Core's build-time helpers, on real seedemu nodes. No Docker."""

from pathlib import Path

import pytest
from seedemu.core import Binding, Emulator, Filter
from seedemu.layers import Base

from software.Core.files import HOME, add_command, place_files


def lab(names):
    """A tiny emulation: one network with the named machines, each bound by its name."""
    emu, base = Emulator(), Base()
    asn = base.createAutonomousSystem(170)
    asn.createNetwork("net0")
    hosts = {name: asn.createHost(name).joinNetwork("net0") for name in names}
    emu.addLayer(base)
    for name in names:
        emu.addBinding(Binding(name, filter=Filter(asn=170, nodeName=name)))
    return emu, asn, hosts


def written(node):
    """{path: content} of what was written onto a node as text."""
    return {item.get()[0]: item.get()[1] for item in node.getFiles()}


def story(tmp_path):
    """A folder as a case has it: documents, one of them in a subfolder."""
    folder = tmp_path / "documents"
    (folder / "last-year").mkdir(parents=True)
    (folder / "notes.txt").write_text("Team handover notes\n")
    (folder / "budget.csv").write_text("department,allocated,spent\n")
    (folder / "last-year" / "report.md").write_text("# Last year\n")
    return folder


def test_a_folder_is_copied_as_it_is(tmp_path):
    _, _, hosts = lab(["victim1"])
    count = place_files(hosts["victim1"], story(tmp_path), "/home/seed/Documents")
    assert count == 3
    assert written(hosts["victim1"]) == {
        "/home/seed/Documents/notes.txt": "Team handover notes\n",
        "/home/seed/Documents/budget.csv": "department,allocated,spent\n",
        "/home/seed/Documents/last-year/report.md": "# Last year\n",
    }


def test_several_machines_get_the_same_files(tmp_path):
    _, _, hosts = lab(["victim1", "victim2", "router"])
    place_files([hosts["victim1"], hosts["victim2"]], story(tmp_path), "/home/seed/Documents")
    assert written(hosts["victim1"]) == written(hosts["victim2"])
    assert len(written(hosts["victim1"])) == 3
    assert written(hosts["router"]) == {}                     # only the machines that were named


def test_a_case_can_name_the_machines(tmp_path):
    """The way a case writes it: the names it gave its machines, and its network.

    seedemu only knows a machine by name once the emulation renders, so the
    names are looked up where they were made: in the network itself."""
    _, network, hosts = lab(["victim1", "victim2", "router"])
    place_files(["victim1", "victim2"], story(tmp_path), "/home/seed/Documents", network=network)
    assert len(written(hosts["victim1"])) == 3 and len(written(hosts["victim2"])) == 3
    assert written(hosts["router"]) == {}


def test_a_name_needs_the_network_and_must_exist(tmp_path):
    _, network, hosts = lab(["victim1"])
    documents = story(tmp_path)
    with pytest.raises(ValueError, match="pass the network"):
        place_files(["victim1"], documents, "/home/seed/Documents")
    with pytest.raises(ValueError, match="no machine named 'nobody'"):
        place_files(["nobody"], documents, "/home/seed/Documents", network=network)
    assert written(hosts["victim1"]) == {}                # a failed call places nothing


def test_one_file_goes_to_its_full_new_path(tmp_path):
    _, _, hosts = lab(["victim1"])
    program = tmp_path / "stack"
    program.write_bytes(b"\x7fELF\x00\x00\x00binary")
    assert place_files(hosts["victim1"], program, "/bof/stack") == 1
    assert hosts["victim1"].getImportedFiles() == {"/bof/stack": str(program)}


def test_programs_are_imported_as_real_files_never_written_as_text(tmp_path):
    """A program has bytes that no text file can carry."""
    _, _, hosts = lab(["victim1"])
    folder = tmp_path / "piece"
    (folder / "bin").mkdir(parents=True)
    (folder / "bin" / "with-zero").write_bytes(b"abc\x00def")
    (folder / "bin" / "no-utf8").write_bytes(b"abc\xff\xfe\xfd")
    (folder / "run.py").write_text("print('hi')\n")
    place_files(hosts["victim1"], folder, HOME + "/piece")
    assert written(hosts["victim1"]) == {HOME + "/piece/run.py": "print('hi')\n"}
    assert {path: Path(source).name for path, source in hosts["victim1"].getImportedFiles().items()} == {
        HOME + "/piece/bin/with-zero": "with-zero",
        HOME + "/piece/bin/no-utf8": "no-utf8",
    }


def test_leftover_python_cache_is_not_copied(tmp_path):
    _, _, hosts = lab(["victim1"])
    folder = tmp_path / "piece"
    (folder / "__pycache__").mkdir(parents=True)
    (folder / "__main__.py").write_text("")
    (folder / "__pycache__" / "__main__.cpython-310.pyc").write_bytes(b"\x00")
    (folder / "old.pyc").write_bytes(b"\x00")
    assert place_files(hosts["victim1"], folder, HOME + "/piece") == 1
    assert list(written(hosts["victim1"])) == [HOME + "/piece/__main__.py"]


def test_a_command_runs_its_package_and_needs_no_reminder():
    _, _, hosts = lab(["attacker"])
    node = hosts["attacker"]
    add_command(node, "worm", "yom_worm")
    assert written(node)["/usr/local/bin/worm"] == (
        '#!/bin/bash\nPYTHONPATH={} exec python3 -m yom_worm "$@"\n'.format(HOME))
    assert "python3" in node.getSoftware()
    assert node.getStartCommands() == [("chmod +x /usr/local/bin/worm", False)]   # before anything uses it
