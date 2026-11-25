"""Vulnerable_Server: the service, the marks it leaves, and the Morris programs. No Docker.

seedemu itself is real here: every test builds a small emulation and renders it.
"""

import hashlib
import subprocess
import time
from pathlib import Path

import pytest
from seedemu.core import Binding, Emulator, Filter, Layer
from seedemu.layers import Base, Routing

from software.Core.marks import mark, marked_hosts
from software.Vulnerable_Server import MorrisBof, MorrisBofExploit, VulnerableServer
from software.Vulnerable_Server import Vulnerability, vulnerable_hosts
from software.Vulnerable_Server.morris_bof import vulnerability as morris

# sha256 of Prof. Du's two programs, as they are in his Morris worm example.
HIS_PROGRAMS = {
    "server": "f0773df565f7424c5c89e0544cf7e64bc11a7f342b587ef0585ca553c9f10e65",
    "stack": "e1232b120bd7e148f390ee2bbe7724f67fab1d15846b27d3f7c838773c9d30d8",
}
ASSETS = morris.ASSETS


class WeakLogin(Vulnerability):
    """A vulnerability with no exploit at all: a service anyone can log into."""

    name = "weak-login"
    port = 2323

    def __init__(self):
        self.installed_on = []

    def install(self, node):
        self.installed_on.append(node.getName())
        node.setFile("/etc/weak-login", "password: password\n")


class Probe(Layer):
    """Stands in for any other piece: asks for machines while the emulation renders."""

    def __init__(self):
        super().__init__()
        self.found = None

    def getName(self) -> str:
        return "Probe"

    def render(self, emulator):
        self.found = [node.getName() for node in vulnerable_hosts(emulator, "morris-bof")]


def build(vulns, victims=("victim1", "victim2", "victim3"), others=("bystander",), before=()):
    """A small lab: the victims, machines that are left alone, and the service."""
    emu, base = Emulator(), Base()
    asn = base.createAutonomousSystem(171)
    asn.createNetwork("net0")
    asn.createRouter("router0").joinNetwork("net0")
    hosts = {name: asn.createHost(name).joinNetwork("net0") for name in tuple(victims) + tuple(others)}
    emu.addLayer(base)
    emu.addLayer(Routing())
    for layer in before:
        emu.addLayer(layer)
    emu.addLayer(vulns)
    for name in victims:
        vulns.install(name)
        emu.addBinding(Binding(name, filter=Filter(asn=171, nodeName=name)))
    return emu, hosts


def names(nodes):
    return [node.getName() for node in nodes]


# ---- a vulnerability stands alone ----

def test_a_vulnerability_is_useful_without_any_exploit():
    weak = WeakLogin()
    assert isinstance(weak, Vulnerability)
    assert not hasattr(weak, "exploit")                # nothing has to break in

    emu, hosts = build(VulnerableServer(weak), victims=("victim1", "victim2"))
    emu.render()
    assert sorted(weak.installed_on) == ["victim1", "victim2"]   # seedemu picks the order
    for name in ("victim1", "victim2"):
        assert hosts[name].getFile("/etc/weak-login").get()[1] == "password: password\n"
    assert not hosts["bystander"].getFile("/etc/weak-login").get()[1]   # left alone


# ---- marks ----

def test_the_service_marks_each_machine_and_others_find_them_by_the_mark():
    emu, hosts = build(VulnerableServer(MorrisBof()))
    emu.render()
    found = vulnerable_hosts(emu, "morris-bof")
    assert names(found) == ["victim1", "victim2", "victim3"]       # found, never typed
    assert marked_hosts(emu, "morris-bof") == found                # the same machines, through Core
    assert vulnerable_hosts(emu, "weak-login") == []               # nobody has that one


def test_one_machine_can_get_a_different_vulnerability():
    vulns = VulnerableServer(MorrisBof())
    vulns.install("victim2").setVulnerability(WeakLogin())
    emu, hosts = build(vulns)
    emu.render()
    assert names(vulnerable_hosts(emu, "morris-bof")) == ["victim1", "victim3"]
    assert names(vulnerable_hosts(emu, "weak-login")) == ["victim2"]
    assert "/bof/server" in hosts["victim1"].getImportedFiles()
    assert "/bof/server" not in hosts["victim2"].getImportedFiles()
    assert "/etc/weak-login" in {item.get()[0] for item in hosts["victim2"].getFiles()}


def test_a_machine_gets_one_vulnerability():
    """Two installations with two vulnerabilities on the same machine is a mistake. Say so, at build time."""
    vulns = VulnerableServer(MorrisBof())
    vulns.install("first")
    vulns.install("second").setVulnerability(WeakLogin())
    emu, base = Emulator(), Base()
    asn = base.createAutonomousSystem(171)
    asn.createNetwork("net0")
    asn.createHost("victim1").joinNetwork("net0")
    emu.addLayer(base)
    emu.addLayer(vulns)
    emu.addBinding(Binding("first", filter=Filter(asn=171, nodeName="victim1")))
    emu.addBinding(Binding("second", filter=Filter(asn=171, nodeName="victim1", allowBound=True)))
    with pytest.raises(ValueError, match="'weak-login' as well as 'morris-bof': a machine gets one vulnerability"):
        emu.render()


def test_the_service_s_machines_may_still_carry_other_pieces_marks():
    """Core lets a machine carry several marks; the one-vulnerability rule is only this service's."""
    emu, hosts = build(VulnerableServer(MorrisBof()))
    emu.render()
    mark(hosts["victim1"], "operator")
    assert names(marked_hosts(emu, "morris-bof")) == ["victim1", "victim2", "victim3"]
    assert names(marked_hosts(emu, "operator")) == ["victim1"]


def test_the_marks_are_there_before_any_piece_renders():
    """A piece may be added before VulnerableServer and still find the machines."""
    probe = Probe()
    emu, _ = build(VulnerableServer(MorrisBof()), before=(probe,))
    emu.render()
    assert probe.found == ["victim1", "victim2", "victim3"]


def test_installing_the_same_machine_twice_installs_it_once():
    vulns = VulnerableServer(MorrisBof())
    assert vulns.install("victim1") is vulns.install("victim1")


def test_the_service_needs_a_vulnerability():
    for not_a_vulnerability in (None, "morris-bof", object()):
        with pytest.raises(TypeError, match="choose a vulnerability"):
            VulnerableServer(not_a_vulnerability)


# ---- what the host must provide is a warning at build time ----

@pytest.mark.parametrize("setting, warned", [("2", True), ("0", False), (None, True)])
def test_building_warns_when_the_host_cannot_run_the_vulnerability(
        monkeypatch, capsys, setting, warned):
    monkeypatch.setattr(morris, "aslr_setting", lambda: setting)
    emu, _ = build(VulnerableServer(MorrisBof()))
    emu.render()
    said = capsys.readouterr().out
    assert ("WARNING: morris-bof needs ASLR switched off" in said) is warned
    if warned:
        assert said.count("WARNING") == 1                 # once, not once per machine
        assert "sudo sysctl -w kernel.randomize_va_space=0" in said
        assert "sudo sysctl -w kernel.randomize_va_space=2" in said      # and how to undo it


# ---- the Morris programs ----

def test_the_installer_puts_prof_dus_programs_on_the_machine():
    node = type("Node", (), {"files": [], "commands": []})()
    node.importFile = lambda host, container: node.files.append((container, Path(host)))
    node.appendStartCommand = lambda cmd, fork=False: node.commands.append((cmd, fork))
    MorrisBof().install(node)

    assert [path for path, _ in node.files] == ["/bof/server", "/bof/stack"]
    assert [Path(source).name for _, source in node.files] == ["server", "stack"]
    assert node.commands == [
        (morris.FIX_SHELL, False),                        # 1. the shell an exploit gets stays bash
        ("chmod +x /bof/server /bof/stack", False),       # 2. imported files arrive without +x
        (morris.WAIT_FOR_ASLR_OFF + "cd /bof && ./server", True),   # 3. start, but only when ASLR is off
    ]


def test_the_programs_are_prof_dus_unchanged_and_come_with_their_sources():
    for name, digest in HIS_PROGRAMS.items():
        assert hashlib.sha256((ASSETS / name).read_bytes()).hexdigest() == digest
    for name in ("Makefile", "server.c", "stack.c"):
        assert (ASSETS / "src" / name).is_file()
    assert (ASSETS / "NOTICE").is_file()


def test_the_server_waits_for_aslr_to_go_off(tmp_path):
    """Switching ASLR off after the lab has started must work too."""
    knob = tmp_path / "randomize_va_space"                 # stands in for the kernel's file
    knob.write_text("2\n")
    loop = (morris.WAIT_FOR_ASLR_OFF + "echo server-started").replace(
        "/proc/sys/kernel/randomize_va_space", str(knob))
    waiting = subprocess.Popen(["bash", "-c", loop], stdout=subprocess.PIPE, text=True)

    time.sleep(2.5)
    assert waiting.poll() is None                          # still waiting: the knob is not 0

    knob.write_text("0\n")
    output, _ = waiting.communicate(timeout=10)
    assert waiting.returncode == 0 and output == "server-started\n"


def run_with_connection_as_input(command, home):
    """Run a shell command the way an exploit does: with a connection as its input."""
    import socket
    ours, theirs = socket.socketpair()
    try:
        return subprocess.run(
            ["bash", "-c", command], stdin=ours.fileno(), capture_output=True, timeout=20,
            env={"PATH": __import__("os").environ["PATH"], "HOME": str(home)},
        )
    finally:
        ours.close()
        theirs.close()


def test_why_the_shell_fix_is_needed_and_that_it_works(tmp_path):
    """Bash reads ~/.bashrc when started with -c and a connection as input."""
    home = tmp_path / "home"
    home.mkdir()

    (home / ".bashrc").write_text("exec true\n")          # a stand-in for the image's "exec zsh"
    swallowed = run_with_connection_as_input("printf 'ran\\n'", home)
    assert swallowed.stdout == b""                        # the command never ran

    (home / ".bashrc").write_text(morris.GUARDED_BASHRC)
    fixed = run_with_connection_as_input("printf 'ran\\n'", home)
    assert fixed.stdout == b"ran\n"


def test_the_shell_fix_rewrites_only_the_known_file(tmp_path):
    bashrc = tmp_path / ".bashrc"
    command = morris.FIX_SHELL.replace("/root/.bashrc", str(bashrc))

    bashrc.write_text("exec zsh\n")
    subprocess.run(["bash", "-c", command], check=True)
    assert bashrc.read_text() == morris.GUARDED_BASHRC

    bashrc.write_text("# somebody's own shell setup\n")
    subprocess.run(["bash", "-c", command], check=True)
    assert bashrc.read_text() == "# somebody's own shell setup\n"


# ---- the exploit is optional and separate ----

def test_the_exploit_comes_from_the_vulnerability_and_names_it():
    bof = MorrisBof()
    exploit = bof.exploit()
    assert isinstance(exploit, MorrisBofExploit)
    assert exploit.vulnerability == bof.name == "morris-bof"
    assert exploit.port == bof.port == 9090
    assert exploit.SLOT == "exploit"
    assert bof.exploit() is not exploit                  # a new one every time: it keeps state


def test_the_exploit_brings_a_probe_program_to_the_first_machine():
    node = type("Node", (), {"files": [], "commands": []})()
    node.importFile = lambda host, container: node.files.append((container, Path(host)))
    node.appendStartCommand = lambda cmd, fork=False: node.commands.append((cmd, fork))
    MorrisBofExploit.stage(node)
    assert node.files == [("/opt/yom/launcher/morris_bof/stack", ASSETS / "stack")]
    assert node.commands == [("chmod +x /opt/yom/launcher/morris_bof/stack", False)]
