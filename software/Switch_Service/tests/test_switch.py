"""The switch: its DNS client, the worm's reader in both modes, and the instructor's tool.

No Docker. A small server that speaks real DNS stands in for the switch
machine's BIND, and the installer is run on a real seedemu emulation.
"""

import inspect
import json
import socket
import struct
import threading
from pathlib import Path

import pytest
from seedemu.core import Binding, Emulator, Filter
from seedemu.layers import Base, Routing

from software.Switch_Service import DnsSwitch, SwitchReader, SwitchUnreachable
from software.Switch_Service import service
from software.Switch_Service.yom_switch import __main__ as tool
from software.Switch_Service.yom_switch import dnsquery, reader

#: The kill switch of the real WannaCry: the long nonsense domain it looked for.
KILL_DOMAIN = "www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com"
HIS_NAME = "worm.com"                       # the control name in Prof. Du's Morris worm


class FakeServer:
    """Answers DNS questions the way the lab's server does, on a free port.

    `code` is the answer code (3 = no such name, 0 = yes, 5 = refused). With
    code 0 and `has_address`, the reply carries one address record.
    """

    def __init__(self, code, has_address=False, address="127.0.0.1"):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.settimeout(2)
        self.port = self.sock.getsockname()[1]
        self.code, self.has_address, self.rdata = code, has_address, address
        self.questions = []

        def serve():
            while True:
                try:
                    question, client = self.sock.recvfrom(4096)
                except OSError:
                    return
                self.questions.append(question)
                flags = 0x8000 | self.code                  # a response, with this code
                answers = int(self.code == 0 and self.has_address)
                header = question[:2] + struct.pack(">HHHHH", flags, 1, answers, 0, 0)
                record = b""
                if answers:
                    record = b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 5, 4)
                    record += bytes(int(part) for part in self.rdata.split("."))
                self.sock.sendto(header + question[12:] + record, client)

        threading.Thread(target=serve, daemon=True).start()

    def asked_name(self):
        """The name in the first question it was asked (the labels sit right after the header)."""
        labels, index = [], 12
        question = self.questions[0]
        while question[index]:
            size = question[index]
            labels.append(question[index + 1:index + 1 + size].decode())
            index += size + 1
        return ".".join(labels)


def closed_port():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def a_reader(server, mode="killswitch", domain=KILL_DOMAIN):
    """A reader that asks the given stand-in for the switch machine."""
    return SwitchReader(domain, mode, server="127.0.0.1", port=server.port, timeout=1, tries=2)


# ---- the DNS client ----

@pytest.mark.parametrize(
    "code,has_address,expected",
    [(3, False, ("missing", None)), (0, False, ("missing", None)),
     (5, False, ("refused", None)), (0, True, ("exists", "127.0.0.1"))],
)
def test_the_client_reads_the_answer(code, has_address, expected):
    server = FakeServer(code, has_address)
    assert dnsquery.query("127.0.0.1", KILL_DOMAIN, timeout=1, tries=2, port=server.port) == expected
    assert server.asked_name() == KILL_DOMAIN              # it asked for exactly that name


def test_the_client_reads_whichever_address_the_record_holds():
    server = FakeServer(0, has_address=True, address="10.159.0.75")
    assert dnsquery.query("127.0.0.1", KILL_DOMAIN, timeout=1, tries=2, port=server.port) == (
        "exists", "10.159.0.75")


def test_the_client_tells_when_nobody_answered():
    assert dnsquery.query("127.0.0.1", KILL_DOMAIN, timeout=0.2, tries=2, port=closed_port()) == (
        None, None)


# ---- the reader is a part the worm can carry ----

def test_the_reader_is_plain_data_for_the_worm_s_control_slot():
    arguments = [name for name in inspect.signature(SwitchReader.__init__).parameters if name != "self"]
    mine = SwitchReader(KILL_DOMAIN, "killswitch", "10.0.0.5")
    assert mine.SLOT == "control"
    assert arguments == ["domain", "mode", "server", "port", "timeout", "tries"]
    # Every argument is kept in an attribute of the same name, and all of it is plain data.
    assert json.loads(json.dumps({name: getattr(mine, name) for name in arguments})) == {
        "domain": KILL_DOMAIN, "mode": "killswitch", "server": "10.0.0.5",
        "port": 53, "timeout": 2.0, "tries": 3}


# ---- the reader in killswitch mode ----

def test_killswitch_the_worm_runs_while_nobody_registered_the_domain_and_stops_once_it_answers():
    assert a_reader(FakeServer(3)).answer() == "run"             # not registered
    assert a_reader(FakeServer(0, has_address=True)).answer() == "stop"


def test_killswitch_the_worm_asks_for_the_domain_exactly_as_given():
    """A live run once failed here: the tool registered a name without www. and the worm asked with it."""
    server = FakeServer(3)
    a_reader(server).answer()
    assert server.asked_name() == KILL_DOMAIN == "www." + service.DnsSwitch(KILL_DOMAIN).zone.rstrip(".")


def test_the_worm_never_guesses_when_the_switch_machine_is_silent():
    with pytest.raises(SwitchUnreachable, match="did not answer"):
        SwitchReader(KILL_DOMAIN, server="127.0.0.1", port=1, timeout=0.2, tries=1).answer()


def test_the_worm_stops_when_the_switch_refuses_the_name():
    with pytest.raises(SwitchUnreachable, match="refused"):
        a_reader(FakeServer(5)).answer()


def test_a_reader_without_a_switch_machine_says_so():
    with pytest.raises(SwitchUnreachable, match="not installed"):
        SwitchReader(KILL_DOMAIN).answer()


# ---- the reader in control mode: Prof. Du's encoding, unchanged ----

@pytest.mark.parametrize(
    "address,expected",
    [("0.0.0.0", "run"), ("1.0.0.0", "stop"), ("2.0.0.0", "pause"),
     ("10.0.0.0", "run"), ("11.0.0.0", "run"), ("9.9.9.9", "run")],
)
def test_control_the_first_number_of_the_address_is_the_command(address, expected):
    """His worm.py reads the first number of the address of worm.com: 0 run, 1 stop, 2 pause.

    10 (show) and 11 (off) only change how his worm is drawn, and anything else is run.
    """
    assert a_reader(FakeServer(0, has_address=True, address=address), "control", HIS_NAME).answer() == expected


def test_control_the_tool_writes_exactly_his_addresses():
    assert tool.ADDRESSES == {"run": "0.0.0.0", "stop": "1.0.0.0", "pause": "2.0.0.0"}


def test_control_an_absent_name_means_run_and_a_silent_switch_is_no_go():
    assert a_reader(FakeServer(3), "control", HIS_NAME).answer() == "run"
    with pytest.raises(SwitchUnreachable, match="did not answer"):
        SwitchReader(HIS_NAME, "control", server="127.0.0.1", port=1, timeout=0.2, tries=1).answer()


# ---- the instructor's tool ----

def run_tool(monkeypatch, tmp_path, settings):
    scripts = []
    done = type("Done", (), {"returncode": 0, "stdout": "", "stderr": ""})()
    monkeypatch.setattr("subprocess.run", lambda args, **kw: scripts.append(kw["input"]) or done)
    path = tmp_path / "switch.json"
    path.write_text(json.dumps(settings))
    monkeypatch.setattr(tool, "SETTINGS", path)
    return scripts


SETTINGS = {"mode": "killswitch", "domain": "www.example.com", "zone": "example.com.",
            "server": "10.0.0.5", "port": 53}


def test_killswitch_the_tool_registers_and_unregisters_the_domain(monkeypatch, tmp_path):
    scripts = run_tool(monkeypatch, tmp_path, SETTINGS)
    assert tool.main(["register"]) == 0
    assert tool.main(["unregister"]) == 0
    assert scripts == [
        "server 10.0.0.5\nzone example.com.\nupdate delete www.example.com A\n"
        "update add www.example.com 5 A 10.0.0.5\nsend\n",           # registered: points at the switch machine
        "server 10.0.0.5\nzone example.com.\nupdate delete www.example.com A\nsend\n",   # gone
    ]


def test_control_the_tool_writes_the_command_into_the_record(monkeypatch, tmp_path):
    scripts = run_tool(monkeypatch, tmp_path, dict(SETTINGS, mode="control", domain=HIS_NAME, zone="com."))
    assert [tool.main([verb]) for verb in ("run", "pause", "stop")] == [0, 0, 0]
    assert scripts == [
        "server 10.0.0.5\nzone com.\nupdate delete worm.com A\nupdate add worm.com 5 A 0.0.0.0\nsend\n",
        "server 10.0.0.5\nzone com.\nupdate delete worm.com A\nupdate add worm.com 5 A 2.0.0.0\nsend\n",
        "server 10.0.0.5\nzone com.\nupdate delete worm.com A\nupdate add worm.com 5 A 1.0.0.0\nsend\n",
    ]


def test_the_tool_offers_only_its_own_mode_s_commands_and_explains_itself(monkeypatch, tmp_path, capsys):
    run_tool(monkeypatch, tmp_path, dict(SETTINGS, domain=HIS_NAME))
    for argv in ([], ["frobnicate"], ["stop"], ["register", "extra"]):
        assert tool.main(argv) == 2                      # "stop" is not a killswitch command
    assert "usage: switch register | unregister | status" in capsys.readouterr().out

    run_tool(monkeypatch, tmp_path, dict(SETTINGS, mode="control", domain=HIS_NAME, zone="com."))
    assert tool.main(["register"]) == 2                  # and "register" is not a control command
    assert "usage: switch run | pause | stop | status" in capsys.readouterr().out


def test_the_tool_says_when_it_is_not_on_the_switch_machine(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(tool, "SETTINGS", tmp_path / "nowhere" / "switch.json")
    assert tool.main(["register"]) == 2
    assert "not the switch machine" in capsys.readouterr().out


@pytest.mark.parametrize(
    "code,has_address,expected",
    [(3, False, "not registered, so nothing answers; the worm runs"),
     (0, True, "registered at 127.0.0.1; the worm stops")],
)
def test_killswitch_status_says_what_the_worm_would_conclude(
        monkeypatch, tmp_path, capsys, code, has_address, expected):
    server = FakeServer(code, has_address)
    run_tool(monkeypatch, tmp_path, dict(SETTINGS, server="127.0.0.1", port=server.port))
    assert tool.main(["status"]) == 0
    assert capsys.readouterr().out == "www.example.com: {}\n".format(expected)


def test_status_never_says_run_when_the_switch_machine_is_silent(monkeypatch, tmp_path, capsys):
    run_tool(monkeypatch, tmp_path, dict(SETTINGS, server="127.0.0.1", port=closed_port()))
    assert tool.main(["status"]) == 0
    assert "the switch machine did not answer; the worm stops" in capsys.readouterr().out


# ---- the installer, on a real emulator ----

def build(mode="killswitch", domain=KILL_DOMAIN, with_switch=True, **options):
    emu, base = Emulator(), Base()
    asn = base.createAutonomousSystem(173)
    asn.createNetwork("net0")
    asn.createRouter("router0").joinNetwork("net0")
    hosts = {name: asn.createHost(name).joinNetwork("net0") for name in ("victim1", "victim2", "switch")}
    emu.addLayer(base)
    emu.addLayer(Routing())
    switch = DnsSwitch(domain, mode=mode, **options)
    emu.addLayer(switch)
    reader = switch.reader()                    # asked for before anything has an address
    if with_switch:
        switch.install("switch")
        emu.addBinding(Binding("switch", filter=Filter(asn=173, nodeName="switch")))
    return emu, hosts, switch, reader


def address(host):
    return str(host.getInterfaces()[0].getAddress())


def written(node):
    return {item.get()[0]: item.get()[1] for item in node.getFiles()}


def test_the_switch_fills_its_own_address_into_the_reader_and_the_tool():
    emu, hosts, switch, reader = build()
    assert reader.server is None and switch.address is None     # nothing is known, or typed, yet
    emu.render()
    assert switch.address == address(hosts["switch"])
    assert reader.server == switch.address                      # found by the switch itself
    settings = json.loads(written(hosts["switch"])["/opt/yom/switch.json"])
    assert settings == {"mode": "killswitch", "domain": KILL_DOMAIN,
                        "zone": "iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com.",
                        "server": switch.address, "port": 53}
    assert switch.reader().server == switch.address             # asked for later: known at once


def test_the_switch_machine_runs_a_real_dns_server_for_the_zone():
    emu, hosts, switch, _ = build()
    emu.render()
    node = hosts["switch"]
    assert "bind9" in node.getSoftware()
    assert ("service named start", False) in node.getStartCommands()
    zone_file = written(node)["/etc/bind/zones/" + switch.zone]
    assert "@ SOA ns1." + switch.zone in zone_file and "@ NS ns1." + switch.zone in zone_file
    assert switch.domain.split(".")[0] not in zone_file         # the record itself is not there yet
    assert "allow-update { any; }" in written(node)["/etc/bind/named.conf.zones"]   # so a command can add it


def test_the_switch_machine_gets_the_switch_command():
    emu, hosts, _, _ = build()
    emu.render()
    node = hosts["switch"]
    assert written(node)["/usr/local/bin/switch"] == (
        '#!/bin/bash\nPYTHONPATH=/opt/yom exec python3 -m yom_switch "$@"\n')
    assert "/opt/yom/yom_switch/reader.py" in written(node)
    assert "python3" in node.getSoftware()


def test_by_default_the_switch_changes_no_machine_s_resolver():
    """The reader asks the switch machine directly, so the lab needs no resolver change."""
    emu, hosts, switch, _ = build()
    emu.render()
    assert switch.lab_nameserver is False
    for name, node in hosts.items():
        commands = " ".join(command for command, _ in node.getStartCommands())
        assert "resolv.conf" not in commands and "nameserver" not in commands, name


def test_a_switch_may_make_every_machine_ask_it_for_names():
    """An option for a class: students look the domain up on any machine and watch it appear."""
    emu, hosts, switch, _ = build(lab_nameserver=True)
    emu.render()
    for name, node in hosts.items():
        server = "127.0.0.1" if name == "switch" else switch.address
        assert node.getStartCommands()[:2] == [
            (": > /etc/resolv.conf", False),
            ('echo "nameserver {}" >> /etc/resolv.conf'.format(server), False),
        ], name


def test_it_is_dns_only():
    emu, hosts, _, _ = build()
    emu.render()
    for command, _ in hosts["switch"].getStartCommands():
        assert "http" not in command.lower() and "responder" not in command
    for path in Path(service.RUNTIME_DIR).glob("*.py"):
        assert "http.server" not in path.read_text(encoding="utf-8"), path.name
    assert sorted(p.name for p in Path(service.RUNTIME_DIR).iterdir() if p.is_file()) == [
        "__init__.py", "__main__.py", "dnsquery.py", "reader.py"]


def test_the_switch_is_one_machine():
    emu, _, switch, _ = build()
    assert switch.install("switch") is switch.install("switch")      # the same machine again: fine
    with pytest.raises(ValueError, match="already on 'switch'"):
        switch.install("another")
    emu, _, _, _ = build(with_switch=False)
    with pytest.raises(ValueError, match="needs its one machine"):
        emu.render()


def test_a_control_switch_serves_prof_du_s_name_in_its_zone():
    emu, hosts, switch, reader = build("control", HIS_NAME)
    emu.render()
    assert switch.zone == "com." and reader.mode == "control"
    assert json.loads(written(hosts["switch"])["/opt/yom/switch.json"])["domain"] == HIS_NAME
    assert switch.reader().mode == "control"


@pytest.mark.parametrize("domain, mode", [("com", "killswitch"), ("www.example.com", "toggle")])
def test_it_refuses_what_it_cannot_serve(domain, mode):
    with pytest.raises(ValueError):
        DnsSwitch(domain, mode=mode)
