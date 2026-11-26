"""The worm: its three slots, the spread loop, and the installer. No Docker needed.

The loop is run for real with stand-in parts; the installer is run on a real
seedemu emulation with the real exploit, the real switch reader and a
stand-in payload.
"""

import io
import json
import re
import shutil
import socket
import subprocess
import sys
import tarfile
import time
from pathlib import Path

import pytest

import label as label_format
import software.Ransomware_Service.yom_ransomware as ransomware_package
import software.Switch_Service.yom_switch as switch_package
import software.Vulnerable_Server.morris_bof.yom_morris_bof as bof_package
import software.Worm_Service.yom_worm as yom_worm_package
from software.Ransomware_Service import service as ransom_service
from software.Ransomware_Service.yom_ransomware import keys as ransom_keys
from software.Vulnerable_Server.morris_bof.yom_morris_bof import MorrisBofExploit
from software.Vulnerable_Server.morris_bof.yom_morris_bof import exploit as morris
from software.Worm_Service import Pace, ShuffleScanner, Worm
from software.Worm_Service.yom_worm import body, plugs
from software.Worm_Service.yom_worm import engine as engine_module
from software.Worm_Service.yom_worm.engine import Engine
from software.Worm_Service.yom_worm.spec import SLOTS, describe

# Inside a container the runtime package is called yom_worm. Lend it that name
# here so the loader takes the same path it takes there.
sys.modules.setdefault("yom_worm", yom_worm_package)
sys.modules.setdefault("yom_worm.builtin", yom_worm_package.builtin)

WORM_DIR = Path(yom_worm_package.__file__).parent


# ---- stand-in parts: the same source the engine will import from a fake package ----

FAKE_PACKAGE = '''
SLOT = "scanner"


class ListScanner:
    """Goes down the list, skips what is excluded, and starts over at the end."""

    SLOT = SLOT

    def __init__(self, targets=None):
        self.targets = list(targets or [])
        self._rest = []

    def next_target(self, exclude=()):
        while True:
            if not self._rest:
                self._rest = list(self.targets)
            target = self._rest.pop(0)
            if target not in exclude:
                return target
            if not self._rest and all(t in exclude for t in self.targets):
                return None


class OneByOne:
    SLOT = "exploit"

    def __init__(self, fail=(), refuse=(), measured=None):
        self.fail = list(fail)
        self.refuse = list(refuse)
        # Stands for something patient zero measures before it attacks, such
        # as the addresses of `stack`: it has to travel inside the bundle.
        self.measured = measured
        self.hits = []

    def prepare(self, worm):
        self._worm = worm

    def check_host(self):
        self.measured = "measured here"
        return list(self.refuse)

    def break_in(self, target, bundle):
        # Records whether the payload had finished its own work by then.
        self.hits.append((target, bundle, (self._worm.home / "payload-ran").exists()))
        return None if target in self.fail else "arrived"


class Signal:
    SLOT = "control"

    def __init__(self, says="run", then=None, after=0):
        self.says = says          # what it answers, until `then` takes over
        self.then = then          # a later answer: "run", "stop", or "down" for silence
        self.after = after        # ... after this many questions
        self.asked = 0

    def answer(self):
        self.asked += 1
        answer = self.then if (self.then is not None and self.asked > self.after) else self.says
        if answer == "down":
            raise RuntimeError("no answer from the switch machine")
        return answer
'''

PACE = dict(attempt_delay=0.05, announce_wait=0.1, body_wait=0.05, max_seconds=0.6,
            startup_wait=0.3, pause_seconds=0.2, announce_port=0)


def payload_that(command) -> dict:
    """A stand-in payload's label whose start command is `command`."""
    return {"name": "stand-in", "start": command, "settings": {}, "needs": {}}


SLOW_MARKER = payload_that(
    "python3 -c \"import time,pathlib;time.sleep(0.3);pathlib.Path('payload-ran').write_text('done')\"")


class _Fake:
    """Instances built from the fake source, only to write the settings file."""

    def __init__(self, source):
        namespace = {}
        exec(source, namespace)
        for name, obj in namespace.items():
            if isinstance(obj, type):
                setattr(self, name, obj)


FAKE = _Fake(FAKE_PACKAGE)


def free_udp_port():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def make_home(tmp_path, entry=None, control=None, pace=None, payload=SLOW_MARKER):
    """A folder laid out like /opt/yom on patient zero, with stand-in parts."""
    tmp_path.mkdir(parents=True, exist_ok=True)
    (tmp_path / "fake_parts").mkdir()
    (tmp_path / "fake_parts" / "__init__.py").write_text(FAKE_PACKAGE)
    (tmp_path / "yom_worm").mkdir()
    shutil.copy(label_format.__file__, tmp_path / "label.py")
    packages = ["fake_parts"]
    if payload is not None:
        (tmp_path / "fake_payload").mkdir()
        (tmp_path / "fake_payload" / "label.json").write_text(json.dumps(payload))
        packages.append("fake_payload")
    manifest = {
        "scanner": describe(FAKE.ListScanner(["a", "b", "c"])),
        "exploit": describe(entry or FAKE.OneByOne()),
        "payload": {"folder": "fake_payload"} if payload is not None else None,
        "packages": packages,
        "pace": pace or dict(PACE, announce_port=free_udp_port()),
    }
    if control is not None:
        manifest["control"] = describe(control)
    (tmp_path / "worm.json").write_text(json.dumps(manifest))
    return tmp_path


def events(home):
    return [json.loads(line) for line in (home / "events.jsonl").read_text().splitlines()]


def kinds(home):
    return [record["event"] for record in events(home)]


# ---- the slots ----

def test_a_part_needs_a_slot_and_its_method():
    class NoSlot:
        def run(self):
            pass

    class WrongMethod:
        SLOT = "control"

        def allowed(self):                  # it must be answer(), not something else
            return True

    with pytest.raises(TypeError, match="SLOT"):
        describe(NoSlot())
    with pytest.raises(TypeError, match="no answer"):
        describe(WrongMethod())


def test_describe_writes_the_constructor_arguments_and_nothing_else():
    class Entry:
        SLOT = "exploit"

        def __init__(self, port):
            self.port = port
            self.socket = object()          # running state: must stay behind
            self._private = "hidden"

        def break_in(self, target, bundle):
            pass

    assert describe(Entry(9090)) == {"type": "Entry", "settings": {"port": 9090}}

    class Careless:
        SLOT = "exploit"

        def __init__(self, port):           # forgets to keep its argument
            pass

        def break_in(self, target, bundle):
            pass

    with pytest.raises(TypeError, match="same name"):
        describe(Careless(9090))


def test_scanner_covers_everyone_in_a_new_order_each_pass():
    scanner = ShuffleScanner(["a", "b", "c"], seed=1)
    first_pass = [scanner.next_target() for _ in range(3)]
    assert sorted(first_pass) == ["a", "b", "c"]
    assert scanner.next_target(exclude="abc") is None
    assert scanner.next_target() is not None             # and around again


def test_worm_needs_an_exploit_and_checks_its_parts_at_once():
    with pytest.raises(ValueError, match="exploit"):
        Worm()
    with pytest.raises(TypeError):
        Worm(exploit=object())


def test_worm_without_a_control_or_a_payload_writes_neither():
    worm = Worm(exploit=FAKE.OneByOne(), scanner=FAKE.ListScanner(["a"]))
    assert "control" not in worm.manifest() and worm.manifest()["payload"] is None
    assert set(worm.manifest()) == {"scanner", "exploit", "payload", "pace", "packages"}


# ---- the loop ----

def test_launch_packs_a_bundle_and_attacks_everyone(tmp_path):
    home = make_home(tmp_path)
    engine = Engine(home)
    engine.run("launch")
    log = events(home)
    assert log[0]["event"] == "launch"
    attempts = [record for record in log if record["event"] == "attempt"]
    assert [record["target"] for record in attempts][:3] == ["a", "b", "c"]
    assert all(record["result"] == "arrived" for record in attempts)
    assert log[-1]["event"] == "halted" and log[-1]["reason"] == "time limit"
    assert all(bundle[:2] == b"\x1f\x8b" for _, bundle, _ in engine.exploit.hits)   # a gzip bundle each time
    # Patient zero carries the payload; it never runs it there.
    assert "payload" not in kinds(home) and not (home / "payload-ran").exists()


def test_a_machine_that_does_not_answer_is_tried_again_later(tmp_path):
    home = make_home(tmp_path, entry=FAKE.OneByOne(fail=["b"]))
    engine = Engine(home)
    engine.run("launch")
    assert engine.done == {"a", "c"}


def test_the_bundle_holds_the_parts_the_payload_and_the_settings(tmp_path):
    home = make_home(tmp_path, entry=FAKE.OneByOne())
    packed = body.pack(home, ["fake_parts", "fake_payload"], {"scanner": {"type": "ListScanner"}})
    with tarfile.open(fileobj=io.BytesIO(packed)) as archive:
        names = archive.getnames()
        manifest = json.load(archive.extractfile("worm.json"))
        label_shipped = archive.extractfile("label.py").read()
    assert {"worm.json", "label.py", "fake_parts/__init__.py", "fake_payload/label.json"} <= set(names)
    assert label_shipped == Path(label_format.__file__).read_bytes()      # the label's format travels along
    assert not any("__pycache__" in name for name in names)
    assert manifest["scanner"] == {"type": "ListScanner"}


def listening_infector():
    """A socket standing in for the machine that just infected us: it listens for "ARRIVED"."""
    infector = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    infector.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    infector.bind(("127.0.0.1", 0))
    infector.settimeout(3)
    return infector


def test_on_arrival_it_answers_then_runs_the_payload_to_the_end_and_only_then_spreads(tmp_path, monkeypatch):
    """The order on every reached machine: unpack, report arrived, payload, then the loop."""
    infector = listening_infector()
    home = make_home(tmp_path, pace=dict(PACE, max_seconds=1.2, announce_port=infector.getsockname()[1]))
    monkeypatch.setenv("FROM", "127.0.0.1")

    started = time.monotonic()
    engine = Engine(home)
    engine.run("run")
    assert infector.recvfrom(64)[0] == b"ARRIVED"            # it told its infector at once

    log = events(home)
    assert log[0]["event"] == "arrived" and log[0]["infector"] == "127.0.0.1"
    assert kinds(home)[1:3] == ["payload", "payload finished"]   # the payload ran, and ended
    assert kinds(home).count("payload") == 1                 # once, never again
    assert kinds(home)[3] == "attempt" and kinds(home)[-1] == "halted"
    assert engine.exploit.hits and all(finished for _, _, finished in engine.exploit.hits)   # never before
    assert (home / "payload-ran").read_text() == "done"
    assert log[2]["exit"] == 0 and log[1]["name"] == "stand-in"
    assert time.monotonic() - started >= 0.3                 # it really waited for the payload


def test_a_payload_that_asks_for_a_person_ends_at_once_and_the_worm_goes_on(tmp_path, monkeypatch):
    """The payload never waits for anyone: nobody can answer a machine the worm just reached."""
    home = make_home(tmp_path, payload=payload_that("python3 -c \"input('password: ')\""),
                     pace=dict(PACE, max_seconds=1.0, announce_port=free_udp_port()))
    monkeypatch.setenv("FROM", "")
    Engine(home).run("run")
    log = events(home)
    assert kinds(home)[:3] == ["arrived", "payload", "payload finished"]
    assert log[2]["exit"] != 0                               # nobody answered: it ended at once
    assert "attempt" in kinds(home)                          # and the worm went on


def test_a_payload_that_fails_does_not_stop_the_worm(tmp_path, monkeypatch):
    home = make_home(tmp_path, payload=payload_that("python3 -c \"raise SystemExit(3)\""),
                     pace=dict(PACE, max_seconds=1.0, announce_port=free_udp_port()))
    monkeypatch.setenv("FROM", "")
    Engine(home).run("run")
    assert kinds(home)[:3] == ["arrived", "payload", "payload finished"]
    assert events(home)[2]["exit"] == 3 and "attempt" in kinds(home)


def test_a_payload_without_a_label_is_reported_and_the_worm_goes_on(tmp_path, monkeypatch):
    home = make_home(tmp_path, pace=dict(PACE, max_seconds=1.0, announce_port=free_udp_port()))
    (home / "fake_payload" / "label.json").unlink()
    monkeypatch.setenv("FROM", "")
    Engine(home).run("run")
    assert kinds(home)[:3] == ["arrived", "payload failed", "attempt"]


def test_a_payload_s_real_exit_code_is_read_even_when_the_worm_came_through_a_program_that_ignores_sigchld(
        tmp_path, monkeypatch):
    """A live run showed 'payload finished, exit 0' for a payload that had crashed.

    The vulnerable server ignores the "a child has ended" signal, SIGCHLD, so
    that its children leave no zombies. The shell the exploit opens, and the
    worm in it, inherit that setting. With it, a child's exit status cannot
    be read, and Python takes it for 0. The worm must undo that first.
    """
    import signal

    home = make_home(tmp_path, payload=payload_that("python3 -c \"raise SystemExit(3)\""),
                     pace=dict(PACE, max_seconds=1.0, announce_port=free_udp_port()))
    monkeypatch.setenv("FROM", "")
    signal.signal(signal.SIGCHLD, signal.SIG_IGN)      # what the worm really inherits there
    try:
        Engine(home).run("run")
    finally:
        signal.signal(signal.SIGCHLD, signal.SIG_DFL)
    finished = events(home)[2]
    assert finished["event"] == "payload finished"
    assert finished["exit"] == 3                       # the truth, not "0"


# ---- everything real: the real worm, started as a victim gets it, runs the real ransomware ----

RANSOM_DIR = Path(ransomware_package.__file__).parent

#: Put into the bundle by the test only: the ransomware keeps its files in a
#: temporary folder instead of /opt/wannacry and /usr/local/bin.
ONLY_FOR_THE_TEST = """
import os
from pathlib import Path
import yom_ransomware.paths as paths

state = Path(os.environ["YOM_TEST_DIRS"])
paths.STATE = state / "wannacry"
for name in ("KEYLOG", "RECORD", "WALLET", "REQUEST", "REPLY", "ACCEPTED", "CHAIN"):
    setattr(paths, name, paths.STATE / name)
paths.MENU = state / "bin" / "ransom"
"""


def test_the_real_ransomware_locks_the_documents_when_the_real_worm_runs_it(tmp_path):
    """A live run found this the hard way: the worm reached every victim, and the
    payload crashed on its first line.

    So nothing is stood in for. A shell like the exploit's, with almost no
    environment and SIGCHLD ignored, starts the real worm from an unpacked
    bundle. The worm reads the ransomware's real label and runs its real
    start command, `python3 -m yom_ransomware detonate`.
    """
    import signal

    home = make_home(tmp_path, payload=None,
                     pace=dict(PACE, max_seconds=2.0, announce_port=free_udp_port()))
    shutil.copytree(WORM_DIR, home / "yom_worm", dirs_exist_ok=True)
    shutil.copytree(RANSOM_DIR, home / "yom_ransomware",
                    ignore=shutil.ignore_patterns("__pycache__"))
    (home / "sitecustomize.py").write_text(ONLY_FOR_THE_TEST)
    documents = tmp_path / "Documents"
    documents.mkdir()
    for name in ("notes.txt", "budget.csv"):
        (documents / name).write_text("original " + name)
    attacker = ransom_keys.new_rsa_keypair()
    public_key = ransom_keys.pub_pem(attacker.public_key()).decode("ascii")
    label_format.write_label(home / "yom_ransomware", label_format.new_label(
        "ransomware", "python3 -m yom_ransomware detonate",
        settings={"documents": str(documents), "suffix": ".WNCRY", "note": "Locked by a test.",
                  "price_eth": 1, "payment": None, "attacker_pub_pem": public_key},
        needs=ransom_service.NEEDS))
    manifest = json.loads((home / "worm.json").read_text())
    manifest["payload"] = {"folder": "yom_ransomware"}
    (home / "worm.json").write_text(json.dumps(manifest))

    ours, theirs = socket.socketpair()
    victim = subprocess.Popen(
        ["bash", "-c", "cd {} && python3 -m yom_worm run".format(home)],
        stdin=ours.fileno(), stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        env={"FROM": "127.0.0.1", "YOM_TEST_DIRS": str(tmp_path / "state")},
        preexec_fn=lambda: signal.signal(signal.SIGCHLD, signal.SIG_IGN),   # inherited from the server
    )
    ours.close()
    output = victim.communicate(timeout=40)[0].decode()
    assert victim.returncode == 0, output

    # What the ransomware leaves behind on a machine.
    assert sorted(p.name for p in documents.iterdir()) == ["READ_ME.txt", "budget.csv.WNCRY", "notes.txt.WNCRY"]
    assert (documents / "READ_ME.txt").read_text() == "Locked by a test."
    state = tmp_path / "state"
    keylog = json.loads((state / "wannacry" / "KEYLOG").read_text())
    assert sorted(keylog["files"]) == ["budget.csv", "notes.txt"]
    assert (state / "bin" / "ransom").read_text() == (
        '#!/bin/bash\nPYTHONPATH={} exec python3 -m yom_ransomware "$@"\n'.format(home))
    # What the worm wrote down: arrived, the payload, and its real exit code.
    log = events(home)
    assert [record["event"] for record in log][:3] == ["arrived", "payload", "payload finished"]
    assert log[2]["exit"] == 0 and log[2]["name"] == "ransomware"


def test_without_a_payload_nothing_is_run(tmp_path, monkeypatch):
    home = make_home(tmp_path, payload=None, pace=dict(PACE, max_seconds=0.8, announce_port=free_udp_port()))
    monkeypatch.setenv("FROM", "")
    Engine(home).run("run")
    assert kinds(home)[0] == "arrived" and kinds(home)[1] == "attempt"


# ---- what the control says ----

def test_the_control_can_stop_the_worm(tmp_path):
    home = make_home(tmp_path, control=FAKE.Signal("stop"))
    engine = Engine(home)
    engine.run("launch")
    assert events(home)[-1]["event"] == "halted"
    assert events(home)[-1]["reason"] == "stop signal"
    assert engine.exploit.hits == []


def test_a_pause_holds_the_worm_until_the_control_says_run_again(tmp_path):
    """As in the Morris worm example: while the control says pause, nobody is attacked."""
    home = make_home(tmp_path, control=FAKE.Signal("pause", then="run", after=3),
                     pace=dict(PACE, max_seconds=1.0, announce_port=free_udp_port()))
    engine = Engine(home)
    engine.run("launch")
    log = events(home)
    paused = next(i for i, record in enumerate(log) if record["event"] == "paused")
    running = next(i for i, record in enumerate(log) if record["event"] == "running again")
    assert paused < running
    assert not [i for i, record in enumerate(log) if record["event"] == "attempt" and paused < i < running]
    assert engine.control.asked > 4                           # it kept asking while paused
    assert any(record["event"] == "attempt" for record in log[running:])


def test_a_silent_control_stops_the_worm_instead_of_letting_it_guess(tmp_path):
    """If the switch machine does not answer at all, the worm stops. "Not registered" is a real answer."""
    home = make_home(tmp_path, control=FAKE.Signal("down"))
    with pytest.raises(SystemExit) as stopped:
        Engine(home).run("launch")
    assert stopped.value.code == 1
    assert events(home)[-1]["reason"] == "the switch machine did not answer"
    assert "launch" not in kinds(home)


def test_a_control_that_goes_silent_later_stops_the_worm_too(tmp_path):
    home = make_home(tmp_path, control=FAKE.Signal("run", then="down", after=2),
                     pace=dict(PACE, max_seconds=1.0, announce_port=free_udp_port()))
    Engine(home).run("launch")
    assert events(home)[-1]["reason"] == "the switch machine did not answer"
    assert len([record for record in events(home) if record["event"] == "attempt"]) <= 2


def test_the_worm_waits_for_the_control_machine_before_it_starts(tmp_path):
    """The switch machine may still be booting: give it time, but never start without an answer."""
    home = make_home(tmp_path, control=FAKE.Signal("down", then="run", after=2),
                     pace=dict(PACE, max_seconds=0.6, startup_wait=10, pause_seconds=0.05,
                               announce_port=free_udp_port()))
    Engine(home).run("launch")
    assert kinds(home)[0] == "launch"                        # it waited, got an answer, and launched
    assert "attempt" in kinds(home)


# ---- before anything is attacked ----

def test_an_exploit_that_cannot_work_here_refuses_to_launch(tmp_path):
    home = make_home(tmp_path, entry=FAKE.OneByOne(refuse=["ASLR is on"]))
    with pytest.raises(SystemExit) as stopped:
        Engine(home).run("launch")
    assert stopped.value.code == 1
    assert events(home)[0]["event"] == "refused"
    assert events(home)[0]["reasons"] == ["ASLR is on"]
    assert not (home / ".lock").read_text() if (home / ".lock").exists() else True


def test_the_bundle_carries_what_patient_zero_measured(tmp_path):
    """A live run once shipped empty addresses: the bundle was packed before measuring."""
    home = make_home(tmp_path)
    engine = Engine(home)
    engine.run("launch")
    with tarfile.open(fileobj=io.BytesIO(engine.exploit.hits[0][1])) as archive:
        shipped = json.load(archive.extractfile("worm.json"))
    assert shipped["exploit"]["settings"]["measured"] == "measured here"


def test_only_one_worm_per_machine(tmp_path, capsys):
    home = make_home(tmp_path)
    import fcntl
    lock = (home / ".lock").open("a")
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    with pytest.raises(SystemExit) as stopped:
        Engine(home)._lock()
    assert stopped.value.code == 0
    assert "already running" in capsys.readouterr().out


def test_the_loader_finds_parts_by_name_and_says_when_one_is_missing(tmp_path):
    home = make_home(tmp_path)
    registry = plugs.load(home, ["fake_parts"])
    assert registry[("exploit", "OneByOne")].__name__ == "OneByOne"
    assert registry[("control", "Signal")].__name__ == "Signal"
    assert registry[("scanner", "ShuffleScanner")].__name__ == "ShuffleScanner"   # ships with the worm
    with pytest.raises(LookupError, match="shipped inside the bundle"):
        plugs.build(registry, "exploit", {"type": "NoSuchExploit", "settings": {}})


def test_a_real_bundle_unpacks_into_a_working_worm(tmp_path, monkeypatch):
    """Pack from a real home (the worm's own files included), unpack elsewhere, and run it there."""
    infector = listening_infector()
    source = make_home(tmp_path / "patient-zero",
                       pace=dict(PACE, max_seconds=0.8, announce_port=infector.getsockname()[1]))
    shutil.copytree(WORM_DIR, source / "yom_worm", dirs_exist_ok=True)
    manifest = json.loads((source / "worm.json").read_text())
    packed = body.pack(source, manifest["packages"], manifest)

    arrived = tmp_path / "yomw"
    arrived.mkdir()
    with tarfile.open(fileobj=io.BytesIO(packed)) as archive:
        assert {"yom_worm/engine.py", "yom_worm/__main__.py", "label.py", "worm.json",
                "fake_parts/__init__.py", "fake_payload/label.json"} <= set(archive.getnames())
        archive.extractall(arrived)
    monkeypatch.setenv("FROM", "127.0.0.1")

    sys.path.insert(0, str(arrived))
    try:
        Engine(arrived).run("run")
    finally:
        sys.path.remove(str(arrived))
    assert infector.recvfrom(64)[0] == b"ARRIVED"
    assert kinds(arrived)[:3] == ["arrived", "payload", "payload finished"]
    assert "attempt" in kinds(arrived)


# ---- the installer, on a real emulator ----

BOF_PACKAGE = Path(__file__).resolve().parents[2] / "Vulnerable_Server/morris_bof/yom_morris_bof"
MORRIS_CONSTANTS = (0xFFFFD5E8, 0xFFFFD578)        # ebp, buf, as written in the Morris worm's worm.py


def stand_in_payload(where, needs=None):
    """A payload as another piece hands it over: a folder plus a label."""
    folder = where / "yom_fake_payload"
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "run.py").write_text("print('payload')\n")
    return label_format.Payload(folder, dict(
        payload_that("python3 run.py"),
        needs=needs if needs is not None else {"software": ["python3-cryptography"],
                                               "build": ["pip3 install --break-system-packages eth-account==0.13.7"]}))


def build(tmp_path, with_victims=True, payload=True, control=True, autostart=False):
    """A lab as a case writes it: the real switch, the real vulnerability, a stand-in payload."""
    from seedemu.core import Binding, Emulator, Filter
    from seedemu.layers import Base, Routing
    from software.Switch_Service import DnsSwitch
    from software.Vulnerable_Server import MorrisBof, VulnerableServer

    emu, base = Emulator(), Base()
    asn = base.createAutonomousSystem(158)
    asn.createNetwork("net0")
    asn.createRouter("router0").joinNetwork("net0")
    hosts = {name: asn.createHost(name).joinNetwork("net0")
             for name in ("victim1", "victim2", "patient-zero", "switch")}
    emu.addLayer(base)
    emu.addLayer(Routing())

    switch = DnsSwitch("stop.yom.test")
    emu.addLayer(switch)
    switch.install("switch")
    emu.addBinding(Binding("switch", filter=Filter(asn=158, nodeName="switch")))

    bof = MorrisBof()
    if with_victims:
        vulns = VulnerableServer(bof)
        emu.addLayer(vulns)
        for name in ("victim1", "victim2"):
            vulns.install("vuln-" + name)
            emu.addBinding(Binding("vuln-" + name, filter=Filter(asn=158, nodeName=name)))

    worm = Worm(exploit=bof.exploit(),
                payload=stand_in_payload(tmp_path) if payload else None,
                control=switch.reader() if control else None,
                autostart=autostart)
    emu.addLayer(worm)
    worm.launchFrom("patient-zero")
    emu.addBinding(Binding("patient-zero", filter=Filter(asn=158, nodeName="patient-zero")))
    return emu, hosts, switch, worm


def address(host):
    return str(host.getInterfaces()[0].getAddress())


def staged_files(host):
    """Every path put on a node, as text or as a real file."""
    return sorted({item.get()[0] for item in host.getFiles()} | set(host.getImportedFiles()))


def staged_text(host):
    return {item.get()[0]: item.get()[1] for item in host.getFiles()}


def test_the_installer_fills_in_what_nobody_should_have_to_type(tmp_path):
    emu, hosts, switch, worm = build(tmp_path)
    emu.render()

    # Who to attack: exactly the machines that have the vulnerability, found by their mark.
    assert sorted(worm.scanner.targets) == sorted([address(hosts["victim1"]), address(hosts["victim2"])])
    # Where the machine that controls the worm is: the switch filled that in itself.
    assert worm.control.server == switch.address == address(hosts["switch"])
    # Every machine that runs one of our commands can run Python.
    for name in ("patient-zero", "switch", "victim1", "victim2"):
        assert "python3" in hosts[name].getSoftware()


def test_the_worm_never_imports_another_piece():
    """It is handed small objects; it never reaches into the pieces that made them."""
    folder = Path(__file__).resolve().parents[1]
    for path in list(folder.glob("*.py")) + list((folder / "yom_worm").glob("*.py")):
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.startswith(("from software.", "import software.")):
                assert line.startswith("from software.Core"), (path.name, line)
    for path in (folder / "yom_worm").glob("*.py"):             # and its machine-side code never imports seedemu
        assert not re.search(r"^\s*(from|import)\s+seedemu", path.read_text(encoding="utf-8"), re.M), path.name


def test_reached_machines_get_what_the_bundle_and_the_payload_need_and_nothing_more(tmp_path):
    emu, hosts, _, _ = build(tmp_path)
    emu.render()
    for name in ("victim1", "victim2"):
        node = hosts[name]
        for software in ("python3", "python3-cryptography"):
            assert software in node.getSoftware()
        assert any("eth-account" in command for command in node.getBuildCommands())
        staged = staged_files(node)
        assert "/bof/server" in staged and "/bof/stack" in staged     # the vulnerability, from its own piece
        assert not any(path.startswith("/opt/yom") or path == "/usr/local/bin/worm" for path in staged)


def test_patient_zero_gets_the_whole_worm(tmp_path):
    emu, hosts, switch, worm = build(tmp_path)
    emu.render()
    zero = hosts["patient-zero"]
    assert {
        "/usr/local/bin/worm",
        "/opt/yom/worm.json",
        "/opt/yom/label.py",                              # the label's format: the worm reads it on arrival
        "/opt/yom/launcher/morris_bof/stack",             # to measure the addresses
        "/opt/yom/yom_worm/engine.py",
        "/opt/yom/yom_morris_bof/exploit.py",             # the exploit it uses
        "/opt/yom/yom_switch/reader.py",                  # the control it obeys
        "/opt/yom/yom_fake_payload/run.py",               # what it carries, with its label
        "/opt/yom/yom_fake_payload/label.json",
    } <= set(staged_files(zero))
    assert "python3" in zero.getSoftware()
    assert zero.getStartCommands()[-1] == ("chmod +x /usr/local/bin/worm", False)

    settings = json.loads(staged_text(zero)["/opt/yom/worm.json"])
    assert settings["packages"] == ["yom_morris_bof", "yom_switch"]     # what the next machine imports
    assert settings["exploit"]["type"] == "MorrisBofExploit"
    assert settings["control"]["settings"]["server"] == address(hosts["switch"])
    assert settings["payload"] == {"folder": "yom_fake_payload"}
    assert sorted(settings["scanner"]["settings"]["targets"]) == sorted(
        [address(hosts["victim1"]), address(hosts["victim2"])])
    shipped = json.loads(staged_text(zero)["/opt/yom/yom_fake_payload/label.json"])
    assert shipped["start"] == "python3 run.py" and shipped["needs"]["software"] == ["python3-cryptography"]


def test_autostart_runs_the_worm_when_the_machine_boots(tmp_path):
    emu, hosts, _, _ = build(tmp_path, autostart=True)
    emu.render()
    assert ("worm launch", True) in hosts["patient-zero"].getStartCommands()


def test_the_installer_refuses_a_worm_whose_vulnerability_is_nowhere(tmp_path):
    emu, _, _, _ = build(tmp_path, with_victims=False)
    with pytest.raises(ValueError, match="no machine is marked with it"):
        emu.render()


def test_a_payload_must_be_a_folder_plus_a_label():
    with pytest.raises(TypeError, match="folder plus a label"):
        Worm(exploit=FAKE.OneByOne(), payload="yom_ransomware")


def test_what_the_installer_writes_rebuilds_into_the_same_parts(tmp_path):
    """The settings file must build the same parts again on every machine the bundle lands on."""
    emu, hosts, _, worm = build(tmp_path)
    emu.render()
    manifest = json.loads(staged_text(hosts["patient-zero"])["/opt/yom/worm.json"])

    home = tmp_path / "arrived"
    home.mkdir()
    for name, package in (("yom_worm", yom_worm_package), ("yom_morris_bof", bof_package),
                          ("yom_switch", switch_package)):
        (home / name).mkdir()
        source = Path(package.__file__).parent
        for item in source.iterdir():
            if item.is_file() and item.suffix in (".py", ".txt"):
                shutil.copy(item, home / name / item.name)
    registry = plugs.load(home, manifest["packages"])

    for slot in SLOTS:
        rebuilt = plugs.build(registry, slot, manifest[slot])
        assert type(rebuilt).__name__ == manifest[slot]["type"]
        settings = manifest[slot]["settings"]
        assert {name: vars(rebuilt)[name] for name in settings} == settings
    assert type(worm.scanner).__name__ == "ShuffleScanner"


# ---- the real exploit hands the real bundle to a machine ----

def run_like_a_victim(command, home):
    """Start the command the way the shellcode does: bash -c, with a connection as input."""
    ours, theirs = socket.socketpair()
    process = subprocess.Popen(
        ["bash", "-c", command], stdin=ours.fileno(), stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, env={"PATH": __import__("os").environ["PATH"], "HOME": str(home)},
    )
    ours.close()
    process.peer = theirs                 # kept open: the other end of the "exploit's" line
    return process


def command_inside(badfile: bytes) -> str:
    """The command the shellcode carries: it follows the stub and its strings inside the shellcode."""
    shellcode = badfile[-len(morris._STUB + morris._STRINGS + b" " * morris.COMMAND_ROOM + b"*"):]
    start = len(morris._STUB + morris._STRINGS)
    return shellcode[start:start + morris.COMMAND_ROOM].decode("ascii")


def test_the_real_exploit_hands_the_real_bundle_to_a_machine(tmp_path, monkeypatch):
    """The worm's engine with the real Morris exploit, against a machine that runs the exploit's command.

    Only one thing is stood in for: the vulnerable program itself. When the
    badfile arrives, the test plays the shellcode and runs the command that
    is inside it. Everything else is real: the badfile, the bundle, the
    socket it travels through, and the answer that comes back.
    """
    if shutil.which("nc") is None:
        pytest.skip("this test needs netcat")
    # At launch the real exploit measures the addresses with its probe program.
    probe = tmp_path / "probe" / "stack"
    probe.parent.mkdir()
    shutil.copy(morris.ASSETS / "stack", probe)
    if morris.aslr_setting() == "0":
        exploit_part = MorrisBofExploit(probe_binary=str(probe), body_port=free_port())
    else:                                   # this machine randomises addresses: skip the measuring
        exploit_part = MorrisBofExploit(ebp=MORRIS_CONSTANTS[0], buf=MORRIS_CONSTANTS[1], body_port=free_port())
        monkeypatch.setattr(MorrisBofExploit, "check_host", lambda self: [])
    announce_port = free_udp_port()
    payload = payload_that("true")
    # As in a real lab, the machine that is attacked gets time to start listening and to answer.
    home = make_home(tmp_path, payload=payload, pace=dict(
        PACE, max_seconds=1.5, announce_port=announce_port, body_wait=3.0, announce_wait=3.0))
    shutil.copytree(WORM_DIR, home / "yom_worm", dirs_exist_ok=True)
    shutil.copytree(BOF_PACKAGE, home / "yom_morris_bof")
    (home / "fake_worm").mkdir()
    # On the machine the bundle lands on, a copy of the worm that only reports what it got.
    (home / "fake_worm" / "__main__.py").write_text(
        "import json, os, pathlib, socket\n"
        "home = pathlib.Path.cwd()\n"
        "port = json.loads((home / 'worm.json').read_text())['pace']['announce_port']\n"
        "sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n"
        "for _ in range(3):\n"
        "    sock.sendto(b'ARRIVED', (os.environ['FROM'], port))\n"
        "(home / 'started').write_text('started by ' + os.environ['FROM'])\n")
    manifest = json.loads((home / "worm.json").read_text())
    manifest.update(
        scanner=describe(ShuffleScanner(["127.0.0.1"])),
        exploit=describe(exploit_part),
        packages=["yom_morris_bof", "fake_worm"])
    (home / "worm.json").write_text(json.dumps(manifest))

    victims = []
    def overflow(self, ip, port, badfile, wait):
        """The vulnerable program is sent the badfile; its shellcode runs the command inside it."""
        command = command_inside(badfile)
        assert command.startswith("export FROM=127.0.0.1;")          # it tells the machine where to fetch the bundle
        assert "/tmp/yomw" in command                               # where the bundle unpacks itself on a machine
        command = command.replace("/tmp/yomw", str(tmp_path / "yomw"))   # this machine is a temporary folder
        command = command.replace("python3 -m yom_worm run", "python3 -m fake_worm")
        victims.append(run_like_a_victim(command, tmp_path / "no-shell-setup"))

    monkeypatch.setattr(Engine, "exchange", overflow)
    Engine(home).run("launch")
    victim = victims[0]
    output = victim.communicate(timeout=20)[0].decode()
    assert victim.returncode == 0, output

    arrived = tmp_path / "yomw"                           # where the bundle unpacks itself
    assert (arrived / "started").read_text() == "started by 127.0.0.1"
    for shipped in ("yom_worm/engine.py", "yom_morris_bof/exploit.py", "fake_payload/label.json",
                    "fake_worm/__main__.py", "label.py", "worm.json"):
        assert (arrived / shipped).is_file(), shipped
    log = events(home)
    attempts = [record for record in log if record["event"] == "attempt"]
    assert attempts and all(record["result"] == "arrived" for record in attempts)   # it came back: "arrived"
    assert len(victims) == 1                               # and the machine is never attacked twice


# ---- the Internet Map ----

def map_add_on(tmp_path, monkeypatch, restore_takes=0):
    """A stand-in for the map's add-on, strict like the real map's server.

    It records every action it is asked for, and it answers "ok" only when a
    style file is given: the real server reads a JSON body for "flash" and
    "highlight", and fails without one (a live run showed it).
    """
    actions = tmp_path / "map-actions"
    hook = tmp_path / "submit_event.sh"
    hook.write_text(HOOK_SCRIPT.format(actions, restore_takes))
    monkeypatch.setattr(engine_module, "MAP_HOOK", str(hook))
    monkeypatch.setattr(engine_module, "MAP_FLASH_SECONDS", 0)
    return tmp_path / "map-actions"


HOOK_SCRIPT = """#!/bin/bash
style=""
while [ $# -gt 0 ]; do
    case "$1" in -a) action="$2"; shift 2;; -s) style="$2"; shift 2;; *) shift;; esac
done
json=no
[ -n "$style" ] && [ -f "$style" ] && json=yes
echo "-a $action json=$json" >> {0}
if [ "$json" = no ]; then echo '{{"ok":false}}'; exit 0; fi
echo '{{"ok":true,"result":{{"currentFilter":"success"}}}}'
case "$action" in restore) sleep {1};; esac
"""


def arrived_home(tmp_path, control=None):
    infector = listening_infector()
    return make_home(tmp_path, control=control, payload=payload_that("true"),
                     pace=dict(PACE, max_seconds=0.6, announce_port=infector.getsockname()[1]))


def wait_until(what, seconds=5):
    deadline = time.monotonic() + seconds
    while not what():
        assert time.monotonic() < deadline, "the map was never told"
        time.sleep(0.05)


def test_on_arrival_the_worm_tells_the_map_to_flash_and_highlight(tmp_path, monkeypatch):
    """The same two actions the Morris worm example asks the map for."""
    actions = map_add_on(tmp_path, monkeypatch)
    monkeypatch.setenv("FROM", "127.0.0.1")
    Engine(arrived_home(tmp_path)).run("run")
    wait_until(lambda: actions.exists() and "highlight" in actions.read_text())
    assert actions.read_text().splitlines()[:2] == [
        "-a flash json=yes", "-a highlight json=yes"]     # a JSON body each time, as the map needs
    assert (tmp_path / "map-highlight.json").read_text() == '{"highlight": {"borderWidth": 4}}'
    assert [record for record in events(tmp_path) if record["event"] == "map"][0]["ok"] is True


def test_a_halted_worm_is_taken_off_the_map(tmp_path, monkeypatch):
    actions = map_add_on(tmp_path, monkeypatch)
    monkeypatch.setenv("FROM", "127.0.0.1")
    home = arrived_home(tmp_path, control=FAKE.Signal("stop"))
    Engine(home).run("run")
    told = actions.read_text().splitlines()
    assert "-a flash json=yes" in told and "-a restore json=yes" in told
    assert all(record["ok"] for record in events(home) if record["event"] == "map")


def test_without_the_map_add_on_nothing_is_told_to_any_map(tmp_path, monkeypatch):
    monkeypatch.setattr(engine_module, "MAP_HOOK", str(tmp_path / "not-installed"))
    monkeypatch.setenv("FROM", "127.0.0.1")
    home = arrived_home(tmp_path)
    Engine(home).run("run")
    assert not [record for record in events(home) if record["event"] == "map"]
    assert "attempt" in kinds(home)                      # a lab without the map is still a lab


def test_a_machine_that_was_never_on_the_map_is_not_taken_off_it(tmp_path, monkeypatch):
    """Patient zero never arrives anywhere, so the map has nothing to restore."""
    actions = map_add_on(tmp_path, monkeypatch)
    home = make_home(tmp_path, control=FAKE.Signal("stop"),
                     pace=dict(PACE, announce_port=free_udp_port()))
    Engine(home).run("launch")
    assert not actions.exists() or "restore" not in actions.read_text()


def test_the_worm_says_it_halted_before_it_tells_the_map(tmp_path, monkeypatch):
    """Telling the map must never delay the stop: the map could be slow or away."""
    actions = map_add_on(tmp_path, monkeypatch, restore_takes=2)
    monkeypatch.setenv("FROM", "127.0.0.1")
    home = arrived_home(tmp_path, control=FAKE.Signal("stop"))
    monkeypatch.setattr(engine_module, "MAP_CALL_SECONDS", 8)
    Engine(home).run("run")
    log = events(home)
    halted_at = next(i for i, record in enumerate(log) if record["event"] == "halted")
    restored_at = next(i for i, record in enumerate(log)
                       if record["event"] == "map" and record["action"] == "restore")
    assert halted_at < restored_at                      # "halted" is on record first


def test_the_worm_believes_the_map_s_own_answer_not_the_add_on_s_exit_code(tmp_path, monkeypatch):
    """A live run showed "ok: true" for a flash the map had refused with an internal
    error: the add-on ends well whenever the map answered at all."""
    actions = map_add_on(tmp_path, monkeypatch)
    hook = tmp_path / "submit_event.sh"
    hook.write_text(HOOK_SCRIPT.replace('"ok":true', '"ok":false').format(actions, 0))
    monkeypatch.setenv("FROM", "127.0.0.1")
    home = arrived_home(tmp_path)
    Engine(home).run("run")
    told = [record for record in events(home) if record["event"] == "map"]
    assert told and all(record["ok"] is False for record in told)   # refused: the worm says so
    assert "attempt" in kinds(home)                                # and the worm went on regardless
