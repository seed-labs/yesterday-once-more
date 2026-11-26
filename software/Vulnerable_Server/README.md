# Vulnerable Server

Puts a vulnerability on machines. A vulnerability is useful on its own,
without any worm: for manual labs, detection labs, patching labs.

```python
from seedemu.core import Binding, Filter
from software.Vulnerable_Server import MorrisBof, VulnerableServer

bof = MorrisBof()                      # pick one vulnerability
vulns = VulnerableServer(bof)          # the service that installs it
emu.addLayer(vulns)
for victim in VICTIMS:
    vulns.install(victim)              # one virtual node per machine
    emu.addBinding(Binding(victim, filter=Filter(asn=150, nodeName=victim)))
```

## What the service does

- **It installs, and knows nothing else.** A vulnerability is an object with
  a name, a port and `install(node)`. The service never changes when one is
  added.
- **Every machine is marked** with the name of its vulnerability. The mark is
  made through Core, so another piece finds these machines through Core too
  (`marked_hosts`) and never has to import this service. Under this piece's
  own name it is the same call:

  ```python
  vulnerable_hosts(emu, bof.name)      # the machines that have it
  ```

- **A machine gets one vulnerability.** Machines may have different ones;
  two on the same machine are refused when the emulation is built.

- **One machine can differ from the rest:**

  ```python
  vulns.install("victim2").setVulnerability(another)
  ```

- **What the Docker host must provide is a warning.** Building the emulation
  prints it; it does not stop the build.

## The vulnerabilities

| Vulnerability | Port | What the Docker host needs |
| --- | --- | --- |
| `MorrisBof` | 9090/tcp | ASLR switched off (`sudo sysctl -w kernel.randomize_va_space=0`) |

### MorrisBof

The buffer-overflow server of the Morris worm example, unchanged.
`server` listens on port 9090 and hands each connection to `stack`, a 32-bit
program with an executable stack that copies whatever it receives into a
100-byte buffer. The two programs and their sources are in
[`morris_bof/assets/`](morris_bof/assets/NOTICE).

**Why ASLR has to be off.** An exploit has to name the exact place in memory
where `stack` keeps its frame. With ASLR on, that place changes on every run.
So the server waits until ASLR is off before it starts. Switching it off
after the lab has started works too: a program that was started while ASLR
was on would keep randomising its children.

**Its exploit is optional.** When a worm has to get in, the case hands it
over from the same object, and nothing else is written:

```python
worm = Worm(exploit=bof.exploit(), ...)
```

Without a worm, leave it out and the lab simply has a vulnerable program.

## What an exploit has to provide

A worm never imports an exploit. It writes the exploit into its settings
file, carries its code along in its bundle, and builds it again on every
machine it reaches. So an exploit is a small object:

| It has | What it is for |
| --- | --- |
| `SLOT = "exploit"` | tells the worm which slot it fills |
| `vulnerability` | the name of the vulnerability it fits. The worm attacks the machines marked with that name. |
| a constructor with plain arguments | each argument is kept in an attribute of the same name. That is how the exploit travels in the settings file. |
| `break_in(target, bundle)` | gets into the machine at address `target` and hands over the worm's bundle. Returns `"arrived"`, `"already"` (the machine had it before) or `None` (it never answered). |

Three more are optional:

| | Called |
| --- | --- |
| `prepare(worm)` | first, on every machine. Keep the worm: it does the networking. |
| `check_host()` | on patient zero, before anything is attacked: a list of problems that stop the launch. It may also measure something there and keep it, because that travels in the settings file too. |
| `stage(node)` | at build time, on patient zero only: what the exploit needs there, for example a program to measure with. |

`break_in` asks the worm to do the networking:

| | |
| --- | --- |
| `worm.home` | the folder the worm lives in on this machine |
| `worm.announce_port` | the UDP port that machines answer on |
| `worm.my_ip_toward(target)` | our own address, as the target will see it |
| `worm.exchange(ip, port, data, wait)` | send everything, close our side, then wait |
| `worm.deliver(ip, port, data)` | wait for a port to start listening, then send everything |
| `worm.wait_answer(target)` | wait for the machine that was just attacked to answer |

The code of an exploit has two rules: the standard library only, and no
import from the worm package or from anything that stays on the build
machine. It has to run on any machine the bundle lands on.

`MorrisBofExploit` is the example:
[`morris_bof/yom_morris_bof/exploit.py`](morris_bof/yom_morris_bof/exploit.py).

## Two traps in the base image, handled here

- **zsh swallows the shell an exploit gets.** This image's `/root/.bashrc`
  is just `exec zsh`. Bash also reads that file when it is started with `-c`
  and its input is a network connection, which is the situation an exploit
  creates. It is changed to run zsh only for interactive shells, so people
  keep zsh. The Morris worm example deletes the file instead.
- **Imported files are not executable.** A file put on a machine arrives
  with no executable bit, so it is set when the machine boots.

## Adding a vulnerability

Make a folder under this one, following `morris_bof/`:

1. a class deriving from `Vulnerability`, with a `name`, a `port`,
   `install(node)` and, if the host must provide something, `check_host()`;
2. only if it should have one: an exploit in a small package named
   `yom_<vulnerability>/`, written by the rules above, and a method
   `exploit()` that hands it out.

Then export the class from `Vulnerable_Server/__init__.py`. The service
itself stays as it is.

## Tests

From the repository root: `python -m pytest`. They need no Docker. Where a
test can, it runs the real thing: the command the Morris exploit sends is run
by bash, and a bundle is pushed through a real socket.
