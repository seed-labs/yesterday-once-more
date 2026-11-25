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
- **Every machine is marked** with the name of its vulnerability. Another
  piece finds them by that mark and never has to look inside this service:

  ```python
  vulnerable_hosts(emu, bof.name)      # the machines that have it
  ```

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

The buffer-overflow server from Dr. Du's Morris worm example, unchanged.
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

## Two traps in the base image, handled here

- **zsh swallows the shell an exploit gets.** This image's `/root/.bashrc`
  is just `exec zsh`. Bash also reads that file when it is started with `-c`
  and its input is a network connection, which is the situation an exploit
  creates. It is changed to run zsh only for interactive shells, so people
  keep zsh. Dr. Du's example deletes the file instead.
- **Imported files are not executable.** A file put on a machine arrives
  with no executable bit, so it is set when the machine boots.

## Adding a vulnerability

Make a folder under this one, following `morris_bof/`:

1. a class deriving from `Vulnerability`, with a `name`, a `port`,
   `install(node)` and, if the host must provide something, `check_host()`;
2. only if it should have one: an exploit in a small package named
   `yom_<vulnerability>/`, written by the rules in
   [Worm_Service](../Worm_Service/README.md), and a method `exploit()` that
   hands it out.

Then export the class from `Vulnerable_Server/__init__.py`. The service
itself stays as it is.

## Tests

From the repository root: `python -m pytest`. They need no Docker. Where a
test can, it runs the real thing: the command the Morris exploit sends is run
by bash, and a bundle is pushed through a real socket.
