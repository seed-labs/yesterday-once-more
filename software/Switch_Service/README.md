# Switch Service

One machine that holds one DNS record. The instructor changes the record
with one command, and every worm that asks sees the change.

```python
KILL_DOMAIN = "www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com"   # the real WannaCry kill switch

switch = DnsSwitch(domain=KILL_DOMAIN, mode="killswitch")
switch.install("switch")                   # the machine that holds the record
emu.addLayer(switch)
emu.addBinding(Binding("switch", filter=Filter(asn=150, nodeName="switch")))

worm = Worm(..., control=switch.reader())  # the worm asks it: run, pause or stop?
```

A worm never imports this piece. The case hands it the reader
(`switch.reader()`), and the switch fills its own address into that reader
when the emulation is built. No address is typed anywhere.

## Two modes

| Mode | The record is absent | The record exists | Commands on the switch machine |
| --- | --- | --- | --- |
| `killswitch` | the worm runs | every worm stops | `switch register`, `switch unregister` |
| `control` | the worm runs | the first number of the address is the command | `switch run`, `switch pause`, `switch stop` |

Both also answer `switch status`: is the record there, and what would a worm
do now?

### killswitch: the real WannaCry

The real worm began by looking up a long nonsense domain. Nobody had
registered it, so nothing answered, and the worm went to work. During the
outbreak a researcher registered the domain; from then on, new copies found
it and stopped.

The lab does the same, with DNS only. The domain is absent, so the worm
runs. The instructor runs `switch register`, the domain answers, and every
copy that asks stops. `switch unregister` makes it spread again.

### control: Prof. Du's encoding

This is the control of his Morris worm, unchanged. The address of the
record is the command, and a worm reads its first number:

| The record | The worm |
| --- | --- |
| `0.0.0.0` | runs |
| `1.0.0.0` | stops |
| `2.0.0.0` | pauses |

His `10.0.0.0` (show) and `11.0.0.0` (off) only change how his worm is drawn
on a map, so for this worm they mean: keep going.

## What never changes

- **The worm asks the switch machine directly**, by its address. There is no
  DNS hierarchy, and the system resolver is never used.
- **A missing answer is never a "go".** If the switch machine does not
  answer at all, the worm stops instead of guessing. "The name is not
  registered" is a real answer, and it means run.
- **One switch per emulation.**
- **No machine's resolver is changed** unless `lab_nameserver=True` is
  asked for.

## On the machines

- The switch machine runs a real BIND server, seedemu's own, for the zone
  the name lives in. The tool changes the record with `nsupdate`, the same
  tool Dr. Du's Morris worm uses.
- By default the switch changes nothing else in the lab. No machine's
  resolver is touched: the reader asks the switch machine by its address.

  For a class, one option makes every machine in the lab ask the switch
  machine for names. Then a student can look the domain up on any machine
  and watch it appear:

  ```python
  switch = DnsSwitch(domain=KILL_DOMAIN, mode="killswitch", lab_nameserver=True)
  ```

  ```sh
  nslookup www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com
  ```

  The switch machine answers only for its own zone; it resolves no other
  names. So with this option on, machines in the lab cannot look up any
  other name.

## Running it

With the lab up:

```sh
docker compose exec <switch container> switch status
docker compose exec <switch container> switch register     # every worm stops
```

## Tests

From the repository root: `python -m pytest`. They need no Docker: a small
server that speaks real DNS stands in for the switch machine, and the
installer runs on a real seedemu emulation.
