# Worm Service

The spread loop, with three slots that a case fills in.

```python
worm = Worm(exploit=bof.exploit(),                  # how to get in: from the vulnerability
            payload=ransom.payload(),               # what to carry: a folder plus a label
            control=switch.reader())                # when to stop: run, pause or stop
emu.addLayer(worm)
worm.launchFrom("patient-zero")
```

## The three slots

| Slot | The question it answers | If a case leaves it out |
| --- | --- | --- |
| `exploit` | How does the worm get in? | Must be given. Take it from the vulnerability: `bof.exploit()` |
| `payload` | What does it carry? | Nothing: the worm only spreads, like Morris |
| `control` | Keep going, pause or stop? | Only the time limit can stop it |

Who to attack is not typed by a case: the installer fills it in.

The same worm serves several cases by swapping slots. Morris is the same
exploit with nothing carried.

## How it spreads

1. A person runs `worm launch` on patient zero (or it starts at boot).
2. The worm checks that its exploit can work here. If not, it says why and
   stops before touching anyone.
3. It waits until the machine that controls it has answered once. If that
   machine never answers, the worm stops: a missing answer is never a "go".
4. It packs its bundle: its own code, the code of the parts, the payload's
   folder with its label, and the settings file.
5. Round after round, in this order: ask the control, pick a target, break in
   and hand over the bundle, wait for the target's answer.
6. On the target, the bundle unpacks itself to `/tmp/yomw`. The copy there
   answers "arrived", **runs the payload until it has finished its own work**,
   and only then starts spreading too. The payload never waits for a person:
   a victim pays long after the worm has moved on.

Nothing of the worm is put on a victim when the emulation is built. It gets
there by breaking in, which is what makes it a worm.

## What the installer does for a case

- **Who to attack.** The worm asks Core for every machine marked with the
  exploit's vulnerability, and attacks exactly those. It never looks inside
  the piece that made the marks.
- **What a reached machine needs.** The bundle is Python, so `python3` is put
  on every machine the worm can reach. A payload says in its label what else
  it needs, and that is put there too, as ordinary machine software. The
  payload itself is not.
- **No address is typed.** The control part finds its own machine: the piece
  that made it fills the address in.

The worm never imports another piece. It is handed three small objects and
writes each into its settings file by looking at it: the class's name and
what its constructor took.

## The Internet Map

The map is seedemu's own dashboard. With its `submit_event` add-on installed
(one command, see the WannaCry case), a machine **flashes on the map the
moment the worm arrives on it** and stays highlighted. When the worm stops
there, the highlight goes away. On a lab without the map, or without the
add-on, the worm says nothing to any map.

## Running it

```sh
docker compose exec <patient zero container> worm launch
docker compose logs <the containers>
```

Every machine prints one JSON line per thing it does. The same lines are
kept in `events.jsonl` in the worm's folder: `/opt/yom/` on patient zero and
`/tmp/yomw/` on a machine it reached.

`Worm(..., autostart=True)` starts the worm when patient zero boots, for
demos where nobody runs the command by hand.

## What the worm will not do

- Attack a machine that is not on its list.
- Start when its exploit cannot work on this machine.
- Start, or go on, when the machine that controls it does not answer.
- Run longer than `max_seconds` (30 minutes by default).
- Run twice on one machine, or overwrite a machine that already has it.

## Writing a part

Any class can fill a slot if it follows three rules:

1. a class attribute `SLOT` naming its slot (`scanner`, `exploit`, `control`);
2. a constructor whose arguments are plain data, each kept in an attribute
   of the same name;
3. the method of its slot.

| Slot | Method | Called |
| --- | --- | --- |
| `scanner` | `next_target(exclude)` → address or `None` | each round |
| `exploit` | `break_in(target, bundle)` → `"arrived"`, `"already"` or `None` | each round |
| `control` | `answer()` → `"run"`, `"pause"` or `"stop"` | each round, before anything else |

A part may also have a few more things, all optional:

| | What it is for |
| --- | --- |
| `prepare(worm)` | called once on every machine; the `worm` does the networking for the part |
| `check_host()` | on patient zero, before anything is attacked: problems that stop the launch. It may also measure something there, which then travels in the settings file |
| `stage(node)` | on patient zero at build time: what the part needs there |

A part lives in its own small package next to the piece that provides it
(for example `yom_morris_bof/`, `yom_switch/`). The installer ships that
folder inside the bundle. Keep it to the standard library, and do not import
the worm package from it: the part has to run on any machine. What an
exploit in particular has to provide is written in
[Vulnerable_Server](../Vulnerable_Server/README.md).

## Carrying a payload

A payload is a folder plus a label (see Core's `label.py`). Its start
command does the payload's own work on a machine the worm just arrived on,
and returns when that work is done. The worm reads the label on arrival and
runs that command. The payload's settings are its own: only the payload
reads them.

## Options

`Worm(..., pace=Pace(...))` sets the loop itself:

| | Default | |
| --- | --- | --- |
| `attempt_delay` | 2.0 | seconds between two attempts |
| `announce_wait` | 8.0 | how long to wait for a machine to answer |
| `body_wait` | 8.0 | how long to wait for a machine to take the bundle |
| `max_seconds` | 1800 | the worm always stops after this |
| `startup_wait` | 60 | how long to wait for the control machine at start |
| `pause_seconds` | 5 | how long a pause lasts before asking again |
| `announce_port` | 9998 | UDP port that machines answer on |

## Tests

From the repository root: `python -m pytest`. They need no Docker.
