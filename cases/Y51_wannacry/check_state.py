#!/usr/bin/env python3
"""Is the story complete? Compare the victims' documents with the originals.

Run it on the host, from this folder, while the lab is up:

    python3 check_state.py

It reads each victim's documents folder through `docker compose exec` and
compares every document with the file of the same name in documents/. It
changes nothing on a victim. The exit status is 0 when every victim holds
documents identical to the originals.
"""

import argparse
import io
from pathlib import Path
import subprocess
import sys
import tarfile

HERE = Path(__file__).resolve().parent

VICTIMS = ["victim1", "victim2", "victim3"]
DOCUMENTS = "/home/seed/Documents"
SUFFIX = ".WNCRY"
NOTE = "READ_ME.txt"
ASN = 180


def service_of(victim: str) -> str:
    """The name docker compose knows a machine by."""
    return "hnode_{}_{}".format(ASN, victim)


def unpack(listing: bytes) -> dict:
    """{name: bytes} of the files in a tar listing, as `tar -cf - .` prints one."""
    with tarfile.open(fileobj=io.BytesIO(listing)) as archive:
        return {member.name.lstrip("./"): archive.extractfile(member).read()
                for member in archive.getmembers() if member.isfile()}


def read_folder(compose_file: Path, service: str) -> dict:
    """{name: bytes} of every file in a machine's documents folder."""
    listing = subprocess.run(
        ["docker", "compose", "-f", str(compose_file), "exec", "-T", service,
         "tar", "-C", DOCUMENTS, "-cf", "-", "."],
        capture_output=True, check=True,
    ).stdout
    return unpack(listing)


def compare(folder: dict, originals: dict) -> dict:
    """How far a machine's documents are from the originals."""
    restored = sorted(name for name in originals if folder.get(name) == originals[name])
    changed = sorted(name for name in originals if name in folder and folder[name] != originals[name])
    locked = sorted(name for name in originals
                    if name not in folder and name + SUFFIX in folder)
    gone = sorted(name for name in originals
                  if name not in folder and name + SUFFIX not in folder)
    if len(restored) == len(originals) and not changed and not locked:
        # Every document is identical again. With the ransom note still there,
        # that means the worm came and the documents were brought back.
        state = "RESTORED" if NOTE in folder else "NOT ATTACKED"
    elif not restored and len(locked) == len(originals):
        state = "LOCKED"                # the worm came, and nothing was paid for yet
    else:
        state = "PARTLY"
    return {"state": state, "restored": restored, "changed": changed,
            "locked": locked, "gone": gone, "note": NOTE in folder}


def report(victim: str, found: dict, total: int) -> str:
    line = "{}: {} of {} documents identical to the originals".format(
        victim, len(found["restored"]), total)
    details = []
    if found["locked"]:
        details.append("{} still locked ({}), their originals gone".format(len(found["locked"]), SUFFIX))
    if found["changed"]:
        details.append("{} changed".format(len(found["changed"])))
    if found["gone"]:
        details.append("{} missing".format(len(found["gone"])))
    if found["note"]:
        details.append("the ransom note is there")
    if details:
        line += ". " + "; ".join(details)
    return "{}  [{}]".format(line, found["state"])


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--output", type=Path, default=HERE / "output",
                        help="the compiled lab, where docker-compose.yml is")
    args = parser.parse_args(argv)
    compose_file = args.output.expanduser().resolve() / "docker-compose.yml"
    if not compose_file.is_file():
        print("no lab in {}. Build it first:  ../../.venv/bin/python emulator.py".format(compose_file.parent))
        return 2
    originals = {path.name: path.read_bytes() for path in sorted((HERE / "documents").iterdir())
                 if path.is_file()}
    states = []
    for victim in VICTIMS:
        try:
            found = compare(read_folder(compose_file, service_of(victim)), originals)
        except subprocess.CalledProcessError as error:
            print("{}: not reachable. Is the lab up? ({})".format(victim, error.stderr.decode().strip()))
            states.append("UNREACHABLE")
            continue
        print(report(victim, found, len(originals)))
        states.append(found["state"])
    if all(state == "RESTORED" for state in states):
        print("\nThe story is complete: every victim got its documents back.")
        return 0
    print("\nThe story is not complete yet.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
