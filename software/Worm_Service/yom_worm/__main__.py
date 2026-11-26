"""`worm launch` on patient zero. `worm run` happens by itself on every other machine."""

import sys

from .engine import ARRIVE, LAUNCH, Engine

USAGE = "usage: worm launch      start the outbreak from this machine"


def main(argv) -> int:
    mode = argv[0] if argv else ""
    if mode not in (LAUNCH, ARRIVE):
        print(USAGE)
        return 2
    Engine().run(mode)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
