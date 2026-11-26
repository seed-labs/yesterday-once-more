"""The parts that ship with the worm itself."""

import random


class ShuffleScanner:
    """Who to attack: a list of machines, in a new order on every pass.

    This is the only scanner that ships with the worm. A case normally leaves
    `targets` empty: the worm's installer fills it with every machine that is
    marked with the exploit's vulnerability, so nobody has to type addresses.
    """

    SLOT = "scanner"

    def __init__(self, targets=None, seed=None):
        self.targets = list(targets or [])
        self.seed = seed          # a number makes the order the same on every run

    def next_target(self, exclude=()):
        """The next machine to try, or None when they are all in `exclude`."""
        if not self.targets or all(target in exclude for target in self.targets):
            return None
        while True:
            if not getattr(self, "_queue", None):
                self._passes = getattr(self, "_passes", 0) + 1
                self._queue = list(self.targets)
                seed = None if self.seed is None else self.seed + self._passes
                random.Random(seed).shuffle(self._queue)
            target = self._queue.pop()
            if target not in exclude:
                return target
