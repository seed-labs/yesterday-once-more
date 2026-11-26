"""The Morris buffer overflow, as in the Morris worm example.

Two halves, built against the same program:

    MorrisBof         the vulnerability: the server installed on victims
    MorrisBofExploit  the exploit that matches it, for a worm to use
"""

from .vulnerability import MorrisBof
from .yom_morris_bof import MorrisBofExploit

__all__ = ["MorrisBof", "MorrisBofExploit"]
