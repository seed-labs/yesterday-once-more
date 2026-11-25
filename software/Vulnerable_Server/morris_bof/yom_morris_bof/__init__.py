"""The exploit half of morris-bof. This package travels inside the worm's bundle."""

from .exploit import MorrisBofExploit, aslr_setting

__all__ = ["MorrisBofExploit", "aslr_setting"]
