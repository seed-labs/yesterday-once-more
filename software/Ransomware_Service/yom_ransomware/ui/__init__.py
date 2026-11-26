"""The terminal menu of a locked machine.

It looks the same in every case; only the note text and the price come from
the case. The payment screens (wallet, exchange, document recovery) are shown
only when the lab has a payment chain.
"""

from .menu import run_interface

__all__ = ["run_interface"]
