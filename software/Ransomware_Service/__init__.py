"""Ransomware_Service: what the worm carries for WannaCry.

    from software.Ransomware_Service import Ransomware

    ransom = Ransomware(documents="/home/seed/Documents", suffix=".WNCRY",
                        note=NOTE, price_eth=1)
    ransom.paymentIn(lab, "net0", emu=emu)          its payment chain
    ransom.operatorTools("patient-zero", network=lab)   the operator's tools
    emu.addLayer(ransom)

    worm = Worm(..., payload=ransom.payload())
"""

from .service import Ransomware

__all__ = ["Ransomware"]
