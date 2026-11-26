"""The ransomware: what the worm carries for WannaCry.

Nothing in here is installed on a victim when the lab is built. The folder
travels inside the worm's bundle, and the payload leaves the `ransom` command
behind. It never imports seedemu, and it has to run on any machine the
bundle lands on: heavy libraries are imported only where they are used.

Payment lives in `payment/`: the rest of this package talks to it only
through that folder's client functions.
"""
