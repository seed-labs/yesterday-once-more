"""The worm's own runtime package. It travels inside the worm's bundle.

Only the spread loop lives here (engine.py). The three parts it is made of
(who to attack, how to get in, when to stop) come from other packages; what
such a part has to look like is written in spec.py. What it carries (the
payload) is a folder plus a label, see Core's label.py.
"""
