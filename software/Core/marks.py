"""Marks: how one piece says which machines are which, and another finds them.

A mark is a name a machine carries, for example the name of its
vulnerability. One piece marks machines without knowing who will look for
them; another piece finds them by that name alone. So the two never import
each other. It is the way seedemu's own BotnetService publishes its server.

A machine can carry several marks, each in the words of the piece that made
it. A piece that wants a narrower rule (for example "one vulnerability per
machine") keeps that rule itself.

Marks exist while the emulation renders, from a service: seedemu registers
its machines when the rendering starts, and only from then on does it keep a
node's marks.
"""

from seedemu.core import Node

#: What a machine is marked with: the list of its marks.
MARK = "yom_marks"


def mark(node, name: str) -> None:
    """Mark a machine: from now on it is one of the machines called `name`.

    A machine can carry several marks. The same mark twice is refused.
    """
    try:
        present = node.getAttribute(MARK)
    except AttributeError:              # the rendering has not started yet
        raise ValueError(
            "as{}/{} has no marks yet. seedemu gives a machine its marks when the "
            "rendering starts, so mark it from a service.".format(
                node.getAsn(), node.getName())
        ) from None
    present = list(present or [])
    if name in present:
        raise ValueError("as{}/{} already carries the mark '{}'".format(
            node.getAsn(), node.getName(), name))
    present.append(name)
    node.setAttribute(MARK, present)


def marked_hosts(emu, name: str) -> list:
    """The machines that carry this mark, in the order the emulation made them."""
    return [node for node in emu.getRegistry().getAll().values()
            if isinstance(node, Node) and name in (node.getAttribute(MARK) or [])]
