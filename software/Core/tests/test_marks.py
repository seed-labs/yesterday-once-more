"""Marks, on a real seedemu emulation: one piece marks, another finds. No Docker."""

import pytest
from seedemu.core import Binding, Emulator, Filter, Layer
from seedemu.layers import Base, Routing

from software.Core.marks import mark, marked_hosts


def network(names):
    """One small network with the named machines, already rendered."""
    emu, base = Emulator(), Base()
    asn = base.createAutonomousSystem(172)
    asn.createNetwork("net0")
    hosts = {name: asn.createHost(name).joinNetwork("net0") for name in names}
    asn.createRouter("router0").joinNetwork("net0")
    emu.addLayer(base)
    emu.addLayer(Routing())
    for name in names:
        emu.addBinding(Binding(name, filter=Filter(asn=172, nodeName=name)))
    return emu, asn, hosts


def names(nodes):
    return [node.getName() for node in nodes]


class Marker(Layer):
    """Stands in for a piece that marks machines while the emulation is configured."""

    def __init__(self, nodes, name="the-chosen", layer="Marker"):
        super().__init__()
        self.nodes, self.name, self.layer = nodes, name, layer

    def getName(self) -> str:
        return self.layer          # seedemu wants one name per layer

    def configure(self, emulator):
        for node in self.nodes:
            mark(node, self.name)

    def render(self, emulator):
        pass


class Finder(Layer):
    """Stands in for another piece: looks for machines while it renders."""

    def __init__(self):
        super().__init__()
        self.found = None

    def getName(self) -> str:
        return "Finder"

    def render(self, emulator):
        self.found = names(marked_hosts(emulator, "the-chosen"))


# ---- what a mark is ----

def test_an_emulation_where_nobody_marked_anything_has_no_marked_machines():
    emu, _, _ = network(["victim1"])
    emu.render()
    assert marked_hosts(emu, "the-chosen") == []


def test_a_marked_machine_is_found_by_its_mark():
    emu, _, hosts = network(["victim1", "victim2"])
    emu.render()
    mark(hosts["victim2"], "the-chosen")
    assert marked_hosts(emu, "the-chosen") == [hosts["victim2"]]     # the node itself
    assert marked_hosts(emu, "something-else") == []                 # and under no other name


def test_a_machine_can_carry_several_marks():
    """Each piece marks in its own words; Core keeps no rule about what they mean."""
    emu, _, hosts = network(["victim1", "victim2"])
    emu.render()
    mark(hosts["victim1"], "the-chosen")
    mark(hosts["victim1"], "the-operator")
    mark(hosts["victim2"], "the-operator")
    assert marked_hosts(emu, "the-chosen") == [hosts["victim1"]]
    assert marked_hosts(emu, "the-operator") == [hosts["victim1"], hosts["victim2"]]


def test_the_same_mark_twice_is_refused_and_changes_nothing():
    emu, _, hosts = network(["victim1"])
    emu.render()
    mark(hosts["victim1"], "the-chosen")
    with pytest.raises(ValueError, match="as172/victim1 already carries the mark 'the-chosen'"):
        mark(hosts["victim1"], "the-chosen")
    assert marked_hosts(emu, "the-chosen") == [hosts["victim1"]]


def test_machines_come_in_the_order_the_emulation_made_them():
    emu, _, hosts = network(["victim3", "victim1", "victim2"])
    emu.render()
    for name in ("victim2", "victim3", "victim1"):        # marked in another order
        mark(hosts[name], "the-chosen")
    assert names(marked_hosts(emu, "the-chosen")) == ["victim3", "victim1", "victim2"]


def test_a_router_can_be_marked_too():
    emu, asn, _ = network(["victim1"])
    emu.render()
    router = asn.getRouter("router0")
    mark(router, "the-chosen")
    assert marked_hosts(emu, "the-chosen") == [router]


# ---- when marks exist ----

def test_before_the_rendering_starts_a_machine_has_no_marks_yet():
    """seedemu gives a machine its marks when the rendering starts. Say so, do not crash."""
    _, _, hosts = network(["victim1"])
    with pytest.raises(ValueError, match="when the rendering starts, so mark it from a service"):
        mark(hosts["victim1"], "the-chosen")


# ---- two pieces, through the marks only ----

def test_one_piece_marks_and_another_finds_without_importing_it():
    """The piece that looks may even be added to the emulation before the one that marks."""
    emu, _, hosts = network(["victim1", "victim2", "bystander"])
    finder, marker = Finder(), Marker([hosts["victim1"], hosts["victim2"]])
    emu.addLayer(finder)
    emu.addLayer(marker)
    emu.render()
    assert finder.found == ["victim1", "victim2"]
    assert marked_hosts(emu, "the-chosen") == [hosts["victim1"], hosts["victim2"]]


def test_two_pieces_can_mark_the_same_machine_each_in_their_own_words():
    emu, _, hosts = network(["victim1", "victim2"])
    victims = Marker([hosts["victim1"], hosts["victim2"]], "vulnerable", "Victims")
    operators = Marker([hosts["victim2"]], "operator", "Operators")
    emu.addLayer(victims)
    emu.addLayer(operators)
    emu.render()
    assert names(marked_hosts(emu, "vulnerable")) == ["victim1", "victim2"]
    assert names(marked_hosts(emu, "operator")) == ["victim2"]
