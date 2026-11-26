"""A smallest-possible DNS client: one A question, sent straight to one server.

The worm's reader and the switch's own tool must not depend on how a machine
is told to resolve names, so neither uses the system resolver. They ask the
switch machine by its address and read the answer themselves.

Rules for this file: standard library only. It has to run on any machine the
worm's bundle lands on.
"""

import os
import socket


def _question(name: str) -> bytes:
    labels = name.rstrip(".").split(".")
    packet = b"".join(bytes([len(part)]) + part.encode("ascii") for part in labels)
    return packet + b"\x00" + b"\x00\x01\x00\x01"      # end of the name, type A, class IN


def _first_address(reply: bytes, question: bytes):
    """The IPv4 address in the first answer record, when that record is an A record.

    A reply is 12 bytes of header, then the question again, then the answer
    records. One record, counted from where it starts:

        0- 2  the name, as a pointer back to the question (0xC0 0x0C)
        2- 4  type        4- 6  class       6-10  time to live
       10-12  data length   12-..  the data (4 bytes for an address)
    """
    start = 12 + len(question)
    if len(reply) < start + 12 or reply[start] & 0xC0 != 0xC0:
        return None                                 # no name pointer: no answer to read
    record_type = int.from_bytes(reply[start + 2:start + 4], "big")
    data_length = int.from_bytes(reply[start + 10:start + 12], "big")
    data = reply[start + 12:start + 12 + data_length]
    if record_type != 1 or data_length != 4 or len(data) != 4:
        return None
    return ".".join(str(byte) for byte in data)


def query(server: str, name: str, timeout: float = 2.0, tries: int = 3, port: int = 53):
    """Ask `server` for an A record of `name`.

    Returns a state and an address: ("missing", None) when the name has no
    address, ("exists", "a.b.c.d") when it has one, ("refused", None) when the
    server answered but not for this name, or (None, None) when no answer
    arrived at all.
    """
    question = _question(name)
    for _ in range(tries):
        ident = os.urandom(2)
        header = ident + b"\x00\x00" + b"\x00\x01" + b"\x00\x00\x00\x00\x00\x00"
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(timeout)
                sock.sendto(header + question, (server, port))
                while True:
                    reply, _ = sock.recvfrom(4096)
                    if reply[:2] != ident:
                        continue                            # an answer to someone else
                    code = reply[3] & 0x0F                 # response code
                    if code == 3:
                        return "missing", None             # NXDOMAIN: no such name
                    if code != 0:
                        return "refused", None
                    address = _first_address(reply, question)
                    return ("exists", address) if address else ("missing", None)
        except OSError:
            pass                                          # no answer: try again
    return None, None
