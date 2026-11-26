"""Putting files and one-word commands onto machines at build time.

The pieces use this to place their code on machines; the cases use it to
place the files of their story. It runs on the machine that builds the
emulation and never travels into a container.
"""

from pathlib import Path

#: The folder inside a machine where every piece keeps its code.
HOME = "/opt/yom"


def place_files(machines, source, dest, network=None) -> int:
    """Copy a folder, or one file, onto machines. Returns how many files each got.

    A folder is copied as it is, subfolders included, and `dest` is the folder
    that will hold it. A single file is copied to `dest`, its full new path.

    Every file is imported as a real file, byte for byte. (A file written as
    text gets an extra empty line at its end, and a document would then no
    longer be identical to its original.) An imported file arrives without
    its executable bit, so a program needs `chmod +x` when the machine boots.

    A machine is a node, or several nodes in a list. A case may also name
    machines instead, as it named them when it built its network, and pass
    that network:

        place_files(node, "yom_worm", "/opt/yom/yom_worm")
        place_files(VICTIMS, HERE / "documents", "/home/seed/Documents", network=lab)
    """
    if isinstance(machines, str) or hasattr(machines, "getFiles"):
        machines = [machines]
    nodes = []
    for machine in machines:
        if isinstance(machine, str):
            if network is None:
                raise ValueError(f"'{machine}' is a name: pass the network that holds it (network=...)")
            try:
                machine = network.getHost(machine)
            except (KeyError, TypeError) as error:
                raise ValueError(f"no machine named '{machine}' in that network") from error
        nodes.append(machine)

    source = Path(source).resolve()
    if source.is_dir():
        copies = [(path, "{}/{}".format(dest, path.relative_to(source).as_posix()))
                  for path in sorted(source.rglob("*"))
                  if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc"]
    else:
        copies = [(source, str(dest))]

    for node in nodes:
        for path, target in copies:
            node.importFile(str(path), target)
    return len(copies)


def add_command(node, name: str, package: str) -> None:
    """Give a machine a one-word command that starts one of our packages.

    For example `add_command(node, "worm", "yom_worm")` gives it `worm launch`.
    The command runs the package from Core's HOME folder, and the Python it
    needs is installed on the machine as well.
    """
    node.setFile(
        "/usr/local/bin/{}".format(name),
        '#!/bin/bash\nPYTHONPATH={} exec python3 -m {} "$@"\n'.format(HOME, package),
    )
    node.addSoftware("python3")
    node.appendStartCommand("chmod +x /usr/local/bin/{}".format(name))
