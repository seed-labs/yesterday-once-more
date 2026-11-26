"""The bundle: one tarball with everything a copy of the worm needs.

It holds the worm's own package, the packages of the parts it uses, the
payload's folder with its label, the label's format (`label.py`, which the
worm and the payload both read), and the settings file `worm.json`. The same
bundle is handed on from machine to machine.
"""

import io
import json
import tarfile
from pathlib import Path


def pack(home, packages, manifest: dict) -> bytes:
    """Bundle everything that stands in `home` for the worm.

    `packages` are the folders of the parts, which the next machine imports.
    The payload's folder, if there is one, is carried too but never imported:
    it is started by its own command.
    """
    home = Path(home)
    carried = ["yom_worm"] + list(packages)
    if manifest.get("payload"):
        carried.append(manifest["payload"]["folder"])
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        for name in carried:
            for path in sorted((home / name).rglob("*")):
                if path.is_file() and "__pycache__" not in path.parts:
                    archive.add(path, arcname=path.relative_to(home).as_posix())
        archive.add(home / "label.py", arcname="label.py")
        data = (json.dumps(manifest, indent=2) + "\n").encode("utf-8")
        info = tarfile.TarInfo("worm.json")
        info.size = len(data)
        archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()
