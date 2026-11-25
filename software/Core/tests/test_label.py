"""The label: the one thing the worm and a payload's piece have to agree on."""

import ast
import importlib
import sys
from pathlib import Path

import pytest

from software.Core import label as label_format

HERE = Path(label_format.__file__).parent


def test_a_label_travels_through_its_file_and_comes_back_the_same(tmp_path):
    given = label_format.new_label(
        "ransomware", "python3 -m yom_ransomware detonate",
        settings={"documents": "/home/seed/Documents", "suffix": ".WNCRY"},
        needs={"software": ["python3-cryptography"], "build": ["pip3 install eth-account"]},
    )
    path = label_format.write_label(tmp_path / "yom_ransomware", given)

    assert path.name == label_format.LABEL_FILE                # inside the payload's folder
    assert label_format.read_label(path.parent) == given


def test_a_payload_is_a_folder_plus_a_label(tmp_path):
    folder = tmp_path / "yom_ransomware"
    label = label_format.new_label("ransomware", "python3 -m yom_ransomware detonate")
    payload = label_format.Payload(folder, label)
    assert payload.folder == folder and payload.label is label


def test_a_label_without_a_name_or_a_start_command_is_not_written(tmp_path):
    with pytest.raises(ValueError, match="needs a name"):
        label_format.write_label(tmp_path, {"start": "python3 -m x"})
    with pytest.raises(ValueError, match="needs a start"):
        label_format.write_label(tmp_path, {"name": "x"})
    assert not (tmp_path / label_format.LABEL_FILE).exists()


def test_reading_says_where_no_payload_is(tmp_path):
    with pytest.raises(ValueError, match="no payload in"):
        label_format.read_label(tmp_path / "nothing-here")


def test_a_label_that_lost_its_start_command_is_refused(tmp_path):
    (tmp_path / label_format.LABEL_FILE).write_text('{"name": "ransomware"}')
    with pytest.raises(ValueError, match="no start"):
        label_format.read_label(tmp_path)


def test_settings_and_needs_are_there_even_when_nobody_filled_them(tmp_path):
    label_format.write_label(tmp_path, {"name": "x", "start": "true"})
    assert label_format.read_label(tmp_path) == {"name": "x", "start": "true", "settings": {}, "needs": {}}


def test_the_format_file_can_travel_into_any_machine():
    """Both sides import it, inside containers too: standard library only."""
    tree = ast.parse((HERE / "label.py").read_text(encoding="utf-8"))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported |= {alias.name.split(".")[0] for alias in node.names}
        elif isinstance(node, ast.ImportFrom) and node.level == 0:
            imported.add(node.module.split(".")[0])
    assert imported and imported <= set(sys.stdlib_module_names)

    # And it works on its own, the way the worm and a payload load it there.
    sys.path.insert(0, str(HERE))
    try:
        assert importlib.import_module("label").LABEL_FILE == "label.json"
    finally:
        sys.path.remove(str(HERE))
        sys.modules.pop("label", None)
