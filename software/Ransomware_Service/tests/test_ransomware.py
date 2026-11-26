"""The ransomware, tested on this machine without Docker.

A victim's disk is a temporary folder: the documents, the infection's files
and the `ransom` command all live there for the duration of a test. Where
the chain is needed, a fake stands in for it behind the payment client.
"""

import base64
import builtins
import io
import json
import re
import socket
from contextlib import redirect_stdout
from pathlib import Path

import eth_account
import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import label as label_format          # the way machine-side code imports it (see pytest.ini)
from software.Ransomware_Service import Ransomware
from software.Ransomware_Service.yom_ransomware import files, keys, operator, payment, paths, victim
from software.Ransomware_Service.yom_ransomware.ui import menu

#: What the menu of the earlier WannaCry case printed for KEYSTROKES below
#: (its terminal_ui.py, cases/Y51_wannacry at commit 70a5218, before the
#: scripts were replaced by the pieces). The menu must keep printing exactly this.
MENU_REFERENCE = Path(__file__).with_name("menu_reference.txt")
ASN = 180

DOCUMENTS = {
    "notes.txt": "Team handover notes\nPrepare the weekly report on Friday.\n",
    "budget.csv": "department,allocated,spent\noperations,12000,9500\n",
    "report.md": "# Monthly report\n\nThe team completed three training sessions this month.\n",
}
ENCRYPTED = {name: "ENCRYPTED (.WNCRY) — ransomware envelope present" for name in DOCUMENTS}
ORIGINAL = {name: "ORIGINAL — baseline matches" for name in DOCUMENTS}


@pytest.fixture
def machine(tmp_path, monkeypatch):
    """A machine with documents on its disk; every path points into a temporary folder."""
    documents = tmp_path / "Documents"
    documents.mkdir()
    for name, text in DOCUMENTS.items():
        (documents / name).write_text(text)
    state = tmp_path / "wannacry"
    for name in ("STATE", "KEYLOG", "RECORD", "WALLET", "REQUEST", "REPLY", "ACCEPTED", "CHAIN"):
        monkeypatch.setattr(paths, name, state / name)
    operator_dir = tmp_path / "operator"
    for name in ("ATTACKER_KEYS", "CHAIN_KEY", "OPERATOR_CHAIN"):
        monkeypatch.setattr(paths, name, operator_dir / name)
    monkeypatch.setattr(paths, "OPERATOR", operator_dir)
    monkeypatch.setattr(paths, "MENU", tmp_path / "bin" / "ransom")
    return tmp_path, documents


def operator_keys(where):
    """Create the operator's key pair, far away from the victim's disk."""
    operator.init(where)


def lock(machine, note="The documents of this machine are locked.", suffix=".WNCRY", chain=None):
    """Lock the documents the way the worm's payload does. Returns the worm's folder."""
    where, documents = machine
    operator_keys(where / "operator-side")
    attacker_pub = keys.read_json(paths.ATTACKER_KEYS)["attacker_pub_pem"]
    home = where / "yomw"
    victim.detonate(home, {
        "documents": str(documents), "suffix": suffix, "note": note,
        "attacker_pub_pem": attacker_pub, "payment": chain,
    })
    return home


def shown(what) -> str:
    """What a command prints."""
    out = io.StringIO()
    with redirect_stdout(out):
        what()
    return out.getvalue()


# ---- locking and restoring one folder ----

def test_lock_then_unlock_round_trip(tmp_path):
    for name, text in DOCUMENTS.items():
        (tmp_path / name).write_text(text)
    original = {name: (tmp_path / name).read_bytes() for name in DOCUMENTS}

    key = AESGCM.generate_key(bit_length=256)
    record = files.encrypt_all(tmp_path, "victim1", key, ".WNCRY")
    files.apply_lock(tmp_path, record, ".WNCRY")
    assert sorted(p.name for p in tmp_path.iterdir()) == sorted(n + ".WNCRY" for n in DOCUMENTS)
    assert files.inspect(tmp_path, record, ".WNCRY") == ENCRYPTED
    assert (tmp_path / "notes.txt.WNCRY").read_bytes().startswith(files.MAGIC)

    assert files.unlock(tmp_path, "victim1", key, record, ".WNCRY") == sorted(DOCUMENTS)
    assert {p.name: p.read_bytes() for p in tmp_path.iterdir()} == original
    assert files.inspect(tmp_path, record, ".WNCRY") == ORIGINAL


def test_the_key_is_bound_to_the_victim(tmp_path):
    key = AESGCM.generate_key(bit_length=256)
    (tmp_path / "a.txt").write_text("secret")
    record = files.encrypt_all(tmp_path, "victim1", key, ".WNCRY")
    with pytest.raises(Exception):
        files.unlock(tmp_path, "victim2", key, record, ".WNCRY")    # the name is part of every seal


def test_a_changed_or_broken_document_is_reported_in_the_earlier_case_s_words(tmp_path):
    (tmp_path / "a.txt").write_text("original")
    record = files.encrypt_all(tmp_path, "v", AESGCM.generate_key(bit_length=256), ".WNCRY")
    assert files.inspect(tmp_path, record, ".WNCRY") == {"a.txt": "ORIGINAL — baseline matches"}
    (tmp_path / "a.txt").unlink()
    assert files.inspect(tmp_path, record, ".WNCRY") == {"a.txt": "MISSING"}
    (tmp_path / "a.txt").write_text("not the original")
    assert files.inspect(tmp_path, record, ".WNCRY") == {"a.txt": "CHANGED OR BASELINE MISMATCH"}
    (tmp_path / "a.txt.WNCRY").write_text("not an envelope")
    assert files.inspect(tmp_path, record, ".WNCRY") == {
        "a.txt": "INCONSISTENT — both plaintext and .WNCRY envelope exist"}
    (tmp_path / "a.txt").unlink()
    assert files.inspect(tmp_path, record, ".WNCRY") == {"a.txt": "ENCRYPTED (.WNCRY) — UNEXPECTED FORMAT"}


@pytest.mark.parametrize("folder", ["/", "/home", "/home/seed", "/etc", "/tmp", "/opt", "/root"])
def test_it_refuses_to_lock_system_folders(folder):
    with pytest.raises(ValueError, match="system folder"):
        files.check_folder(folder, ".WNCRY")


@pytest.mark.parametrize("suffix", ["", "WNCRY", ".a/b", paths.NOTE_NAME])
def test_it_refuses_what_is_not_a_suffix(suffix):
    with pytest.raises(ValueError, match="not a file suffix"):
        files.check_suffix(suffix)


def test_it_leaves_subfolders_and_links_alone(tmp_path):
    (tmp_path / "Documents").mkdir()
    (tmp_path / "Documents" / "a.txt").write_text("original")
    (tmp_path / "Documents" / "sub").mkdir()
    (tmp_path / "Documents" / "sub" / "b.txt").write_text("b")
    (tmp_path / "outside.txt").write_text("outside")
    (tmp_path / "Documents" / "link.txt").symlink_to(tmp_path / "outside.txt")
    (tmp_path / "Documents" / paths.NOTE_NAME).write_text("note")
    key = AESGCM.generate_key(bit_length=256)
    record = files.encrypt_all(tmp_path / "Documents", "v", key, ".WNCRY")
    assert list(record) == ["a.txt"]                    # only the files that are really documents
    files.apply_lock(tmp_path / "Documents", record, ".WNCRY")
    files.unlock(tmp_path / "Documents", "v", key, record, ".WNCRY")
    assert (tmp_path / "Documents" / "a.txt").read_text() == "original"
    assert (tmp_path / "Documents" / "link.txt").read_text() == "outside"


# ---- what the payload does on arrival ----

def test_arrival_locks_documents_and_leaves_the_menu_and_the_note(machine):
    where, documents = machine
    home = lock(machine, note="Pay up.")

    assert sorted(p.name for p in documents.iterdir()) == sorted(
        [*[n + ".WNCRY" for n in DOCUMENTS], paths.NOTE_NAME])
    assert (documents / paths.NOTE_NAME).read_text() == "Pay up."
    command = paths.MENU
    assert command.read_text() == (
        '#!/bin/bash\nPYTHONPATH={} exec python3 -m yom_ransomware "$@"\n'.format(home))
    assert command.stat().st_mode & 0o111

    keylog = keys.read_json(paths.KEYLOG)
    assert sorted(keylog["files"]) == sorted(DOCUMENTS)
    assert (keylog["suffix"], keylog["documents"]) == (".WNCRY", str(documents))
    assert keylog["participant_id"] == victim.participant_id()
    assert paths.KEYLOG.stat().st_mode & 0o077 == 0            # owner-only

    record = keys.read_json(paths.RECORD)
    assert record["state"] == "ENCRYPTED"                     # what the menu shows as "Recorded state"
    assert record["original_hashes"] == {n: e["sha256"] for n, e in keylog["files"].items()}

    # The operator's private key never reached this machine.
    private = keys.read_json(paths.ATTACKER_KEYS)["attacker_priv_pem"]
    for path in list(where.rglob("*.json")) + [command]:
        assert private not in path.read_text(), path
    assert not paths.CHAIN.exists()                           # no payment in this lab


def test_a_machine_is_never_locked_twice(machine):
    lock(machine)
    with pytest.raises(ValueError, match="already locked"):
        lock(machine)


def test_without_the_operator_s_public_key_nothing_is_locked(machine):
    where, documents = machine
    with pytest.raises(KeyError, match="attacker public key"):
        victim.detonate(where / "yomw", {"documents": str(documents), "suffix": ".WNCRY"})
    assert sorted(p.name for p in documents.iterdir()) == sorted(DOCUMENTS)
    assert not paths.KEYLOG.exists() and not paths.MENU.exists()


def test_the_start_command_reads_its_label_and_does_the_same(machine):
    """What the worm really runs: `python3 -m yom_ransomware detonate`, next to the label."""
    where, documents = machine
    operator_keys(where / "operator-side")
    payload = Ransomware(documents=str(documents), note="From the label.").payload()
    payload.label["settings"]["attacker_pub_pem"] = keys.read_json(paths.ATTACKER_KEYS)["attacker_pub_pem"]
    folder = where / "unpacked" / "yom_ransomware"
    label_format.write_label(folder, payload.label)

    out = io.StringIO()
    with redirect_stdout(out):
        count = victim.run(where / "unpacked", folder)
    assert count == len(DOCUMENTS) and "locked 3 documents" in out.getvalue()
    assert (documents / paths.NOTE_NAME).read_text() == "From the label."
    assert paths.MENU.read_text().endswith('PYTHONPATH={} exec python3 -m yom_ransomware "$@"\n'.format(
        where / "unpacked"))


# ---- paying, and getting the key back ----

def granted_key(out: str) -> str:
    lines = [line for line in out.splitlines() if re.fullmatch(r"  [A-Za-z0-9+/=]{44}", line)]
    assert len(lines) == 1, "exactly one KEY GRANTED line is expected"
    return lines[0].strip()


def test_by_hand_pay_get_the_key_and_decrypt_restores_every_document(machine):
    where, documents = machine
    lock(machine)
    original = {name: text for name, text in DOCUMENTS.items()}

    out = shown(victim.recovery_step)                # no wallet: build the request, explain the rest
    assert keys.read_json(paths.REQUEST)["victim_priv_sealed"]
    assert "ransom reply --request" in out

    reply = shown(lambda: operator.reply(paths.REQUEST))     # on the operator's machine
    paths.REPLY.write_text(reply)                              # carried over by hand

    out = shown(victim.recovery_step)                        # on the victim: accept it
    key = granted_key(out)
    assert "KEY GRANTED - YOUR DECRYPTION KEY (copy it):" in out
    assert "ransom decrypt" in out

    out = shown(lambda: victim.decrypt(key))
    assert "3 documents recovered and verified" in out
    assert "All ransomware envelopes removed. Your documents are back." in out
    assert {p.name: p.read_text() for p in documents.iterdir()} == {
        **original, paths.NOTE_NAME: "The documents of this machine are locked."}
    assert not list(documents.glob("*.WNCRY"))
    assert files.inspect(documents, keys.read_json(paths.KEYLOG)["files"], ".WNCRY") == ORIGINAL
    assert keys.read_json(paths.RECORD)["state"] == "RESTORED"   # and the menu says so


def test_a_wrong_key_restores_nothing(machine):
    where, documents = machine
    lock(machine)
    victim.recovery_step()
    paths.REPLY.write_text(shown(lambda: operator.reply(paths.REQUEST)))
    key = granted_key(shown(victim.recovery_step))
    bad = bytearray(base64.b64decode(key))
    bad[0] ^= 1

    with pytest.raises(Exception):
        victim.decrypt(keys.b64(bytes(bad)))
    assert sorted(p.name for p in documents.iterdir()) == sorted(
        [*[n + ".WNCRY" for n in DOCUMENTS], paths.NOTE_NAME])
    assert victim.decrypt(key) == len(DOCUMENTS)      # and the right key still works afterwards
    for bad_key in ("not base64!!", keys.b64(b"short")):
        with pytest.raises(ValueError):
            victim.decrypt(bad_key)


def test_a_key_with_anything_added_or_removed_is_refused(machine):
    """Found by hand in the lab: junk appended to the key still decrypted.

    Python's forgiving base64 decoder ignores everything after the final "="
    and drops characters that are not base64. The key itself was the right
    one, so the decryption was real; but a decryptor that accepts a changed
    key looks like a fake one. It is strict now.
    """
    lock(machine)
    victim.recovery_step()
    paths.REPLY.write_text(shown(lambda: operator.reply(paths.REQUEST)))
    key = granted_key(shown(victim.recovery_step))
    from software.Ransomware_Service.yom_ransomware import __main__ as command

    for changed in (key + "abc", key + " x9!@#", key[:-1], key[1:]):
        with pytest.raises(SystemExit, match="not valid base64"):
            command.decrypt(changed)
        with pytest.raises(ValueError, match="not valid base64"):
            victim.decrypt(changed)


def test_an_empty_reply_is_refused(machine):
    lock(machine)
    victim.recovery_step()
    paths.REPLY.write_text(json.dumps({"victim_priv_pem": ""}))
    with pytest.raises(ValueError):
        victim.recovery_step()


def test_a_request_sealed_for_another_attacker_is_refused(machine, tmp_path, monkeypatch):
    """The operator's private key opens only what was sealed under its public key."""
    lock(machine)
    victim.recovery_step()
    saved = paths.ATTACKER_KEYS
    monkeypatch.setattr(paths, "ATTACKER_KEYS", tmp_path / "other-operator" / "attacker_keys.json")
    operator_keys(tmp_path / "other-operator")
    with pytest.raises(ValueError, match="different attacker key"):
        operator.reply(paths.REQUEST)


# ---- the operator's side ----

def test_boot_creates_the_keys_once_and_puts_only_the_public_half_in_the_label(machine, tmp_path):
    where, _ = machine
    payload = Ransomware().payload()
    folder = where / "payload"
    label_format.write_label(folder, payload.label)

    out = shown(lambda: operator.init(folder))
    assert "attacker keypair created" in out
    first = paths.ATTACKER_KEYS.read_bytes()
    shipped = label_format.read_label(folder)
    assert shipped["settings"]["attacker_pub_pem"].startswith("-----BEGIN PUBLIC KEY-----")
    assert "PRIVATE KEY" not in json.dumps(shipped)         # only the public half travels

    out = shown(lambda: operator.init(folder))               # a second boot changes nothing
    assert "already exist" in out and paths.ATTACKER_KEYS.read_bytes() == first


def test_boot_without_a_payload_on_the_machine_says_so(machine, capsys):
    where, _ = machine
    operator_keys(where / "no-payload-here")
    assert "no payload label on this machine" in capsys.readouterr().out


def test_the_operator_answers_what_is_really_on_the_chain(machine, monkeypatch):
    """The chain carries the sealed blob alone, not the whole request.

    This goes through the real watch code against a faked chain.
    """
    where, documents = machine
    lock(machine)
    victim.recovery_step()
    request = keys.read_json(paths.REQUEST)
    contract_attacker = eth_account.Account.create()
    paths.CHAIN_KEY.write_text(json.dumps(
        {"address": contract_attacker.address, "private_key": contract_attacker.key.hex()}))
    paths.OPERATOR_CHAIN.write_text(json.dumps({"chain_id": 18000}))
    keylog = keys.read_json(paths.KEYLOG)
    on_chain = [{"id": 0, "victim": "0x" + "22" * 20, "answered": False,
                 "sealed_blob_json": json.dumps(request["victim_priv_sealed"])}]
    posted = []
    monkeypatch.setattr(payment, "paid_requests", lambda config: on_chain)
    monkeypatch.setattr(payment, "answer",
                        lambda config, key_file, request_id, reply: posted.append((request_id, reply)) or "0xtx")

    assert [entry["id"] for entry in operator.watch()] == [0]

    # What went back on the chain is the victim's private key, and it opens the documents.
    request_id, reply_bytes = posted[0]
    reply = json.loads(reply_bytes)
    file_key = keys.victim_accept_reply(reply, keylog)["file_key"]
    assert len(files.unlock(documents, keylog["participant_id"], file_key, keylog["files"], ".WNCRY")) == 3

    on_chain[0]["answered"] = True
    assert operator.watch() == [] and len(posted) == 1    # nothing left to answer


def test_a_request_the_operator_cannot_open_stops_the_answering(machine, monkeypatch):
    """A live run once failed here: a request sealed for another key must not be paid a reply."""
    lock(machine)
    victim.recovery_step()
    operator_keys(machine[0] / "another-operator")
    paths.OPERATOR_CHAIN.write_text(json.dumps({"chain_id": 18000}))
    monkeypatch.setattr(payment, "paid_requests", lambda config: [{
        "id": 0, "victim": "0x" + "22" * 20, "answered": False,
        "sealed_blob_json": json.dumps({"wrap": "", "nonce": "", "ct": ""})}])
    answered = []
    monkeypatch.setattr(payment, "answer", lambda *args: answered.append(args))
    with pytest.raises(ValueError):
        operator.watch()
    assert answered == []


def test_a_victim_is_named_by_its_address():
    """The first live run of the earlier version showed students a container id instead."""
    try:
        address = socket.gethostbyname(socket.gethostname())
    except OSError:
        address = None
    assert victim.participant_id() in (address, socket.gethostname())




# ---- the installer, on a real emulator ----

def build(paid=True, operator_machine="patient-zero", before=None):
    """A lab with a victim and the operator's machine, plus the ransomware piece."""
    from seedemu.core import Emulator
    from seedemu.layers import Base, Routing

    emu, base = Emulator(), Base()
    asn = base.createAutonomousSystem(ASN)
    asn.createNetwork("net0")
    asn.createRouter("router0").joinNetwork("net0")
    hosts = {name: asn.createHost(name).joinNetwork("net0") for name in ("victim1", "patient-zero")}
    emu.addLayer(base)
    emu.addLayer(Routing())
    ransom = Ransomware()
    if paid:
        ransom.paymentIn(asn, "net0", emu=emu)
    if operator_machine:
        ransom.operatorTools(operator_machine, network=asn)
    if before:
        emu.addLayer(before(ransom))             # added first, so it renders first
    emu.addLayer(ransom)
    return emu, asn, hosts, ransom


def texts(node):
    """{path on the machine: what stands there}: the text of a written file, the source of an imported one."""
    return {**{item.get()[0]: item.get()[1] for item in node.getFiles()},
            **dict(node.getImportedFiles())}


def test_the_operator_s_tools_go_on_the_machine_the_case_names():
    emu, _, hosts, ransom = build()
    emu.render()
    node = hosts["patient-zero"]
    on_it = texts(node)
    assert "/usr/local/bin/ransom" in on_it
    assert "/opt/yom/yom_ransomware/keys.py" in on_it
    assert "/opt/yom/yom_ransomware/ui/menu.py" in on_it
    assert "/opt/yom/label.py" in on_it                    # the label's format travels with it
    assert json.loads(on_it["/opt/yom/ransom/chain_key.json"]) == ransom.chain_key
    assert json.loads(on_it["/opt/yom/ransom/chain.json"]) == ransom.payload().label["settings"]["payment"]
    commands = [command for command, _ in node.getStartCommands()]
    assert commands.index("chmod +x /usr/local/bin/ransom") < commands.index("ransom init")
    for package in ("python3", "python3-cryptography", "python3-pip"):
        assert package in node.getSoftware()
    assert any("eth-account" in command for command in node.getBuildCommands())


def test_victims_are_left_alone_at_build_time_and_the_label_names_what_they_need():
    emu, _, hosts, ransom = build()
    emu.render()
    assert not any("yom" in path or "ransom" in path for path in texts(hosts["victim1"]))
    needs = ransom.payload().label["needs"]
    assert needs == {"software": ["python3-cryptography", "python3-pip"],
                     "build": ["pip3 install --break-system-packages eth-account==0.13.7"]}


def test_the_label_is_complete_before_any_piece_renders():
    """Whoever carries the payload (the worm) may render before this piece: the label is ready."""
    from seedemu.core import Layer

    class Taker(Layer):
        def __init__(self, piece):
            super().__init__()
            self.piece, self.seen = piece, None

        def getName(self):
            return "Taker"

        def render(self, emulator):
            self.seen = json.loads(json.dumps(self.piece.payload().label))

    emu, _, _, ransom = build(before=Taker)
    emu.render()
    taken = emu.getLayer("Taker").seen
    settings = taken["settings"]
    assert taken["name"] == "ransomware" and taken["start"] == "python3 -m yom_ransomware detonate"
    assert settings["payment"]["rpc_url"].startswith("http://10.180.0.")
    assert settings["payment"]["ransom_wei"] == 10**18          # the price, in wei
    assert (settings["price_eth"], settings["suffix"], settings["payment"]["chain_id"]) == (1, ".WNCRY", 18000)
    assert ransom.chain_key["private_key"] not in json.dumps(taken)   # a secret never travels


def test_nobody_types_an_address_and_the_private_key_stays_home():
    emu, _, hosts, ransom = build()
    emu.render()
    private = ransom.chain_key["private_key"]
    holds = {name: private in json.dumps(texts(node)) for name, node in hosts.items()}
    for machine in ("ransom-utility", "ransom-chain-2", "ransom-faucet"):
        holds[machine] = private in json.dumps(texts(emu.getBindingFor(machine)))
    assert holds == {"patient-zero": True, "victim1": False, "ransom-utility": True,
                     "ransom-chain-2": False, "ransom-faucet": False}


def test_a_name_needs_the_network_and_must_exist():
    _, asn, _, _ = build()
    with pytest.raises(ValueError, match="pass the network"):
        Ransomware().operatorTools("patient-zero")
    with pytest.raises(ValueError, match="no machine named 'nobody'"):
        Ransomware().operatorTools("nobody", network=asn)
    node = asn.getHost("patient-zero")
    Ransomware().operatorTools(node)                       # a node itself needs no network
    assert "/usr/local/bin/ransom" in texts(node)


def test_without_payment_the_label_has_no_payment_and_nobody_waits_for_a_chain():
    emu, _, hosts, ransom = build(paid=False)
    emu.render()
    assert ransom.payload().label["settings"]["payment"] is None
    assert "/opt/yom/ransom/chain_key.json" in texts(hosts["patient-zero"])   # keys are made anyway
    assert "/opt/yom/ransom/chain.json" not in texts(hosts["patient-zero"])   # nothing to talk to


@pytest.mark.parametrize("what", [{"price_eth": 2}, {"price_eth": 0}, {"suffix": "WNCRY"}, {"suffix": ""}])
def test_the_piece_refuses_what_cannot_work(what):
    with pytest.raises(ValueError):
        Ransomware(**what)


# ---- the menu: the earlier case's, screen for screen ----

def drive(monkeypatch, run, answers) -> str:
    """Run a menu with scripted answers to its prompts; return everything it printed.

    A terminal echoes what is typed, so the fake input prints the prompt and
    the answer it gives.
    """
    def answer(prompt=""):
        given = answers.pop(0)
        print(prompt + given)
        return given

    monkeypatch.setattr(builtins, "input", answer)
    out = io.StringIO()
    with redirect_stdout(out):
        run()
    assert not answers, "the menu stopped asking earlier than expected"
    return out.getvalue()


KEYSTROKES = ["6", "b", "3", "b", "2", "", "0"]      # wallet, exchange, inspect, leave


def test_the_menu_is_the_earlier_case_s_menu_screen_for_screen(machine, monkeypatch):
    """The same keystrokes must print what the earlier case's menu printed.

    The text is in menu_reference.txt. With one deliberate difference:
    "Recorded state" tells the truth, where the earlier menu left it at
    PREPARED even on a locked machine.
    """
    where, documents = machine
    monkeypatch.setattr(victim, "participant_id", lambda: "10.9.9.9")
    monkeypatch.setenv("COLUMNS", "80")             # the menu draws its rulers as wide as the terminal
    lock(machine)
    paths.CHAIN.write_text(json.dumps({"chain_id": 18000}))
    ours = drive(monkeypatch, menu.run_interface, list(KEYSTROKES))

    reference = MENU_REFERENCE.read_text(encoding="utf-8")
    # Every time the home screen came up: four times in this walkthrough.
    assert ours.count("  Recorded state   ENCRYPTED") == reference.count("  Recorded state   PREPARED") == 4
    # Apart from that one line, not a character differs.
    assert ours.replace("  Recorded state   ENCRYPTED", "  Recorded state   PREPARED") == reference
    # And what was printed is the earlier case's menu, line for line:
    for line in ('  [5] Document recovery (exchange)',
                 "Ransom payment is enforced by the RansomExchange contract on chain 18000.",
                 "Private chain 18000 / local password-protected keystore",
                 "Play-money market / settlement on private chain 18000",
                 "  Deposit address  No wallet yet — create one first (option 6)",
                 "  notes.txt        ENCRYPTED (.WNCRY) — ransomware envelope present"):
        assert line in ours, line


def test_without_payment_the_payment_screens_are_hidden(machine, monkeypatch):
    lock(machine)                                   # no payment chain on this machine
    out = drive(monkeypatch, menu.run_interface, ["6", "", "0"])
    home = out.split("Home > ")[0]
    for line in ("  [1] Instructions", "  [2] Inspect documents", "  [0] Exit"):
        assert line in home, line
    for hidden in ("[3]", "[5]", "[6]", "WALLET & FUNDING", "Ransom payment"):
        assert hidden not in out, hidden
    assert "Choose one of the displayed actions." in out       # "6" is not offered here


def test_the_instructions_name_the_commands_and_the_folder(machine, monkeypatch):
    lock(machine)
    out = drive(monkeypatch, menu.run_interface, ["1", "", "0"])
    instructions = out.split("Participant guide")[1].split("Press Enter")[0]
    assert "\n    ransom\n" in instructions and "ransom decrypt" in instructions
    assert str(machine[1]) in instructions
    assert "wannacry-v2" not in instructions                     # nothing left of the earlier case's paths


def test_only_one_menu_per_machine(machine, monkeypatch, capsys):
    import fcntl
    lock(machine)
    capsys.readouterr()
    paths.STATE.mkdir(parents=True, exist_ok=True)
    holder = (paths.STATE / ".participant-ui.lock").open("a")
    fcntl.flock(holder, fcntl.LOCK_EX | fcntl.LOCK_NB)
    try:
        menu.run_interface()
    finally:
        holder.close()
    assert capsys.readouterr().out == "Another participant menu is already open. Close it before opening a new one.\n"


# ---- the commands ----

def test_the_decryptor_banner_and_the_refusals_match_the_earlier_case(machine, monkeypatch, capsys):
    lock(machine)
    from software.Ransomware_Service.yom_ransomware import __main__ as command

    with pytest.raises(SystemExit) as stopped:
        command.decrypt("not base64!!")
    assert stopped.value.code == "that is not valid base64; copy the key exactly as printed"
    victim.recovery_step()
    paths.REPLY.write_text(shown(lambda: operator.reply(paths.REQUEST)))
    key = granted_key(shown(victim.recovery_step))
    capsys.readouterr()
    with pytest.raises(SystemExit) as stopped:
        command.decrypt(keys.b64(b"short"))
    assert stopped.value.code.startswith("expected a 32-byte AES-256 key (got 5 bytes)")
    out = capsys.readouterr().out
    assert out.startswith("=" * 60 + "\n  WANNACRY LAB DECRYPTOR\n  Paste the decryption key the attacker granted you.\n" + "=" * 60 + "\n")
    assert command.decrypt(key) == len(DOCUMENTS)


def test_status_is_one_look_at_the_machine_and_moves_no_money(machine, capsys):
    lock(machine)
    capsys.readouterr()
    paths.CHAIN.write_text(json.dumps({"chain_id": 18000, "rpc_url": "http://127.0.0.1:1"}))
    victim.status()
    out = capsys.readouterr().out
    assert out.startswith("documents: 3 locked, in ")
    assert "\nchain:     unreachable or wrong (" in out
    assert "wallet" not in out and "contract" not in out
