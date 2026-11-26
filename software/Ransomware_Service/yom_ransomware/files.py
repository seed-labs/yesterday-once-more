"""Locking and unlocking the files of one folder.

This is a lab. It only ever touches the files that sit directly in the
folder a case filled with documents: no subfolders, no links, nothing
outside.

The scheme: each document is replaced by an envelope named
<name><suffix> holding a magic line, a 12-byte nonce and the ciphertext
(AES-256-GCM, one file key for all), and the plaintext original is removed.
The same nonce and ciphertext, with the hash of the original, are kept in
the keylog: that is what the decryptor works from, and how it can verify
what it restored.
"""

import os
from pathlib import Path

from . import paths
from .keys import b64, sha256, unb64, write_atomic

MAGIC = b"Y04LAB1\n"
NONCE_SIZE = 12
TAG_SIZE = 16

#: Folders that must never be locked, however a case is written.
NEVER_LOCK = {
    "/", "/bin", "/boot", "/dev", "/etc", "/home", "/home/seed", "/lib", "/opt",
    "/proc", "/root", "/sbin", "/sys", "/tmp", "/usr", "/var",
}


def check_suffix(suffix: str) -> str:
    """A suffix is what is appended to a document's name, like '.WNCRY'."""
    if not suffix or not suffix.startswith(".") or "/" in suffix or suffix == paths.NOTE_NAME:
        raise ValueError(f"'{suffix}' is not a file suffix like '.WNCRY'")
    return suffix


def check_folder(folder, suffix: str) -> Path:
    """Refuse anything that does not look like a folder of documents."""
    check_suffix(suffix)
    folder = Path(folder)
    if str(folder.resolve()) in NEVER_LOCK:
        raise ValueError(f"refusing to lock {folder}: it is a system folder, not documents")
    if folder.is_symlink():
        raise ValueError(f"{folder} is a link; refusing to lock through it")
    if not folder.is_dir():
        raise ValueError(f"{folder} is not a folder")
    return folder


def documents_in(folder: Path, suffix: str):
    """The files directly in the folder: no subfolders, no links, not the note, not locked ones."""
    return sorted(
        path for path in folder.iterdir()
        if path.is_file() and not path.is_symlink()
        and path.name != paths.NOTE_NAME
        and not path.name.endswith(suffix)
    )


def _context(participant_id: str, name: str) -> bytes:
    return f"{participant_id}/{name}".encode("utf-8")


def encrypt_all(folder: Path, participant_id: str, file_key: bytes, suffix: str) -> dict:
    """Encrypt every document in memory. Returns {name: {nonce, ciphertext, sha256}}."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    record = {}
    for path in documents_in(folder, suffix):
        plain = path.read_bytes()
        nonce = os.urandom(NONCE_SIZE)
        record[path.name] = {
            "nonce": b64(nonce),
            "ciphertext": b64(AESGCM(file_key).encrypt(nonce, plain, _context(participant_id, path.name))),
            "sha256": sha256(plain),
        }
    return record


def apply_lock(folder: Path, record: dict, suffix: str):
    """Replace each document with its envelope and remove the original."""
    for name, entry in record.items():
        write_atomic(
            folder / (name + suffix),
            MAGIC + unb64(entry["nonce"]) + unb64(entry["ciphertext"]),
        )
        (folder / name).unlink()


def unlock(folder: Path, participant_id: str, file_key: bytes, record: dict, suffix: str):
    """Restore every document, check it against its recorded hash, drop the envelope."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    restored = []
    for name in sorted(record):
        entry = record[name]
        plain = AESGCM(file_key).decrypt(
            unb64(entry["nonce"]), unb64(entry["ciphertext"]), _context(participant_id, name)
        )
        if sha256(plain) != entry["sha256"]:
            raise ValueError(f"recovered sample does not match its baseline: {name}")
        write_atomic(folder / name, plain)
        # Restore the original name by removing the ransomware envelope.
        (folder / (name + suffix)).unlink(missing_ok=True)
        restored.append(name)
    return restored


def inspect(folder: Path, record: dict = None, suffix: str = ".WNCRY") -> dict:
    """The state of every document, without changing anything."""
    folder = Path(folder)
    record = record or {}
    names = sorted({path.name for path in documents_in(folder, suffix)}
                   | {path.name[:-len(suffix)] for path in folder.iterdir()
                      if path.name.endswith(suffix)}
                   | set(record))
    state = {}
    for name in names:
        plain, envelope = folder / name, folder / (name + suffix)
        try:
            plain_present = not plain.is_symlink() and plain.is_file()
            cipher_present = not envelope.is_symlink() and envelope.is_file()
            if plain_present and cipher_present:
                state[name] = f"INCONSISTENT — both plaintext and {suffix} envelope exist"
            elif cipher_present:
                data = envelope.read_bytes()
                if data.startswith(MAGIC) and len(data) == envelope_size(record.get(name)):
                    state[name] = f"ENCRYPTED ({suffix}) — ransomware envelope present"
                else:
                    state[name] = f"ENCRYPTED ({suffix}) — UNEXPECTED FORMAT"
            elif plain_present:
                baseline = record.get(name, {}).get("sha256")
                if baseline and sha256(plain.read_bytes()) == baseline:
                    state[name] = "ORIGINAL — baseline matches"
                else:
                    state[name] = "CHANGED OR BASELINE MISMATCH"
            else:
                state[name] = "MISSING"
        except OSError as error:
            state[name] = f"UNREADABLE — {error}"
    return state


def envelope_size(entry: dict) -> int:
    """How long a well-formed envelope for this document is."""
    return len(MAGIC) + NONCE_SIZE + len(unb64(entry["ciphertext"])) if entry else -1
