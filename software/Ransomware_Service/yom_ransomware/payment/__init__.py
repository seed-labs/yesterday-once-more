"""The payment client: the only door into payment for the rest of the ransomware.

Nothing outside this folder imports eth-account or talks to the chain. The
rest asks in plain terms: read a balance, create a wallet, buy lab money,
pay for a request, wait for the reply; and on the operator's side: see the
paid requests, answer them, take the money out.

A `config` is the chain's addresses, as the piece's installer wrote them into
a chain config file: chain_id, rpc_url, faucet_url, utility_url,
contract_name, ransom_wei.
"""

import json
from pathlib import Path

from . import wallet
from .exchange import (contract_attacker, discover_contract, post_reply, register_request,
                       requests_on_chain, sweep, wait_reply)

#: The most lab ETH the exchange sells at a time.
FUND_AMOUNT = wallet.FUND_AMOUNT
POLL_SECONDS = 5


def load(path) -> dict:
    """Read a chain config file."""
    return json.loads(Path(path).read_text(encoding="utf-8"))


def connect(config: dict) -> dict:
    """Check that this is the lab's chain before money moves. Returns the config."""
    on_node = int(wallet.rpc(config, "eth_chainId", []), 16)
    if on_node != config["chain_id"]:
        raise ValueError(
            f"expected the lab's chain {config['chain_id']}, but this node runs chain {on_node}"
        )
    return config


# ---- a victim ----

wallet_address = wallet.wallet_address
create_wallet = wallet.create_wallet
balance_wei = wallet.balance_wei
format_ether = wallet.format_ether
validate_address = wallet.validate_address


def fund(config: dict, address: str, amount: int = FUND_AMOUNT) -> dict:
    """Buy lab ETH: the faucet sends them."""
    return wallet.request_funds(config, address, amount)


def contract(config: dict) -> str:
    """The deployed RansomExchange contract's address."""
    return discover_contract(config)


def code_size(config: dict, contract_address: str) -> int:
    """How many bytes of code stand at the address (0 means the deployment failed)."""
    code = wallet.rpc(config, "eth_getCode", [contract_address, "latest"])
    return (len(code) - 2) // 2


def pay(config: dict, wallet_file, password: str, request_path) -> dict:
    """Register the saved request on the chain, with the ransom attached.

    Returns the request, now with its on-chain id. Calling this twice would
    pay twice, so the caller must not: a request that already has an id is
    only waited for.
    """
    return register_request(config, wallet_file, password, request_path)


def await_reply(config: dict, request_id: int, seconds: int = 600) -> dict:
    """Wait until the operator's reply for a request is on the chain."""
    return wait_reply(config, request_id, seconds)


# ---- the operator ----

def account_address(account_file) -> str:
    return json.loads(Path(account_file).read_text(encoding="utf-8"))["address"]


def paid_requests(config: dict) -> list:
    """Every request on the chain: id, victim, the sealed blob, and whether it was answered."""
    return requests_on_chain(config)


def is_attacker(config: dict, account_file) -> bool:
    """Is this the account the contract lets answer requests?"""
    onchain = contract_attacker(config, discover_contract(config))
    return onchain.lower() == account_address(account_file).lower()


def answer(config: dict, account_file, request_id: int, reply: bytes) -> str:
    """Post the reply for one paid request. Returns the transaction hash."""
    return post_reply(config, account_file, request_id, reply)


def collect_ransoms(config: dict, account_file) -> str:
    """Take the ransoms the contract holds out of it."""
    return sweep(config, account_file)
