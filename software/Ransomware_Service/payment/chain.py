"""The payment machines: a small private chain, built where the case says.

Three chain nodes, a faucet that hands out lab money, and a utility server
that deploys the RansomExchange contract when the lab starts.

The account is made when the emulation is built, and handed to the utility
server and to the operator; nobody copies it by hand. The contract's deployer
is its "attacker", so they must share it.

Every line that uses chainseed lives in this folder. It is chainseed 1.0: the
service declares its own Docker images (it is an EthereumService), so the
emulation is compiled with seedemu's plain Docker compiler.
"""

import json
from pathlib import Path

from chainseed.services.ethereum import ConsensusMechanism, EthereumService
from eth_account import Account
from seedemu.core import Action, Binding, Filter

CONTRACTS = Path(__file__).resolve().parent / "contracts"

CONTRACT_NAME = "RansomExchange"
CHAIN_ID = 18000
RPC_PORT = 8545
UTILITY_PORT = 8080

#: Names of the payment machines. Each is also its virtual node name.
CHAIN_NODE = "ransom-chain-{}"          # 0, 1, 2
RPC_NODE = CHAIN_NODE.format(2)         # the node victims and the operator talk to
FAUCET = "ransom-faucet"
UTILITY = "ransom-utility"
MACHINES = (CHAIN_NODE.format(0), CHAIN_NODE.format(1), RPC_NODE, FAUCET, UTILITY)

#: Where the utility server keeps the account it deploys with.
UTILITY_ACCOUNT = "/utility_server/account.json"

#: What chain-seed's utility server runs to create its account. Its own
#: version makes a new random account on every boot; this one reuses an
#: account placed there when the lab was built.
_REUSE_ACCOUNT = """\
def reuseOrCreateAccount():
    # Reuse a key placed here when the lab was built, so that the attacker can
    # hold the very account the contract will call its attacker.
    path = DIR_PREFIX + '/account.json'
    if __import__('os').path.exists(path):
        with open(path) as handle:
            saved = json.load(handle)
        return saved['address'], saved['private_key']
    return createAccount()

"""


def _adjust_chainseed_templates():
    """Two small corrections to chain-seed's utility server scripts.

    - The contract needs more deployment gas than chain-seed's pinned
      2,000,000; without it the deployment dies silently.
    - Reuse an account that is already there instead of making a new one.
    """
    from chainseed.services.ethereum.EthTemplates import UtilityServerFileTemplates

    deploy = UtilityServerFileTemplates["deploy_contract"]
    if "'gas': 2000000" in deploy:
        UtilityServerFileTemplates["deploy_contract"] = deploy.replace(
            "'gas': 2000000", "'gas': 4500000"
        )
    fund = UtilityServerFileTemplates["fund_account"]
    if "reuseOrCreateAccount" not in fund:
        changed = fund.replace("def createAccount():", _REUSE_ACCOUNT + "def createAccount():")
        changed = changed.replace(
            "account_address, private_key = createAccount()",
            "account_address, private_key = reuseOrCreateAccount()",
        )
        if ("def reuseOrCreateAccount():" not in changed
                or "= reuseOrCreateAccount()" not in changed):
            raise RuntimeError(
                "chain-seed's fund_account.py changed; the account reuse patch no longer fits"
            )
        UtilityServerFileTemplates["fund_account"] = changed


_adjust_chainseed_templates()


def new_chain_account() -> dict:
    """A fresh account for the lab: the one that deploys the ransom contract."""
    account = Account.create()
    return {"address": account.address, "private_key": account.key.hex()}


def address_of(node) -> str:
    return str(node.getInterfaces()[0].getAddress())


class PaymentChain(EthereumService):
    """The payment chain as a seedemu service. The ransomware service is built on it."""

    def __init__(self):
        super().__init__()
        self.chain_id = CHAIN_ID
        #: The contract's deployer is its "attacker". The utility server and the
        #: operator's machine get this key; it is never shipped in a worm.
        self.chain_key = new_chain_account()
        #: The chain's addresses, for whoever talks to it. Known once the emulation renders.
        self.chain = {}

    def installIn(self, asn, network: str, emu) -> None:
        """Make the payment machines on that network, in that autonomous system.

        `emu` is the emulation: the machines are new, so their bindings are
        added to it right here and the case has nothing left to do.
        """
        chain = self.createBlockchain(chainName="RansomLab", consensus=ConsensusMechanism.POA)
        chain.setChainId(self.chain_id)

        def machine(name):
            asn.createHost(name).joinNetwork(network)
            emu.addBinding(Binding(name, Action.FIRST, Filter(asn=asn.getAsn(), nodeName=name)))

        for index in range(3):
            name = CHAIN_NODE.format(index)
            machine(name)
            node = chain.createNode(name)
            node.enableGethHttp()
            node.unlockAccounts()
            if index < 2:
                node.startMiner()
            if index == 0:
                node.setBootNode(True)

        machine(FAUCET)
        chain.createFaucetServer(vnode=FAUCET, port=80, linked_eth_node=RPC_NODE,
                                 balance=10000, max_fund_amount=10)

        machine(UTILITY)
        utility = chain.createEthUtilityServer(vnode=UTILITY, port=UTILITY_PORT,
                                               linked_eth_node=RPC_NODE, linked_faucet_node=FAUCET)
        utility.deployContractByContent(
            CONTRACT_NAME,
            (CONTRACTS / (CONTRACT_NAME + ".abi")).read_text(encoding="utf-8"),
            (CONTRACTS / (CONTRACT_NAME + ".bytecode")).read_text(encoding="utf-8"),
        )

    def configure(self, emulator):
        super().configure(emulator)
        if not self._pending_targets:
            return                          # no payment in this lab
        # The addresses exist by now (the machines have joined their network),
        # so they are read here, while every layer is still being configured:
        # whoever uses them renders later and finds them ready.
        utility = emulator.getBindingFor(UTILITY)
        self.chain = {
            "chain_id": self.chain_id,
            "rpc_url": "http://{}:{}".format(address_of(emulator.getBindingFor(RPC_NODE)), RPC_PORT),
            "faucet_url": "http://{}/fundme".format(address_of(emulator.getBindingFor(FAUCET))),
            "utility_url": "http://{}:{}".format(address_of(utility), UTILITY_PORT),
            "contract_name": CONTRACT_NAME,
        }
        utility.setFile(UTILITY_ACCOUNT, json.dumps(self.chain_key, indent=2) + "\n")
