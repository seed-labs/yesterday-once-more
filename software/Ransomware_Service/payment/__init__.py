"""The payment of the ransomware: everything that uses chainseed, and nothing else.

`chain.py` makes the payment machines when the emulation is built. The rest
of the ransomware never comes here: it talks to the payment through a small
client at run time (`yom_ransomware/payment/`).
"""

from .chain import (CHAIN_ID, CONTRACT_NAME, FAUCET, MACHINES, RPC_NODE, UTILITY,
                    PaymentChain, new_chain_account)

__all__ = ["CHAIN_ID", "CONTRACT_NAME", "FAUCET", "MACHINES", "RPC_NODE", "UTILITY",
           "PaymentChain", "new_chain_account"]
