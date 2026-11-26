#!/usr/bin/env python3
"""Compile RansomExchange.sol offline and write .abi/.bytecode beside the source.

Run it with this file's folder as the working directory, or from anywhere:

    python3 compile_contract.py

It needs py-solc-x (`pip install py-solc-x`); the compiler itself is fetched
on first use. The lab deploys the two generated files. The compiler version
is pinned, so that the shipped files can always be reproduced.

The Solidity compiler is deterministic: the same source and the same
settings give the same bytes. The payment tests use that to check that the
shipped files are exactly what the source compiles to.
"""

import json
from pathlib import Path

import solcx

HERE = Path(__file__).resolve().parent
SOL_VERSION = "0.8.20"
PRAGMA = f"pragma solidity {SOL_VERSION};"


def compile_contract() -> dict:
    """Compile the contract next to this file with the pinned compiler.

    Returns {"abi": [...], "bytecode": "<hex>"}.
    """
    installed = [str(v) for v in solcx.get_installed_solc_versions()]
    if SOL_VERSION not in installed:
        solcx.install_solc(SOL_VERSION)

    source = (HERE / "RansomExchange.sol").read_text(encoding="utf-8")
    if PRAGMA not in source:
        raise SystemExit("contract pragma does not match the pinned solc version")

    result = solcx.compile_source(
        source,
        output_values=("abi", "bin"),
        solc_version=SOL_VERSION,
        optimize=True,
        optimize_runs=200,
        # The lab's geth image predates the Shanghai EVM: PUSH0 (0x5f) is an
        # invalid opcode there and silently burns all deployment gas.
        evm_version="london",
    )
    _, artifacts = next(iter(result.items()))
    return {"abi": artifacts["abi"], "bytecode": artifacts["bin"].strip()}


def main():
    artifacts = compile_contract()
    (HERE / "RansomExchange.abi").write_text(
        json.dumps(artifacts["abi"], indent=2) + "\n", encoding="utf-8"
    )
    (HERE / "RansomExchange.bytecode").write_text(artifacts["bytecode"] + "\n", encoding="utf-8")
    print(f"compiled: {len(artifacts['bytecode']) // 2} bytes of bytecode")
    print("wrote RansomExchange.abi and RansomExchange.bytecode")


if __name__ == "__main__":
    main()
