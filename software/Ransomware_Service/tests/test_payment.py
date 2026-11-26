"""The payment chain, built and compiled on chainseed 1.0. No Docker daemon needed.

seedemu and chainseed are real here. The emulation is even compiled with
seedemu's plain Docker compiler, into a temporary folder, and the files it
writes are read back.
"""

import importlib
import json
import re
from pathlib import Path

import pytest
from eth_account import Account
from eth_utils import keccak
from seedemu.compiler import Docker, Platform
from seedemu.core import Emulator
from seedemu.layers import Base, Routing

from software.Ransomware_Service.payment import MACHINES, PaymentChain, chain as payment

ASN = 180


def build():
    """A lab with one victim and the payment chain, rendered."""
    emu, base = Emulator(), Base()
    asn = base.createAutonomousSystem(ASN)
    asn.createNetwork("net0")
    asn.createRouter("router0").joinNetwork("net0")
    asn.createHost("victim1").joinNetwork("net0")
    emu.addLayer(base)
    emu.addLayer(Routing())
    payment_chain = PaymentChain()
    emu.addLayer(payment_chain)
    payment_chain.installIn(asn, "net0", emu)
    emu.render()
    return emu, asn, payment_chain


def address(emu, vnode) -> str:
    return str(emu.getBindingFor(vnode).getInterfaces()[0].getAddress())


def node_files(node):
    return {item.get()[0]: item.get()[1] for item in node.getFiles()}


def staged(node_dir: Path, path: str) -> str:
    """What a node's Dockerfile copies to `path`. The compiler stores files under hash names."""
    dockerfile = (node_dir / "Dockerfile").read_text(encoding="utf-8")
    stored = re.search(r"^COPY (\w+) {}$".format(re.escape(path)), dockerfile, re.M).group(1)
    return (node_dir / stored).read_text(encoding="utf-8")


# ---- what the installer makes ----

def test_the_payment_machines_are_made_where_the_case_says():
    emu, asn, _ = build()
    assert asn.getHosts() == ["victim1", *MACHINES]           # five machines, next to the victim
    for name in MACHINES:
        node = emu.getBindingFor(name)
        assert (node.getAsn(), node.getName()) == (ASN, name)
        assert str(node.getInterfaces()[0].getAddress()).startswith("10.180.0.")   # on the lab's own network


def test_nobody_types_an_address():
    """The chain's addresses are the machines' own, read back after the rendering."""
    emu, _, chain = build()
    assert chain.chain == {
        "chain_id": 18000,
        "rpc_url": "http://{}:8545".format(address(emu, "ransom-chain-2")),
        "faucet_url": "http://{}/fundme".format(address(emu, "ransom-faucet")),
        "utility_url": "http://{}:8080".format(address(emu, "ransom-utility")),
        "contract_name": "RansomExchange",
    }


def test_the_contract_s_deployer_is_the_account_on_the_utility_server():
    emu, _, chain = build()
    files = node_files(emu.getBindingFor("ransom-utility"))
    account = json.loads(files["/utility_server/account.json"])
    assert account == chain.chain_key                             # the very same account, in one place
    assert Account.from_key(account["private_key"]).address == account["address"]  # and the key fits
    assert "def reuseOrCreateAccount():" in files["/utility_server/fund_account.py"]
    assert "= reuseOrCreateAccount()" in files["/utility_server/fund_account.py"]
    assert "'gas': 4500000" in files["/utility_server/deploy_contract.py"]
    assert files["/utility_server/contracts/RansomExchange.bin"].strip()      # the compiled contract is there


def test_the_patch_to_chainseed_is_safe_to_apply_more_than_once():
    from chainseed.services.ethereum.EthTemplates import UtilityServerFileTemplates
    payment._adjust_chainseed_templates()
    fund = UtilityServerFileTemplates["fund_account"]
    assert fund.count("def reuseOrCreateAccount():") == 1
    assert "account_address, private_key = createAccount()" not in fund
    payment._adjust_chainseed_templates()
    assert UtilityServerFileTemplates["fund_account"] == fund
    assert "'gas': 4500000" in UtilityServerFileTemplates["deploy_contract"]


def test_a_chain_without_payment_machines_is_simply_empty():
    """A ransomware without payment adds nothing to the lab."""
    emu, base = Emulator(), Base()
    asn = base.createAutonomousSystem(ASN)
    asn.createNetwork("net0")
    asn.createHost("victim1").joinNetwork("net0")
    emu.addLayer(base)
    chain = PaymentChain()
    emu.addLayer(chain)
    emu.render()
    assert chain.chain == {} and chain.getTargets() == set()


# ---- the contract, shipped compiled with its source ----

def walk(code: bytes):
    """One pass over compiled code: (offset, opcode, immediate) for every instruction.

    PUSH1..PUSH32 carry an immediate; a byte count is not an opcode.
    """
    i = 0
    while i < len(code):
        op = code[i]
        if 0x60 <= op <= 0x7F:
            size = op - 0x5F
            yield i, op, code[i + 1:i + 1 + size]
            i += 1 + size
        else:
            yield i, op, b""
            i += 1


def selectors_in(code: bytes) -> set:
    """The 4-byte selectors the contract's runtime code uses, as hex.

    The optimizer does not always push a selector as it is. To save a byte it
    may push it shifted to the right and shift it back at run time
    (PUSH4 x, PUSH1 k, SHL). Both ways are read. Looking only for plain
    PUSH4 <selector> finds every function but no custom error, which looks
    like a mismatch between the code and its source. There is none.
    """
    meta_len = int.from_bytes(code[-2:], "big")
    end = len(code) - 2 - meta_len           # the runtime code ends where its metadata begins
    started, found, pushed, shift = False, set(), None, None
    for i, op, imm in walk(code):
        if i >= end:
            break
        if op == 0xF3 and not started:       # the constructor's RETURN: the runtime code follows
            started, found = True, set()
        elif not started:
            continue
        if op == 0x63:                       # PUSH4
            found.add(imm.hex())
            pushed = imm
        elif op == 0x60 and pushed is not None:
            shift = imm[0]
        elif op == 0x1B and pushed is not None and shift is not None:   # SHL
            if shift >= 224:                 # the result's first four bytes are revert data
                found.add(((int.from_bytes(pushed, "big") << shift) >> 224).to_bytes(4, "big").hex())
            pushed = None
        else:
            pushed = None
    return found


def test_the_compiled_contract_is_the_one_the_abi_describes():
    """Every function and every custom error of the ABI is in the compiled code."""
    contracts = payment.CONTRACTS
    code = bytes.fromhex((contracts / "RansomExchange.bytecode").read_text().strip())
    abi = json.loads((contracts / "RansomExchange.abi").read_text())
    used = selectors_in(code)

    functions = [item for item in abi if item["type"] == "function"]
    errors = [item for item in abi if item["type"] == "error"]
    assert (len(functions), len(errors)) == (9, 5)
    for item in functions + errors:
        selector = keccak(text="{}({})".format(
            item["name"], ",".join(argument["type"] for argument in item["inputs"])))[:4]
        assert selector.hex() in used, item["name"]
    assert (contracts / "RansomExchange.sol").is_file()            # its source is next to it
    assert "RansomExchange.bytecode" in (contracts / "compile_contract.py").read_text()   # and how to rebuild


def test_the_optimizer_s_shifted_selectors_are_read_correctly():
    """Why selectors_in() must read the shifted form: this is how the compiler stored two errors."""
    contracts = payment.CONTRACTS
    code = bytes.fromhex((contracts / "RansomExchange.bytecode").read_text().strip())
    # PUSH4 0x0b8fc7cd, PUSH1 0xe2, SHL  is  EmptyPayload()  (0x2e3f1f34) shifted right by two bits
    assert bytes.fromhex("630b8fc7cd60e21b") in code
    assert bytes.fromhex("63387f4b1360e11b") in code         # NoReplyYet(), shifted right by one bit
    plain = {imm.hex() for _, op, imm in walk(code) if op == 0x63}
    assert "0b8fc7cd" in plain and "2e3f1f34" not in plain
    assert {"2e3f1f34", "70fe9626"} <= selectors_in(code)


def test_the_shipped_contract_is_what_its_source_compiles_to():
    """With the pinned compiler, the shipped files are exactly what the source compiles to.

    The compiler is deterministic. This needs py-solc-x and the compiler
    0.8.20 on the machine; without them it is skipped.
    """
    solcx = pytest.importorskip("solcx")
    if "0.8.20" not in [str(v) for v in solcx.get_installed_solc_versions()]:
        pytest.skip("the Solidity compiler 0.8.20 is not installed on this machine")
    spec = importlib.util.spec_from_file_location(
        "compile_contract", payment.CONTRACTS / "compile_contract.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    artifacts = module.compile_contract()
    shipped = payment.CONTRACTS / "RansomExchange.bytecode"
    assert artifacts["bytecode"] == shipped.read_text(encoding="utf-8").strip()
    assert json.dumps(artifacts["abi"], indent=2) + "\n" == (
        payment.CONTRACTS / "RansomExchange.abi").read_text(encoding="utf-8")


# ---- chainseed 1.0: the plain compiler ----

def test_chainseed_1_0_has_no_compiler_of_its_own():
    with pytest.raises(ModuleNotFoundError):
        importlib.import_module("chainseed.compiler")


def test_the_lab_compiles_with_seedemu_s_plain_docker_compiler(tmp_path):
    emu, _, chain = build()
    out = tmp_path / "lab"
    emu.compile(Docker(platform=Platform.AMD64), str(out), override=True)

    compose = (out / "docker-compose.yml").read_text(encoding="utf-8")
    for machine in ("victim1", *MACHINES):
        assert "    hnode_{}_{}:".format(ASN, machine) in compose          # one service per machine
    assert 'seedemu.meta.ethereum.chain_id: "18000"' in compose

    # The chain nodes stand on chainseed's own image, which the Ethereum service
    # declared; the victim stands on seedemu's base image. Each is built first
    # as a "dummy" service, whose Dockerfile is a file under dummies/, and the
    # machines start from it.
    def base_image(machine):
        dockerfile = out / "hnode_{}_{}".format(ASN, machine) / "Dockerfile"
        from_id = next(line.split()[1] for line in dockerfile.read_text().splitlines()
                       if line.startswith("FROM "))
        return (out / "dummies" / from_id).read_text()

    for name in ("ransom-chain-0", "ransom-chain-1", "ransom-chain-2"):
        assert "seedemu-ethereum" in base_image(name)
    assert "seedemu-base" in base_image("victim1")

    # And what the utility server starts with, as compiled:
    utility = out / "hnode_{}_ransom-utility".format(ASN)
    assert "'gas': 4500000" in staged(utility, "/utility_server/deploy_contract.py")
    assert "reuseOrCreateAccount()" in staged(utility, "/utility_server/fund_account.py")
    assert json.loads(staged(utility, "/utility_server/account.json")) == chain.chain_key
    assert staged(utility, "/utility_server/contracts/RansomExchange.abi").strip()
    assert staged(utility, "/utility_server/contracts/RansomExchange.bin").strip()
