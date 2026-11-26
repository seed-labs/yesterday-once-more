# Ransomware Service

What the worm carries for WannaCry. It locks the documents of a machine and
leaves a menu behind. The victim pays on a private chain and receives a key;
a decryptor brings the documents back.

```python
NOTE = (HERE / "note.txt").read_text()

ransom = Ransomware(documents="/home/seed/Documents", suffix=".WNCRY",
                    note=NOTE, price_eth=1)
ransom.paymentIn(lab, "net0", emu=emu)              # its payment chain
ransom.operatorTools("patient-zero", network=lab)   # the attacker's tools
emu.addLayer(ransom)

worm = Worm(..., payload=ransom.payload())          # the worm carries it
```

A case chooses four things: the documents folder, the suffix, the note text
and the price. Nothing of the ransomware is put on a victim when the lab is
built. It gets there by the worm.

## What it is made of

| Folder | Runs on | What it holds |
| --- | --- | --- |
| `service.py` | the build machine | the payment machines, the operator's tools, the payload's label |
| `payment/` | the build machine | everything that uses chainseed: the payment chain and the contract |
| `yom_ransomware/` | machines, inside the worm | the keys, locking, the operator's commands |
| `yom_ransomware/payment/` | machines | talking to the chain, behind a small client |
| `yom_ransomware/ui/` | machines | the terminal menu |

Nothing outside `payment/` uses chainseed, and nothing outside
`yom_ransomware/payment/` talks to the chain. The rest asks the client in
plain words: read a balance, create a wallet, buy lab money, pay for a
request, wait for the reply.

## The story, step by step

1. **Build.** The payment machines are made where the case says. The
   operator's tools go on the machine the case names.
2. **Boot.** The operator's machine creates its key pair (`ransom init`).
   Only the public half goes into the payload. The chain starts, and the
   utility server deploys the `RansomExchange` contract.
3. **The worm arrives** on a victim and runs the payload's start command,
   `python3 -m yom_ransomware detonate`. It locks every document in the
   folder, leaves the note, and leaves the `ransom` command behind. Then the
   worm goes on spreading.
4. **The victim** opens the menu with `ransom`: create a wallet, buy lab ETH
   on the exchange, pay. The payment is one transaction on the chain.
5. **The operator** runs `ransom watch`. It opens every paid request and posts
   the key back on the chain.
6. **The victim** chooses document recovery again, gets the key on screen,
   and runs `ransom decrypt` with it. Every document comes back and is
   checked against its original.

## The keys

Three keys:

- The operator's RSA key pair. The private half never leaves the operator's
  machine. The public half travels inside the worm.
- Each victim's own key pair. Its private half is sealed under the
  operator's public key, so only the operator can open it.
- One file key, which encrypts the documents. It is sealed under the
  victim's public key.

The chain only carries the victim's sealed key and, after payment, the same
key opened. That is why the operator never needs to touch a victim.

## The payment chain

Three chain nodes, a faucet that hands out lab money, and a utility server
that deploys the contract when the lab starts. It is built on chainseed 1.0,
so the lab is compiled with seedemu's plain `Docker` compiler.

The account that deploys the contract is the only one the contract lets
answer requests. It is made when the emulation is built and handed to the
utility server and to the operator automatically; nobody copies it by hand.

The price is 1 ETH. It is a constant of the contract, because chain-seed
cannot pass arguments to a contract it deploys, so `price_eth` must be 1.

## The menu

The screens: inspect, instructions, wallet, exchange, document recovery,
the KEY GRANTED screen and the decryptor. A test drives this menu with
fixed keystrokes and expects exactly the text kept in
`tests/menu_reference.txt`, so the screens cannot drift by accident.
"Recorded state" tells the truth: ENCRYPTED on a locked machine and
RESTORED after the decryptor.

Without a payment chain, the payment screens are hidden.

## Commands

| Where | Command | What it does |
| --- | --- | --- |
| operator machine | `ransom init` | creates the key pair; runs at boot |
| operator machine | `ransom watch` | answers every paid request |
| operator machine | `ransom withdraw` | takes the collected ransoms out of the contract |
| operator machine | `ransom status` | one look at the chain and the account |
| victim | `ransom` | opens the menu |
| victim | `ransom decrypt` | paste the granted key, get the documents back |
| victim | `ransom status` | one look at this machine |

`ransom reply --request FILE` is the manual path for a lab without the chain
on hand: it turns a victim's saved request into the reply to copy over.

## Locking

Only the files directly in one folder are locked: no subfolders, no links,
nothing outside, and never a system folder. Each document becomes
`<name>.WNCRY`. The worm's payload needs the machine to have Python's
cryptography library and `eth-account`; its label says so, and the worm's
installer puts them on every machine it can reach.

## Tests

From the repository root: `python -m pytest`. They need no Docker. The
payment chain is built and compiled for real into a temporary folder, and
the ransomware runs on temporary folders that stand in for a victim's disk.
