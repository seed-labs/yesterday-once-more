"""Where the ransomware keeps its files on a machine."""

from pathlib import Path

#: On a victim: what the infection leaves behind.
STATE = Path("/opt/wannacry")
KEYLOG = STATE / "ransomware.json"          # the keys, and the record of the locked documents
RECORD = STATE / "participant.json"         # the participant's id, and the state the menu shows
WALLET = STATE / "wallet.json"
REQUEST = STATE / "exchange_request.json"
REPLY = STATE / "exchange_reply.json"
ACCEPTED = STATE / "accepted.json"
CHAIN = STATE / "chain.json"                # the payment chain's addresses

#: On the operator's machine: the keys and the chain's addresses.
OPERATOR = Path("/opt/yom/ransom")
ATTACKER_KEYS = OPERATOR / "attacker_keys.json"
CHAIN_KEY = OPERATOR / "chain_key.json"
OPERATOR_CHAIN = OPERATOR / "chain.json"

#: The command the victim is left with. It starts the menu from the code the
#: worm brought.
MENU = Path("/usr/local/bin/ransom")

#: What the note is called inside the documents folder.
NOTE_NAME = "READ_ME.txt"
