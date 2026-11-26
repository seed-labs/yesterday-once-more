# Y51 — WannaCry (2017)

A worm that carried ransomware, recreated on SEED Emulator from reusable
pieces.

## What happens

1. Three victims have documents. The attacker starts the worm.
2. The worm breaks in through a buffer overflow, carrying the ransomware,
   and locks the documents of every machine it reaches. Each machine then
   spreads it further.
3. A victim opens the `ransom` menu the worm left behind, creates a wallet,
   buys lab money and pays on a private chain.
4. The operator answers, the victim receives the key and restores every
   document.
5. The instructor can stop every worm at any moment with the kill switch of
   the real incident: registering one nonsense domain.

The ransomware is never put on a victim when the lab is built. It arrives
with the worm, as it did in 2017.

## Run it

Needs Docker, this repository's `.venv`, and ASLR switched off on the host
(the Morris worm lab needs the same):

```sh
sudo sysctl -w kernel.randomize_va_space=0
cd cases/Y51_wannacry
../../.venv/bin/python emulator.py                  # builds ./output
cd output
docker compose up -d --build                        # the first build takes a while
docker compose logs hnode_180_ransom-utility        # wait for "Contract deployed"
curl -X POST -H "Content-Type: application/json" -d '{"name": "submit_event"}' \
     http://10.180.0.250:7071/api/v1/install        # once: infected machines can show
                                                    # themselves on the map
```

The map is at `http://localhost:8082`. Then:

```sh
docker compose exec -d hnode_180_patient-zero sh -c 'worm launch > /tmp/worm.out 2>&1'
docker compose logs hnode_180_victim1               # it arrives and locks
docker compose exec -it hnode_180_victim1 ransom    # the victim's menu
docker compose exec hnode_180_patient-zero ransom watch   # the operator answers
docker compose exec hnode_180_switch switch register      # every worm stops
```

Run `ransom watch` while a victim is waiting in the menu: the victim pays
first, then the operator answers, then the victim gets its key.

From the host, to see how far the story is:

```sh
python3 check_state.py          # in cases/Y51_wannacry, while the lab is up
```

When you are done:

```sh
docker compose down
sudo sysctl -w kernel.randomize_va_space=2
```

The add-on is installed through `10.180.0.250`, the map's address inside
the lab. The map writes "the address the request came in on" into every
machine's copy of the add-on, and `localhost:8082` is an address no machine
can reach.

## A victim's way through the menu

1. `6`: create a wallet (choose a password, twice). `b` to go back.
2. `3`: buy lab ETH. `b`.
3. `5`: document recovery. Enter the wallet's password. The victim pays and
   waits for the operator.
4. The operator runs `ransom watch`.
5. The victim sees the KEY GRANTED screen and copies the key. `0` to leave.
6. `ransom decrypt`: paste the key. Every document comes back.

## The pieces

| Piece | Role in this case |
| --- | --- |
| [`Vulnerable_Server`](../../software/Vulnerable_Server/README.md) | the buffer overflow the worm breaks in through |
| [`Worm_Service`](../../software/Worm_Service/README.md) | spreads, carrying the ransomware |
| [`Ransomware_Service`](../../software/Ransomware_Service/README.md) | locks the documents; the menu; the payment chain |
| [`Switch_Service`](../../software/Switch_Service/README.md) | the kill-switch domain |

The whole case is the few lines in [`emulator.py`](emulator.py): the
network, the documents, and the four pieces connected.

## Differences from the real incident

- **Bitcoin and Tor became a private chain.** The chain enforces the payment
  and keeps the whole exchange visible to students.
- **The vulnerability is the Morris buffer overflow**, from the Morris worm
  example of SEED-Emulator, standing in for the SMB bug.
- **The kill switch is checked before every attempt,** so a live outbreak
  can be stopped. The real worm checked once, at start.

## A second demo

The worm stops by itself 30 minutes after it is launched, and a victim is
locked only once. For a second demo:

```sh
docker compose down
docker compose up -d                               # no rebuild
```

Then switch on the map add-on again (the `curl` line above) and launch the
worm again.
