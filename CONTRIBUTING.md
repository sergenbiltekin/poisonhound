# Contributing

Thanks for considering a contribution to PoisonHound.

## Getting set up

```bash
git clone https://github.com/sergenbiltekin/poisonhound.git
cd poisonhound
python -m venv .venv
source .venv/bin/activate  # or .venv\Scripts\activate on Windows
pip install -e ".[dev]"
```

## Before opening a pull request

```bash
ruff check src tests
pytest
```

All tests inject synthetic packets directly into detectors and never touch
the network, so they don't need root/administrator privileges to run.

## Adding a new detector

1. Add a config model for it in `src/poisonhound/core/config.py`.
2. Create `src/poisonhound/detectors/your_detector.py` implementing
   `BaseDetector` (see `arp_spoof.py` for the simplest example). Include a
   fixed `REMEDIATION` list and build `evidence` with
   `poisonhound.net.evidence.build_evidence`.
3. Wire it into `src/poisonhound/core/registry.py`.
4. Add tests under `tests/unit/` that construct synthetic Scapy packets and
   feed them directly into `handle_packet()`.

## Extending the OUI vendor table

`src/poisonhound/net/oui_lookup.py` intentionally ships with a small,
high-confidence set of vendor prefixes rather than a full external
database. Adding more known-good entries is a great first contribution.

## Code style

- Python 3.10+, type hints throughout, no bare `except:`.
- Keep detectors and notifiers boring and predictable - this project
  favors a small number of well-tested modules over configurability for
  its own sake.
