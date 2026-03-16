# UASI — Universal Authenticated Sender Identity

One signature format for every protocol on the Internet.

## Overview

UASI is a proposed IETF standard ([draft-uasi-framework-00](https://datatracker.ietf.org/doc/draft-uasi-framework/)) that provides protocol-agnostic cryptographic sender authentication using DNS-published Ed25519 keys. Think "DKIM, but for everything."

| Component | Location | Status |
|-----------|----------|--------|
| Internet-Draft | [`spec/draft-uasi-framework-00.txt`](https://datatracker.ietf.org/doc/draft-uasi-framework/) | Live on IETF datatracker |
| Reference library | `lib/` | 23 tests passing, MIT license |
| Report schema | `schema/draft-uasi-report-format-00.txt` | Companion I-D |
| 5-minute explainer | `docs/uasi-in-5-minutes.md` | For platform engineers |

## Quick Start

```bash
cd lib
pip install cryptography dnspython
PYTHONPATH=src python examples/webhook_demo.py
```

## Run Tests

```bash
cd lib
pip install cryptography dnspython pytest
PYTHONPATH=src python -m pytest tests/ -v
```

## License

Library: MIT. Spec: IETF Trust.
