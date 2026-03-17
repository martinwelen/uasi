# UASI — Universal Authenticated Sender Identity

Unified sender authentication across protocols.

## Overview

UASI is a proposed IETF standard ([draft-uasi-framework](https://datatracker.ietf.org/doc/draft-uasi-framework/)) that provides cross-protocol sender authentication using DNS-based key discovery and unified verification policy. For HTTP it profiles RFC 9421 (HTTP Message Signatures); for SMTP it wraps DKIM; for MQTT, CoAP, and WebSocket it provides native Ed25519 signing.

| Component | Location | Status |
|-----------|----------|--------|
| Internet-Draft (-01) | `spec/draft-uasi-framework-01.txt` | Revised with adapter architecture |
| Internet-Draft (-00) | [`spec/draft-uasi-framework-00.txt`](https://datatracker.ietf.org/doc/draft-uasi-framework/) | On IETF datatracker |
| Reference library | `lib/` | 40 tests passing, MIT license |
| Report schema | `schema/draft-uasi-report-format-00.txt` | Companion I-D |
| 5-minute explainer | `docs/uasi-in-5-minutes.md` | For platform engineers |

## Quick Start

```bash
cd lib
pip install cryptography dnspython
PYTHONPATH=src python3 examples/webhook_demo.py
```

## Run Tests

```bash
cd lib
pip install cryptography dnspython pytest
PYTHONPATH=src python3 -m pytest tests/ -v
```

## License

Library: MIT. Spec: IETF Trust.
