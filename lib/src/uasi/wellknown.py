"""UASI .well-known/uasi-keys endpoint format support (Section 8 of -01)."""

from __future__ import annotations

from .models import UASIKeyRecord


def key_to_wellknown_json(key_pair) -> dict:
    """Convert a UASIKeyPair to .well-known/uasi-keys JSON format.

    The JSON is served at https://<domain>/.well-known/uasi-keys/<selector>
    and provides WebPKI-anchored key discovery as a fallback when DNSSEC
    is unavailable.
    """
    return {
        "v": "UASI1",
        "k": "ed25519",
        "p": key_pair.public_key_b64,
    }


def parse_wellknown_json(data: dict) -> UASIKeyRecord:
    """Parse .well-known/uasi-keys JSON response into a UASIKeyRecord."""
    return UASIKeyRecord(
        version=data["v"],
        algorithm=data["k"],
        public_key_b64=data["p"],
    )
