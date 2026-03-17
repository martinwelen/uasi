"""
UASI — Universal Authenticated Sender Identity

Reference implementation of draft-uasi-framework-00.

Quick start (webhook signing):

    from uasi import UASIKeyPair, sign_http_request, verify_http_request, UASIVerifier

    # --- Sender side ---
    key_pair = UASIKeyPair.generate("webhooks", "sender.example.com")
    print(key_pair.dns_zone_entry())   # Publish this in DNS

    sig_header = sign_http_request(
        key_pair,
        method="POST",
        target_uri="https://receiver.example.org/webhooks/orders",
        body=b'{"order_id": "123"}',
        headers={"content-type": "application/json"},
    )

    # --- Receiver side ---
    verifier = UASIVerifier()
    verifier.add_key("sender.example.com", "webhooks", key_pair.dns_key_record())

    result = verify_http_request(
        verifier,
        signature_header=sig_header,
        method="POST",
        target_uri="https://receiver.example.org/webhooks/orders",
        body=b'{"order_id": "123"}',
        headers={"content-type": "application/json"},
    )
    assert result.passed
"""

__version__ = "0.1.0"

# Core classes
from .keys import UASIKeyPair, parse_key_record, parse_policy_record
from .models import (
    Algorithm,
    Canonicalization,
    PolicyMode,
    TrustTier,
    UASIKeyRecord,
    UASIPolicyRecord,
    UASISignature,
    VerificationResult,
)
from .signer import UASISigner
from .verifier import NonceCache, UASIVerifier, VerificationDetail, trust_tier_satisfies_policy
from .wellknown import key_to_wellknown_json, parse_wellknown_json

# HTTP binding convenience functions
from .bindings.http import sign_http_request, verify_http_request

__all__ = [
    # Key management
    "UASIKeyPair",
    "parse_key_record",
    "parse_policy_record",
    # Models
    "Algorithm",
    "Canonicalization",
    "PolicyMode",
    "TrustTier",
    "UASIKeyRecord",
    "UASIPolicyRecord",
    "UASISignature",
    "VerificationResult",
    # Signing & verification
    "UASISigner",
    "UASIVerifier",
    "VerificationDetail",
    "NonceCache",
    "trust_tier_satisfies_policy",
    # .well-known key format
    "key_to_wellknown_json",
    "parse_wellknown_json",
    # HTTP binding
    "sign_http_request",
    "verify_http_request",
]
