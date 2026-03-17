#!/usr/bin/env python3
"""
UASI Webhook Demo — End-to-end signing and verification (RFC 9421 profile).

This script demonstrates the -01 revision of UASI using HTTP Message
Signatures (RFC 9421) with UASI key discovery:

  1. Generating a UASI key pair
  2. Producing the DNS TXT record to publish
  3. Signing an outgoing webhook (RFC 9421 format)
  4. Verifying the webhook on the receiver side
  5. Detecting body tampering (via Content-Digest)
  6. Detecting replay attacks (via nonce)
  7. Intermediary resilience (non-signed headers survive)

Run:
    cd lib
    PYTHONPATH=src python3 examples/webhook_demo.py
"""

import json
from uasi import (
    UASIKeyPair,
    UASIVerifier,
    sign_http_request,
    verify_http_request,
    key_to_wellknown_json,
)


def separator(title: str) -> None:
    print(f"\n{'=' * 60}")
    print(f"  {title}")
    print(f"{'=' * 60}\n")


def main() -> None:
    # 1. Generate key pair
    separator("1. Key Generation")

    key_pair = UASIKeyPair.generate("webhooks", "saas.example.com")

    print(f"Selector:   {key_pair.selector}")
    print(f"Domain:     {key_pair.domain}")
    print(f"UID:        {key_pair.uid}")
    print(f"Public key: {key_pair.public_key_b64[:40]}...")
    print()

    # 2. DNS record
    separator("2. DNS Record (publish this)")
    print(key_pair.dns_zone_entry(ttl=86400, notes="Webhook signing key"))
    print()

    # 2b. .well-known fallback
    separator("2b. .well-known/uasi-keys JSON (serve at HTTPS endpoint)")
    wk = key_to_wellknown_json(key_pair)
    print(f"GET https://saas.example.com/.well-known/uasi-keys/webhooks")
    print(json.dumps(wk, indent=2))
    print()

    # 3. Sign a webhook (RFC 9421 format)
    separator("3. Signing a Webhook (RFC 9421)")

    body = json.dumps({
        "event": "order.completed",
        "order_id": "ORD-789",
        "total": 99.50,
        "currency": "SEK",
    }).encode()

    headers = {
        "content-type": "application/json; charset=utf-8",
    }

    sig_headers = sign_http_request(
        key_pair,
        method="POST",
        target_uri="https://customer.example.org/webhooks/orders",
        body=body,
        headers=headers,
        expiry_seconds=300,
    )

    print(f"Signature-Input: {sig_headers['signature-input'][:80]}...")
    print(f"Signature:       {sig_headers['signature'][:60]}...")
    print(f"Content-Digest:  {sig_headers['content-digest'][:60]}...")
    print()

    # 4. Verify the webhook
    separator("4. Verification (receiver side)")

    verifier = UASIVerifier()
    verifier.add_key("saas.example.com", "webhooks", key_pair.dns_key_record())

    result = verify_http_request(
        verifier,
        signature_input=sig_headers["signature-input"],
        signature=sig_headers["signature"],
        method="POST",
        target_uri="https://customer.example.org/webhooks/orders",
        body=body,
        headers=headers,
    )

    print(f"Result:     {result.result.value}")
    print(f"Trust tier: {result.trust_tier.value}")
    print(f"Reason:     {result.reason}")
    print(f"Passed:     {result.passed}")
    print()

    # 5. Tampered body detection
    separator("5. Tampered Body Detection")

    tampered_body = json.dumps({
        "event": "order.completed",
        "order_id": "ORD-789",
        "total": 0.01,       # Attacker changed the amount
        "currency": "SEK",
    }).encode()

    result_tampered = verify_http_request(
        verifier,
        signature_input=sig_headers["signature-input"],
        signature=sig_headers["signature"],
        method="POST",
        target_uri="https://customer.example.org/webhooks/orders",
        body=tampered_body,
        headers=headers,
    )

    print(f"Result:  {result_tampered.result.value}")
    print(f"Reason:  {result_tampered.reason}")
    print(f"Passed:  {result_tampered.passed}")
    print()

    # 6. Replay detection
    separator("6. Replay Detection")

    # First verification already cached the nonce.
    result_replay = verify_http_request(
        verifier,
        signature_input=sig_headers["signature-input"],
        signature=sig_headers["signature"],
        method="POST",
        target_uri="https://customer.example.org/webhooks/orders",
        body=body,
        headers=headers,
    )

    print(f"Result:  {result_replay.result.value}")
    print(f"Reason:  {result_replay.reason}")
    print(f"Passed:  {result_replay.passed}")
    print()

    # 7. Intermediary resilience
    separator("7. Intermediary Adds Headers")

    sig_headers2 = sign_http_request(
        key_pair,
        method="POST",
        target_uri="https://customer.example.org/webhooks/orders",
        body=body,
        headers={"content-type": "application/json"},
    )

    # Receiver sees extra headers added by CDN/proxy
    received_headers = {
        "content-type": "application/json",
        "x-forwarded-for": "10.0.0.1",
        "via": "1.1 cloudflare",
        "cf-ray": "abc123",
        "x-real-ip": "203.0.113.42",
    }

    result_intermediary = verify_http_request(
        verifier,
        signature_input=sig_headers2["signature-input"],
        signature=sig_headers2["signature"],
        method="POST",
        target_uri="https://customer.example.org/webhooks/orders",
        body=body,
        headers=received_headers,
    )

    print(f"Result:  {result_intermediary.result.value}")
    print(f"Reason:  {result_intermediary.reason}")
    print(f"Passed:  {result_intermediary.passed}")
    print(f"(5 extra headers added by intermediaries -- signature survived)")
    print()

    separator("Done")


if __name__ == "__main__":
    main()
