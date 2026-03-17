# uasi — Universal Authenticated Sender Identity

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Tests](https://img.shields.io/badge/tests-40%20passing-brightgreen.svg)]()

Reference implementation of the [UASI framework](https://github.com/martinwelen/uasi) (`draft-uasi-framework-01`), a cross-protocol sender authentication framework that unifies identity, key discovery, and verification policy across Internet protocols.

**UASI provides DNS-based key discovery and unified policy for existing signing standards (RFC 9421 for HTTP, DKIM for SMTP), plus native message-level signing for protocols that lack one (MQTT, CoAP, WebSocket).**

## Install

```bash
pip install uasi
```

## Quick Start: Sign a Webhook (RFC 9421 Profile)

```python
from uasi import UASIKeyPair, sign_http_request

# Generate a key pair (one-time setup)
key_pair = UASIKeyPair.generate("webhooks", "your-saas.example.com")
print(key_pair.dns_zone_entry())
# -> webhooks._uasi.your-saas.example.com. 3600 IN TXT "v=UASI1; k=ed25519; p=..."

# Sign an outgoing webhook (produces RFC 9421 Signature-Input + Signature headers)
sig_headers = sign_http_request(
    key_pair,
    method="POST",
    target_uri="https://customer.example.org/webhooks/orders",
    body=b'{"order_id": "789", "total": 99.50}',
    headers={"content-type": "application/json"},
)
# Add to HTTP request:
#   Signature-Input: uasi=("@method" "@authority" ...);keyid="webhooks._uasi.your-saas.example.com";...
#   Signature: uasi=:<base64>:
#   Content-Digest: sha-256=:<base64>:
```

## Quick Start: Verify a Webhook

```python
from uasi import UASIVerifier, verify_http_request

# Set up verifier with sender's public key (from DNS in production)
verifier = UASIVerifier()
verifier.add_key_from_txt(
    "sender.example.com", "webhooks",
    "v=UASI1; k=ed25519; p=<base64-public-key>"
)

# Verify incoming request
result = verify_http_request(
    verifier,
    signature_input=request.headers["Signature-Input"],
    signature=request.headers["Signature"],
    method=request.method,
    target_uri=request.url,
    body=request.body,
    headers=dict(request.headers),
)

if result.passed:
    print(f"Verified (trust: {result.trust_tier.value})")
    process_webhook(request)
else:
    print(f"Verification failed: {result.reason}")
```

## What UASI Solves

Today, every protocol reinvents sender authentication independently:

| Protocol | Current Auth | Problems |
|----------|-------------|----------|
| Email | SPF + DKIM + DMARC | Three specs, decade-long adoption |
| Webhooks | Shared secrets (if anything) | No standard, per-provider |
| MQTT/IoT | PSK or nothing | No domain-level identity |
| APIs | OAuth/mTLS | Heavy, no message-level signing |

UASI provides a unified framework:
- **HTTP**: Profiles RFC 9421 (HTTP Message Signatures) with DNS-based key discovery
- **SMTP**: Wraps DKIM with unified policy and reporting
- **MQTT/CoAP/WebSocket**: Native Ed25519 message signing

One identity model, one key management approach, one policy engine across all protocols.

## Features

- **Ed25519 signatures** — 64-byte signatures, fast verification, small DNS records
- **RFC 9421 HTTP profile** — uses existing HTTP Message Signatures standard, not a custom format
- **DNS-anchored trust** — publish keys as TXT records; DNSSEC preferred
- **WebPKI fallback** — `.well-known/uasi-keys` HTTPS endpoint when DNSSEC is unavailable
- **Three trust tiers** — `dnssec-verified`, `https-verified`, `dns-unsigned`
- **Nonce-based replay detection** — optional per-message nonces with configurable cache
- **Cross-protocol replay prevention** — `z=` context tag prevents protocol confusion
- **Content-Digest** — SHA-256 body integrity per RFC 9530
- **Prohibited header list** — prevents signing volatile headers that break in transit
- **DMARC-style policy** — `none` -> `report` -> `enforce` gradual rollout
- **Minimum trust policy** — `mt=` tag lets operators require DNSSEC or accept WebPKI

## API Reference

### Key Management

```python
from uasi import UASIKeyPair, key_to_wellknown_json

# Generate
key_pair = UASIKeyPair.generate(selector="webhooks", domain="example.com")

# DNS record
print(key_pair.dns_zone_entry(ttl=86400))

# .well-known JSON (serve at https://example.com/.well-known/uasi-keys/webhooks)
import json
print(json.dumps(key_to_wellknown_json(key_pair)))
# -> {"v": "UASI1", "k": "ed25519", "p": "<base64>"}

# Export / reload
private_b64 = key_pair.private_key_b64  # Store securely
key_pair = UASIKeyPair.from_private_key_b64(private_b64, "webhooks", "example.com")
```

### Low-Level Signing (MQTT, CoAP, WebSocket)

```python
from uasi import UASISigner, UASIKeyPair, Canonicalization

key_pair = UASIKeyPair.generate("fleet-a", "iot.example.com")
signer = UASISigner(
    key_pair,
    canonicalization=Canonicalization.SIMPLE,
    default_expiry_seconds=300,
    use_nonce=True,
)

sig = signer.sign(
    body=b'{"temp_c": 22.5}',
    context="mqtt5",
    fields={"@topic": "sensors/building-7/temp"},
    signed_fields=["@topic"],
)
header_value = sig.serialize()
```

### Policy with Trust Tiers

```python
from uasi import parse_policy_record, TrustTier, trust_tier_satisfies_policy

# Parse policy with minimum trust requirement
policy = parse_policy_record("v=UASI1; p=enforce; mt=https; rua=mailto:reports@example.com")

# Check if a trust tier satisfies the policy
trust_tier_satisfies_policy(TrustTier.DNSSEC_VERIFIED, policy)  # True
trust_tier_satisfies_policy(TrustTier.HTTPS_VERIFIED, policy)   # True
trust_tier_satisfies_policy(TrustTier.DNS_UNSIGNED, policy)     # False
```

## Security Properties

| Property | Mechanism |
|----------|-----------|
| Sender authentication | Ed25519 digital signature |
| Body integrity | Content-Digest (RFC 9530) for HTTP; SHA-256 body hash for native |
| Cross-protocol replay prevention | `z=` context tag / RFC 9421 `tag` parameter |
| Intra-protocol replay detection | Nonce with receiver-side cache |
| Key discovery | DNS TXT (DNSSEC preferred) + `.well-known` HTTPS fallback |
| Trust verification | Three tiers: dnssec-verified, https-verified, dns-unsigned |
| Intermediary resilience | Only signed components are verified |

## Specification

This library implements [`draft-uasi-framework-01`](https://datatracker.ietf.org/doc/draft-uasi-framework/). The full Internet-Draft is available in the [spec/](spec/) directory.

## Contributing

Contributions, issues, and feedback are welcome — especially:

- Live DNS resolver integration (DNSSEC validation + `.well-known` fallback)
- Framework integrations (Flask, FastAPI, Django, Express)
- Additional protocol bindings (MQTT, CoAP native signing)
- Interoperability testing

## License

MIT — see [LICENSE](LICENSE).
