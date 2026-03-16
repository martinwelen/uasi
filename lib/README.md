# uasi — Universal Authenticated Sender Identity

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Tests](https://img.shields.io/badge/tests-23%20passing-brightgreen.svg)]()

Reference implementation of the [UASI framework](https://github.com/mwelen/uasi) (`draft-uasi-framework-00`), a protocol-agnostic mechanism for cryptographic sender identity assertion and verification across Internet communication protocols.

**UASI lets any sender — webhook, API, email server, IoT device — prove its identity using DNS-published keys and a single signature format that works across all protocols.**

## Install

```bash
pip install uasi
```

## Quick Start: Sign a Webhook in 5 Lines

```python
from uasi import UASIKeyPair, sign_http_request

# Generate a key pair (one-time setup)
key_pair = UASIKeyPair.generate("webhooks", "your-saas.example.com")
print(key_pair.dns_zone_entry())
# → webhooks._uasi.your-saas.example.com. 3600 IN TXT "v=UASI1; k=ed25519; p=..."

# Sign an outgoing webhook
signature = sign_http_request(
    key_pair,
    method="POST",
    target_uri="https://customer.example.org/webhooks/orders",
    body=b'{"order_id": "789", "total": 99.50}',
    headers={"x-webhook-event": "order.completed"},
    signed_fields=["@method", "@target-uri", "x-webhook-event"],
)
# Add as HTTP header: UASI-Signature: <signature>
```

## Quick Start: Verify a Webhook in 5 Lines

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
    signature_header=request.headers["UASI-Signature"],
    method=request.method,
    target_uri=request.url,
    body=request.body,
    headers=dict(request.headers),
)

if result.passed:
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

UASI provides **one mechanism** that works across all of them: DNS-published Ed25519 keys, a unified signature format, and a DMARC-style policy framework.

## Features

- **Ed25519 signatures** — 64-byte signatures, fast verification, small DNS records
- **DNS-anchored trust** — no PKI/CA required; publish keys as TXT records
- **Protocol bindings** — HTTP (included), SMTP, MQTT, CoAP, WebSocket (spec-defined)
- **Nonce-based replay detection** — optional per-message nonces with configurable cache
- **Cross-protocol replay prevention** — `z=` context tag prevents protocol confusion
- **Strict canonicalization** — signatures survive CDN/proxy header modifications
- **Prohibited header list** — prevents signing volatile headers that break in transit
- **DMARC-style policy** — `none` → `report` → `enforce` gradual rollout

## API Reference

### Key Management

```python
from uasi import UASIKeyPair

# Generate
key_pair = UASIKeyPair.generate(selector="webhooks", domain="example.com")

# Export for storage
private_key_b64 = key_pair.private_key_b64  # Store securely
public_key_b64 = key_pair.public_key_b64    # Publish in DNS

# Reload
key_pair = UASIKeyPair.from_private_key_b64(private_key_b64, "webhooks", "example.com")

# DNS records
print(key_pair.dns_zone_entry(ttl=86400))
print(key_pair.dns_txt_value(expiry=1735689600, notes="Q1 2026 key"))
```

### Low-Level Signing

```python
from uasi import UASISigner, UASIKeyPair, Canonicalization

key_pair = UASIKeyPair.generate("api-v2", "example.com")
signer = UASISigner(
    key_pair,
    canonicalization=Canonicalization.STRICT,
    default_expiry_seconds=300,
    use_nonce=True,
)

sig = signer.sign(
    body=b"payload bytes",
    context="http",  # Protocol context tag
    fields={"@method": "POST", "x-request-id": "req-123"},
    signed_fields=["@method", "x-request-id"],
)

header_value = sig.serialize()
```

### Low-Level Verification

```python
from uasi import UASIVerifier, NonceCache

cache = NonceCache(max_size=1_000_000)
cache.set_fail_closed(True)  # For high-security endpoints

verifier = UASIVerifier(nonce_cache=cache)
verifier.add_key("sender.com", "webhooks", key_record)

result = verifier.verify(
    signature_header="v=1; a=ed25519-sha256; ...",
    body=b"payload bytes",
    context="http",
    fields={"@method": "POST", "x-request-id": "req-123"},
)

print(result.result)   # VerificationResult.PASS
print(result.reason)   # "Signature verified successfully"
print(result.passed)   # True
```

### DNS Record Parsing

```python
from uasi import parse_key_record, parse_policy_record

key = parse_key_record("v=UASI1; k=ed25519; p=BASE64KEY==")
print(key.algorithm, key.is_expired)

policy = parse_policy_record("v=UASI1; p=enforce; pct=50; b=http")
print(policy.policy, policy.percentage, policy.bindings)
```

## Security Properties

| Property | Mechanism |
|----------|-----------|
| Sender authentication | Ed25519 digital signature over canonical message content |
| Body integrity | SHA-256 hash of canonicalized body included in signature |
| Cross-protocol replay prevention | `z=` context tag bound into signature |
| Intra-protocol replay detection | Optional `n=` nonce with receiver-side cache |
| Key discovery | DNS TXT records (DNSSEC recommended) |
| Intermediary resilience | Strict mode signs only sender-controlled fields |

## Specification

This library implements `draft-uasi-framework-00`. The full Internet-Draft is available in the [spec/](spec/) directory.

## Contributing

This is a reference implementation accompanying an Internet-Draft. Contributions, issues, and feedback are welcome — especially:

- Additional protocol bindings (MQTT, CoAP, SMTP)
- Production DNS resolver integration
- Framework integrations (Flask, FastAPI, Django, Express)
- Interoperability testing

## License

MIT — see [LICENSE](LICENSE).
