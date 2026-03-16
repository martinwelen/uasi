# UASI in 5 Minutes

**Universal Authenticated Sender Identity — one signature format for every protocol**

## The Problem (30 seconds)

You send webhooks. Your customers ask: "How do I verify this request actually came from you?"

Today, every SaaS product invents its own answer. Stripe uses HMAC-SHA256 with a shared secret. GitHub uses a different HMAC scheme. Slack uses signing secrets with timestamps. Twilio does something else entirely. Your IoT platform? Probably nothing.

There is no standard. Every integration requires reading vendor-specific docs, writing vendor-specific verification code, and managing vendor-specific secrets. Multiply this by every webhook provider, every API callback, every IoT data stream. It's the same problem email had before DKIM — and it took three separate RFCs (SPF, DKIM, DMARC) plus a decade of adoption to partially solve it for just that one protocol.

## The Fix (60 seconds)

UASI is DKIM generalized to any protocol. Three components:

**1. DNS-published keys.** You generate an Ed25519 key pair and publish the public key as a DNS TXT record:

```
webhooks._uasi.your-saas.com. 3600 IN TXT "v=UASI1; k=ed25519; p=<base64-pubkey>"
```

No certificates. No PKI. No shared secrets to rotate per-customer. You publish once; every receiver on the Internet can verify.

**2. A signature header.** Every outgoing message carries a `UASI-Signature` header with a standard format that works the same way whether it's an HTTP header, an SMTP header, or an MQTT user property:

```
UASI-Signature: v=1; a=ed25519-sha256; d=your-saas.com; s=webhooks;
  t=1710500000; x=1710500300; z=http; c=strict;
  n=550e8400-e29b-41d4-a716-446655440000;
  h=@method:@target-uri:x-webhook-event;
  bh=<body-hash>; b=<signature>
```

**3. A policy record.** You declare your authentication posture in DNS, enabling gradual rollout from monitoring to enforcement — just like DMARC:

```
_uasi-policy.your-saas.com. 3600 IN TXT "v=UASI1; p=enforce; b=http"
```

## Why Not Just Use [X]? (60 seconds)

**"We already use HMAC shared secrets for webhooks."**
Great — but you're managing a separate secret per customer, you can't prove to a third party that the message is authentic (symmetric key), and you've built a bespoke system that doesn't work for your MQTT streams or your email. UASI uses asymmetric crypto: the private key stays with you, the public key is in DNS, and any receiver can verify without you exchanging secrets.

**"We use mTLS."**
mTLS authenticates the transport connection, not the message. If a proxy terminates TLS and re-forwards, the authentication is gone. UASI signs the message itself — it survives proxies, load balancers, and CDNs.

**"HTTP Message Signatures (RFC 9421) exists."**
It does, and it's good — for HTTP. UASI's HTTP binding is essentially a profile of RFC 9421 with DNS-based key discovery and a cross-protocol policy framework bolted on. If you only care about HTTP, RFC 9421 works. If you also send MQTT telemetry, email notifications, and CoAP commands, UASI gives you one system instead of four.

**"DKIM already solved this for email."**
DKIM solved it for email and only email. UASI is DKIM's design pattern — DNS keys, domain-level identity, signature headers — extracted into a protocol-agnostic framework. The SMTP binding is intentionally parallel to DKIM so migration is straightforward.

## Show Me the Code (90 seconds)

Install: `pip install uasi`

### Sender (3 lines that matter)

```python
from uasi import UASIKeyPair, sign_http_request

key_pair = UASIKeyPair.generate("webhooks", "your-saas.com")

# One-time: publish this in DNS
print(key_pair.dns_zone_entry())
# → webhooks._uasi.your-saas.com. 3600 IN TXT "v=UASI1; k=ed25519; p=..."

# Per-request: sign and attach
sig = sign_http_request(
    key_pair,
    method="POST",
    target_uri="https://customer.example.org/webhooks/orders",
    body=b'{"order_id": "789", "status": "shipped"}',
    headers={"x-webhook-event": "order.completed"},
    signed_fields=["@method", "@target-uri", "x-webhook-event"],
)
# Add header: UASI-Signature: {sig}
```

### Receiver (3 lines that matter)

```python
from uasi import UASIVerifier, verify_http_request

verifier = UASIVerifier()
verifier.add_key_from_txt(
    "your-saas.com", "webhooks",
    "v=UASI1; k=ed25519; p=<from-DNS>"
)

result = verify_http_request(
    verifier,
    signature_header=request.headers["UASI-Signature"],
    method="POST",
    target_uri=request.url,
    body=request.body,
    headers=dict(request.headers),
)

if result.passed:
    process_webhook()
else:
    log.warning(f"UASI verification failed: {result.reason}")
```

That's it. The library handles canonicalization, body hashing, nonce generation, replay detection, and signature computation. The receiver needs zero shared secrets — just a DNS lookup.

## What Happens in Transit (30 seconds)

UASI is designed to survive real-world infrastructure:

- **CDN adds headers?** Strict mode only signs fields you list in `h=`. New headers don't break the signature.
- **Proxy modifies Content-Type?** Don't sign volatile headers. The body hash (`bh=`) already proves the payload is intact.
- **Attacker replays the request?** The `n=` nonce tag + receiver-side cache catches it. The `x=` expiry limits the replay window to 5 minutes.
- **Attacker replays an HTTP signature as MQTT?** The `z=http` context tag is baked into the signature. Cross-protocol replay fails automatically.

## Deployment Path (30 seconds)

Same as DMARC, proven over a decade:

1. **Monitor** — Publish key + policy with `p=none`. Start signing. No receiver impact.
2. **Report** — Switch to `p=report`. Receivers verify and send aggregate reports. You diagnose failures.
3. **Gradual enforce** — `p=enforce; pct=10` → `pct=25` → `pct=50` → `pct=100`.
4. **Full enforcement** — All unsigned or failing messages are rejected.

Start with HTTP webhooks. Add SMTP and MQTT once HTTP is stable.

## The Spec

The spec covers:

- 5 protocol bindings (SMTP, HTTP, MQTT v5, CoAP, WebSocket)
- Ed25519 mandatory-to-implement, ECDSA P-256 recommended
- DNS key records, policy records, reporting framework
- Nonce-based replay detection with cache saturation guidance
- KDF-hint model for constrained IoT devices
- DNSSEC validation states (bogus vs. insecure)
- Content-Type normalization guidance for CDN environments

Full text: `draft-uasi-framework-00`
Reference library: `pip install uasi`
License: MIT
