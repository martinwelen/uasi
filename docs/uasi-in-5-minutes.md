# UASI in 5 Minutes

**Universal Authenticated Sender Identity — unified sender authentication across protocols**

## The Problem (30 seconds)

You send webhooks. Your customers ask: "How do I verify this request actually came from you?"

Today, every SaaS product invents its own answer. Stripe uses HMAC-SHA256 with a shared secret. GitHub uses a different HMAC scheme. Slack uses signing secrets with timestamps. Twilio does something else entirely. Your IoT platform? Probably nothing.

There is no standard. Every integration requires reading vendor-specific docs, writing vendor-specific verification code, and managing vendor-specific secrets. And good signing standards like HTTP Message Signatures (RFC 9421) exist but lack standardized key discovery — how does a receiver find the sender's public key?

## The Fix (60 seconds)

UASI is a cross-protocol framework that provides three things:

**1. DNS-based key discovery.** You generate an Ed25519 key pair and publish the public key as a DNS TXT record:

```
webhooks._uasi.your-saas.com. 3600 IN TXT "v=UASI1; k=ed25519; p=<base64-pubkey>"
```

No certificates. No PKI. No shared secrets to rotate per-customer. You publish once; every receiver on the Internet can look it up. If DNSSEC isn't available, serve the key at `https://your-saas.com/.well-known/uasi-keys/webhooks` — the TLS certificate provides the trust anchor.

**2. Protocol adapters.** UASI uses existing signing standards where they exist:

- **HTTP**: Profiles RFC 9421 (HTTP Message Signatures). Your webhook carries standard `Signature-Input` and `Signature` headers. The `keyid` points to your UASI DNS record.
- **SMTP**: Wraps DKIM. No second signature — UASI adds unified policy and reporting on top.
- **MQTT/CoAP/WebSocket**: Native UASI signing (these protocols have no existing standard).

**3. A unified policy framework.** Declare your authentication posture in DNS, with a minimum trust requirement:

```
_uasi-policy.your-saas.com. 3600 IN TXT "v=UASI1; p=enforce; mt=https; b=http"
```

`mt=https` means verifiers must retrieve the key via DNSSEC or HTTPS — unsigned DNS alone isn't enough. Gradual rollout from `p=none` to `p=report` to `p=enforce`, just like DMARC.

## Why Not Just Use [X]? (60 seconds)

**"We already use HMAC shared secrets for webhooks."**
Great — but you're managing a separate secret per customer, you can't prove to a third party that the message is authentic (symmetric key), and it doesn't work for your MQTT streams or email. UASI uses asymmetric crypto: the private key stays with you, the public key is in DNS.

**"We use mTLS."**
mTLS authenticates the transport connection, not the message. If a proxy terminates TLS and re-forwards, the authentication is gone. UASI signs the message itself — it survives proxies, load balancers, and CDNs.

**"HTTP Message Signatures (RFC 9421) exists."**
It does, and UASI uses it. The HTTP adapter is literally an RFC 9421 profile — UASI adds the missing piece: standardized DNS-based key discovery. If you only care about HTTP, the UASI HTTP adapter is RFC 9421 with a `keyid` that resolves via DNS. If you also send MQTT telemetry and email, UASI gives you one identity across all of them.

**"DKIM already solved this for email."**
DKIM solved it for email only. For SMTP, UASI wraps DKIM and adds a cross-protocol policy layer — it doesn't replace it.

## Show Me the Code (90 seconds)

Install: `pip install uasi`

### Sender (signs with RFC 9421)

```python
from uasi import UASIKeyPair, sign_http_request

key_pair = UASIKeyPair.generate("webhooks", "your-saas.com")

# One-time: publish in DNS
print(key_pair.dns_zone_entry())

# Per-request: sign (returns RFC 9421 headers)
sig_headers = sign_http_request(
    key_pair,
    method="POST",
    target_uri="https://customer.example.org/webhooks/orders",
    body=b'{"order_id": "789", "status": "shipped"}',
    headers={"content-type": "application/json"},
)
# Add to request:
#   Signature-Input: sig_headers["signature-input"]
#   Signature: sig_headers["signature"]
#   Content-Digest: sig_headers["content-digest"]
```

### Receiver (verifies with RFC 9421)

```python
from uasi import UASIVerifier, verify_http_request

verifier = UASIVerifier()
verifier.add_key_from_txt(
    "your-saas.com", "webhooks",
    "v=UASI1; k=ed25519; p=<from-DNS>"
)

result = verify_http_request(
    verifier,
    signature_input=request.headers["Signature-Input"],
    signature=request.headers["Signature"],
    method="POST",
    target_uri=request.url,
    body=request.body,
    headers=dict(request.headers),
)

if result.passed:
    print(f"Verified (trust: {result.trust_tier.value})")
else:
    log.warning(f"UASI verification failed: {result.reason}")
```

That's it. The library handles canonicalization, Content-Digest computation, nonce generation, replay detection, and signature computation. The receiver needs zero shared secrets — just a DNS lookup.

## What Happens in Transit (30 seconds)

- **CDN adds headers?** Only signed components are verified. New headers don't break the signature.
- **Proxy modifies Content-Type?** Content-Digest (SHA-256) proves the payload is intact.
- **Attacker replays the request?** The nonce + receiver-side cache catches it. The expiry limits the replay window.
- **Attacker replays an HTTP signature as MQTT?** The RFC 9421 `tag="uasi"` parameter and the `z=` context tag prevent cross-protocol replay.

## Deployment Path (30 seconds)

Same as DMARC, proven over a decade:

1. **Monitor** — Publish key + policy with `p=none`. Start signing. No receiver impact.
2. **Report** — Switch to `p=report`. Receivers verify and send aggregate reports.
3. **Gradual enforce** — `p=enforce; pct=10` -> `pct=25` -> `pct=50` -> `pct=100`.
4. **Full enforcement** — All unsigned or failing messages are rejected.

Start with HTTP webhooks. Add SMTP and MQTT once HTTP is stable.

## The Spec

`draft-uasi-framework-01` covers:

- 5 protocol adapters (HTTP/RFC 9421, SMTP/DKIM, MQTT v5, CoAP, WebSocket)
- Ed25519 mandatory-to-implement, ECDSA P-256 recommended
- DNS key discovery with `.well-known` HTTPS fallback
- Three trust tiers: dnssec-verified, https-verified, dns-unsigned
- Policy framework with minimum trust (`mt=`) and DKIM alignment (`da=`)
- Nonce-based replay detection
- Aggregate reporting

Full text: `draft-uasi-framework-01`
Reference library: `pip install uasi`
License: MIT
