"""Tests for the UASI reference implementation."""

import json
import time

import pytest

from uasi import (
    Algorithm,
    Canonicalization,
    NonceCache,
    PolicyMode,
    TrustTier,
    UASIKeyPair,
    UASIKeyRecord,
    UASIPolicyRecord,
    UASISignature,
    UASISigner,
    UASIVerifier,
    VerificationResult,
    parse_key_record,
    parse_policy_record,
    sign_http_request,
    verify_http_request,
    trust_tier_satisfies_policy,
    key_to_wellknown_json,
    parse_wellknown_json,
)


# ─── Trust Tiers & Policy (new in -01) ───


class TestTrustTier:
    def test_trust_tier_values(self):
        assert TrustTier.DNSSEC_VERIFIED.value == "dnssec-verified"
        assert TrustTier.HTTPS_VERIFIED.value == "https-verified"
        assert TrustTier.DNS_UNSIGNED.value == "dns-unsigned"
        assert TrustTier.LOCAL.value == "local"


class TestMinimumTrust:
    def test_policy_record_mt_tag(self):
        txt = "v=UASI1; p=enforce; mt=dnssec; rua=mailto:uasi@example.com"
        record = parse_policy_record(txt)
        assert record.minimum_trust == "dnssec"

    def test_policy_record_mt_default(self):
        txt = "v=UASI1; p=enforce; rua=mailto:uasi@example.com"
        record = parse_policy_record(txt)
        assert record.minimum_trust == "https"

    def test_policy_record_da_tag(self):
        txt = "v=UASI1; p=enforce; da=relaxed; rua=mailto:uasi@example.com"
        record = parse_policy_record(txt)
        assert record.dkim_alignment == "relaxed"

    def test_policy_record_mt_roundtrip(self):
        txt = "v=UASI1; p=enforce; mt=dnssec; da=strict; rua=mailto:uasi@example.com"
        record = parse_policy_record(txt)
        serialized = record.to_dns_txt()
        assert "mt=dnssec" in serialized
        assert "da=strict" in serialized

    def test_policy_mt_check_pass(self):
        """mt=https should accept both dnssec-verified and https-verified."""
        policy = UASIPolicyRecord(version="UASI1", policy=PolicyMode.ENFORCE, minimum_trust="https")
        assert trust_tier_satisfies_policy(TrustTier.DNSSEC_VERIFIED, policy)
        assert trust_tier_satisfies_policy(TrustTier.HTTPS_VERIFIED, policy)
        assert not trust_tier_satisfies_policy(TrustTier.DNS_UNSIGNED, policy)

    def test_policy_mt_dnssec_strict(self):
        """mt=dnssec should only accept dnssec-verified."""
        policy = UASIPolicyRecord(version="UASI1", policy=PolicyMode.ENFORCE, minimum_trust="dnssec")
        assert trust_tier_satisfies_policy(TrustTier.DNSSEC_VERIFIED, policy)
        assert not trust_tier_satisfies_policy(TrustTier.HTTPS_VERIFIED, policy)
        assert not trust_tier_satisfies_policy(TrustTier.DNS_UNSIGNED, policy)

    def test_policy_mt_any(self):
        """mt=any should accept everything."""
        policy = UASIPolicyRecord(version="UASI1", policy=PolicyMode.ENFORCE, minimum_trust="any")
        assert trust_tier_satisfies_policy(TrustTier.DNSSEC_VERIFIED, policy)
        assert trust_tier_satisfies_policy(TrustTier.HTTPS_VERIFIED, policy)
        assert trust_tier_satisfies_policy(TrustTier.DNS_UNSIGNED, policy)
        assert trust_tier_satisfies_policy(TrustTier.LOCAL, policy)


class TestTrustTierVerification:
    def test_local_key_returns_local_trust_tier(self):
        kp = UASIKeyPair.generate("s1", "example.com")
        signer = UASISigner(kp, use_nonce=False)
        sig = signer.sign(b"hello", "http", {}, [])
        verifier = UASIVerifier()
        verifier.add_key("example.com", "s1", kp.dns_key_record())
        result = verifier.verify(sig.serialize(), b"hello", "http", {})
        assert result.passed
        assert result.trust_tier == TrustTier.LOCAL


# ─── .well-known Key Format ───


class TestWellKnown:
    def test_key_to_wellknown_json(self):
        kp = UASIKeyPair.generate("s1", "example.com")
        data = key_to_wellknown_json(kp)
        assert data["v"] == "UASI1"
        assert data["k"] == "ed25519"
        assert data["p"] == kp.public_key_b64

    def test_parse_wellknown_json(self):
        kp = UASIKeyPair.generate("s1", "example.com")
        data = key_to_wellknown_json(kp)
        record = parse_wellknown_json(data)
        assert record.version == "UASI1"
        assert record.algorithm == "ed25519"
        assert record.public_key_b64 == kp.public_key_b64

    def test_wellknown_roundtrip(self):
        kp = UASIKeyPair.generate("s1", "example.com")
        data = key_to_wellknown_json(kp)
        record = parse_wellknown_json(data)
        # Verify the key can actually be used for verification
        from uasi import UASIVerifier, UASISigner
        signer = UASISigner(kp, use_nonce=False)
        sig = signer.sign(b"test", "http")
        verifier = UASIVerifier()
        verifier.add_key("example.com", "s1", record)
        result = verifier.verify(sig.serialize(), b"test", "http")
        assert result.passed


# ─── Key Management ───


class TestKeyPair:
    def test_generate(self):
        kp = UASIKeyPair.generate("webhooks", "example.com")
        assert kp.selector == "webhooks"
        assert kp.domain == "example.com"
        assert kp.uid == "webhooks._uasi.example.com"
        assert len(kp.public_key_b64) > 0

    def test_dns_txt_value(self):
        kp = UASIKeyPair.generate("mail", "example.com")
        txt = kp.dns_txt_value(notes="Test key")
        assert "v=UASI1" in txt
        assert "k=ed25519" in txt
        assert "p=" in txt
        assert "n=Test key" in txt

    def test_dns_zone_entry(self):
        kp = UASIKeyPair.generate("api", "example.com")
        entry = kp.dns_zone_entry(ttl=86400)
        assert "api._uasi.example.com." in entry
        assert "86400" in entry
        assert "IN TXT" in entry

    def test_roundtrip_private_key(self):
        kp1 = UASIKeyPair.generate("test", "example.com")
        kp2 = UASIKeyPair.from_private_key_b64(
            kp1.private_key_b64, "test", "example.com"
        )
        assert kp1.public_key_b64 == kp2.public_key_b64


# ─── DNS Record Parsing ───


class TestRecordParsing:
    def test_parse_key_record(self):
        txt = "v=UASI1; k=ed25519; p=dGVzdA==; x=1735689600; n=Test"
        rec = parse_key_record(txt)
        assert rec.version == "UASI1"
        assert rec.algorithm == "ed25519"
        assert rec.public_key_b64 == "dGVzdA=="
        assert rec.expiry == 1735689600
        assert rec.notes == "Test"

    def test_parse_policy_record(self):
        txt = "v=UASI1; p=enforce; pct=50; rua=mailto:reports@example.com; b=smtp:http; rl=d"
        rec = parse_policy_record(txt)
        assert rec.policy == PolicyMode.ENFORCE
        assert rec.percentage == 50
        assert rec.report_aggregate_uri == "mailto:reports@example.com"
        assert rec.bindings == ["smtp", "http"]
        assert rec.report_level == "d"

    def test_key_record_roundtrip(self):
        kp = UASIKeyPair.generate("test", "example.com")
        original = kp.dns_key_record(expiry=9999999999, notes="Roundtrip test")
        txt = original.to_dns_txt()
        parsed = parse_key_record(txt)
        assert parsed.version == original.version
        assert parsed.algorithm == original.algorithm
        assert parsed.public_key_b64 == original.public_key_b64
        assert parsed.expiry == original.expiry

    def test_policy_record_roundtrip(self):
        original = UASIPolicyRecord(
            version="UASI1",
            policy=PolicyMode.REPORT,
            percentage=25,
            bindings=["http", "mqtt5"],
            report_level="d",
        )
        txt = original.to_dns_txt()
        parsed = parse_policy_record(txt)
        assert parsed.policy == original.policy
        assert parsed.percentage == original.percentage
        assert parsed.bindings == original.bindings
        assert parsed.report_level == "d"


# ─── Signature Parsing ───


class TestSignatureParsing:
    def test_parse_and_serialize(self):
        raw = (
            "v=1; a=ed25519-sha256; d=example.com; s=webhooks; "
            "t=1710500000; z=http; c=strict; n=abc123; "
            "h=@method:content-type; bh=testhash==; b=testsig=="
        )
        sig = UASISignature.parse(raw)
        assert sig.domain == "example.com"
        assert sig.selector == "webhooks"
        assert sig.context == "http"
        assert sig.nonce == "abc123"
        assert sig.signed_fields == ["@method", "content-type"]
        assert sig.body_hash == "testhash=="

        # Re-serialize and re-parse
        serialized = sig.serialize()
        sig2 = UASISignature.parse(serialized)
        assert sig2.domain == sig.domain
        assert sig2.nonce == sig.nonce


# ─── End-to-End Signing & Verification ───


class TestSignAndVerify:
    def setup_method(self):
        self.key_pair = UASIKeyPair.generate("webhooks", "sender.example.com")
        self.body = b'{"order_id": "789", "total": 99.50}'

    def test_basic_sign_and_verify(self):
        signer = UASISigner(self.key_pair, use_nonce=False)
        sig = signer.sign(
            body=self.body,
            context="http",
            fields={"@method": "POST", "content-type": "application/json"},
            signed_fields=["@method", "content-type"],
        )

        verifier = UASIVerifier()
        verifier.add_key(
            "sender.example.com", "webhooks", self.key_pair.dns_key_record()
        )

        result = verifier.verify(
            signature_header=sig.serialize(),
            body=self.body,
            context="http",
            fields={"@method": "POST", "content-type": "application/json"},
        )
        assert result.passed
        assert result.result == VerificationResult.PASS

    def test_body_modification_detected(self):
        signer = UASISigner(self.key_pair, use_nonce=False)
        sig = signer.sign(body=self.body, context="http")

        verifier = UASIVerifier()
        verifier.add_key(
            "sender.example.com", "webhooks", self.key_pair.dns_key_record()
        )

        # Modify body
        result = verifier.verify(
            signature_header=sig.serialize(),
            body=b'{"order_id": "789", "total": 0.01}',
            context="http",
        )
        assert not result.passed
        assert "Body hash mismatch" in result.reason

    def test_cross_protocol_replay_rejected(self):
        signer = UASISigner(self.key_pair, use_nonce=False)
        sig = signer.sign(body=self.body, context="http")

        verifier = UASIVerifier()
        verifier.add_key(
            "sender.example.com", "webhooks", self.key_pair.dns_key_record()
        )

        # Try to verify with wrong context
        result = verifier.verify(
            signature_header=sig.serialize(),
            body=self.body,
            context="mqtt5",  # Wrong!
        )
        assert not result.passed
        assert "Protocol context mismatch" in result.reason

    def test_expired_signature_rejected(self):
        signer = UASISigner(self.key_pair, use_nonce=False, default_expiry_seconds=1)
        sig = signer.sign(body=self.body, context="http")

        # Hack the expiry to the past
        sig.expiry = int(time.time()) - 3600
        sig_header = sig.serialize()

        verifier = UASIVerifier()
        verifier.add_key(
            "sender.example.com", "webhooks", self.key_pair.dns_key_record()
        )

        result = verifier.verify(
            signature_header=sig_header,
            body=self.body,
            context="http",
        )
        assert not result.passed
        assert "expired" in result.reason.lower()

    def test_wrong_key_rejected(self):
        signer = UASISigner(self.key_pair, use_nonce=False)
        sig = signer.sign(body=self.body, context="http")

        # Register a DIFFERENT key
        wrong_key = UASIKeyPair.generate("webhooks", "sender.example.com")
        verifier = UASIVerifier()
        verifier.add_key(
            "sender.example.com", "webhooks", wrong_key.dns_key_record()
        )

        result = verifier.verify(
            signature_header=sig.serialize(),
            body=self.body,
            context="http",
        )
        assert not result.passed
        assert "verification failed" in result.reason.lower()

    def test_missing_key_returns_none(self):
        signer = UASISigner(self.key_pair, use_nonce=False)
        sig = signer.sign(body=self.body, context="http")

        verifier = UASIVerifier()
        # Don't register any keys

        result = verifier.verify(
            signature_header=sig.serialize(),
            body=self.body,
            context="http",
        )
        assert result.result == VerificationResult.NONE
        assert "No key record" in result.reason


# ─── Nonce / Replay Detection ───


class TestReplayDetection:
    def test_nonce_replay_detected(self):
        key_pair = UASIKeyPair.generate("api", "example.com")
        signer = UASISigner(key_pair, use_nonce=True)
        sig = signer.sign(body=b"test", context="http")
        sig_header = sig.serialize()

        verifier = UASIVerifier()
        verifier.add_key("example.com", "api", key_pair.dns_key_record())

        # First verification: pass
        r1 = verifier.verify(sig_header, b"test", "http")
        assert r1.passed

        # Second verification (same nonce): fail
        r2 = verifier.verify(sig_header, b"test", "http")
        assert not r2.passed
        assert "Replay detected" in r2.reason

    def test_different_nonces_both_pass(self):
        key_pair = UASIKeyPair.generate("api", "example.com")
        signer = UASISigner(key_pair, use_nonce=True)

        sig1 = signer.sign(body=b"test1", context="http")
        sig2 = signer.sign(body=b"test2", context="http")

        verifier = UASIVerifier()
        verifier.add_key("example.com", "api", key_pair.dns_key_record())

        r1 = verifier.verify(sig1.serialize(), b"test1", "http")
        r2 = verifier.verify(sig2.serialize(), b"test2", "http")
        assert r1.passed
        assert r2.passed

    def test_cache_saturation_fail_closed(self):
        cache = NonceCache(max_size=2)
        cache.set_fail_closed(True)

        key_pair = UASIKeyPair.generate("api", "example.com")
        signer = UASISigner(key_pair, use_nonce=True)

        verifier = UASIVerifier(nonce_cache=cache)
        verifier.add_key("example.com", "api", key_pair.dns_key_record())

        # Fill the cache
        for _ in range(2):
            sig = signer.sign(body=b"msg", context="http")
            result = verifier.verify(sig.serialize(), b"msg", "http")
            assert result.passed

        # Third should trigger fail-closed
        sig3 = signer.sign(body=b"msg", context="http")
        result = verifier.verify(sig3.serialize(), b"msg", "http")
        assert result.result == VerificationResult.TEMPERROR
        assert "saturated" in result.reason.lower()


# ─── HTTP Binding (RFC 9421 Profile) ───


class TestHTTPBinding:
    def test_sign_and_verify_webhook(self):
        """End-to-end sign and verify using RFC 9421 format."""
        key_pair = UASIKeyPair.generate("webhooks", "saas.example.com")
        body = json.dumps({"order_id": "123", "status": "shipped"}).encode()

        result_headers = sign_http_request(
            key_pair,
            method="POST",
            target_uri="https://customer.example.org/webhooks/orders",
            body=body,
            headers={
                "content-type": "application/json",
            },
        )

        assert "signature-input" in result_headers
        assert "signature" in result_headers
        assert "content-digest" in result_headers

        verifier = UASIVerifier()
        verifier.add_key("saas.example.com", "webhooks", key_pair.dns_key_record())

        detail = verify_http_request(
            verifier,
            signature_input=result_headers["signature-input"],
            signature=result_headers["signature"],
            method="POST",
            target_uri="https://customer.example.org/webhooks/orders",
            body=body,
            headers={"content-type": "application/json"},
        )
        assert detail.passed

    def test_keyid_is_uasi_identity(self):
        """keyid should be the full UASI DNS name."""
        kp = UASIKeyPair.generate("s1", "example.com")
        result = sign_http_request(
            kp, method="POST",
            target_uri="https://example.com/hook",
            body=b'{"test": true}',
        )
        assert "s1._uasi.example.com" in result["signature-input"]

    def test_tag_parameter_is_uasi(self):
        """RFC 9421 tag parameter should be 'uasi'."""
        kp = UASIKeyPair.generate("s1", "example.com")
        result = sign_http_request(
            kp, method="POST",
            target_uri="https://example.com/hook",
            body=b'{"test": true}',
        )
        assert 'tag="uasi"' in result["signature-input"]

    def test_prohibited_header_raises(self):
        key_pair = UASIKeyPair.generate("test", "example.com")
        with pytest.raises(ValueError, match="prohibited"):
            sign_http_request(
                key_pair,
                method="POST",
                target_uri="https://example.com/test",
                body=b"test",
                signed_fields=["x-forwarded-for"],  # Prohibited!
            )

    def test_body_modification_detected(self):
        """Tampered body should fail verification."""
        kp = UASIKeyPair.generate("s1", "example.com")
        body = b'{"amount": 100}'
        result = sign_http_request(
            kp, method="POST",
            target_uri="https://example.com/hook", body=body,
        )
        verifier = UASIVerifier()
        verifier.add_key("example.com", "s1", kp.dns_key_record())
        detail = verify_http_request(
            verifier,
            signature_input=result["signature-input"],
            signature=result["signature"],
            method="POST",
            target_uri="https://example.com/hook",
            body=b'{"amount": 999}',  # Tampered!
        )
        assert not detail.passed

    def test_intermediary_adds_header_signature_survives(self):
        """Signature survives when intermediary adds non-signed headers."""
        key_pair = UASIKeyPair.generate("webhooks", "sender.example.com")
        body = b'{"data": true}'

        result_headers = sign_http_request(
            key_pair,
            method="POST",
            target_uri="https://receiver.example.com/webhook",
            body=body,
            headers={"content-type": "application/json"},
        )

        verifier = UASIVerifier()
        verifier.add_key("sender.example.com", "webhooks", key_pair.dns_key_record())

        # Simulate intermediary adding headers (not in signed components)
        detail = verify_http_request(
            verifier,
            signature_input=result_headers["signature-input"],
            signature=result_headers["signature"],
            method="POST",
            target_uri="https://receiver.example.com/webhook",
            body=body,
            headers={
                "content-type": "application/json",
                "x-forwarded-for": "10.0.0.1",     # Added by proxy
                "via": "1.1 cloudflare",             # Added by CDN
                "cf-ray": "abc123",                  # Added by CDN
            },
        )
        assert detail.passed, f"Failed: {detail.reason}"

    def test_content_digest_included_for_body(self):
        """Requests with a body should include content-digest."""
        kp = UASIKeyPair.generate("s1", "example.com")
        result = sign_http_request(
            kp, method="POST",
            target_uri="https://example.com/hook",
            body=b'{"test": true}',
        )
        assert "content-digest" in result
        assert "content-digest" in result["signature-input"]

    def test_wrong_key_rejected_rfc9421(self):
        """Wrong key should fail verification."""
        kp = UASIKeyPair.generate("s1", "example.com")
        wrong_kp = UASIKeyPair.generate("s1", "example.com")
        body = b"test"
        result = sign_http_request(
            kp, method="POST",
            target_uri="https://example.com/hook", body=body,
        )
        verifier = UASIVerifier()
        verifier.add_key("example.com", "s1", wrong_kp.dns_key_record())
        detail = verify_http_request(
            verifier,
            signature_input=result["signature-input"],
            signature=result["signature"],
            method="POST",
            target_uri="https://example.com/hook",
            body=body,
        )
        assert not detail.passed
        assert "verification failed" in detail.reason.lower()


# ─── Nonce Cache ───


class TestNonceCache:
    def test_expiry_cleans_entries(self):
        cache = NonceCache(max_size=100)
        # Add entry that expires immediately
        cache.check_and_store("d", "s", "n1", time.time() - 1)
        # Should be pruned
        assert cache.check_and_store("d", "s", "n1", time.time() + 60)

    def test_fail_open_eviction(self):
        cache = NonceCache(max_size=2)
        cache.check_and_store("d", "s", "n1", time.time() + 3600)
        cache.check_and_store("d", "s", "n2", time.time() + 3600)
        # Should evict oldest and succeed
        assert cache.check_and_store("d", "s", "n3", time.time() + 3600)
