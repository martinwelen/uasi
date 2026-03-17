"""UASI signature verification (Section 9)."""

from __future__ import annotations

import base64
import hashlib
import time
from typing import Optional

from cryptography.exceptions import InvalidSignature

from .canonical import build_signing_input, canonicalize_body
from .keys import load_public_key_from_b64, parse_key_record, parse_policy_record
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


class NonceCache:
    """Simple in-memory nonce cache for replay detection (Section 7.5.2).

    For production use, replace with a distributed TTL-aware cache.
    """

    def __init__(self, max_size: int = 100_000):
        self.max_size = max_size
        self._cache: dict[str, float] = {}  # (d, s, n) key -> expiry time
        self._fail_closed: bool = False

    def check_and_store(
        self, domain: str, selector: str, nonce: str, expiry: float
    ) -> bool:
        """
        Check if a nonce has been seen; if not, store it.

        Returns True if the nonce is fresh (not seen before).
        Returns False if the nonce is a replay.

        Raises RuntimeError if cache is saturated and fail_closed is True.
        """
        self._prune_expired()
        cache_key = f"{domain}:{selector}:{nonce}"

        if cache_key in self._cache:
            return False  # Replay detected

        if len(self._cache) >= self.max_size:
            if self._fail_closed:
                raise RuntimeError("Nonce cache saturated (fail-closed mode)")
            # Fail-open: evict oldest
            oldest_key = min(self._cache, key=self._cache.get)
            del self._cache[oldest_key]

        self._cache[cache_key] = expiry
        return True

    def _prune_expired(self) -> None:
        now = time.time()
        expired = [k for k, exp in self._cache.items() if exp <= now]
        for k in expired:
            del self._cache[k]

    def set_fail_closed(self, enabled: bool = True) -> None:
        """Enable/disable fail-closed mode for cache saturation."""
        self._fail_closed = enabled


class VerificationDetail:
    """Detailed result of UASI verification."""

    def __init__(
        self,
        result: VerificationResult,
        reason: str = "",
        signature: Optional[UASISignature] = None,
        key_record: Optional[UASIKeyRecord] = None,
        policy_record: Optional[UASIPolicyRecord] = None,
        trust_tier: TrustTier = TrustTier.LOCAL,
    ):
        self.result = result
        self.reason = reason
        self.signature = signature
        self.key_record = key_record
        self.policy_record = policy_record
        self.trust_tier = trust_tier

    @property
    def passed(self) -> bool:
        return self.result == VerificationResult.PASS

    def __repr__(self) -> str:
        return (
            f"VerificationDetail(result={self.result.value}, "
            f"trust_tier={self.trust_tier.value}, reason={self.reason!r})"
        )


# Trust tier ordering for policy evaluation
_TRUST_TIER_LEVEL = {
    TrustTier.DNSSEC_VERIFIED: 3,
    TrustTier.HTTPS_VERIFIED: 2,
    TrustTier.DNS_UNSIGNED: 1,
    TrustTier.LOCAL: 0,
}

# Minimum trust tier required for each mt= policy value
_MT_REQUIRED_LEVEL = {
    "dnssec": 3,  # Only dnssec-verified
    "https": 2,   # dnssec-verified or https-verified
    "any": 0,     # Any tier
}


def trust_tier_satisfies_policy(tier: TrustTier, policy: UASIPolicyRecord) -> bool:
    """Check whether a trust tier satisfies a policy's mt= requirement."""
    tier_level = _TRUST_TIER_LEVEL[tier]
    required_level = _MT_REQUIRED_LEVEL.get(policy.minimum_trust, 2)
    return tier_level >= required_level


class UASIVerifier:
    """Verifies UASI-Signature headers against DNS key records.

    For local/testing use, provide key records directly via key_records dict.
    For production use with live DNS, use verify_with_dns() or provide a
    custom key_resolver callable.

    Usage (local / testing):
        verifier = UASIVerifier()
        verifier.add_key(domain, selector, key_record)
        result = verifier.verify(
            signature_header="v=1; a=ed25519-sha256; ...",
            body=b'{"order": 123}',
            context="http",
            fields={"content-type": "application/json", "@method": "POST"},
        )
        print(result.passed, result.reason)
    """

    def __init__(
        self,
        nonce_cache: Optional[NonceCache] = None,
        clock_skew_tolerance: int = 60,
    ):
        self.nonce_cache = nonce_cache or NonceCache()
        self.clock_skew_tolerance = clock_skew_tolerance
        self._key_records: dict[str, UASIKeyRecord] = {}
        self._policy_records: dict[str, UASIPolicyRecord] = {}

    def add_key(self, domain: str, selector: str, record: UASIKeyRecord) -> None:
        """Register a key record for local verification."""
        cache_key = f"{selector}._uasi.{domain}"
        self._key_records[cache_key] = record

    def add_key_from_txt(self, domain: str, selector: str, txt_value: str) -> None:
        """Register a key record from a DNS TXT record value string."""
        self.add_key(domain, selector, parse_key_record(txt_value))

    def add_policy(self, domain: str, record: UASIPolicyRecord) -> None:
        """Register a policy record for local verification."""
        cache_key = f"_uasi-policy.{domain}"
        self._policy_records[cache_key] = record

    def _get_key_record(self, domain: str, selector: str) -> Optional[UASIKeyRecord]:
        cache_key = f"{selector}._uasi.{domain}"
        return self._key_records.get(cache_key)

    def _get_policy_record(self, domain: str) -> Optional[UASIPolicyRecord]:
        cache_key = f"_uasi-policy.{domain}"
        return self._policy_records.get(cache_key)

    def verify(
        self,
        signature_header: str,
        body: bytes,
        context: str,
        fields: Optional[dict[str, str]] = None,
    ) -> VerificationDetail:
        """
        Verify a UASI-Signature header (Section 9.2).

        Args:
            signature_header: The raw UASI-Signature header value string.
            body: The raw message body bytes.
            context: The protocol context (must match z= tag).
            fields: Dict of field_name -> field_value for all available
                    headers/metadata.

        Returns:
            VerificationDetail with result code and reason.
        """
        fields = fields or {}

        # Step 2: Parse
        try:
            sig = UASISignature.parse(signature_header)
        except (KeyError, ValueError) as e:
            return VerificationDetail(
                VerificationResult.PERMERROR,
                reason=f"Malformed signature: {e}",
            )

        # Step 3: Check protocol context
        if sig.context != context:
            return VerificationDetail(
                VerificationResult.FAIL,
                reason=f"Protocol context mismatch: expected {context!r}, got {sig.context!r}",
                signature=sig,
            )

        # Step 4: Check expiry
        now = time.time()
        if sig.expiry is not None and now > sig.expiry + self.clock_skew_tolerance:
            return VerificationDetail(
                VerificationResult.FAIL,
                reason=f"Signature expired at {sig.expiry}, current time {int(now)}",
                signature=sig,
            )

        # Step 5: Get key record
        key_record = self._get_key_record(sig.domain, sig.selector)
        if key_record is None:
            return VerificationDetail(
                VerificationResult.NONE,
                reason=f"No key record found for {sig.selector}._uasi.{sig.domain}",
                signature=sig,
            )

        if key_record.is_expired:
            return VerificationDetail(
                VerificationResult.FAIL,
                reason="Key record has expired",
                signature=sig,
                key_record=key_record,
            )

        # Step 6: Check algorithm compatibility
        expected_alg = f"{key_record.algorithm}-sha256"
        if sig.algorithm.value != expected_alg:
            return VerificationDetail(
                VerificationResult.PERMERROR,
                reason=f"Algorithm mismatch: key has {key_record.algorithm}, signature has {sig.algorithm.value}",
                signature=sig,
                key_record=key_record,
            )

        # Step 7-8: Canonicalize and check body hash
        canon_body = canonicalize_body(body, sig.canonicalization)
        computed_bh = base64.b64encode(hashlib.sha256(canon_body).digest()).decode("ascii")
        if computed_bh != sig.body_hash:
            return VerificationDetail(
                VerificationResult.FAIL,
                reason="Body hash mismatch (body was modified in transit)",
                signature=sig,
                key_record=key_record,
            )

        # Step 9: Reconstruct signing input
        # Build the signature template with b= empty
        sig_copy = UASISignature(
            version=sig.version,
            algorithm=sig.algorithm,
            domain=sig.domain,
            selector=sig.selector,
            timestamp=sig.timestamp,
            body_hash=sig.body_hash,
            signature="",  # Empty for signing input
            canonicalization=sig.canonicalization,
            context=sig.context,
            expiry=sig.expiry,
            signed_fields=sig.signed_fields,
            nonce=sig.nonce,
        )
        sig_template = sig_copy.serialize()

        signing_input = build_signing_input(
            fields=fields,
            signed_field_names=sig.signed_fields,
            context=context,
            body_hash=sig.body_hash,
            signature_value_template=sig_template,
            mode=sig.canonicalization,
            nonce=sig.nonce,
        )

        # Step 10: Verify signature
        try:
            public_key = load_public_key_from_b64(key_record.public_key_b64)
            raw_sig = base64.b64decode(sig.signature)
            public_key.verify(raw_sig, signing_input)
        except (InvalidSignature, Exception) as e:
            return VerificationDetail(
                VerificationResult.FAIL,
                reason=f"Signature verification failed: {e}",
                signature=sig,
                key_record=key_record,
            )

        # Step 11: Nonce check
        if sig.nonce:
            nonce_expiry = float(sig.expiry) if sig.expiry else (now + 300)
            try:
                is_fresh = self.nonce_cache.check_and_store(
                    sig.domain, sig.selector, sig.nonce, nonce_expiry
                )
            except RuntimeError:
                return VerificationDetail(
                    VerificationResult.TEMPERROR,
                    reason="Nonce cache saturated (fail-closed)",
                    signature=sig,
                    key_record=key_record,
                )
            if not is_fresh:
                return VerificationDetail(
                    VerificationResult.FAIL,
                    reason=f"Replay detected: nonce {sig.nonce!r} already seen",
                    signature=sig,
                    key_record=key_record,
                )

        # Step 12: Pass
        policy_record = self._get_policy_record(sig.domain)
        return VerificationDetail(
            VerificationResult.PASS,
            reason="Signature verified successfully",
            signature=sig,
            key_record=key_record,
            policy_record=policy_record,
        )
