"""Data models for UASI signatures, keys, and policies."""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Algorithm(str, Enum):
    """Supported signing algorithms (Section 6.3)."""
    ED25519_SHA256 = "ed25519-sha256"
    ES256_SHA256 = "es256-sha256"


class Canonicalization(str, Enum):
    """Canonicalization modes (Section 7.2)."""
    SIMPLE = "simple"
    RELAXED = "relaxed"
    STRICT = "strict"


class PolicyMode(str, Enum):
    """Policy enforcement modes (Section 6.2)."""
    NONE = "none"
    REPORT = "report"
    ENFORCE = "enforce"


class VerificationResult(str, Enum):
    """Verification result codes (Section 9.3)."""
    PASS = "pass"
    FAIL = "fail"
    NONE = "none"
    PERMERROR = "permerror"
    TEMPERROR = "temperror"


class TrustTier(str, Enum):
    """Trust tier for key discovery (Section 5 of -01)."""
    DNSSEC_VERIFIED = "dnssec-verified"
    HTTPS_VERIFIED = "https-verified"
    DNS_UNSIGNED = "dns-unsigned"
    LOCAL = "local"


@dataclass
class UASIKeyRecord:
    """Parsed UASI DNS key record (Section 6.1)."""
    version: str  # "UASI1"
    algorithm: str  # "ed25519", "es256", etc.
    public_key_b64: str  # Base64-encoded public key
    flags: list[str] = field(default_factory=list)
    hash_algorithms: list[str] = field(default_factory=lambda: ["sha256"])
    expiry: Optional[int] = None  # Unix timestamp
    notes: Optional[str] = None

    @property
    def is_expired(self) -> bool:
        if self.expiry is None:
            return False
        return time.time() > self.expiry

    @property
    def is_testing(self) -> bool:
        return "y" in self.flags

    def to_dns_txt(self) -> str:
        """Serialize to DNS TXT record value."""
        parts = [f"v={self.version}", f"k={self.algorithm}", f"p={self.public_key_b64}"]
        if self.flags:
            parts.append(f"t={':'.join(self.flags)}")
        if self.hash_algorithms != ["sha256"]:
            parts.append(f"h={':'.join(self.hash_algorithms)}")
        if self.expiry is not None:
            parts.append(f"x={self.expiry}")
        if self.notes:
            parts.append(f"n={self.notes}")
        return "; ".join(parts)


@dataclass
class UASIPolicyRecord:
    """Parsed UASI DNS policy record (Section 6.2)."""
    version: str  # "UASI1"
    policy: PolicyMode
    report_aggregate_uri: Optional[str] = None
    report_forensic_uri: Optional[str] = None
    percentage: int = 100
    subdomain_policy: Optional[PolicyMode] = None
    bindings: Optional[list[str]] = None  # e.g., ["smtp", "http"]
    report_level: str = "s"  # "d", "s", or "f"
    minimum_trust: str = "https"  # "dnssec", "https", or "any" (mt= tag)
    dkim_alignment: Optional[str] = None  # "relaxed" or "strict" (da= tag)

    def to_dns_txt(self) -> str:
        """Serialize to DNS TXT record value."""
        parts = [f"v={self.version}", f"p={self.policy.value}"]
        if self.minimum_trust != "https":
            parts.append(f"mt={self.minimum_trust}")
        if self.dkim_alignment:
            parts.append(f"da={self.dkim_alignment}")
        if self.percentage != 100:
            parts.append(f"pct={self.percentage}")
        if self.report_aggregate_uri:
            parts.append(f"rua={self.report_aggregate_uri}")
        if self.report_forensic_uri:
            parts.append(f"ruf={self.report_forensic_uri}")
        if self.subdomain_policy:
            parts.append(f"sp={self.subdomain_policy.value}")
        if self.bindings:
            parts.append(f"b={':'.join(self.bindings)}")
        if self.report_level != "s":
            parts.append(f"rl={self.report_level}")
        return "; ".join(parts)


@dataclass
class UASISignature:
    """A parsed or constructed UASI-Signature (Section 7.1)."""
    version: int = 1
    algorithm: Algorithm = Algorithm.ED25519_SHA256
    domain: str = ""
    selector: str = ""
    timestamp: int = field(default_factory=lambda: int(time.time()))
    body_hash: str = ""  # Base64
    signature: str = ""  # Base64
    canonicalization: Canonicalization = Canonicalization.STRICT
    context: str = ""  # Protocol context tag (z=)
    expiry: Optional[int] = None
    signed_fields: list[str] = field(default_factory=list)
    nonce: Optional[str] = None
    query_method: str = "dns/txt"

    def generate_nonce(self) -> str:
        """Generate a UUIDv4 nonce."""
        self.nonce = str(uuid.uuid4())
        return self.nonce

    def serialize(self) -> str:
        """Serialize to UASI-Signature header value."""
        parts = [
            f"v={self.version}",
            f"a={self.algorithm.value}",
            f"d={self.domain}",
            f"s={self.selector}",
            f"t={self.timestamp}",
            f"z={self.context}",
            f"c={self.canonicalization.value}",
        ]
        if self.expiry is not None:
            parts.append(f"x={self.expiry}")
        if self.signed_fields:
            parts.append(f"h={':'.join(self.signed_fields)}")
        if self.nonce:
            parts.append(f"n={self.nonce}")
        parts.append(f"bh={self.body_hash}")
        parts.append(f"b={self.signature}")
        return "; ".join(parts)

    @classmethod
    def parse(cls, value: str) -> UASISignature:
        """Parse a UASI-Signature header value."""
        tags: dict[str, str] = {}
        for part in value.split(";"):
            part = part.strip()
            if "=" in part:
                key, val = part.split("=", 1)
                tags[key.strip()] = val.strip()

        sig = cls()
        sig.version = int(tags.get("v", "1"))
        sig.algorithm = Algorithm(tags["a"])
        sig.domain = tags["d"]
        sig.selector = tags["s"]
        sig.timestamp = int(tags["t"])
        sig.context = tags["z"]
        sig.canonicalization = Canonicalization(tags["c"])
        sig.body_hash = tags["bh"]
        sig.signature = tags["b"]
        sig.expiry = int(tags["x"]) if "x" in tags else None
        sig.signed_fields = tags["h"].split(":") if "h" in tags else []
        sig.nonce = tags.get("n")
        sig.query_method = tags.get("q", "dns/txt")
        return sig
