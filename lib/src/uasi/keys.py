"""Key generation, loading, and DNS record management (Section 6)."""

from __future__ import annotations

import base64
import hashlib
import re
from dataclasses import dataclass
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from .models import UASIKeyRecord, UASIPolicyRecord, PolicyMode


@dataclass
class UASIKeyPair:
    """An Ed25519 key pair for UASI signing."""
    private_key: Ed25519PrivateKey
    public_key: Ed25519PublicKey
    selector: str
    domain: str

    @classmethod
    def generate(cls, selector: str, domain: str) -> UASIKeyPair:
        """Generate a new Ed25519 key pair."""
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        return cls(
            private_key=private_key,
            public_key=public_key,
            selector=selector,
            domain=domain,
        )

    @property
    def uid(self) -> str:
        """The UASI Identity (UID) DNS name."""
        return f"{self.selector}._uasi.{self.domain}"

    @property
    def public_key_b64(self) -> str:
        """Base64-encoded raw public key bytes."""
        raw = self.public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
        return base64.b64encode(raw).decode("ascii")

    @property
    def private_key_b64(self) -> str:
        """Base64-encoded raw private key bytes (for secure storage)."""
        raw = self.private_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        return base64.b64encode(raw).decode("ascii")

    def dns_key_record(
        self,
        expiry: Optional[int] = None,
        notes: Optional[str] = None,
        testing: bool = False,
    ) -> UASIKeyRecord:
        """Generate the DNS TXT key record for this key pair."""
        flags = []
        if testing:
            flags.append("y")
        return UASIKeyRecord(
            version="UASI1",
            algorithm="ed25519",
            public_key_b64=self.public_key_b64,
            flags=flags,
            expiry=expiry,
            notes=notes,
        )

    def dns_txt_value(self, **kwargs) -> str:
        """Generate the DNS TXT record value string."""
        return self.dns_key_record(**kwargs).to_dns_txt()

    def dns_zone_entry(self, ttl: int = 3600, **kwargs) -> str:
        """Generate a full DNS zone file entry."""
        txt = self.dns_txt_value(**kwargs)
        return f'{self.uid}. {ttl} IN TXT "{txt}"'

    @classmethod
    def from_private_key_b64(
        cls, private_key_b64: str, selector: str, domain: str
    ) -> UASIKeyPair:
        """Load a key pair from a base64-encoded private key."""
        raw = base64.b64decode(private_key_b64)
        private_key = Ed25519PrivateKey.from_private_bytes(raw)
        return cls(
            private_key=private_key,
            public_key=private_key.public_key(),
            selector=selector,
            domain=domain,
        )


def parse_key_record(txt_value: str) -> UASIKeyRecord:
    """Parse a DNS TXT record value into a UASIKeyRecord."""
    tags: dict[str, str] = {}
    for part in txt_value.split(";"):
        part = part.strip()
        if "=" in part:
            key, val = part.split("=", 1)
            tags[key.strip()] = val.strip()

    return UASIKeyRecord(
        version=tags.get("v", "UASI1"),
        algorithm=tags.get("k", "ed25519"),
        public_key_b64=tags.get("p", ""),
        flags=tags.get("t", "").split(":") if "t" in tags else [],
        hash_algorithms=tags.get("h", "sha256").split(":"),
        expiry=int(tags["x"]) if "x" in tags else None,
        notes=tags.get("n"),
    )


def parse_policy_record(txt_value: str) -> UASIPolicyRecord:
    """Parse a DNS TXT record value into a UASIPolicyRecord."""
    tags: dict[str, str] = {}
    for part in txt_value.split(";"):
        part = part.strip()
        if "=" in part:
            key, val = part.split("=", 1)
            tags[key.strip()] = val.strip()

    return UASIPolicyRecord(
        version=tags.get("v", "UASI1"),
        policy=PolicyMode(tags.get("p", "none")),
        report_aggregate_uri=tags.get("rua"),
        report_forensic_uri=tags.get("ruf"),
        percentage=int(tags.get("pct", "100")),
        subdomain_policy=PolicyMode(tags["sp"]) if "sp" in tags else None,
        bindings=tags["b"].split(":") if "b" in tags else None,
        report_level=tags.get("rl", "s"),
    )


def load_public_key_from_b64(key_b64: str) -> Ed25519PublicKey:
    """Load an Ed25519 public key from base64-encoded raw bytes."""
    raw = base64.b64decode(key_b64)
    return Ed25519PublicKey.from_public_bytes(raw)
