"""UASI message signing (Section 7)."""

from __future__ import annotations

import base64
import hashlib
import time
from typing import Optional

from .canonical import build_signing_input, canonicalize_body
from .keys import UASIKeyPair
from .models import Algorithm, Canonicalization, UASISignature


class UASISigner:
    """Signs messages with UASI-Signature headers.

    Usage:
        key_pair = UASIKeyPair.generate("webhooks", "example.com")
        signer = UASISigner(key_pair)
        signature = signer.sign(
            body=b'{"order": 123}',
            context="http",
            fields={"content-type": "application/json", "@method": "POST"},
            signed_fields=["@method", "content-type"],
        )
        header_value = signature.serialize()
    """

    def __init__(
        self,
        key_pair: UASIKeyPair,
        algorithm: Algorithm = Algorithm.ED25519_SHA256,
        canonicalization: Canonicalization = Canonicalization.STRICT,
        default_expiry_seconds: Optional[int] = 300,
        use_nonce: bool = True,
    ):
        self.key_pair = key_pair
        self.algorithm = algorithm
        self.canonicalization = canonicalization
        self.default_expiry_seconds = default_expiry_seconds
        self.use_nonce = use_nonce

    def sign(
        self,
        body: bytes,
        context: str,
        fields: Optional[dict[str, str]] = None,
        signed_fields: Optional[list[str]] = None,
        expiry_seconds: Optional[int] = None,
        nonce: Optional[str] = None,
    ) -> UASISignature:
        """
        Sign a message body and metadata fields.

        Args:
            body: Raw message body bytes.
            context: Protocol context tag (e.g., "http", "smtp", "mqtt5").
            fields: Dict of field_name -> field_value for all available
                    headers/metadata.
            signed_fields: List of field names to include in signature.
                          Order matters — signing input is built in this order.
            expiry_seconds: Signature validity window in seconds.
                           Overrides default_expiry_seconds. None = no expiry.
            nonce: Explicit nonce value. If None and use_nonce is True,
                   a UUIDv4 is generated automatically.

        Returns:
            A populated UASISignature object. Call .serialize() to get the
            header value string.
        """
        fields = fields or {}
        signed_fields = signed_fields or []
        now = int(time.time())

        exp_seconds = expiry_seconds if expiry_seconds is not None else self.default_expiry_seconds
        expiry = (now + exp_seconds) if exp_seconds else None

        # Compute body hash
        canon_body = canonicalize_body(body, self.canonicalization)
        body_hash = base64.b64encode(hashlib.sha256(canon_body).digest()).decode("ascii")

        # Build the signature object (without b= value yet)
        sig = UASISignature(
            version=1,
            algorithm=self.algorithm,
            domain=self.key_pair.domain,
            selector=self.key_pair.selector,
            timestamp=now,
            body_hash=body_hash,
            signature="",  # Placeholder
            canonicalization=self.canonicalization,
            context=context,
            expiry=expiry,
            signed_fields=signed_fields,
        )

        # Handle nonce
        if nonce:
            sig.nonce = nonce
        elif self.use_nonce:
            sig.generate_nonce()

        # Build the signature template (b= empty for signing input)
        sig_template = sig.serialize()  # Has b= at the end (empty)

        # Build canonical signing input
        signing_input = build_signing_input(
            fields=fields,
            signed_field_names=signed_fields,
            context=context,
            body_hash=body_hash,
            signature_value_template=sig_template,
            mode=self.canonicalization,
            nonce=sig.nonce,
        )

        # Sign
        raw_signature = self.key_pair.private_key.sign(signing_input)
        sig.signature = base64.b64encode(raw_signature).decode("ascii")

        return sig
