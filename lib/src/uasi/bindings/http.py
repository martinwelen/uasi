"""HTTP protocol binding for UASI (Section 8.2).

Provides helpers for signing and verifying HTTP requests — the most
common UASI use case (webhook delivery, API callbacks).
"""

from __future__ import annotations

from typing import Optional

from ..keys import UASIKeyPair
from ..models import Algorithm, Canonicalization, UASISignature
from ..signer import UASISigner
from ..verifier import UASIVerifier, VerificationDetail

# Headers that MUST NOT be signed (Section 8.2)
PROHIBITED_SIGNED_HEADERS = frozenset({
    "content-length", "transfer-encoding", "via", "x-forwarded-for",
    "x-forwarded-proto", "x-real-ip", "connection", "keep-alive",
    "proxy-authorization", "te", "trailer",
})

# Default headers to sign for webhooks
DEFAULT_WEBHOOK_SIGNED_FIELDS = [
    "@method", "@target-uri", "x-request-id",
]

CONTEXT = "http"


def sign_http_request(
    key_pair: UASIKeyPair,
    method: str,
    target_uri: str,
    body: bytes,
    headers: Optional[dict[str, str]] = None,
    signed_fields: Optional[list[str]] = None,
    expiry_seconds: int = 300,
    use_nonce: bool = True,
) -> str:
    """
    Sign an HTTP request and return the UASI-Signature header value.

    This is the primary convenience function for webhook senders.

    Args:
        key_pair: The UASI key pair to sign with.
        method: HTTP method (GET, POST, etc.).
        target_uri: Full request target URI.
        body: Raw request body bytes.
        headers: Dict of HTTP headers (lowercase keys recommended).
        signed_fields: Fields to sign. Defaults to DEFAULT_WEBHOOK_SIGNED_FIELDS.
                      Pseudo-fields: @method, @target-uri, @authority.
        expiry_seconds: Signature validity window (default: 300s / 5 min).
        use_nonce: Whether to include a nonce for replay detection.

    Returns:
        The UASI-Signature header value string.

    Raises:
        ValueError: If a prohibited header is in signed_fields.
    """
    headers = headers or {}
    signed_fields = signed_fields or DEFAULT_WEBHOOK_SIGNED_FIELDS.copy()

    # Validate: no prohibited headers
    for field in signed_fields:
        if field.lower() in PROHIBITED_SIGNED_HEADERS:
            raise ValueError(
                f"Header {field!r} MUST NOT be signed (routinely modified by intermediaries). "
                f"See UASI Section 8.2."
            )

    # Build the fields dict with pseudo-fields
    all_fields: dict[str, str] = {}
    all_fields["@method"] = method.upper()
    all_fields["@target-uri"] = target_uri
    # Extract authority from headers
    authority = headers.get("host", headers.get("Host", ""))
    all_fields["@authority"] = authority
    # Add all headers (lowercase keys)
    for k, v in headers.items():
        all_fields[k.lower()] = v

    signer = UASISigner(
        key_pair=key_pair,
        canonicalization=Canonicalization.STRICT,
        default_expiry_seconds=expiry_seconds,
        use_nonce=use_nonce,
    )

    sig = signer.sign(
        body=body,
        context=CONTEXT,
        fields=all_fields,
        signed_fields=signed_fields,
    )

    return sig.serialize()


def verify_http_request(
    verifier: UASIVerifier,
    signature_header: str,
    method: str,
    target_uri: str,
    body: bytes,
    headers: Optional[dict[str, str]] = None,
) -> VerificationDetail:
    """
    Verify a UASI-Signature on an HTTP request.

    This is the primary convenience function for webhook receivers.

    Args:
        verifier: A configured UASIVerifier instance.
        signature_header: The UASI-Signature header value.
        method: HTTP method of the received request.
        target_uri: Full request target URI.
        body: Raw request body bytes.
        headers: Dict of HTTP headers from the received request.

    Returns:
        VerificationDetail with result code and reason.
    """
    headers = headers or {}

    # Build fields dict with pseudo-fields
    all_fields: dict[str, str] = {}
    all_fields["@method"] = method.upper()
    all_fields["@target-uri"] = target_uri
    authority = headers.get("host", headers.get("Host", ""))
    all_fields["@authority"] = authority
    for k, v in headers.items():
        all_fields[k.lower()] = v

    return verifier.verify(
        signature_header=signature_header,
        body=body,
        context=CONTEXT,
        fields=all_fields,
    )
