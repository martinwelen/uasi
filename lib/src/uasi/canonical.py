"""Canonicalization algorithms for UASI signatures (Section 7.2)."""

from __future__ import annotations

import re
from typing import Optional

from .models import Canonicalization


def canonicalize_field_name(name: str, mode: Canonicalization) -> str:
    """Canonicalize a header/metadata field name."""
    if mode == Canonicalization.SIMPLE:
        return name
    # Relaxed and Strict: lowercase
    return name.lower()


def canonicalize_field_value(value: str, mode: Canonicalization) -> str:
    """Canonicalize a header/metadata field value."""
    if mode == Canonicalization.SIMPLE:
        return value
    # Relaxed and Strict: strip + collapse whitespace
    value = value.strip()
    value = re.sub(r"\s+", " ", value)
    return value


def canonicalize_body(body: bytes, mode: Canonicalization) -> bytes:
    """Canonicalize a message body."""
    if mode == Canonicalization.SIMPLE:
        return body
    if mode == Canonicalization.STRICT:
        # Strict: exact bytes after transfer-encoding removal
        return body
    # Relaxed: strip trailing empty lines, normalize CRLF
    text = body.decode("utf-8", errors="replace")
    text = text.rstrip("\r\n")
    lines = text.split("\n")
    normalized = "\r\n".join(line.rstrip("\r") for line in lines)
    if normalized:
        normalized += "\r\n"
    return normalized.encode("utf-8")


def build_signing_input(
    fields: dict[str, str],
    signed_field_names: list[str],
    context: str,
    body_hash: str,
    signature_value_template: str,
    mode: Canonicalization,
    nonce: Optional[str] = None,
) -> bytes:
    """
    Construct the canonical signing input per Section 7.3.

    Args:
        fields: Dict of field_name -> field_value (all available fields).
        signed_field_names: Ordered list of field names from h= tag.
        context: Protocol context tag (z= value).
        body_hash: Base64-encoded body hash (bh= value).
        signature_value_template: The full UASI-Signature value with b= empty.
        mode: Canonicalization mode.
        nonce: Optional nonce value (n= tag).

    Returns:
        The bytes to be signed.
    """
    parts: list[str] = []

    # Step 1: Signed fields in order
    for field_name in signed_field_names:
        canon_name = canonicalize_field_name(field_name, mode)
        raw_value = fields.get(field_name, fields.get(field_name.lower(), ""))

        # Strict mode: absent field → empty value
        if mode == Canonicalization.STRICT and field_name not in fields and field_name.lower() not in fields:
            raw_value = ""

        canon_value = canonicalize_field_value(raw_value, mode)
        parts.append(f"{canon_name}: {canon_value}\r\n")

    # Step 2: Protocol context
    parts.append(f"z: {context}\r\n")

    # Step 3: Nonce (if present)
    if nonce:
        parts.append(f"n: {nonce}\r\n")

    # Step 4: Body hash
    parts.append(f"bh: {body_hash}\r\n")

    # Step 5: Signature field itself (with b= empty)
    canon_sig = canonicalize_field_value(signature_value_template, mode)
    parts.append(canon_sig)

    return "".join(parts).encode("utf-8")
