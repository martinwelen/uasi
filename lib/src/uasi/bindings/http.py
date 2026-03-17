"""HTTP protocol adapter for UASI (profiles RFC 9421).

In the -01 revision, the HTTP binding does NOT use UASI's custom
signature format. Instead it profiles RFC 9421 (HTTP Message Signatures)
with UASI-specific key discovery via the keyid parameter.

The keyid is set to the UASI identity (selector._uasi.domain) and the
verifier resolves it via DNS (DNSSEC preferred) or .well-known fallback.
"""

from __future__ import annotations

import base64
import hashlib
import time
import uuid
from typing import Optional
from urllib.parse import urlparse

from cryptography.exceptions import InvalidSignature

from ..keys import UASIKeyPair, load_public_key_from_b64
from ..models import TrustTier, UASISignature, VerificationResult
from ..verifier import UASIVerifier, VerificationDetail

# Headers that MUST NOT be signed (Section 8.2)
PROHIBITED_SIGNED_HEADERS = frozenset({
    "content-length", "transfer-encoding", "via", "x-forwarded-for",
    "x-forwarded-proto", "x-real-ip", "connection", "keep-alive",
    "proxy-authorization", "te", "trailer",
})

# Default covered components for webhook signing
DEFAULT_WEBHOOK_COMPONENTS = [
    "@method", "@authority", "@path", "content-type", "content-digest",
]

CONTEXT = "http"


def _compute_content_digest(body: bytes) -> str:
    """Compute Content-Digest header value per RFC 9530."""
    digest = hashlib.sha256(body).digest()
    return f"sha-256=:{base64.b64encode(digest).decode('ascii')}:"


def _build_signature_base(
    components: list[str],
    component_values: dict[str, str],
    params_str: str,
) -> str:
    """Build the signature base per RFC 9421 Section 2.5.

    Each line is: "<component-name>": <value>
    Final line is: "@signature-params": <params>
    """
    lines = []
    for name in components:
        value = component_values.get(name, "")
        lines.append(f'"{name}": {value}')
    lines.append(f'"@signature-params": {params_str}')
    return "\n".join(lines)


def _build_signature_params(
    components: list[str],
    keyid: str,
    created: int,
    nonce: Optional[str] = None,
    expires: Optional[int] = None,
) -> str:
    """Build the Signature-Input parameters string per RFC 9421.

    Format: (<components>);keyid="...";alg="ed25519";created=...;tag="uasi"
    """
    comp_list = " ".join(f'"{c}"' for c in components)
    params = f"({comp_list})"
    params += f';keyid="{keyid}"'
    params += ';alg="ed25519"'
    params += f";created={created}"
    if expires is not None:
        params += f";expires={expires}"
    if nonce is not None:
        params += f';nonce="{nonce}"'
    params += ';tag="uasi"'
    return params


def sign_http_request(
    key_pair: UASIKeyPair,
    method: str,
    target_uri: str,
    body: bytes,
    headers: Optional[dict[str, str]] = None,
    signed_fields: Optional[list[str]] = None,
    expiry_seconds: int = 300,
    use_nonce: bool = True,
) -> dict[str, str]:
    """
    Sign an HTTP request using RFC 9421 format with UASI key discovery.

    Returns a dict with 'signature-input', 'signature', and
    'content-digest' headers to add to the request.

    Args:
        key_pair: The UASI key pair to sign with.
        method: HTTP method (GET, POST, etc.).
        target_uri: Full request target URI.
        body: Raw request body bytes.
        headers: Dict of HTTP headers (lowercase keys recommended).
        signed_fields: Components to sign. Defaults to DEFAULT_WEBHOOK_COMPONENTS.
        expiry_seconds: Signature validity window (default: 300s / 5 min).
        use_nonce: Whether to include a nonce for replay detection.

    Returns:
        Dict with 'signature-input', 'signature', and 'content-digest' keys.

    Raises:
        ValueError: If a prohibited header is in signed_fields.
    """
    headers = headers or {}
    components = signed_fields or DEFAULT_WEBHOOK_COMPONENTS.copy()

    # Validate: no prohibited headers
    for field in components:
        if field.lower() in PROHIBITED_SIGNED_HEADERS:
            raise ValueError(
                f"Header {field!r} is prohibited from signing "
                f"(routinely modified by intermediaries)."
            )

    # Compute content-digest for body
    content_digest = _compute_content_digest(body) if body else None

    # Parse URI for derived components
    parsed = urlparse(target_uri)
    authority = parsed.netloc or headers.get("host", headers.get("Host", ""))
    path = parsed.path or "/"

    # Build component values
    component_values: dict[str, str] = {}
    component_values["@method"] = method.upper()
    component_values["@authority"] = authority
    component_values["@path"] = path
    if content_digest:
        component_values["content-digest"] = content_digest

    # Add actual headers
    for k, v in headers.items():
        component_values[k.lower()] = v

    # Filter out content-digest from components if no body
    if not body:
        components = [c for c in components if c != "content-digest"]

    now = int(time.time())
    expires = now + expiry_seconds if expiry_seconds else None
    nonce = str(uuid.uuid4()) if use_nonce else None

    # Build signature params
    keyid = key_pair.uid  # selector._uasi.domain
    params_str = _build_signature_params(
        components=components,
        keyid=keyid,
        created=now,
        nonce=nonce,
        expires=expires,
    )

    # Build signature base
    sig_base = _build_signature_base(components, component_values, params_str)

    # Sign with Ed25519
    raw_signature = key_pair.private_key.sign(sig_base.encode("utf-8"))
    sig_b64 = base64.b64encode(raw_signature).decode("ascii")

    result = {
        "signature-input": f"uasi={params_str}",
        "signature": f"uasi=:{sig_b64}:",
    }
    if content_digest:
        result["content-digest"] = content_digest

    return result


def verify_http_request(
    verifier: UASIVerifier,
    signature_input: str,
    signature: str,
    method: str,
    target_uri: str,
    body: bytes,
    headers: Optional[dict[str, str]] = None,
) -> VerificationDetail:
    """
    Verify an RFC 9421 UASI-profiled signature on an HTTP request.

    Args:
        verifier: A configured UASIVerifier instance (with keys registered).
        signature_input: The Signature-Input header value.
        signature: The Signature header value.
        method: HTTP method of the received request.
        target_uri: Full request target URI.
        body: Raw request body bytes.
        headers: Dict of HTTP headers from the received request.

    Returns:
        VerificationDetail with result code and reason.
    """
    headers = headers or {}

    try:
        # Parse signature-input: "uasi=(<components>);keyid=...;..."
        label, params_str = signature_input.split("=", 1)
        label = label.strip()
    except ValueError:
        return VerificationDetail(
            VerificationResult.PERMERROR,
            reason="Malformed Signature-Input header",
        )

    # Parse components list from params
    try:
        comp_start = params_str.index("(")
        comp_end = params_str.index(")")
        comp_raw = params_str[comp_start + 1:comp_end]
        components = [c.strip('"') for c in comp_raw.split() if c.strip('"')]
    except (ValueError, IndexError):
        return VerificationDetail(
            VerificationResult.PERMERROR,
            reason="Malformed component list in Signature-Input",
        )

    # Parse parameters after the component list
    params_after = params_str[comp_end + 1:]
    params: dict[str, str] = {}
    for part in params_after.split(";"):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            params[k.strip()] = v.strip().strip('"')

    keyid = params.get("keyid", "")
    alg = params.get("alg", "")
    tag = params.get("tag", "")
    created = params.get("created", "")
    expires = params.get("expires")
    nonce = params.get("nonce")

    # Validate tag
    if tag != "uasi":
        return VerificationDetail(
            VerificationResult.PERMERROR,
            reason=f"Unexpected tag: {tag!r}, expected 'uasi'",
        )

    # Validate algorithm
    if alg != "ed25519":
        return VerificationDetail(
            VerificationResult.PERMERROR,
            reason=f"Unsupported algorithm: {alg!r}",
        )

    # Check expiry
    now = time.time()
    if expires:
        try:
            if now > int(expires) + verifier.clock_skew_tolerance:
                return VerificationDetail(
                    VerificationResult.FAIL,
                    reason=f"Signature expired at {expires}",
                )
        except ValueError:
            pass

    # Parse keyid to get domain and selector
    # keyid format: selector._uasi.domain
    try:
        parts = keyid.split("._uasi.", 1)
        if len(parts) != 2:
            raise ValueError("Invalid keyid format")
        selector = parts[0]
        domain = parts[1]
    except (ValueError, IndexError):
        return VerificationDetail(
            VerificationResult.PERMERROR,
            reason=f"Cannot parse UASI identity from keyid: {keyid!r}",
        )

    # Look up key
    key_record = verifier._get_key_record(domain, selector)
    if key_record is None:
        return VerificationDetail(
            VerificationResult.NONE,
            reason=f"No key record found for {keyid}",
        )

    if key_record.is_expired:
        return VerificationDetail(
            VerificationResult.FAIL,
            reason="Key record has expired",
            key_record=key_record,
        )

    # Compute content-digest for body verification
    if body and "content-digest" in components:
        expected_digest = _compute_content_digest(body)
        # Check against what's in the component values
        # The content-digest in the signature base should match the body
        provided_digest = headers.get("content-digest", "")
        if not provided_digest:
            # Use computed digest as the component value
            provided_digest = expected_digest

    # Build component values for verification
    parsed = urlparse(target_uri)
    authority = parsed.netloc or headers.get("host", headers.get("Host", ""))
    path = parsed.path or "/"

    component_values: dict[str, str] = {}
    component_values["@method"] = method.upper()
    component_values["@authority"] = authority
    component_values["@path"] = path
    if body:
        component_values["content-digest"] = _compute_content_digest(body)
    for k, v in headers.items():
        component_values[k.lower()] = v

    # Rebuild signature base
    sig_base = _build_signature_base(components, component_values, params_str)

    # Parse the signature value: "uasi=:<base64>:"
    try:
        sig_label, sig_value = signature.split("=", 1)
        sig_b64 = sig_value.strip().strip(":")
    except ValueError:
        return VerificationDetail(
            VerificationResult.PERMERROR,
            reason="Malformed Signature header",
        )

    # Verify Ed25519 signature
    try:
        public_key = load_public_key_from_b64(key_record.public_key_b64)
        raw_sig = base64.b64decode(sig_b64)
        public_key.verify(raw_sig, sig_base.encode("utf-8"))
    except (InvalidSignature, Exception) as e:
        return VerificationDetail(
            VerificationResult.FAIL,
            reason=f"Signature verification failed: {e}",
            key_record=key_record,
        )

    # Nonce check for replay detection
    if nonce:
        nonce_expiry = float(expires) if expires else (now + 300)
        try:
            is_fresh = verifier.nonce_cache.check_and_store(
                domain, selector, nonce, nonce_expiry
            )
        except RuntimeError:
            return VerificationDetail(
                VerificationResult.TEMPERROR,
                reason="Nonce cache saturated (fail-closed)",
                key_record=key_record,
                trust_tier=TrustTier.LOCAL,
            )
        if not is_fresh:
            return VerificationDetail(
                VerificationResult.FAIL,
                reason=f"Replay detected: nonce {nonce!r} already seen",
                key_record=key_record,
                trust_tier=TrustTier.LOCAL,
            )

    # Policy lookup
    policy_record = verifier._get_policy_record(domain)

    return VerificationDetail(
        VerificationResult.PASS,
        reason="Signature verified successfully",
        key_record=key_record,
        policy_record=policy_record,
        trust_tier=TrustTier.LOCAL,  # Local key discovery
    )
