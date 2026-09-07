"""Canonical RFC 4648 Base64 codec implementation for Nuwa."""

from __future__ import annotations

import base64
import binascii


def encode_inner(message_bytes: bytes, context: dict) -> bytes:
    """Encode bytes as canonical padded Base64 ASCII."""
    return base64.b64encode(bytes(message_bytes))


def decode_inner(message_bytes: bytes, context: dict) -> bytes:
    """Strictly decode canonical padded Base64 ASCII."""
    payload = bytes(message_bytes)
    try:
        decoded = base64.b64decode(payload, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("Base64 payload is not valid canonical Base64") from exc
    if base64.b64encode(decoded) != payload:
        raise ValueError("Base64 payload is not canonical")
    return decoded
