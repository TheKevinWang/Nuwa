"""Identity codec for Nuwa's compact UTF-8 JSON messages."""

from __future__ import annotations


def encode_inner(message_bytes: bytes, context: dict) -> bytes:
    """Return the message bytes without an inner presentation transform."""
    return bytes(message_bytes)


def decode_inner(message_bytes: bytes, context: dict) -> bytes:
    """Return the wire bytes without an inner presentation transform."""
    return bytes(message_bytes)
