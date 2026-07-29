"""Decimal codec implementation for Nuwa."""

from __future__ import annotations


def encode_inner(message_bytes: bytes, context: dict) -> bytes:
    return "".join(f"{byte:03d}" for byte in bytes(message_bytes)).encode("ascii")


def decode_inner(message_bytes: bytes, context: dict) -> bytes:
    payload = bytes(message_bytes)
    if len(payload) % 3 != 0:
        raise ValueError("Decimal payload length must be divisible by 3")
    if any(byte < 48 or byte > 57 for byte in payload):
        raise ValueError("Decimal payload must contain only digits")

    decoded = bytearray()
    for index in range(0, len(payload), 3):
        group = payload[index : index + 3]
        value = int(group.decode("ascii"))
        if value < 0 or value > 255:
            raise ValueError("Decimal group must decode to a byte in 0..255")
        decoded.append(value)
    return bytes(decoded)
