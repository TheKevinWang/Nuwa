"""Ranked base-16 emoji codec implementation for Nuwa."""

from __future__ import annotations


EMOJI_ALPHABET: tuple[str, ...] = (
    "😁",
    "😂",
    "😅",
    "😳",
    "🥺",
    "🙄",
    "🤗",
    "😫",
    "🥰",
    "😏",
    "🤭",
    "😉",
    "😃",
    "😨",
    "😰",
    "🤑",
)

_EMOJI_NIBBLES = {token: nibble for nibble, token in enumerate(EMOJI_ALPHABET)}


def encode_inner(message_bytes: bytes, context: dict) -> bytes:
    """Encode each byte as its high and low ranked emoji nibbles."""
    return "".join(
        EMOJI_ALPHABET[byte >> 4] + EMOJI_ALPHABET[byte & 0x0F]
        for byte in bytes(message_bytes)
    ).encode("utf-8")


def decode_inner(message_bytes: bytes, context: dict) -> bytes:
    """Strictly decode canonical UTF-8 emoji nibbles into bytes."""
    payload = bytes(message_bytes).decode("utf-8", errors="strict")
    nibbles: list[int] = []
    cursor = 0

    while cursor < len(payload):
        for token, nibble in _EMOJI_NIBBLES.items():
            if payload.startswith(token, cursor):
                nibbles.append(nibble)
                cursor += len(token)
                break
        else:
            raise ValueError("Emoji payload contains a noncanonical token")

    if len(nibbles) % 2 != 0:
        raise ValueError("Emoji payload must contain an even number of tokens")

    return bytes(
        (nibbles[index] << 4) | nibbles[index + 1]
        for index in range(0, len(nibbles), 2)
    )
