"""Canonical numeric-key agent message wire format.

The two-byte prefix separates v2 from all v1 documents. Values retain the
v1 primitive tags; tag 10 is a map with strictly increasing integer keys.
"""

from __future__ import annotations

import math
import struct
from typing import Any

from .binary_v1 import MAX_DEPTH, MAX_DOCUMENT_BYTES, MAX_U64


PREFIX = bytes((0xF2, 2))
MAP_TAG = 10
MAX_FIELD_ID = 65535


def _uvarint(value: int) -> bytes:
    if type(value) is not int or value < 0 or value > MAX_U64:
        raise ValueError("binary v2 unsigned integer is outside 64-bit range")
    output = bytearray()
    while value >= 128:
        output.append((value & 127) | 128)
        value >>= 7
    output.append(value)
    return bytes(output)


def encode_binary_v2(message: dict[int, Any]) -> bytes:
    if not isinstance(message, dict):
        raise ValueError("binary v2 root must be an integer-key map")
    output = bytearray(PREFIX)

    def write(value: Any, depth: int) -> None:
        if depth > MAX_DEPTH:
            raise ValueError("binary v2 nesting exceeds 20")
        if value is None:
            output.append(0)
        elif value is False:
            output.append(1)
        elif value is True:
            output.append(2)
        elif type(value) is int:
            if value < -(1 << 63) or value > MAX_U64:
                raise ValueError("binary v2 integer is outside supported range")
            if value < 0:
                output.append(3)
                output.extend(_uvarint((-value << 1) - 1))
            else:
                output.append(4)
                output.extend(_uvarint(value))
        elif isinstance(value, float):
            if not math.isfinite(value):
                raise ValueError("binary v2 forbids nonfinite floats")
            output.append(5)
            output.extend(struct.pack(">d", value))
        elif isinstance(value, str):
            encoded = value.encode("utf-8", errors="strict")
            output.append(6)
            output.extend(_uvarint(len(encoded)))
            output.extend(encoded)
        elif isinstance(value, (bytes, bytearray, memoryview)):
            encoded = bytes(value)
            output.append(7)
            output.extend(_uvarint(len(encoded)))
            output.extend(encoded)
        elif isinstance(value, (list, tuple)):
            output.append(8)
            output.extend(_uvarint(len(value)))
            for item in value:
                write(item, depth + 1)
        elif isinstance(value, dict):
            for key in value:
                if type(key) is not int or key < 1 or key > MAX_FIELD_ID:
                    raise ValueError("binary v2 map keys must be positive integer field IDs")
            output.append(MAP_TAG)
            output.extend(_uvarint(len(value)))
            for key in sorted(value):
                output.extend(_uvarint(key))
                write(value[key], depth + 1)
        else:
            raise ValueError(f"binary v2 cannot encode {type(value).__name__}")
        if len(output) > MAX_DOCUMENT_BYTES:
            raise ValueError("binary v2 document exceeds 524288 bytes")

    write(message, 0)
    return bytes(output)


def decode_binary_v2(wire: bytes) -> dict[int, Any]:
    if not isinstance(wire, (bytes, bytearray, memoryview)):
        raise ValueError("binary v2 input must be bytes")
    data = bytes(wire)
    if len(data) > MAX_DOCUMENT_BYTES:
        raise ValueError("binary v2 document exceeds 524288 bytes")
    if not data.startswith(PREFIX):
        raise ValueError("binary v2 version prefix is invalid")
    offset = len(PREFIX)

    def take(length: int) -> bytes:
        nonlocal offset
        if length < 0 or length > len(data) - offset:
            raise ValueError("truncated binary v2 document")
        result = data[offset:offset + length]
        offset += length
        return result

    def read_uvarint() -> int:
        result = 0
        for index in range(10):
            current = take(1)[0]
            if index == 9 and current > 1:
                raise ValueError("binary v2 varint overflows 64 bits")
            result |= (current & 127) << (7 * index)
            if current < 128:
                if len(_uvarint(result)) != index + 1:
                    raise ValueError("binary v2 varint is nonminimal")
                return result
        raise ValueError("binary v2 varint is too long")

    def read(depth: int) -> Any:
        if depth > MAX_DEPTH:
            raise ValueError("binary v2 nesting exceeds 20")
        tag = take(1)[0]
        if tag == 0:
            return None
        if tag == 1:
            return False
        if tag == 2:
            return True
        if tag == 3:
            encoded = read_uvarint()
            if not encoded & 1:
                raise ValueError("binary v2 negative integer is noncanonical")
            return -((encoded >> 1) + 1)
        if tag == 4:
            return read_uvarint()
        if tag == 5:
            value = struct.unpack(">d", take(8))[0]
            if not math.isfinite(value):
                raise ValueError("binary v2 forbids nonfinite floats")
            return value
        if tag in (6, 7):
            raw = take(read_uvarint())
            return raw.decode("utf-8", errors="strict") if tag == 6 else raw
        if tag == 8:
            count = read_uvarint()
            if count > len(data) - offset:
                raise ValueError("binary v2 array count exceeds remaining bytes")
            return [read(depth + 1) for _ in range(count)]
        if tag == MAP_TAG:
            count = read_uvarint()
            if count > (len(data) - offset) // 2:
                raise ValueError("binary v2 map count exceeds remaining bytes")
            result: dict[int, Any] = {}
            previous_key = 0
            for _ in range(count):
                key = read_uvarint()
                if key < 1 or key > MAX_FIELD_ID or key <= previous_key:
                    raise ValueError("binary v2 map keys are invalid, duplicated, or unsorted")
                result[key] = read(depth + 1)
                previous_key = key
            return result
        raise ValueError(f"unsupported binary v2 tag {tag:02x}")

    decoded = read(0)
    if not isinstance(decoded, dict):
        raise ValueError("binary v2 root must be an integer-key map")
    if offset != len(data):
        raise ValueError("binary v2 document has trailing bytes")
    return decoded
