"""Strict, canonical Nuwa inner binary v1 values.

The root is a map. Map ordering and integer encodings are canonical so the
same logical message has exactly one representation in every runtime.
"""

from __future__ import annotations

import math
import struct
from typing import Any


MAX_DOCUMENT_BYTES = 524_288
MAX_DEPTH = 20
MAX_U64 = (1 << 64) - 1


def _uvarint(value: int) -> bytes:
    if value < 0 or value > MAX_U64:
        raise ValueError("binary v1 integer is outside unsigned 64-bit range")
    result = bytearray()
    while value >= 0x80:
        result.append((value & 0x7F) | 0x80)
        value >>= 7
    result.append(value)
    return bytes(result)


def _validate_socks(message: dict[str, Any]) -> None:
    records = message.get("socks")
    has_records = isinstance(records, list) and bool(records)
    has_id = "socks_batch_id" in message
    if "socks" in message and not has_records:
        raise ValueError("socks must be a nonempty array")
    if has_records != has_id:
        raise ValueError("socks_batch_id requires a nonempty socks array")
    if has_id:
        batch_id = message["socks_batch_id"]
        if not isinstance(batch_id, bytes) or len(batch_id) != 16:
            raise ValueError("socks_batch_id must be exactly 16 raw bytes")
        for record in records:
            if not isinstance(record, dict):
                raise ValueError("socks records must be maps")
            if "data" in record and not isinstance(record["data"], bytes):
                raise ValueError("socks data must be raw bytes")
    if "socks_ack" in message:
        acknowledgments = message["socks_ack"]
        if not isinstance(acknowledgments, list) or not acknowledgments:
            raise ValueError("socks_ack must be a nonempty array")
        if any(not isinstance(item, bytes) or len(item) != 16 for item in acknowledgments):
            raise ValueError("each socks_ack entry must be exactly 16 raw bytes")


def encode_binary_v1(message: dict[str, Any]) -> bytes:
    if not isinstance(message, dict):
        raise ValueError("binary v1 root must be a map")
    _validate_socks(message)
    output = bytearray()

    def write(value: Any, depth: int) -> None:
        if depth > MAX_DEPTH:
            raise ValueError("binary v1 nesting exceeds 20")
        if value is None:
            output.append(0)
        elif value is False:
            output.append(1)
        elif value is True:
            output.append(2)
        elif isinstance(value, int):
            if value < 0:
                if value < -(1 << 63):
                    raise ValueError("binary v1 negative integer is outside signed 64-bit range")
                output.append(3)
                output.extend(_uvarint((-value << 1) - 1))
            else:
                output.append(4)
                output.extend(_uvarint(value))
        elif isinstance(value, float):
            if not math.isfinite(value):
                raise ValueError("binary v1 forbids nonfinite floats")
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
            keys = []
            for key in value:
                if not isinstance(key, str):
                    raise ValueError("binary v1 map keys must be strings")
                keys.append((key.encode("utf-8", errors="strict"), key))
            keys.sort(key=lambda pair: pair[0])
            output.append(9)
            output.extend(_uvarint(len(keys)))
            for encoded, key in keys:
                output.extend(_uvarint(len(encoded)))
                output.extend(encoded)
                write(value[key], depth + 1)
        else:
            raise ValueError(f"binary v1 cannot encode {type(value).__name__}")
        if len(output) > MAX_DOCUMENT_BYTES:
            raise ValueError("binary v1 document exceeds 524288 bytes")

    write(message, 0)
    return bytes(output)


def decode_binary_v1(wire: bytes) -> dict[str, Any]:
    if not isinstance(wire, (bytes, bytearray, memoryview)):
        raise ValueError("binary v1 input must be bytes")
    data = bytes(wire)
    if len(data) > MAX_DOCUMENT_BYTES:
        raise ValueError("binary v1 document exceeds 524288 bytes")
    offset = 0

    def take(length: int) -> bytes:
        nonlocal offset
        if length < 0 or length > len(data) - offset:
            raise ValueError("truncated binary v1 document")
        result = data[offset : offset + length]
        offset += length
        return result

    def read_length() -> int:
        nonlocal offset
        result = 0
        for index in range(10):
            current = take(1)[0]
            if index == 9 and current > 1:
                raise ValueError("binary v1 varint overflows 64 bits")
            result |= (current & 0x7F) << (7 * index)
            if current < 0x80:
                if len(_uvarint(result)) != index + 1:
                    raise ValueError("binary v1 varint is nonminimal")
                return result
        raise ValueError("binary v1 varint is too long")

    def read(depth: int) -> Any:
        if depth > MAX_DEPTH:
            raise ValueError("binary v1 nesting exceeds 20")
        tag = take(1)[0]
        if tag == 0:
            return None
        if tag == 1:
            return False
        if tag == 2:
            return True
        if tag == 3:
            encoded = read_length()
            if not encoded & 1:
                raise ValueError("binary v1 negative integer is noncanonical")
            return -((encoded >> 1) + 1)
        if tag == 4:
            return read_length()
        if tag == 5:
            value = struct.unpack(">d", take(8))[0]
            if not math.isfinite(value):
                raise ValueError("binary v1 forbids nonfinite floats")
            return value
        if tag in (6, 7):
            raw = take(read_length())
            return raw.decode("utf-8", errors="strict") if tag == 6 else raw
        if tag == 8:
            count = read_length()
            if count > len(data) - offset:
                raise ValueError("binary v1 array count exceeds remaining bytes")
            return [read(depth + 1) for _ in range(count)]
        if tag == 9:
            count = read_length()
            if count > (len(data) - offset) // 2:
                raise ValueError("binary v1 map count exceeds remaining bytes")
            result: dict[str, Any] = {}
            previous_key: bytes | None = None
            for _ in range(count):
                encoded_key = take(read_length())
                if previous_key is not None and encoded_key <= previous_key:
                    raise ValueError("binary v1 map keys are duplicated or unsorted")
                previous_key = encoded_key
                key = encoded_key.decode("utf-8", errors="strict")
                result[key] = read(depth + 1)
            return result
        raise ValueError(f"unsupported binary v1 tag {tag:02x}")

    decoded = read(0)
    if not isinstance(decoded, dict):
        raise ValueError("binary v1 root must be a map")
    if offset != len(data):
        raise ValueError("binary v1 document has trailing bytes")
    _validate_socks(decoded)
    return decoded
