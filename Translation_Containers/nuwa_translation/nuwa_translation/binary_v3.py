"""Canonical Nuwa v3 binary document with payload-selected tags and markers."""

from __future__ import annotations

import math
import re
import struct
from typing import Any

from .binary_v1 import MAX_DEPTH, MAX_DOCUMENT_BYTES, MAX_U64
from .binary_v2 import _uvarint
from .control_identifiers_v3 import ResolvedControlProfile


_KEY = re.compile(r"[A-Za-z][A-Za-z0-9_-]{0,63}\Z", re.ASCII)


def _key_sort(key: int | str) -> tuple[int, int | bytes]:
    if type(key) is int and 1 <= key <= 65535:
        return 0, key
    if type(key) is str and _KEY.fullmatch(key):
        return 1, key.encode("ascii")
    raise ValueError("binary v3 map key must be a field ID or short ASCII identifier")


def encode_binary_v3(record: dict[int | str, Any], profile: ResolvedControlProfile) -> bytes:
    if not isinstance(record, dict):
        raise ValueError("binary v3 root must be a map")
    tags = profile.namespaces["primitive_tags"]
    marker = profile.namespaces["marker_bytes"]
    out = bytearray((marker["first"], marker["second"]))

    def write(value: Any, depth: int) -> None:
        if depth > MAX_DEPTH:
            raise ValueError("binary v3 nesting exceeds 20")
        if value is None:
            out.append(tags["null"])
        elif value is False:
            out.append(tags["false"])
        elif value is True:
            out.append(tags["true"])
        elif type(value) is int:
            if value < -(1 << 63) or value > MAX_U64:
                raise ValueError("binary v3 integer exceeds 64-bit range")
            out.append(tags["negative_integer"] if value < 0 else tags["unsigned_integer"])
            out.extend(_uvarint((-value << 1) - 1 if value < 0 else value))
        elif type(value) is float:
            if not math.isfinite(value):
                raise ValueError("binary v3 forbids nonfinite floats")
            out.append(tags["float"])
            out.extend(struct.pack(">d", value))
        elif isinstance(value, str):
            raw = value.encode("utf-8", errors="strict")
            out.append(tags["text"])
            out.extend(_uvarint(len(raw)))
            out.extend(raw)
        elif isinstance(value, (bytes, bytearray, memoryview)):
            raw = bytes(value)
            out.append(tags["bytes"])
            out.extend(_uvarint(len(raw)))
            out.extend(raw)
        elif isinstance(value, (list, tuple)):
            out.append(tags["array"])
            out.extend(_uvarint(len(value)))
            for item in value:
                write(item, depth + 1)
        elif isinstance(value, dict):
            keys = sorted(value, key=_key_sort)
            out.append(tags["map"])
            out.extend(_uvarint(len(keys)))
            for key in keys:
                write(key, depth + 1)
                write(value[key], depth + 1)
        else:
            raise ValueError(f"binary v3 cannot encode {type(value).__name__}")
        if len(out) > MAX_DOCUMENT_BYTES:
            raise ValueError("binary v3 document exceeds 524288 bytes")

    write(record, 0)
    return bytes(out)


def decode_binary_v3(wire: bytes, profile: ResolvedControlProfile) -> dict[int | str, Any]:
    if not isinstance(wire, (bytes, bytearray, memoryview)):
        raise ValueError("binary v3 input must be bytes")
    data = bytes(wire)
    if len(data) > MAX_DOCUMENT_BYTES:
        raise ValueError("binary v3 document exceeds 524288 bytes")
    marker = profile.namespaces["marker_bytes"]
    if len(data) < 3 or data[:2] != bytes((marker["first"], marker["second"])):
        raise ValueError("binary v3 marker does not match payload profile")
    tags = profile.namespaces["primitive_tags"]
    reverse = {value: name for name, value in tags.items()}
    offset = 2

    def take(size: int) -> bytes:
        nonlocal offset
        if size < 0 or size > len(data) - offset:
            raise ValueError("truncated binary v3 document")
        value = data[offset:offset + size]
        offset += size
        return value

    def uvarint() -> int:
        result = 0
        for index in range(10):
            byte = take(1)[0]
            if index == 9 and byte > 1:
                raise ValueError("binary v3 varint overflows 64 bits")
            result |= (byte & 127) << (7 * index)
            if byte < 128:
                if len(_uvarint(result)) != index + 1:
                    raise ValueError("binary v3 varint is nonminimal")
                return result
        raise ValueError("binary v3 varint is too long")

    def read(depth: int) -> Any:
        if depth > MAX_DEPTH:
            raise ValueError("binary v3 nesting exceeds 20")
        kind = reverse.get(take(1)[0])
        if kind == "null":
            return None
        if kind == "false":
            return False
        if kind == "true":
            return True
        if kind == "negative_integer":
            encoded = uvarint()
            if not encoded & 1:
                raise ValueError("binary v3 negative integer is noncanonical")
            return -((encoded >> 1) + 1)
        if kind == "unsigned_integer":
            return uvarint()
        if kind == "float":
            value = struct.unpack(">d", take(8))[0]
            if not math.isfinite(value):
                raise ValueError("binary v3 forbids nonfinite floats")
            return value
        if kind in {"text", "bytes"}:
            raw = take(uvarint())
            return raw.decode("utf-8", errors="strict") if kind == "text" else raw
        if kind == "array":
            count = uvarint()
            if count > len(data) - offset:
                raise ValueError("binary v3 array count exceeds remaining bytes")
            return [read(depth + 1) for _ in range(count)]
        if kind == "map":
            count = uvarint()
            if count > (len(data) - offset) // 2:
                raise ValueError("binary v3 map count exceeds remaining bytes")
            result: dict[int | str, Any] = {}
            previous: tuple[int, int | bytes] | None = None
            for _ in range(count):
                key = read(depth + 1)
                sorted_key = _key_sort(key)
                if previous is not None and sorted_key <= previous:
                    raise ValueError("binary v3 map keys are duplicate or unsorted")
                result[key] = read(depth + 1)
                previous = sorted_key
            return result
        raise ValueError("unsupported binary v3 tag")

    decoded = read(0)
    if not isinstance(decoded, dict):
        raise ValueError("binary v3 root must be a map")
    if offset != len(data):
        raise ValueError("binary v3 document has trailing bytes")
    return decoded
