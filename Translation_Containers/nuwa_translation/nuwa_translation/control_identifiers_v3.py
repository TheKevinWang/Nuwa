"""Canonical, payload-scoped Nuwa control identifier profiles.

This source is generated into the payload builder package from the same file.
The registry in schema/control-identifiers-v3-default.json is the only editable
list of names and default values.
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping


MAX_CUSTOM_FILE_BYTES = 65_536
MAX_PROFILE_BYTES = 262_144
_IDENTIFIER = re.compile(r"[A-Za-z][A-Za-z0-9_-]{0,63}\Z", re.ASCII)
_BYTE_NAMESPACES = frozenset({"primitive_tags", "marker_bytes"})
_INDEX_NAMESPACES = frozenset({
    "local_slots", "crypto_slots", "socks_private_slots", "codec_private_slots",
    "response_private_slots", "diagnostic_positions",
})
_DEFAULT_PATH = Path(__file__).with_name("control_identifiers_v3_default.json")


@dataclass(frozen=True)
class ResolvedControlProfile:
    mode: str
    payload_uuid: str
    namespaces: Mapping[str, Mapping[str, int | str]]
    reverse_maps: Mapping[str, Mapping[int | str, str]]
    kind: str

def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for name, value in pairs:
        if name in result:
            raise ValueError(f"duplicate JSON name {name!r}")
        result[name] = value
    return result


def load_default_profile() -> dict[str, Any]:
    value = json.loads(_DEFAULT_PATH.read_text(encoding="utf-8"), object_pairs_hook=_unique_json_object)
    if type(value) is not dict or type(value.get("version")) is not int or value["version"] != 3:
        raise ValueError("Nuwa v3 default profile version is invalid")
    return value


def _range_for(namespace: str, name: str) -> tuple[int, int]:
    if namespace in _BYTE_NAMESPACES:
        return 0, 255
    if namespace == "diagnostic_header" and name == "version":
        return 1, 255
    if namespace in {"local_slots", "crypto_slots", "diagnostic_positions", "framing_modes"}:
        return 0, 65535
    return 1, 65535


def _check_value(namespace: str, name: str, value: Any) -> None:
    if type(value) is int:
        minimum, maximum = _range_for(namespace, name)
        if not minimum <= value <= maximum:
            raise ValueError(f"{namespace}.{name} must be an integer from {minimum} to {maximum}")
        return
    if namespace in _BYTE_NAMESPACES:
        raise ValueError(f"{namespace}.{name} must be an integer byte")
    if namespace == "diagnostic_positions":
        raise ValueError(f"{namespace}.{name} must be an integer array position")
    if type(value) is not str or _IDENTIFIER.fullmatch(value) is None:
        raise ValueError(f"{namespace}.{name} must be a short ASCII identifier or valid integer")


def validate_control_profile(profile: Mapping[str, Any], defaults: Mapping[str, Any] | None = None) -> None:
    source = defaults or load_default_profile()
    namespaces = profile.get("namespaces")
    expected = source["namespaces"]
    if type(namespaces) is not dict or set(namespaces) != set(expected):
        raise ValueError("profile namespaces must exactly match the Nuwa registry")
    for namespace, names in expected.items():
        selected = namespaces[namespace]
        if type(selected) is not dict or set(selected) != set(names):
            raise ValueError(f"{namespace} must contain every registered name")
        seen: set[str] = set()
        for name, value in selected.items():
            _check_value(namespace, name, value)
            normalized = str(value).casefold()
            if normalized in seen:
                raise ValueError(f"{namespace}.{name} duplicates another identifier")
            seen.add(normalized)
        if namespace in _INDEX_NAMESPACES and all(type(v) is int for v in selected.values()):
            if set(selected.values()) != set(names.values()):
                raise ValueError(f"{namespace} numeric slots must be a complete permutation")


class _HashStream:
    def __init__(self, payload_uuid: str, namespace: str):
        self.seed = f"Nuwa control identifiers v3\0{payload_uuid}\0{namespace}\0".encode("ascii")
        self.counter = 0

    def draw(self, minimum: int, maximum: int) -> int:
        span = maximum - minimum + 1
        ceiling = (1 << 32) - ((1 << 32) % span)
        while True:
            block = hashlib.sha256(self.seed + self.counter.to_bytes(8, "big")).digest()
            self.counter += 1
            for offset in range(0, 32, 4):
                number = int.from_bytes(block[offset:offset + 4], "big")
                if number < ceiling:
                    return minimum + number % span


def _randomize_namespace(payload_uuid: str, namespace: str, names: Mapping[str, int]) -> dict[str, int]:
    stream = _HashStream(payload_uuid, namespace)
    entries = list(names)
    if namespace in _INDEX_NAMESPACES:
        values = list(names.values())
        # Sattolo's cycle changes every position while preserving the legal set.
        for index in range(len(values) - 1, 0, -1):
            swap = stream.draw(0, index - 1)
            values[index], values[swap] = values[swap], values[index]
        return dict(zip(entries, values))
    used: set[int] = set()
    result: dict[str, int] = {}
    for name in entries:
        minimum, maximum = _range_for(namespace, name)
        while True:
            value = stream.draw(minimum, maximum)
            if value not in used and value != names[name]:
                used.add(value)
                result[name] = value
                break
    return result


def _compact_randomize_namespace(payload_uuid: str, namespace: str,
                                 names: Mapping[str, int]) -> dict[str, int]:
    if namespace in _INDEX_NAMESPACES:
        return _randomize_namespace(payload_uuid, namespace, names)
    entries = list(names)
    minimum = min(_range_for(namespace, name)[0] for name in entries)
    values = list(range(minimum, minimum + len(entries)))
    stream = _HashStream(payload_uuid, f"{namespace}\0compact")
    for _ in range(4096):
        candidate = values.copy()
        for index in range(len(candidate) - 1, 0, -1):
            swap = stream.draw(0, index)
            candidate[index], candidate[swap] = candidate[swap], candidate[index]
        if all(value != names[name] for name, value in zip(entries, candidate)):
            return dict(zip(entries, candidate))
    raise ValueError(f"could not assign compact Nuwa identifiers for {namespace}")


def _merge_custom(namespaces: dict[str, dict[str, int | str]], edits: Mapping[str, Any]) -> None:
    for namespace, overrides in edits.items():
        if namespace not in namespaces:
            raise ValueError(f"unknown Nuwa namespace {namespace}")
        if type(overrides) is not dict:
            raise ValueError(f"{namespace} must be an object")
        selected = namespaces[namespace]
        for name, value in overrides.items():
            if name not in selected:
                raise ValueError(f"{namespace}.{name} is not a registered identifier")
            _check_value(namespace, name, value)
        specified = set(overrides)
        override_values: set[str] = set()
        for name, value in overrides.items():
            normalized = str(value).casefold()
            if normalized in override_values:
                raise ValueError(f"{namespace}.{name} duplicates another override")
            override_values.add(normalized)
        for name, value in overrides.items():
            previous = selected[name]
            occupant = next((key for key, current in selected.items() if current == value and key != name), None)
            if occupant is not None and occupant not in specified:
                selected[occupant] = previous
            selected[name] = value


def resolve_control_profile(
    defaults: Mapping[str, Any], mode: str, payload_uuid: str,
    custom_file_bytes: bytes | None = None,
    *, random_style: str = "wide",
) -> ResolvedControlProfile:
    if mode not in {"default", "custom", "random"}:
        raise ValueError("control_id_mode must be default, custom, or random")
    try:
        canonical_uuid = str(uuid.UUID(payload_uuid))
    except (TypeError, ValueError, AttributeError) as exc:
        raise ValueError("payload UUID must be canonical") from exc
    if canonical_uuid != payload_uuid:
        raise ValueError("payload UUID must be canonical")
    if mode != "custom" and custom_file_bytes is not None:
        raise ValueError("control_id_file is only valid in custom mode")
    if type(defaults) is not dict or defaults.get("version") != 3:
        raise ValueError("Nuwa default profile version must be 3")
    namespaces = {name: dict(values) for name, values in defaults["namespaces"].items()}
    validate_control_profile({"namespaces": namespaces}, defaults)
    if mode == "custom":
        if not isinstance(custom_file_bytes, bytes):
            raise ValueError("control_id_file is required in custom mode")
        if len(custom_file_bytes) > MAX_CUSTOM_FILE_BYTES:
            raise ValueError(f"control_id_file exceeds {MAX_CUSTOM_FILE_BYTES} bytes")
        try:
            custom = json.loads(custom_file_bytes.decode("utf-8", errors="strict"), object_pairs_hook=_unique_json_object)
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise ValueError("control_id_file must contain valid UTF-8 JSON") from exc
        if type(custom) is not dict or set(custom) != {"version", "namespaces"} or type(custom["version"]) is not int or custom["version"] != 3:
            raise ValueError("control_id_file must contain version 3 and namespaces only")
        if type(custom["namespaces"]) is not dict:
            raise ValueError("control_id_file namespaces must be an object")
        _merge_custom(namespaces, custom["namespaces"])
    elif mode == "random":
        if random_style not in {"wide", "compact"}:
            raise ValueError("control_id_random_style must be compact or wide")
        randomizer = _compact_randomize_namespace if random_style == "compact" else _randomize_namespace
        namespaces = {
            name: randomizer(payload_uuid, name, values)
            for name, values in namespaces.items()
        }
    validate_control_profile({"namespaces": namespaces}, defaults)
    canonical = json.dumps({"version": 3, "namespaces": namespaces}, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode("ascii")
    if len(canonical) > MAX_PROFILE_BYTES:
        raise ValueError(f"expanded Nuwa control profile exceeds {MAX_PROFILE_BYTES} bytes")
    frozen = MappingProxyType({name: MappingProxyType(values) for name, values in namespaces.items()})
    reverse = MappingProxyType({
        name: MappingProxyType({value: key for key, value in values.items()})
        for name, values in namespaces.items()
    })
    return ResolvedControlProfile(mode, payload_uuid, frozen, reverse,
                                  "binary-v3" if mode != "default" else "legacy")
