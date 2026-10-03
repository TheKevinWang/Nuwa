"""Translate named Mythic messages through an explicit Nuwa v3 profile."""

from __future__ import annotations

import json
from typing import Any

from .control_identifiers_v3 import ResolvedControlProfile
from .diagnostics import expand_agent_output_v3


ENUM_FIELDS = {"action": "actions", "command": "commands", "status": "statuses"}
HOST_FIELDS = {"os", "architecture", "user", "host"}


def _parameters_to_agent(value: Any, profile: ResolvedControlProfile) -> dict[int | str, Any]:
    if not isinstance(value, str):
        raise ValueError("task parameters must be text")
    names = profile.namespaces["parameter_fields"]
    if not value.lstrip().startswith("{"):
        return {names["raw_text"]: value}
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError as exc:
        raise ValueError("task parameters are invalid JSON") from exc
    if not isinstance(parsed, dict) or any(
        not isinstance(key, str) or key not in names or key == "raw_text"
        or isinstance(item, (dict, list)) for key, item in parsed.items()
    ):
        raise ValueError("task parameters contain an unknown or nested field")
    actions = profile.namespaces["socks_actions"]
    return {
        names[key]: actions.get(item, item) if key == "action" and isinstance(item, str) else item
        for key, item in parsed.items()
    }


def _parameters_from_agent(value: Any, profile: ResolvedControlProfile) -> str:
    if not isinstance(value, dict):
        raise ValueError("v3 task parameters must be a map")
    names = profile.reverse_maps["parameter_fields"]
    if any(key not in names for key in value):
        raise ValueError("v3 task parameters contain an unknown field")
    raw = profile.namespaces["parameter_fields"]["raw_text"]
    if raw in value:
        if len(value) != 1 or not isinstance(value[raw], str):
            raise ValueError("v3 raw task parameters are invalid")
        return value[raw]
    actions = profile.reverse_maps["socks_actions"]
    return json.dumps({
        names[key]: actions.get(item, item) if names[key] == "action" else item
        for key, item in value.items()
    }, separators=(",", ":"), ensure_ascii=False)


def _encode_field(field: str, value: Any, profile: ResolvedControlProfile) -> Any:
    if field == "parameters":
        return _parameters_to_agent(value, profile)
    if field in ENUM_FIELDS:
        mapping = profile.namespaces[ENUM_FIELDS[field]]
        if not isinstance(value, str) or value not in mapping:
            raise ValueError(f"unknown {field} value")
        return mapping[value]
    if field in HOST_FIELDS:
        if not isinstance(value, str):
            raise ValueError(f"{field} must be host text")
        return profile.namespaces["host_values"].get(value, value)
    return _encode(value, profile)


def _decode_field(field: str, value: Any, profile: ResolvedControlProfile) -> Any:
    if field == "parameters":
        return _parameters_from_agent(value, profile)
    if field == "user_output":
        return expand_agent_output_v3(value, profile)
    if field == "sleep_info" and isinstance(value, dict):
        fields = profile.namespaces["fields"]
        expected = {fields["interval"], fields["jitter"], fields["c2_profile"]}
        if set(value) != expected:
            raise ValueError("v3 sleep info has invalid fields")
        interval, jitter = value[fields["interval"]], value[fields["jitter"]]
        code = value[fields["c2_profile"]]
        if type(interval) is not int or interval < 0 or type(jitter) is not int or jitter < 0:
            raise ValueError("v3 sleep info has invalid timing")
        if code not in profile.reverse_maps["profiles"]:
            raise ValueError("v3 sleep info has invalid profile")
        return json.dumps({profile.reverse_maps["profiles"][code]: {
            "interval": interval, "jitter": jitter,
        }}, separators=(",", ":"))
    if field in ENUM_FIELDS:
        reverse = profile.reverse_maps[ENUM_FIELDS[field]]
        if value not in reverse:
            raise ValueError(f"unknown v3 {field} value")
        return reverse[value]
    if field in HOST_FIELDS:
        if value in profile.reverse_maps["host_values"]:
            return profile.reverse_maps["host_values"][value]
        if not isinstance(value, str):
            raise ValueError(f"{field} must be host text or a known code")
        return value
    return _decode(value, profile)


def _encode(value: Any, profile: ResolvedControlProfile) -> Any:
    if isinstance(value, dict):
        ids = profile.namespaces["fields"]
        result: dict[int | str, Any] = {}
        for name, item in value.items():
            if not isinstance(name, str) or name not in ids:
                raise ValueError(f"unknown Mythic field {name!r}")
            result[ids[name]] = _encode_field(name, item, profile)
        return result
    if isinstance(value, list):
        return [_encode(item, profile) for item in value]
    return value


def _decode(value: Any, profile: ResolvedControlProfile) -> Any:
    if isinstance(value, dict):
        names = profile.reverse_maps["fields"]
        result: dict[str, Any] = {}
        for key, item in value.items():
            if key not in names:
                raise ValueError(f"unknown v3 agent field {key!r}")
            field = names[key]
            result[field] = _decode_field(field, item, profile)
        return result
    if isinstance(value, list):
        return [_decode(item, profile) for item in value]
    return value


def to_agent_record(message: dict[str, Any], profile: ResolvedControlProfile) -> dict[int | str, Any]:
    if not isinstance(message, dict):
        raise ValueError("Mythic message must be a map")
    return _encode(message, profile)


def from_agent_record(record: dict[int | str, Any], profile: ResolvedControlProfile) -> dict[str, Any]:
    if not isinstance(record, dict):
        raise ValueError("v3 agent message must be a map")
    return _decode(record, profile)
