"""Map numeric agent records to the Mythic message vocabulary at the host boundary."""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

from .diagnostics import expand_agent_output


SCHEMA_PATH = Path(__file__).with_name("agent_message_schema_v2.json")
ENUM_FIELDS = {"action": "actions", "command": "commands", "status": "statuses"}
HOST_FIELDS = {"os", "architecture", "user", "host"}


def _encode_task_parameters(value: Any) -> dict[int, Any]:
    if not isinstance(value, str):
        raise ValueError("task parameters must be text")
    names = load_schema()["parameter_fields"]
    if not value.lstrip().startswith("{"):
        return {names["raw_text"]: value}
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError as exc:
        raise ValueError("task parameters are invalid JSON") from exc
    if not isinstance(parsed, dict):
        raise ValueError("task parameters must be an object")
    if any(not isinstance(key, str) or key not in names or key == "raw_text" for key in parsed):
        raise ValueError("task parameters contain an unknown field")
    if any(isinstance(item, (dict, list)) for item in parsed.values()):
        raise ValueError("task parameters must contain scalar values")
    actions = load_schema()["socks_actions"]
    return {
        names[key]: actions.get(item, item) if key == "action" and isinstance(item, str) else item
        for key, item in parsed.items()
    }


def _decode_task_parameters(value: Any) -> str:
    if not isinstance(value, dict):
        raise ValueError("numeric task parameters must be a map")
    names = _reverse("parameter_fields")
    if any(type(key) is not int or key not in names for key in value):
        raise ValueError("numeric task parameters contain an unknown field")
    if load_schema()["parameter_fields"]["raw_text"] in value:
        if len(value) != 1 or not isinstance(value[load_schema()["parameter_fields"]["raw_text"]], str):
            raise ValueError("numeric raw task parameters are invalid")
        return value[load_schema()["parameter_fields"]["raw_text"]]
    actions = _reverse("socks_actions")
    return json.dumps({
        names[key]: actions.get(item, item) if names[key] == "action" and type(item) is int else item
        for key, item in value.items()
    }, separators=(",", ":"), ensure_ascii=False)


@lru_cache(maxsize=1)
def load_schema() -> dict[str, Any]:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    if schema.get("version") != 2:
        raise ValueError("agent message schema version is invalid")
    return schema


def _reverse(category: str) -> dict[int, str]:
    return {identifier: name for name, identifier in load_schema()[category].items()}


def _encode_field_value(field: str, value: Any) -> Any:
    if field == "parameters":
        return _encode_task_parameters(value)
    category = ENUM_FIELDS.get(field)
    if category is not None:
        if not isinstance(value, str) or value not in load_schema()[category]:
            raise ValueError(f"unknown {field} value")
        return load_schema()[category][value]
    if field in HOST_FIELDS:
        if not isinstance(value, str):
            raise ValueError(f"{field} must be host text")
        return load_schema()["host_values"].get(value, value)
    return _encode(value)


def _decode_field_value(field: str, value: Any) -> Any:
    if field == "parameters":
        return _decode_task_parameters(value)
    if field == "user_output":
        return expand_agent_output(value)
    if field == "sleep_info" and isinstance(value, dict):
        fields = load_schema()["fields"]
        expected = {fields["interval"], fields["jitter"], fields["c2_profile"]}
        if set(value) != expected:
            raise ValueError("numeric sleep info has invalid fields")
        interval, jitter = value[fields["interval"]], value[fields["jitter"]]
        profile_code = value[fields["c2_profile"]]
        if type(interval) is not int or interval < 0 or type(jitter) is not int or jitter < 0:
            raise ValueError("numeric sleep info has invalid timing")
        if type(profile_code) is not int or profile_code not in _reverse("profiles"):
            raise ValueError("numeric sleep info has invalid profile")
        profile = _reverse("profiles")[profile_code]
        return json.dumps({profile: {"interval": interval, "jitter": jitter}}, separators=(",", ":"))
    category = ENUM_FIELDS.get(field)
    if category is not None:
        if type(value) is not int or value not in _reverse(category):
            raise ValueError(f"unknown numeric {field} value")
        return _reverse(category)[value]
    if field in HOST_FIELDS:
        if type(value) is int:
            if value not in _reverse("host_values"):
                raise ValueError(f"unknown numeric {field} value")
            return _reverse("host_values")[value]
        if not isinstance(value, str):
            raise ValueError(f"{field} must be host text or a known code")
        return value
    return _decode(value)


def _encode(value: Any) -> Any:
    if isinstance(value, dict):
        field_ids = load_schema()["fields"]
        result: dict[int, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str) or key not in field_ids:
                raise ValueError(f"unknown Mythic field {key!r}")
            result[field_ids[key]] = _encode_field_value(key, item)
        return result
    if isinstance(value, list):
        return [_encode(item) for item in value]
    return value


def _decode(value: Any) -> Any:
    if isinstance(value, dict):
        field_names = _reverse("fields")
        result: dict[str, Any] = {}
        for key, item in value.items():
            if type(key) is not int or key not in field_names:
                raise ValueError(f"unknown numeric agent field {key!r}")
            field = field_names[key]
            result[field] = _decode_field_value(field, item)
        return result
    if isinstance(value, list):
        return [_decode(item) for item in value]
    return value


def to_agent_record(message: dict[str, Any]) -> dict[int, Any]:
    if not isinstance(message, dict):
        raise ValueError("Mythic message must be a map")
    return _encode(message)


def from_agent_record(message: dict[int, Any]) -> dict[str, Any]:
    if not isinstance(message, dict):
        raise ValueError("numeric agent message must be a map")
    return _decode(message)
