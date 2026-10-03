"""Expand compact agent task output after decoding a numeric message."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


TAG = 20053
VERSION = 1
SLEEP_UPDATED = 1045
UPLOAD_COMPLETE = 1076
DOWNLOAD_FILE_ID = 1086
CD_REQUIRES_PATH = 1077

TEXT_DIAGNOSTICS: dict[int, tuple[str, tuple[type, ...]]] = {
    1000: ("Agent exiting", ()),
    1028: ("Download chunk upload was not acknowledged for chunk {0}", (int,)),
    1029: ("Download metadata request did not return a file ID", ()),
    SLEEP_UPDATED: ("Sleep updated", ()),
    1075: ("Upload chunk request did not return chunk data for chunk {0}", (int,)),
    UPLOAD_COMPLETE: ("Uploaded file to {0}", (str,)),
    CD_REQUIRES_PATH: ("cd requires a target path", ()),
    1078: ("download requires a file path", ()),
    1084: ("unknown", ()),
    1085: ("unknown-host", ()),
    1087: ("SOCKS port must be between 1 and 65535", ()),
    1088: ("SOCKS action must be start or stop", ()),
    1089: ("SOCKS5 Gateway ready for Mythic port {0}", (int,)),
    1090: ("SOCKS5 Gateway stopped for Mythic port {0}", (int,)),
    1091: ("Chunk data must be an array of byte values", ()),
    1092: ("Chunk data item {0} must be an integer from 0 through 255", (int,)),
}

_CATALOG = json.loads(Path(__file__).with_name("agent_diagnostics_v2.json").read_text(encoding="utf-8"))
for _entry in _CATALOG["diagnostics"]:
    _code = _entry["code"]
    if _code in TEXT_DIAGNOSTICS:
        raise ValueError(f"duplicate numeric diagnostic code {_code}")
    TEXT_DIAGNOSTICS[_code] = (
        _entry["text"],
        tuple({"int": int, "str": str}[name] for name in _entry["argument_types"]),
    )


def expand_agent_output(value: Any) -> str | None:
    if value is None or isinstance(value, str):
        return value
    if not isinstance(value, list) or len(value) != 4:
        raise ValueError("numeric user output is not a valid diagnostic record")
    tag, version, code, arguments = value
    if (type(tag) is not int or tag != TAG or type(version) is not int or
            version != VERSION or type(code) is not int or not isinstance(arguments, list)):
        raise ValueError("numeric user output has an invalid diagnostic header")
    if code == DOWNLOAD_FILE_ID:
        if len(arguments) != 1 or not isinstance(arguments[0], str):
            raise ValueError("download diagnostic requires one text argument")
        return json.dumps({"agent_file_id": arguments[0]}, ensure_ascii=False, separators=(",", ":"))
    try:
        template, argument_types = TEXT_DIAGNOSTICS[code]
    except KeyError as exc:
        raise ValueError("unknown numeric diagnostic code") from exc
    if len(arguments) != len(argument_types) or any(
        type(argument) is not expected for argument, expected in zip(arguments, argument_types)
    ):
        raise ValueError("numeric diagnostic arguments are invalid")
    return template.format(*arguments)


def expand_agent_output_v3(value: Any, profile: Any) -> str | None:
    """Expand a profile-selected diagnostic through the frozen text catalog."""
    if value is None or isinstance(value, str):
        return value
    positions = profile.namespaces["diagnostic_positions"]
    if not isinstance(value, list) or len(value) != len(positions):
        raise ValueError("v3 user output is not a diagnostic record")
    header = profile.namespaces["diagnostic_header"]
    if value[positions["tag"]] != header["tag"] or value[positions["version"]] != header["version"]:
        raise ValueError("v3 diagnostic header does not match profile")
    selected_code = value[positions["code"]]
    name = profile.reverse_maps["diagnostic_codes"].get(selected_code)
    if name is None:
        raise ValueError("unknown v3 diagnostic code")
    code = int(name.removeprefix("code_"))
    return expand_agent_output([TAG, VERSION, code, value[positions["arguments"]]])
