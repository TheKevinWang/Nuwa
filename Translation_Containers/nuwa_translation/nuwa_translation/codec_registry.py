"""Codec registry for Nuwa translation profiles."""

from __future__ import annotations

from importlib import import_module
from types import ModuleType


_CODEC_MODULES = {
    "base64": "nuwa_translation.codecs.base64_codec",
    "decimal": "nuwa_translation.codecs.decimal",
    "emoji": "nuwa_translation.codecs.emoji",
    "raw": "nuwa_translation.codecs.raw",
}


def get_codec(profile_name: str) -> ModuleType:
    profile = str(profile_name or "").strip().lower()
    if profile not in _CODEC_MODULES:
        raise ValueError(f"Unsupported codec profile '{profile_name}'")
    return import_module(_CODEC_MODULES[profile])


def list_codecs() -> list[str]:
    return sorted(_CODEC_MODULES)
