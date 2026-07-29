"""Nuwa translation container and fixed wire-format helpers."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

try:  # pragma: no cover - exercised in container
    import mythic_container
    from mythic_container.TranslationBase import (  # type: ignore
        TrCustomMessageToMythicC2FormatMessage,
        TrCustomMessageToMythicC2FormatMessageResponse,
        TrGenerateEncryptionKeysMessage,
        TrGenerateEncryptionKeysMessageResponse,
        TrMythicC2ToCustomMessageFormatMessage,
        TrMythicC2ToCustomMessageFormatMessageResponse,
        TranslationContainer,
    )
except ImportError:  # pragma: no cover - unit test fallback
    mythic_container = None

    @dataclass
    class TrGenerateEncryptionKeysMessage:
        TranslationContainerName: str
        C2Name: str
        CryptoParamValue: str
        CryptoParamName: str

    @dataclass
    class TrGenerateEncryptionKeysMessageResponse:
        Success: bool = False
        Error: str = ""
        EncryptionKey: bytes | None = None
        DecryptionKey: bytes | None = None

    @dataclass
    class TrCustomMessageToMythicC2FormatMessage:
        TranslationContainerName: str
        C2Name: str
        Message: bytes
        UUID: str
        MythicEncrypts: bool
        CryptoKeys: list[Any] = field(default_factory=list)

    @dataclass
    class TrCustomMessageToMythicC2FormatMessageResponse:
        Success: bool = False
        Error: str = ""
        Message: dict[str, Any] = field(default_factory=dict)

    @dataclass
    class TrMythicC2ToCustomMessageFormatMessage:
        TranslationContainerName: str
        C2Name: str
        Message: dict[str, Any]
        UUID: str
        MythicEncrypts: bool
        CryptoKeys: list[Any] = field(default_factory=list)

    @dataclass
    class TrMythicC2ToCustomMessageFormatMessageResponse:
        Success: bool = False
        Error: str = ""
        Message: bytes = b""

    class TranslationContainer:
        name: str = ""
        description: str = ""
        author: str = ""
        semver: str = ""

from .codec_registry import get_codec


WIRE_VERSION_MARKER = "NW1"
DEFAULT_CODEC_PROFILE = "decimal"
DEFAULT_CODEC_VERSION = "1"


def start() -> None:
    if mythic_container is None:  # pragma: no cover - local unit test fallback
        return
    mythic_container.mythic_service.start_and_run_forever()


def normalize_context(context: dict[str, Any] | None) -> dict[str, Any]:
    normalized = dict(context or {})
    normalized["codec_profile"] = str(
        normalized.get("codec_profile") or DEFAULT_CODEC_PROFILE
    ).lower()
    normalized["codec_version"] = str(
        normalized.get("codec_version") or DEFAULT_CODEC_VERSION
    )
    normalized.setdefault("direction", "")
    normalized.setdefault("uuid", "")
    normalized.setdefault("message_type", "")
    normalized.setdefault("c2_profile", "")
    return normalized


def build_marker(codec_profile: str) -> bytes:
    return f"{WIRE_VERSION_MARKER}:{codec_profile}:".encode("ascii")


def encode_wire_message(message_bytes: bytes, context: dict[str, Any] | None = None) -> bytes:
    normalized = normalize_context(context)
    codec = get_codec(normalized["codec_profile"])
    inner = codec.encode_inner(bytes(message_bytes), normalized)
    return build_marker(normalized["codec_profile"]) + inner


def decode_wire_message(wire_bytes: bytes, context: dict[str, Any] | None = None) -> bytes:
    normalized = normalize_context(context)
    codec_profile, body_offset = parse_marker(bytes(wire_bytes), normalized)
    codec = get_codec(codec_profile)
    return codec.decode_inner(bytes(wire_bytes[body_offset:]), normalized)


def parse_marker(wire_bytes: bytes, context: dict[str, Any]) -> tuple[str, int]:
    if not wire_bytes.startswith(f"{WIRE_VERSION_MARKER}:".encode("ascii")):
        raise ValueError("Malformed Nuwa wire marker")

    marker_tail_start = len(WIRE_VERSION_MARKER) + 1
    marker_tail = wire_bytes[marker_tail_start:]
    profile_terminator = marker_tail.find(b":")
    if profile_terminator <= 0:
        raise ValueError("Malformed Nuwa wire marker")

    codec_profile = marker_tail[:profile_terminator].decode("ascii")
    expected_profile = context["codec_profile"]
    if codec_profile != expected_profile:
        raise ValueError(
            f"Codec profile mismatch: marker '{codec_profile}' != context '{expected_profile}'"
        )

    return codec_profile, marker_tail_start + profile_terminator + 1


def _resolve_codec_profile(message: dict[str, Any] | None) -> str:
    if not isinstance(message, dict):
        return DEFAULT_CODEC_PROFILE
    direct_value = message.get("codec_profile")
    if direct_value:
        return str(direct_value).strip().lower()
    for nested_name in ("build_parameters", "metadata"):
        nested = message.get(nested_name)
        if isinstance(nested, dict) and nested.get("codec_profile"):
            return str(nested["codec_profile"]).strip().lower()
    return DEFAULT_CODEC_PROFILE


def _infer_message_type(message: dict[str, Any] | None) -> str:
    if not isinstance(message, dict):
        return ""
    for key in ("action", "response_type", "tasking_size"):
        if key in message:
            return str(key)
    return ""


def _build_context(
    *,
    direction: str,
    c2_name: str,
    uuid: str,
    message: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return normalize_context(
        {
            "direction": direction,
            "uuid": uuid,
            "message_type": _infer_message_type(message),
            "c2_profile": c2_name,
            "codec_profile": _resolve_codec_profile(message),
            "codec_version": DEFAULT_CODEC_VERSION,
        }
    )


class NuwaTranslationContainer(TranslationContainer):
    name = "nuwa_translation"
    description = "Nuwa translation container for custom codec-based HTTP wire messages."
    author = "@openai"
    semver = "1.0.0"

    async def generate_keys(
        self, inputMsg: TrGenerateEncryptionKeysMessage
    ) -> TrGenerateEncryptionKeysMessageResponse:
        return TrGenerateEncryptionKeysMessageResponse(Success=True)

    async def translate_to_c2_format(
        self, inputMsg: TrMythicC2ToCustomMessageFormatMessage
    ) -> TrMythicC2ToCustomMessageFormatMessageResponse:
        try:
            context = _build_context(
                direction="outbound",
                c2_name=inputMsg.C2Name,
                uuid=inputMsg.UUID,
                message=inputMsg.Message,
            )
            message_bytes = json.dumps(
                inputMsg.Message,
                ensure_ascii=False,
                separators=(",", ":"),
            ).encode("utf-8")
            return TrMythicC2ToCustomMessageFormatMessageResponse(
                Success=True,
                Message=encode_wire_message(message_bytes, context),
            )
        except Exception as exc:
            return TrMythicC2ToCustomMessageFormatMessageResponse(
                Success=False,
                Error=str(exc),
            )

    async def translate_from_c2_format(
        self, inputMsg: TrCustomMessageToMythicC2FormatMessage
    ) -> TrCustomMessageToMythicC2FormatMessageResponse:
        try:
            context = _build_context(
                direction="inbound",
                c2_name=inputMsg.C2Name,
                uuid=inputMsg.UUID,
            )
            message_json = decode_wire_message(inputMsg.Message, context).decode("utf-8")
            return TrCustomMessageToMythicC2FormatMessageResponse(
                Success=True,
                Message=json.loads(message_json),
            )
        except Exception as exc:
            return TrCustomMessageToMythicC2FormatMessageResponse(
                Success=False,
                Error=str(exc),
            )


__all__ = [
    "DEFAULT_CODEC_PROFILE",
    "DEFAULT_CODEC_VERSION",
    "NuwaTranslationContainer",
    "TrCustomMessageToMythicC2FormatMessage",
    "TrCustomMessageToMythicC2FormatMessageResponse",
    "TrGenerateEncryptionKeysMessage",
    "TrGenerateEncryptionKeysMessageResponse",
    "TrMythicC2ToCustomMessageFormatMessage",
    "TrMythicC2ToCustomMessageFormatMessageResponse",
    "TranslationContainer",
    "WIRE_VERSION_MARKER",
    "build_marker",
    "decode_wire_message",
    "encode_wire_message",
    "normalize_context",
    "parse_marker",
    "start",
]
