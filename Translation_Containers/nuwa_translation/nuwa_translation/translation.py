"""Nuwa translation container and fixed wire-format helpers."""

from __future__ import annotations

import base64
import copy
import json
import re
import secrets
import uuid
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

from .binary_v1 import decode_binary_v1, encode_binary_v1
from .protection import (
    AUTHENTICATION_ERROR,
    HISTORICAL_AES256_HMAC,
    KEY_SIZE,
    PROTECTED_PROFILES,
    PROTECTION_NONE,
    ProtectionAuthenticationError,
    ProtectionConfigurationError,
    ProtectionSelection,
    protect_message,
    resolve_crypto_selection,
    unprotect_message,
)


DEFAULT_CODEC_PROFILE = "binary-v1"
DEFAULT_CODEC_VERSION = "1"
NUWA_CODEC_HINT_FIELD = "nuwa_codec_profile"
NUWA_BINARY_FORMAT_FIELD = "nuwa_binary_format"
NUWA_BYTE_ARRAY_FORMAT = "byte_array"


@dataclass(frozen=True)
class DecodedWireMessage:
    codec_profile: str
    message_bytes: bytes
    message: dict[str, Any]


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


def encode_wire_message(message_bytes: bytes, context: dict[str, Any] | None = None) -> bytes:
    """Return already-serialized binary v1 bytes without another inner codec."""
    decode_binary_v1(message_bytes)
    return bytes(message_bytes)


def probe_wire_message(
    wire_bytes: bytes,
    context: dict[str, Any] | None = None,
    protection: ProtectionSelection | None = None,
) -> DecodedWireMessage:
    selected = protection or ProtectionSelection()
    message_bytes = unprotect_message(selected.profile, selected.key, bytes(wire_bytes))
    return DecodedWireMessage(
        codec_profile=DEFAULT_CODEC_PROFILE,
        message_bytes=message_bytes,
        message=decode_binary_v1(message_bytes),
    )


def decode_with_codec(
    wire_bytes: bytes,
    codec_profile: str,
    context: dict[str, Any] | None = None,
    protection: ProtectionSelection | None = None,
) -> DecodedWireMessage:
    """Decode only the configured binary inner v1 representation."""
    if codec_profile != DEFAULT_CODEC_PROFILE:
        raise ValueError(f"Unsupported Nuwa codec profile: {codec_profile}")
    return probe_wire_message(wire_bytes, context, protection)


def decode_wire_message(
    wire_bytes: bytes,
    context: dict[str, Any] | None = None,
) -> bytes:
    return probe_wire_message(wire_bytes, context).message_bytes


def _boundary_bytes(value: Any, location: str, *, inbound: bool) -> bytes | str:
    if inbound:
        if not isinstance(value, bytes):
            raise ValueError(f"{location} must be raw bytes on binary v1")
        return base64.b64encode(value).decode("ascii")
    if isinstance(value, list):
        if any(type(item) is not int or item < 0 or item > 255 for item in value):
            raise ValueError(f"{location} must contain byte values from 0 to 255")
        return bytes(value)
    if not isinstance(value, str):
        raise ValueError(f"{location} must be Base64 text or a byte array at the Mythic boundary")
    try:
        decoded = base64.b64decode(value, validate=True)
    except Exception as exc:
        raise ValueError(f"{location} is not valid Base64 data") from exc
    if base64.b64encode(decoded).decode("ascii") != value:
        raise ValueError(f"{location} is not canonical Base64 data")
    return decoded


def _boundary_id(value: Any, location: str, *, inbound: bool) -> bytes | str:
    if inbound:
        if not isinstance(value, bytes) or len(value) != 16:
            raise ValueError(f"{location} must be exactly 16 raw bytes")
        return value.hex()
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{32}", value) is None:
        raise ValueError(f"{location} must be 32 lowercase hexadecimal characters")
    return bytes.fromhex(value)


def _normalize_binary_boundaries(message: dict[str, Any], *, inbound: bool) -> dict[str, Any]:
    normalized = copy.deepcopy(message)
    for hint in (NUWA_CODEC_HINT_FIELD, NUWA_BINARY_FORMAT_FIELD):
        if hint in normalized:
            raise ValueError(f"{hint} is not part of Nuwa binary v1")

    responses = normalized.get("responses", [])
    if not isinstance(responses, list):
        raise ValueError("responses must be an array")
    for index, response in enumerate(responses):
        if not isinstance(response, dict):
            continue
        for parent, path in ((response, f"responses[{index}]"),
                             (response.get("download"), f"responses[{index}].download")):
            if isinstance(parent, dict) and "chunk_data" in parent:
                parent["chunk_data"] = _boundary_bytes(
                    parent["chunk_data"], f"{path}.chunk_data", inbound=inbound
                )

    socks = normalized.get("socks", [])
    if not isinstance(socks, list):
        raise ValueError("socks must be an array")
    for index, record in enumerate(socks):
        if not isinstance(record, dict):
            raise ValueError(f"socks[{index}] must be a map")
        if "data" in record:
            record["data"] = _boundary_bytes(
                record["data"], f"socks[{index}].data", inbound=inbound
            )
    if "socks_batch_id" in normalized:
        normalized["socks_batch_id"] = _boundary_id(
            normalized["socks_batch_id"], "socks_batch_id", inbound=inbound
        )
    if "socks_ack" in normalized:
        acknowledgments = normalized["socks_ack"]
        if not isinstance(acknowledgments, list):
            raise ValueError("socks_ack must be an array")
        normalized["socks_ack"] = [
            _boundary_id(item, f"socks_ack[{index}]", inbound=inbound)
            for index, item in enumerate(acknowledgments)
        ]
    return normalized


def _resolve_codec_profile(
    message: dict[str, Any] | None,
    *,
    default: str = DEFAULT_CODEC_PROFILE,
) -> str:
    if not isinstance(message, dict):
        return default
    direct_value = message.get("codec_profile")
    if direct_value:
        return str(direct_value).strip().lower()
    for nested_name in ("build_parameters", "metadata"):
        nested = message.get(nested_name)
        if isinstance(nested, dict) and nested.get("codec_profile"):
            return str(nested["codec_profile"]).strip().lower()
    return default


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
    default_codec_profile: str = DEFAULT_CODEC_PROFILE,
) -> dict[str, Any]:
    return normalize_context(
        {
            "direction": direction,
            "uuid": uuid,
            "message_type": _infer_message_type(message),
            "c2_profile": c2_name,
            "codec_profile": _resolve_codec_profile(
                message,
                default=default_codec_profile,
            ),
            "codec_version": DEFAULT_CODEC_VERSION,
        }
    )


class NuwaTranslationContainer(TranslationContainer):
    name = "nuwa_translation"
    description = "Nuwa translation container for strict binary inner v1 messages."
    author = "@openai"
    semver = "1.3.0"

    async def generate_keys(
        self, inputMsg: TrGenerateEncryptionKeysMessage
    ) -> TrGenerateEncryptionKeysMessageResponse:
        try:
            value = str(inputMsg.CryptoParamValue).strip()
            if value in {PROTECTION_NONE, HISTORICAL_AES256_HMAC}:
                return TrGenerateEncryptionKeysMessageResponse(Success=True)
            if value not in PROTECTED_PROFILES:
                raise ProtectionConfigurationError(
                    f"Unsupported Nuwa protection profile: {value}"
                )
            key = secrets.token_bytes(KEY_SIZE)
            return TrGenerateEncryptionKeysMessageResponse(
                Success=True,
                EncryptionKey=key,
                DecryptionKey=key,
            )
        except Exception as exc:
            return TrGenerateEncryptionKeysMessageResponse(
                Success=False,
                Error=str(exc),
            )

    async def translate_to_c2_format(
        self, inputMsg: TrMythicC2ToCustomMessageFormatMessage
    ) -> TrMythicC2ToCustomMessageFormatMessageResponse:
        try:
            protection = resolve_crypto_selection(
                inputMsg.CryptoKeys,
                direction="outbound",
            )
            if not isinstance(inputMsg.Message, dict):
                raise ValueError("Outbound Nuwa message must be a dictionary")
            normalized_message = _normalize_binary_boundaries(inputMsg.Message, inbound=False)
            message_bytes = encode_binary_v1(normalized_message)
            protected_bytes = protect_message(
                protection.profile,
                protection.key,
                message_bytes,
            )
            route = str(inputMsg.UUID)
            try:
                if str(uuid.UUID(route)) != route:
                    raise ValueError
            except (TypeError, ValueError, AttributeError) as exc:
                raise ValueError("Outbound Nuwa route UUID must be canonical") from exc
            return TrMythicC2ToCustomMessageFormatMessageResponse(
                Success=True,
                Message=route.encode("ascii") + protected_bytes,
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
            protection = resolve_crypto_selection(
                inputMsg.CryptoKeys,
                direction="inbound",
            )
            decoded = probe_wire_message(inputMsg.Message, protection=protection)
            normalized_message = _normalize_binary_boundaries(decoded.message, inbound=True)
            return TrCustomMessageToMythicC2FormatMessageResponse(
                Success=True,
                Message=normalized_message,
            )
        except Exception as exc:
            return TrCustomMessageToMythicC2FormatMessageResponse(
                Success=False,
                Error=str(exc),
            )


__all__ = [
    "DEFAULT_CODEC_PROFILE",
    "DEFAULT_CODEC_VERSION",
    "DecodedWireMessage",
    "NuwaTranslationContainer",
    "NUWA_BINARY_FORMAT_FIELD",
    "NUWA_BYTE_ARRAY_FORMAT",
    "NUWA_CODEC_HINT_FIELD",
    "ProtectionSelection",
    "TrCustomMessageToMythicC2FormatMessage",
    "TrCustomMessageToMythicC2FormatMessageResponse",
    "TrGenerateEncryptionKeysMessage",
    "TrGenerateEncryptionKeysMessageResponse",
    "TrMythicC2ToCustomMessageFormatMessage",
    "TrMythicC2ToCustomMessageFormatMessageResponse",
    "TranslationContainer",
    "decode_wire_message",
    "decode_with_codec",
    "encode_wire_message",
    "normalize_context",
    "probe_wire_message",
    "start",
]
