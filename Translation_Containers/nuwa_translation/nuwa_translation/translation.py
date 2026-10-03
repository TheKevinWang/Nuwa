"""Nuwa translation container and fixed wire-format helpers."""

from __future__ import annotations

import base64
import copy
import json
import re
import secrets
import uuid
from collections import OrderedDict
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
from .binary_v2 import PREFIX as BINARY_V2_PREFIX, decode_binary_v2, encode_binary_v2
from .binary_v3 import decode_binary_v3, encode_binary_v3
from .protocol_v3 import from_agent_record as from_agent_record_v3, to_agent_record as to_agent_record_v3
from .profile_lookup_v3 import resolve_profile_for_route
from .protocol_v2 import from_agent_record, to_agent_record
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


DEFAULT_CODEC_PROFILE = "binary-v2"
DEFAULT_CODEC_VERSION = "2"
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
        normalized.get("codec_version") or
        ("1" if normalized["codec_profile"] == "binary-v1" else DEFAULT_CODEC_VERSION)
    )
    normalized.setdefault("direction", "")
    normalized.setdefault("uuid", "")
    normalized.setdefault("message_type", "")
    normalized.setdefault("c2_profile", "")
    return normalized


def encode_wire_message(message_bytes: bytes, context: dict[str, Any] | None = None) -> bytes:
    """Validate and return an already serialized binary agent message."""
    if bytes(message_bytes).startswith(BINARY_V2_PREFIX):
        from_agent_record(decode_binary_v2(message_bytes))
    else:
        decode_binary_v1(message_bytes)
    return bytes(message_bytes)


def probe_wire_message(
    wire_bytes: bytes,
    context: dict[str, Any] | None = None,
    protection: ProtectionSelection | None = None,
) -> DecodedWireMessage:
    selected = protection or ProtectionSelection()
    message_bytes = unprotect_message(selected.profile, selected.key, bytes(wire_bytes))
    if message_bytes.startswith(BINARY_V2_PREFIX):
        profile = "binary-v2"
        message = from_agent_record(decode_binary_v2(message_bytes))
    else:
        profile = "binary-v1"
        message = decode_binary_v1(message_bytes)
    return DecodedWireMessage(
        codec_profile=profile,
        message_bytes=message_bytes,
        message=message,
    )


def decode_with_codec(
    wire_bytes: bytes,
    codec_profile: str,
    context: dict[str, Any] | None = None,
    protection: ProtectionSelection | None = None,
) -> DecodedWireMessage:
    """Decode the selected canonical binary representation."""
    if codec_profile not in ("binary-v1", "binary-v2"):
        raise ValueError(f"Unsupported Nuwa codec profile: {codec_profile}")
    decoded = probe_wire_message(wire_bytes, context, protection)
    if decoded.codec_profile != codec_profile:
        raise ValueError("Nuwa binary codec version does not match selection")
    return decoded


def decode_wire_message(
    wire_bytes: bytes,
    context: dict[str, Any] | None = None,
) -> bytes:
    return probe_wire_message(wire_bytes, context).message_bytes


def _boundary_bytes(value: Any, location: str, *, inbound: bool) -> bytes | str:
    if inbound:
        if not isinstance(value, bytes):
            raise ValueError(f"{location} must be raw bytes on the agent wire")
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
            raise ValueError(f"{hint} is not part of the Nuwa agent message")

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
    if "socks" in normalized and not socks:
        raise ValueError("socks must be a nonempty array")
    if bool(socks) != ("socks_batch_id" in normalized):
        raise ValueError("socks_batch_id requires a nonempty socks array")
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
        if not isinstance(acknowledgments, list) or not acknowledgments:
            raise ValueError("socks_ack must be a nonempty array")
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
            "codec_version": "1" if _resolve_codec_profile(
                message, default=default_codec_profile
            ) == "binary-v1" else DEFAULT_CODEC_VERSION,
        }
    )


class NuwaTranslationContainer(TranslationContainer):
    name = "nuwa_translation"
    description = "Nuwa translation container for versioned canonical binary messages."
    author = "@openai"
    semver = "1.3.0"

    async def _lookup_control_profile(self, route: str):
        resolver = getattr(self, "_profile_resolver", None)
        if resolver is not None:
            return await resolver(route)
        # Local protocol tests construct the container without a RabbitMQ
        # connection. A live container always uses the authoritative route RPC.
        if mythic_container is None or mythic_container.RabbitmqConnection.conn is None:
            return None
        return await resolve_profile_for_route(route)

    def _remember_wire_version(self, c2_name: str, route: str, profile: str) -> None:
        if not hasattr(self, "_observed_wire_versions"):
            self._observed_wire_versions: OrderedDict[tuple[str, str], str] = OrderedDict()
        key = (str(c2_name), str(route))
        self._observed_wire_versions[key] = profile
        self._observed_wire_versions.move_to_end(key)
        if len(self._observed_wire_versions) > 4096:
            self._observed_wire_versions.popitem(last=False)

    def _wire_version_for_route(self, c2_name: str, route: str) -> str:
        versions = getattr(self, "_observed_wire_versions", {})
        return versions.get((str(c2_name), str(route)), DEFAULT_CODEC_PROFILE)

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
            route = str(inputMsg.UUID)
            control_profile = await self._lookup_control_profile(route)
            if control_profile is not None and control_profile.kind == "binary-v3":
                message_bytes = encode_binary_v3(
                    to_agent_record_v3(normalized_message, control_profile), control_profile,
                )
            else:
                selected_codec = self._wire_version_for_route(inputMsg.C2Name, route)
                message_bytes = (
                    encode_binary_v1(normalized_message)
                    if selected_codec == "binary-v1" else
                    encode_binary_v2(to_agent_record(normalized_message))
                )
            protected_bytes = protect_message(
                protection.profile,
                protection.key,
                message_bytes,
            )
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
            control_profile = await self._lookup_control_profile(str(inputMsg.UUID))
            if control_profile is not None and control_profile.kind == "binary-v3":
                message_bytes = unprotect_message(protection.profile, protection.key, bytes(inputMsg.Message))
                decoded = DecodedWireMessage(
                    codec_profile="binary-v3", message_bytes=message_bytes,
                    message=from_agent_record_v3(
                        decode_binary_v3(message_bytes, control_profile), control_profile,
                    ),
                )
            else:
                decoded = probe_wire_message(inputMsg.Message, protection=protection)
            normalized_message = _normalize_binary_boundaries(decoded.message, inbound=True)
            self._remember_wire_version(inputMsg.C2Name, inputMsg.UUID, decoded.codec_profile)
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
