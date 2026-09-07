"""Nuwa translation container and fixed wire-format helpers."""

from __future__ import annotations

import base64
import copy
import json
import secrets
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

from .codec_registry import get_codec, list_codecs
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


DEFAULT_CODEC_PROFILE = "raw"
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
    normalized = normalize_context(context)
    codec = get_codec(normalized["codec_profile"])
    return codec.encode_inner(bytes(message_bytes), normalized)


def probe_wire_message(
    wire_bytes: bytes,
    context: dict[str, Any] | None = None,
    protection: ProtectionSelection | None = None,
) -> DecodedWireMessage:
    candidates: list[DecodedWireMessage] = []
    payload = bytes(wire_bytes)
    selected = protection or ProtectionSelection()
    authentication_failed = False

    for codec_profile in list_codecs():
        try:
            candidate = decode_with_codec(payload, codec_profile, context, selected)
        except ProtectionAuthenticationError:
            authentication_failed = True
            continue
        except Exception:
            continue
        candidates.append(candidate)

    if not candidates:
        if authentication_failed:
            raise ProtectionAuthenticationError(AUTHENTICATION_ERROR)
        raise ValueError("No Nuwa codec accepted the wire payload")
    if len(candidates) > 1:
        matching_profiles = ", ".join(
            candidate.codec_profile for candidate in candidates
        )
        raise ValueError(f"Ambiguous Nuwa wire payload: {matching_profiles}")
    return candidates[0]


def decode_with_codec(
    wire_bytes: bytes,
    codec_profile: str,
    context: dict[str, Any] | None = None,
    protection: ProtectionSelection | None = None,
) -> DecodedWireMessage:
    """Fully validate one codec candidate without consulting prior messages."""
    if codec_profile not in list_codecs():
        raise ValueError(f"Unsupported Nuwa codec profile: {codec_profile}")
    attempt_context = normalize_context(context)
    attempt_context["codec_profile"] = codec_profile
    selected = protection or ProtectionSelection()
    message_bytes = get_codec(codec_profile).decode_inner(
        bytes(wire_bytes),
        attempt_context,
    )
    message_bytes = unprotect_message(
        selected.profile,
        selected.key,
        message_bytes,
    )
    message_text = message_bytes.decode("utf-8", errors="strict")
    message = json.loads(message_text)
    if not isinstance(message, dict):
        raise ValueError("Nuwa wire message must decode to a JSON object")
    return DecodedWireMessage(
        codec_profile=codec_profile,
        message_bytes=message_bytes,
        message=message,
    )


def decode_wire_message(
    wire_bytes: bytes,
    context: dict[str, Any] | None = None,
) -> bytes:
    return probe_wire_message(wire_bytes, context).message_bytes


def _uses_byte_array_chunks(message: dict[str, Any]) -> bool:
    return message.get(NUWA_BINARY_FORMAT_FIELD) == NUWA_BYTE_ARRAY_FORMAT


def _normalize_inbound_file_chunks(message: dict[str, Any]) -> dict[str, Any]:
    normalized = copy.deepcopy(message)
    if not _uses_byte_array_chunks(normalized):
        return normalized

    responses = normalized.get("responses")
    if responses is None:
        return normalized
    if not isinstance(responses, list):
        raise ValueError("responses must be an array when using byte-array chunks")

    for response_index, response in enumerate(responses):
        if not isinstance(response, dict):
            continue
        download = response.get("download")
        if not isinstance(download, dict) or "chunk_data" not in download:
            continue
        location = f"responses[{response_index}].download.chunk_data"
        chunk_data = download["chunk_data"]
        if not isinstance(chunk_data, list):
            raise ValueError(f"{location} must be an array of integers")
        for item_index, item in enumerate(chunk_data):
            if isinstance(item, bool) or not isinstance(item, int):
                raise ValueError(
                    f"{location}[{item_index}] must be an integer from 0 through 255"
                )
            if item < 0 or item > 255:
                raise ValueError(
                    f"{location}[{item_index}] must be an integer from 0 through 255"
                )
        download["chunk_data"] = base64.b64encode(bytes(chunk_data)).decode("ascii")
    return normalized


def _normalize_outbound_file_chunks(message: dict[str, Any]) -> dict[str, Any]:
    normalized = copy.deepcopy(message)
    if not _uses_byte_array_chunks(normalized):
        return normalized

    normalized.pop(NUWA_BINARY_FORMAT_FIELD, None)
    responses = normalized.get("responses")
    if responses is None:
        return normalized
    if not isinstance(responses, list):
        raise ValueError("responses must be an array when using byte-array chunks")

    for response_index, response in enumerate(responses):
        if not isinstance(response, dict) or "chunk_data" not in response:
            continue
        location = f"responses[{response_index}].chunk_data"
        chunk_data = response["chunk_data"]
        if isinstance(chunk_data, str):
            try:
                decoded = base64.b64decode(chunk_data, validate=True)
            except Exception as exc:
                raise ValueError(f"{location} is not valid Base64 data") from exc
            response["chunk_data"] = list(decoded)
            continue
        if isinstance(chunk_data, list):
            for item_index, item in enumerate(chunk_data):
                if isinstance(item, bool) or not isinstance(item, int):
                    raise ValueError(
                        f"{location}[{item_index}] must be an integer from 0 through 255"
                    )
                if item < 0 or item > 255:
                    raise ValueError(
                        f"{location}[{item_index}] must be an integer from 0 through 255"
                    )
            response["chunk_data"] = list(chunk_data)
            continue
        raise ValueError(
            f"{location} must be a Base64 string or byte array "
            f"(got {type(chunk_data).__name__})"
        )
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
    description = "Nuwa translation container for custom codec-based HTTP wire messages."
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
            cleaned_message = copy.deepcopy(inputMsg.Message)
            codec_profile = cleaned_message.pop(NUWA_CODEC_HINT_FIELD, None)
            if not isinstance(codec_profile, str) or codec_profile not in list_codecs():
                raise ValueError(
                    f"Outbound Nuwa message requires canonical {NUWA_CODEC_HINT_FIELD}"
                )
            normalized_message = _normalize_outbound_file_chunks(cleaned_message)
            context = _build_context(
                direction="outbound",
                c2_name=inputMsg.C2Name,
                uuid=inputMsg.UUID,
                message=normalized_message,
                default_codec_profile=codec_profile,
            )
            context["codec_profile"] = codec_profile
            message_bytes = json.dumps(
                normalized_message,
                ensure_ascii=False,
                separators=(",", ":"),
            ).encode("utf-8")
            protected_bytes = protect_message(
                protection.profile,
                protection.key,
                message_bytes,
            )
            return TrMythicC2ToCustomMessageFormatMessageResponse(
                Success=True,
                Message=encode_wire_message(protected_bytes, context),
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
            context = _build_context(
                direction="inbound",
                c2_name=inputMsg.C2Name,
                uuid=inputMsg.UUID,
            )
            decoded = probe_wire_message(inputMsg.Message, context, protection)
            normalized_message = _normalize_inbound_file_chunks(decoded.message)
            normalized_message[NUWA_CODEC_HINT_FIELD] = decoded.codec_profile
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
