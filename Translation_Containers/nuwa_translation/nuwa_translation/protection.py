"""Versioned, opt-in wire protection for Nuwa translation messages."""

from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass
from typing import Any, Literal, Sequence

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


PROTECTION_NONE = "none"
PROTECTION_XOR_V1 = "nuwa_xor_v1"
PROTECTION_HMAC_SHA256_V1 = "nuwa_hmac_sha256_v1"
PROTECTION_AES256_HMAC_V1 = "nuwa_aes256_hmac_v1"
HISTORICAL_AES256_HMAC = "aes256_hmac"

KEY_SIZE = 32
AES_BLOCK_SIZE = 16
HMAC_SIZE = hashlib.sha256().digest_size
AUTHENTICATION_ERROR = "Nuwa message protection authentication failed"

PROTECTED_PROFILES = frozenset(
    {
        PROTECTION_XOR_V1,
        PROTECTION_HMAC_SHA256_V1,
        PROTECTION_AES256_HMAC_V1,
    }
)


class ProtectionError(ValueError):
    """Base error for Nuwa protection failures."""


class ProtectionConfigurationError(ProtectionError):
    """The selected profile or key metadata is invalid."""


class ProtectionAuthenticationError(ProtectionError):
    """An authenticated message cannot be safely accepted."""


@dataclass(frozen=True)
class ProtectionSelection:
    """One resolved wire-protection profile and its directional key."""

    profile: str = PROTECTION_NONE
    key: bytes | None = None


def _coerce_message_bytes(value: Any, *, name: str) -> bytes:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise ProtectionConfigurationError(f"Nuwa {name} must be bytes")
    return bytes(value)


def _validate_key(profile: str, key: Any) -> bytes | None:
    if profile == PROTECTION_NONE:
        if key is not None and key != b"":
            raise ProtectionConfigurationError(
                "Nuwa plaintext protection must not have key material"
            )
        return None
    if profile not in PROTECTED_PROFILES:
        raise ProtectionConfigurationError(
            f"Unsupported Nuwa protection profile: {profile}"
        )
    if not isinstance(key, (bytes, bytearray, memoryview)) or len(key) != KEY_SIZE:
        raise ProtectionConfigurationError(
            "Nuwa protected profiles require one 32-byte key"
        )
    return bytes(key)


def _authentication_failure() -> ProtectionAuthenticationError:
    return ProtectionAuthenticationError(AUTHENTICATION_ERROR)


def protect_message(
    profile: str,
    key: bytes | bytearray | memoryview | None,
    plaintext: bytes | bytearray | memoryview,
    *,
    iv: bytes | bytearray | memoryview | None = None,
) -> bytes:
    """Apply exactly one selected protection profile to immutable input bytes.

    ``iv`` is accepted only for deterministic AES known-answer tests. Production
    callers omit it so every message receives an OS-generated IV.
    """

    normalized_key = _validate_key(profile, key)
    message = _coerce_message_bytes(plaintext, name="plaintext")

    if profile == PROTECTION_NONE:
        if iv is not None:
            raise ProtectionConfigurationError(
                "Nuwa plaintext protection does not accept an IV"
            )
        return message

    assert normalized_key is not None
    if profile == PROTECTION_XOR_V1:
        if iv is not None:
            raise ProtectionConfigurationError("Nuwa XOR protection does not accept an IV")
        return bytes(
            value ^ normalized_key[index % KEY_SIZE]
            for index, value in enumerate(message)
        )

    if profile == PROTECTION_HMAC_SHA256_V1:
        if iv is not None:
            raise ProtectionConfigurationError("Nuwa HMAC protection does not accept an IV")
        return message + hmac.new(normalized_key, message, hashlib.sha256).digest()

    if iv is None:
        aes_iv = secrets.token_bytes(AES_BLOCK_SIZE)
    else:
        aes_iv = _coerce_message_bytes(iv, name="AES IV")
        if len(aes_iv) != AES_BLOCK_SIZE:
            raise ProtectionConfigurationError("Nuwa AES protection requires a 16-byte IV")

    padder = padding.PKCS7(AES_BLOCK_SIZE * 8).padder()
    padded = padder.update(message) + padder.finalize()
    encryptor = Cipher(
        algorithms.AES(normalized_key),
        modes.CBC(aes_iv),
    ).encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    authenticated_body = aes_iv + ciphertext
    tag = hmac.new(normalized_key, authenticated_body, hashlib.sha256).digest()
    return authenticated_body + tag


def unprotect_message(
    profile: str,
    key: bytes | bytearray | memoryview | None,
    protected: bytes | bytearray | memoryview,
) -> bytes:
    """Reverse one selected profile, authenticating before AES decryption."""

    normalized_key = _validate_key(profile, key)
    message = _coerce_message_bytes(protected, name="protected message")

    if profile == PROTECTION_NONE:
        return message

    assert normalized_key is not None
    if profile == PROTECTION_XOR_V1:
        return bytes(
            value ^ normalized_key[index % KEY_SIZE]
            for index, value in enumerate(message)
        )

    if profile == PROTECTION_HMAC_SHA256_V1:
        if len(message) < HMAC_SIZE:
            raise _authentication_failure()
        plaintext = message[:-HMAC_SIZE]
        received_tag = message[-HMAC_SIZE:]
        expected_tag = hmac.new(normalized_key, plaintext, hashlib.sha256).digest()
        if not hmac.compare_digest(received_tag, expected_tag):
            raise _authentication_failure()
        return plaintext

    if len(message) < AES_BLOCK_SIZE + AES_BLOCK_SIZE + HMAC_SIZE:
        raise _authentication_failure()
    authenticated_body = message[:-HMAC_SIZE]
    received_tag = message[-HMAC_SIZE:]
    expected_tag = hmac.new(
        normalized_key,
        authenticated_body,
        hashlib.sha256,
    ).digest()
    if not hmac.compare_digest(received_tag, expected_tag):
        raise _authentication_failure()

    ciphertext = authenticated_body[AES_BLOCK_SIZE:]
    if not ciphertext or len(ciphertext) % AES_BLOCK_SIZE != 0:
        raise _authentication_failure()
    aes_iv = authenticated_body[:AES_BLOCK_SIZE]
    try:
        decryptor = Cipher(
            algorithms.AES(normalized_key),
            modes.CBC(aes_iv),
        ).decryptor()
        padded = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = padding.PKCS7(AES_BLOCK_SIZE * 8).unpadder()
        return unpadder.update(padded) + unpadder.finalize()
    except ValueError as exc:
        raise _authentication_failure() from exc


def _record_field(record: Any, object_name: str, mapping_name: str) -> Any:
    if isinstance(record, dict):
        if mapping_name in record:
            return record[mapping_name]
        return record.get(object_name)
    return getattr(record, object_name, None)


def _key_is_absent(value: Any) -> bool:
    return value is None or value == b""


def resolve_crypto_selection(
    crypto_keys: Sequence[Any] | None,
    *,
    direction: Literal["outbound", "inbound"] | str,
) -> ProtectionSelection:
    """Resolve the single non-probed profile and directional Mythic key.

    Mythic-to-agent messages use ``EncKey``. Agent-to-Mythic messages use
    ``DecKey``. The keyless historical ``aes256_hmac`` value remains plaintext
    because old Nuwa payload records could contain that unused shared default.
    Mythic's RSA staging handler reuses that value with a runtime key, so an
    exact 32-byte directional key narrowly aliases the versioned AES/HMAC wire
    profile.
    """

    if direction not in {"outbound", "inbound"}:
        raise ProtectionConfigurationError("Invalid Nuwa protection direction")

    records = list(crypto_keys or [])
    if not records:
        return ProtectionSelection()
    if len(records) != 1:
        raise ProtectionConfigurationError(
            "Nuwa requires exactly zero or one crypto-key record"
        )

    record = records[0]
    value = _record_field(record, "Value", "value")
    if not isinstance(value, str):
        raise ProtectionConfigurationError("Nuwa crypto-key record has no profile value")
    profile = value.strip()
    enc_key = _record_field(record, "EncKey", "enc_key")
    dec_key = _record_field(record, "DecKey", "dec_key")

    if profile == PROTECTION_NONE:
        if not _key_is_absent(enc_key) or not _key_is_absent(dec_key):
            raise ProtectionConfigurationError(
                "Nuwa plaintext protection must not have key material"
            )
        return ProtectionSelection()

    if profile == HISTORICAL_AES256_HMAC:
        if _key_is_absent(enc_key) and _key_is_absent(dec_key):
            return ProtectionSelection()

        # Mythic names RSA-staged and callback keys ``aes256_hmac``. Treat only
        # the exact runtime directional key as Nuwa's versioned AES/HMAC bytes;
        # keyless historical payload records above deliberately stay plaintext.
        directional_key = enc_key if direction == "outbound" else dec_key
        normalized_key = _validate_key(
            PROTECTION_AES256_HMAC_V1,
            directional_key,
        )
        return ProtectionSelection(
            profile=PROTECTION_AES256_HMAC_V1,
            key=normalized_key,
        )

    if profile not in PROTECTED_PROFILES:
        raise ProtectionConfigurationError(
            f"Unsupported Nuwa protection profile: {profile}"
        )

    directional_key = enc_key if direction == "outbound" else dec_key
    normalized_key = _validate_key(profile, directional_key)
    return ProtectionSelection(profile=profile, key=normalized_key)


__all__ = [
    "AES_BLOCK_SIZE",
    "AUTHENTICATION_ERROR",
    "HISTORICAL_AES256_HMAC",
    "HMAC_SIZE",
    "KEY_SIZE",
    "PROTECTED_PROFILES",
    "PROTECTION_AES256_HMAC_V1",
    "PROTECTION_HMAC_SHA256_V1",
    "PROTECTION_NONE",
    "PROTECTION_XOR_V1",
    "ProtectionAuthenticationError",
    "ProtectionConfigurationError",
    "ProtectionError",
    "ProtectionSelection",
    "protect_message",
    "resolve_crypto_selection",
    "unprotect_message",
]
