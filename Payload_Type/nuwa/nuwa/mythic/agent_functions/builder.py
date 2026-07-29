from __future__ import annotations

import json
import pathlib
from dataclasses import dataclass
from types import SimpleNamespace
from typing import Any


try:
    from mythic_container.PayloadBuilder import (
        BuildParameter,
        BuildParameterType,
        BuildResponse,
        BuildStatus,
        BuildStep,
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
DEFAULT_COMMANDS = ["sleep", "cd", "whoami", "hostname", "exit", "ls", "shell", "upload", "download"]


@dataclass(frozen=True)
class SelectedC2Profile:
    name: str
    parameters: dict[str, Any]


def _read_text(path: pathlib.Path) -> str:
    return path.read_text(encoding="utf-8").strip() + "\n"


def _ps_literal(value: Any) -> str:
    if isinstance(value, bool):
        return "$true" if value else "$false"
    if value is None:
        return "$null"
    if isinstance(value, (int, float)):
        return str(value)
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


def _base_config(
    *,
    payload_uuid: str,
    c2_profile_name: str,
    c2_parameters: dict[str, Any],
    codec_profile: str,
    debug_logging: bool,
) -> dict[str, Any]:
    return {
        "PayloadUUID": payload_uuid,
        "C2Profile": c2_profile_name,
        "CallbackInterval": int(c2_parameters.get("callback_interval", 3)),
        "CallbackJitter": int(c2_parameters.get("callback_jitter", 30)),
        "ProxyHost": str(c2_parameters.get("proxy_host", "")),
        "ProxyPort": str(c2_parameters.get("proxy_port", "")),
        "ProxyUser": str(c2_parameters.get("proxy_user", "")),
        "ProxyPass": str(c2_parameters.get("proxy_pass", "")),
        "Killdate": str(c2_parameters.get("killdate", "")),
        "CodecProfile": codec_profile,
        "DebugLogging": bool(debug_logging),
        "MessageUuidLength": 36,
    }


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
) -> str:
    config = _base_config(
        payload_uuid=payload_uuid,
        c2_profile_name=c2_profile_name,
        c2_parameters=c2_parameters,
        codec_profile=codec_profile,
        debug_logging=debug_logging,
    )
    config.update(_profile_config(c2_profile_name, c2_parameters))

    sections = [
        "$script:NuwaConfig = " + _ps_hashtable(config),
        "$script:NuwaState = @{ \"CurrentDirectory\" = (Get-Location).Path; \"ExitRequested\" = $false }",
        _read_text(BASE_CODE_ROOT / "utf8.ps1"),
        _read_text(BASE_CODE_ROOT / "base64.ps1"),
        _read_text(BASE_CODE_ROOT / "transport.ps1"),
        _read_text(BASE_CODE_ROOT / "runtime_helpers.ps1"),
        _read_text(BASE_CODE_ROOT / "codec_dispatch.ps1"),
        _read_text(CODEC_ROOT / f"{codec_profile}.ps1"),
        _read_text(PROFILE_ROOT / c2_profile_name / "transport.ps1"),
    ]

    selected_commands = command_names or list(DEFAULT_COMMANDS)
    for command_name in selected_commands:
        command_path = COMMAND_ROOT / f"{command_name}.ps1"
        if command_path.exists():
            sections.append(_read_text(command_path))

    sections.append(_read_text(BASE_CODE_ROOT / "agent_main.ps1"))
    return "\n\n".join(sections) + "\n"


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
    build_parameters = [
        BuildParameter(
            name="codec_profile",
            parameter_type=BuildParameterType.ChooseOne,
            choices=["decimal"],
            default_value="decimal",
            description="Nuwa wire codec profile",
        ),
        BuildParameter(
            name="debug_logging",
            parameter_type=BuildParameterType.Boolean,
            default_value=False,
            description="Enable debug output in the payload",
        ),
    ]

    async def build(self) -> BuildResponse:
        response = BuildResponse(status=BuildStatus.Success)
        try:
            selected_c2 = _resolve_selected_c2_profile(self.c2info)
            payload_source = render_payload_source(
                payload_uuid=self.uuid,
                c2_profile_name=selected_c2.name,
                c2_parameters=selected_c2.parameters,
                codec_profile=str(self.get_parameter("codec_profile") or "decimal"),
                debug_logging=bool(self.get_parameter("debug_logging")),
                command_names=list(self.commands.get_commands()),
            )
            response.payload = payload_source.encode("utf-8")
            response.build_message = "Successfully built Nuwa PowerShell payload"
        except Exception as exc:  # pragma: no cover - exercised in integration
            response.set_status(BuildStatus.Error)
            response.build_stderr = str(exc)
        return response


__all__ = [
    "BuildParameter",
    "BuildParameterType",
    "BuildResponse",
    "BuildStatus",
    "Nuwa",
    "PayloadType",
    "SupportedOS",
    "render_payload_source",
]
