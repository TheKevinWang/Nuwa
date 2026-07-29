from __future__ import annotations

import json
from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Any


try:  # pragma: no cover - exercised in container
    from mythic_container.MythicCommandBase import (  # type: ignore
        BrowserScript,
        CommandAttributes,
        CommandBase,
        CommandParameter,
        ParameterGroupInfo,
        ParameterType,
        PTTaskCreateTaskingMessageResponse,
        PTTaskMessageAllData,
        PTTaskProcessResponseMessageResponse,
        SupportedOS,
        TaskArguments,
    )
except ImportError:  # pragma: no cover - unit test fallback
    class SupportedOS:
        Windows = "Windows"

    class ParameterType:
        String = "String"
        Number = "Number"
        Boolean = "Boolean"
        File = "File"

    @dataclass
    class ParameterGroupInfo:
        required: bool = False
        ui_position: int | None = None
        group_name: str = "Default"

    @dataclass
    class CommandParameter:
        name: str
        type: str
        description: str = ""
        default_value: Any = None
        parameter_group_info: list[ParameterGroupInfo] = field(default_factory=list)

    @dataclass
    class CommandAttributes:
        supported_os: list[str] = field(default_factory=lambda: [SupportedOS.Windows])

    @dataclass
    class BrowserScript:
        script_name: str
        author: str = ""
        for_new_ui: bool = True

    @dataclass
    class PTTaskCreateTaskingMessageResponse:
        TaskID: int
        Success: bool
        DisplayParams: str = ""

    @dataclass
    class PTTaskProcessResponseMessageResponse:
        TaskID: int
        Success: bool

    class PTTaskMessageAllData(SimpleNamespace):
        pass

    class TaskArguments:
        def __init__(self, command_line: str, **kwargs):
            self.command_line = command_line
            self.raw_command_line = command_line
            self.args: list[CommandParameter] = []
            self._arg_values: dict[str, Any] = {}

        def add_arg(self, name: str, value: Any, type: str | None = None) -> None:
            self._arg_values[name] = value

        def set_arg(self, name: str, value: Any) -> None:
            self._arg_values[name] = value

        def get_arg(self, name: str) -> Any:
            return self._arg_values.get(name)

        def has_arg(self, name: str) -> bool:
            return name in self._arg_values

        def remove_arg(self, name: str) -> None:
            self._arg_values.pop(name, None)

        def load_args_from_json_string(self, value: str) -> None:
            self.load_args_from_dictionary(json.loads(value))

        def load_args_from_dictionary(self, dictionary_arguments: dict[str, Any]) -> None:
            for key, value in dictionary_arguments.items():
                self._arg_values[key] = value

    class CommandBase:
        pass


def make_task_data(task_id: int, **kwargs) -> PTTaskMessageAllData:
    return PTTaskMessageAllData(
        Task=SimpleNamespace(ID=task_id),
        args=SimpleNamespace(get_arg=lambda name: kwargs.get(name), has_arg=lambda name: name in kwargs),
    )


__all__ = [
    "BrowserScript",
    "CommandAttributes",
    "CommandBase",
    "CommandParameter",
    "ParameterGroupInfo",
    "ParameterType",
    "PTTaskCreateTaskingMessageResponse",
    "PTTaskMessageAllData",
    "PTTaskProcessResponseMessageResponse",
    "SupportedOS",
    "TaskArguments",
    "make_task_data",
]
