from __future__ import annotations

import json

from .command_base import (
    CommandAttributes,
    CommandBase,
    CommandParameter,
    ParameterType,
    PTTaskCreateTaskingMessageResponse,
    PTTaskMessageAllData,
    PTTaskProcessResponseMessageResponse,
    SupportedOS,
    TaskArguments,
)


class SleepArguments(TaskArguments):
    def __init__(self, command_line: str, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(name="interval", type=ParameterType.Number, description="Sleep interval in seconds"),
            CommandParameter(name="jitter", type=ParameterType.Number, description="Sleep jitter in percent", default_value=30),
        ]

    async def parse_arguments(self):
        if not self.command_line:
            raise ValueError("Must supply sleep interval")
        if self.command_line.startswith("{"):
            self.load_args_from_json_string(self.command_line)
            return
        pieces = self.command_line.split()
        if len(pieces) not in {1, 2}:
            raise ValueError("sleep expects one or two arguments")
        self.add_arg("interval", int(pieces[0]))
        self.add_arg("jitter", int(pieces[1]) if len(pieces) == 2 else 30)


class SleepCommand(CommandBase):
    cmd = "sleep"
    needs_admin = False
    help_cmd = "sleep <seconds> [jitter]"
    description = "Change the callback interval and jitter"
    version = 1
    author = "@openai"
    argument_class = SleepArguments
    attributes = CommandAttributes(supported_os=[SupportedOS.Windows])

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        display = f"{taskData.args.get_arg('interval')}s"
        if taskData.args.has_arg("jitter"):
            display += f" {taskData.args.get_arg('jitter')}%"
        return PTTaskCreateTaskingMessageResponse(TaskID=taskData.Task.ID, Success=True, DisplayParams=display)

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        if isinstance(response, str):
            json.loads(response)
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
