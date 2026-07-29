from __future__ import annotations

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


class CdArguments(TaskArguments):
    def __init__(self, command_line: str, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [CommandParameter(name="path", type=ParameterType.String, description="Target directory")]

    async def parse_arguments(self):
        if not self.command_line:
            raise ValueError("Must supply a path")
        if self.command_line.startswith("{"):
            self.load_args_from_json_string(self.command_line)
        else:
            self.add_arg("path", self.command_line)


class CdCommand(CommandBase):
    cmd = "cd"
    needs_admin = False
    help_cmd = "cd <path>"
    description = "Change the working directory"
    version = 1
    author = "@openai"
    argument_class = CdArguments
    attributes = CommandAttributes(supported_os=[SupportedOS.Windows])

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        return PTTaskCreateTaskingMessageResponse(TaskID=taskData.Task.ID, Success=True, DisplayParams=taskData.args.get_arg("path"))

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
