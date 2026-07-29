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


class ShellArguments(TaskArguments):
    def __init__(self, command_line: str, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="command",
                type=ParameterType.String,
                description="PowerShell command to execute",
            )
        ]

    async def parse_arguments(self):
        if not self.command_line:
            raise ValueError("Must supply a PowerShell command")
        self.add_arg("command", self.command_line)


class ShellCommand(CommandBase):
    cmd = "shell"
    needs_admin = False
    help_cmd = "shell <powershell command>"
    description = "Execute a PowerShell command"
    version = 1
    author = "@openai"
    argument_class = ShellArguments
    attributes = CommandAttributes(supported_os=[SupportedOS.Windows])

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        return PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
            DisplayParams=taskData.args.get_arg("command"),
        )

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
