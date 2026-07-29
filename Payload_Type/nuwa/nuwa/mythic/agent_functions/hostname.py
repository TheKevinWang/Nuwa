from __future__ import annotations

from .command_base import (
    CommandAttributes,
    CommandBase,
    PTTaskCreateTaskingMessageResponse,
    PTTaskMessageAllData,
    PTTaskProcessResponseMessageResponse,
    SupportedOS,
    TaskArguments,
)


class HostnameArguments(TaskArguments):
    def __init__(self, command_line: str, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = []

    async def parse_arguments(self):
        return None


class HostnameCommand(CommandBase):
    cmd = "hostname"
    needs_admin = False
    help_cmd = "hostname"
    description = "Display the host name"
    version = 1
    author = "@openai"
    argument_class = HostnameArguments
    attributes = CommandAttributes(supported_os=[SupportedOS.Windows])

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        return PTTaskCreateTaskingMessageResponse(TaskID=taskData.Task.ID, Success=True)

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
