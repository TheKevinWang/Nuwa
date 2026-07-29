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


class ExitArguments(TaskArguments):
    def __init__(self, command_line: str, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = []

    async def parse_arguments(self):
        return None


class ExitCommand(CommandBase):
    cmd = "exit"
    needs_admin = False
    help_cmd = "exit"
    description = "Terminate the agent"
    version = 1
    author = "@openai"
    supported_ui_features = ["callback_table:exit"]
    is_exit = True
    argument_class = ExitArguments
    attributes = CommandAttributes(supported_os=[SupportedOS.Windows])

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        return PTTaskCreateTaskingMessageResponse(TaskID=taskData.Task.ID, Success=True)

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
