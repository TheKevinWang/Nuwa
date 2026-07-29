from __future__ import annotations

import json
import ntpath

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


class LsArguments(TaskArguments):
    def __init__(self, command_line: str, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [CommandParameter(name="path", type=ParameterType.String, description="Path to list")]

    async def parse_arguments(self):
        if not self.command_line:
            self.add_arg("path", ".")
            return
        if self.command_line.startswith("{"):
            temp_json = json.loads(self.command_line)
            if "file" in temp_json:
                self.add_arg("path", ntpath.join(temp_json["path"], temp_json["file"]))
            else:
                self.add_arg("path", temp_json["path"])
            return
        self.add_arg("path", self.command_line)


class LsCommand(CommandBase):
    cmd = "ls"
    needs_admin = False
    help_cmd = "ls [path]"
    description = "List a file or directory"
    version = 1
    author = "@openai"
    supported_ui_features = ["file_browser:list"]
    argument_class = LsArguments
    attributes = CommandAttributes(supported_os=[SupportedOS.Windows])

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        return PTTaskCreateTaskingMessageResponse(TaskID=taskData.Task.ID, Success=True, DisplayParams=taskData.args.get_arg("path"))

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
