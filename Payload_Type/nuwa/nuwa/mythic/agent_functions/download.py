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


class DownloadArguments(TaskArguments):
    def __init__(self, command_line: str, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [CommandParameter(name="path", type=ParameterType.String, description="Remote file path")]

    async def parse_arguments(self):
        if not self.command_line:
            raise ValueError("Require a path to download")
        if self.command_line.startswith("{"):
            temp_json = json.loads(self.command_line)
            if "file" in temp_json:
                self.add_arg("path", temp_json["file"])
            else:
                self.add_arg("path", temp_json["path"])
            return
        self.add_arg("path", self.command_line.strip('"').strip("'"))


class DownloadCommand(CommandBase):
    cmd = "download"
    needs_admin = False
    help_cmd = "download <path>"
    description = "Download a remote file"
    version = 1
    author = "@openai"
    supported_ui_features = ["file_browser:download"]
    is_download_file = True
    argument_class = DownloadArguments
    attributes = CommandAttributes(supported_os=[SupportedOS.Windows])

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        return PTTaskCreateTaskingMessageResponse(TaskID=taskData.Task.ID, Success=True, DisplayParams=taskData.args.get_arg("path"))

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
