from __future__ import annotations

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


class UploadArguments(TaskArguments):
    def __init__(self, command_line: str, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(name="file", type=ParameterType.File, description="Mythic file identifier"),
            CommandParameter(name="remote_path", type=ParameterType.String, description="Remote output path"),
        ]

    async def parse_arguments(self):
        raise ValueError("Use named arguments or the upload modal")

    async def parse_dictionary(self, dictionary_arguments):
        self.load_args_from_dictionary(dictionary_arguments)
        remote_dir = dictionary_arguments.get("path", "")
        remote_name = dictionary_arguments.get("filename", "")
        if remote_dir and remote_name:
            self.add_arg("remote_path", ntpath.join(remote_dir, remote_name))


class UploadCommand(CommandBase):
    cmd = "upload"
    needs_admin = False
    help_cmd = "upload"
    description = "Upload a file to the target"
    version = 1
    author = "@openai"
    supported_ui_features = ["file_browser:upload"]
    argument_class = UploadArguments
    attributes = CommandAttributes(supported_os=[SupportedOS.Windows])

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        display = taskData.args.get_arg("remote_path") or ""
        return PTTaskCreateTaskingMessageResponse(TaskID=taskData.Task.ID, Success=True, DisplayParams=display)

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
