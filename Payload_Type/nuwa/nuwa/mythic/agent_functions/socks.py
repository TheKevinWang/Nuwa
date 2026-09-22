from __future__ import annotations

from .command_base import (
    CommandAttributes, CommandBase, CommandParameter, ParameterType,
    PTTaskCreateTaskingMessageResponse, PTTaskMessageAllData,
    PTTaskProcessResponseMessageResponse, SupportedOS, TaskArguments,
)

try:  # pragma: no cover - exercised in the Mythic container
    from mythic_container.MythicRPC import (
        MythicRPCProxyStartMessage, MythicRPCProxyStopMessage,
        SendMythicRPCProxyStartCommand, SendMythicRPCProxyStopCommand,
    )
except ImportError:  # local tests replace these callables
    MythicRPCProxyStartMessage = None
    MythicRPCProxyStopMessage = None
    SendMythicRPCProxyStartCommand = None
    SendMythicRPCProxyStopCommand = None


class SocksArguments(TaskArguments):
    def __init__(self, command_line: str, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(name="action", type=ParameterType.String,
                             description="start or stop"),
            CommandParameter(name="port", type=ParameterType.Number,
                             description="Local Mythic SOCKS5 port"),
        ]

    def _validate(self) -> None:
        action = str(self.get_arg("action") or "").strip().lower()
        if action not in {"start", "stop"}:
            raise ValueError("socks action must be start or stop")
        try:
            port = int(self.get_arg("port"))
        except (TypeError, ValueError) as exc:
            raise ValueError("socks port must be an integer") from exc
        if not 1 <= port <= 65535:
            raise ValueError("socks port must be between 1 and 65535")
        self.set_arg("action", action)
        self.set_arg("port", port)

    async def parse_arguments(self):
        line = (self.command_line or "").strip()
        if line.startswith("{"):
            self.load_args_from_json_string(line)
        else:
            parts = line.split()
            if len(parts) != 2:
                raise ValueError("socks expects start <port> or stop <port>")
            self.add_arg("action", parts[0])
            self.add_arg("port", parts[1])
        self._validate()

    async def parse_dictionary(self, dictionary_arguments):
        self.load_args_from_dictionary(dictionary_arguments)
        self._validate()


class SocksCommand(CommandBase):
    cmd = "socks"
    needs_admin = False
    help_cmd = "socks <start|stop> <port>"
    description = "Start or stop an optional FullLanguage DiscordX SOCKS5 listener"
    version = 1
    author = "@openai"
    argument_class = SocksArguments
    attributes = CommandAttributes(supported_os=[SupportedOS.Windows])

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        action = taskData.args.get_arg("action")
        port = int(taskData.args.get_arg("port"))
        if action == "start":
            request = MythicRPCProxyStartMessage(
                TaskID=taskData.Task.ID, PortType="socks", LocalPort=port,
            )
            result = await SendMythicRPCProxyStartCommand(request)
        else:
            request = MythicRPCProxyStopMessage(
                TaskID=taskData.Task.ID, PortType="socks", Port=port,
            )
            result = await SendMythicRPCProxyStopCommand(request)
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=bool(result.Success),
            DisplayParams=f"{action} SOCKS5 on port {port}",
        )
        if not result.Success:
            response.TaskStatus = "error"
            response.Stderr = str(result.Error)
            response.Completed = True
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
