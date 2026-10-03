"""Resolve one message route to its durable payload control profile."""

from __future__ import annotations

from typing import Any, Awaitable, Callable

from .control_identifiers_v3 import (
    ResolvedControlProfile, load_default_profile, resolve_control_profile,
)


ROUTE_LOOKUP_QUEUE = "mythic_rpc_message_route_payload_lookup"
RouteCall = Callable[[str], Awaitable[dict[str, Any]]]
PayloadCall = Callable[[str], Awaitable[Any]]
FileCall = Callable[[str], Awaitable[bytes]]


async def _route_call(route_uuid: str) -> dict[str, Any]:
    import mythic_container
    return await mythic_container.RabbitmqConnection.SendRPCDictMessage(
        queue=ROUTE_LOOKUP_QUEUE, body={"route_uuid": route_uuid},
    )


async def _payload_call(payload_uuid: str) -> Any:
    from mythic_container.MythicGoRPC import (
        MythicRPCPayloadSearchMessage, SendMythicRPCPayloadSearch,
    )
    response = await SendMythicRPCPayloadSearch(
        MythicRPCPayloadSearchMessage(PayloadUUID=payload_uuid)
    )
    if not response.Success or len(response.Payloads) != 1:
        raise ValueError(f"Nuwa payload {payload_uuid} is unavailable: {response.Error}")
    return response.Payloads[0]


async def _file_call(file_id: str) -> bytes:
    from mythic_container.MythicGoRPC import (
        MythicRPCFileGetContentMessage, SendMythicRPCFileGetContent,
    )
    response = await SendMythicRPCFileGetContent(
        MythicRPCFileGetContentMessage(AgentFileId=file_id)
    )
    if not response.Success or not isinstance(response.Content, bytes):
        raise ValueError(f"Nuwa control_id_file {file_id} is unavailable")
    return response.Content


async def resolve_profile_for_route(
    route_uuid: str, *, route_call: RouteCall = _route_call,
    payload_call: PayloadCall = _payload_call, file_call: FileCall = _file_call,
) -> ResolvedControlProfile:
    # Route authority is checked for every message. No route-to-payload cache
    # may survive a callback deletion.
    route = await route_call(route_uuid)
    if not isinstance(route, dict) or not route.get("success"):
        error = route.get("error", "lookup failed") if isinstance(route, dict) else "invalid reply"
        raise ValueError(f"Nuwa route {route_uuid} is unavailable: {error}")
    payload_uuid = route.get("payload_uuid")
    if not isinstance(payload_uuid, str):
        raise ValueError("Nuwa route lookup did not return a payload UUID")
    payload = await payload_call(payload_uuid)
    if payload.PayloadType != "nuwa" or payload.UUID != payload_uuid:
        raise ValueError("Nuwa route resolved to a different payload type or UUID")
    parameters = {item.Name: item.Value for item in (payload.BuildParameters or [])}
    mode = str(parameters.get("control_id_mode") or "default")
    # Historical random payloads have no saved style and used the wide mapping.
    random_style = str(parameters.get("control_id_random_style") or "wide")
    file_id = parameters.get("control_id_file")
    content = None
    if mode == "custom":
        if not isinstance(file_id, str) or not file_id:
            raise ValueError("Nuwa custom payload has no control_id_file ID")
        content = await file_call(file_id)
    elif file_id:
        raise ValueError("Nuwa control_id_file is only valid in custom mode")
    return resolve_control_profile(load_default_profile(), mode, payload_uuid, content,
                                   random_style=random_style)
