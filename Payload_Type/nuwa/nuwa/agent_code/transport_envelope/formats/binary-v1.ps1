$script:NuwaBinaryV1HeaderLength = 37

function ConvertTo-NuwaTransportEnvelopeBytes {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$Wrapper, [Parameter(Mandatory = $true)][string]$Direction)
    $toServer = $Direction -eq 'agent-to-server'
    if (-not $toServer -and $Direction -ne 'server-to-agent') { throw 'Binary transport direction is invalid' }
    if ([bool]$Wrapper.to_server -ne $toServer) { throw 'Binary transport direction mismatch' }
    $route = if ($toServer) { [string]$Wrapper.sender_id } else { [string]$Wrapper.client_id }
    if ($route -cnotmatch '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$') { throw 'Binary transport route is not canonical' }
    $message = [byte[]]$Wrapper.message
    if ($message.Length -eq 0) { throw 'Binary transport message is empty' }
    $raw = [string]$script:NuwaConfig.TransportMessageFormat -eq 'raw-v1'
    if (-not (Test-NuwaTransportFrameRoute -Message $message -Route $route)) { throw 'Binary transport message UUID does not match its route' }
    [byte]$flags = if ($toServer) { 1 } else { 0 }
    if ($raw) { $flags = [byte]($flags -bor 2) }
    return ,([byte[]](Join-NuwaTransportBytes -Parts @([byte[]]@($flags), [byte[]](ConvertTo-NuwaUtf8Bytes -Value $route), $message)))
}

function ConvertFrom-NuwaTransportEnvelopeBytes {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][byte[]]$Bytes, [Parameter(Mandatory = $true)][string]$ExpectedDirection)
    if ($Bytes.Length -le $script:NuwaBinaryV1HeaderLength) { throw 'Binary transport envelope is too short' }
    $flags = [byte]$Bytes[0]
    if (($flags -band 252) -ne 0) { throw 'Binary transport envelope has reserved flag bits' }
    $toServer = ($flags -band 1) -ne 0
    if ($toServer -ne ($ExpectedDirection -eq 'agent-to-server')) { throw 'Binary transport direction mismatch' }
    $raw = ($flags -band 2) -ne 0
    if ($raw -ne ([string]$script:NuwaConfig.TransportMessageFormat -eq 'raw-v1')) { throw 'Binary transport framing mismatch' }
    $route = ConvertFrom-NuwaUtf8Bytes -Bytes (Copy-NuwaTransportBytes -Bytes $Bytes -Offset 1 -Length 36)
    if ($route -cnotmatch '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$') { throw 'Binary transport route is not canonical' }
    $message = [byte[]](Copy-NuwaTransportBytes -Bytes $Bytes -Offset 37 -Length ($Bytes.Length - 37))
    if (-not (Test-NuwaTransportFrameRoute -Message $message -Route $route)) { throw 'Binary transport message UUID does not match its route' }
    $result = @{ message = $message; sender_id = $route; to_server = $toServer; id = 1; final = $true }
    if (-not $toServer) { $result.client_id = $route }
    if ($raw) { $result.message_format = 'raw-v1' }
    return $result
}
