function Test-NuwaTransportFrameRoute {
    param([Parameter(Mandatory = $true)][byte[]]$Message, [Parameter(Mandatory = $true)][string]$Route)
    return $Message.Length -ge 36 -and (ConvertFrom-NuwaUtf8Bytes -Bytes (Copy-NuwaTransportBytes -Bytes $Message -Offset 0 -Length 36)) -ceq $Route
}

function New-NuwaTransportRequestBody {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Uuid, [Parameter(Mandatory = $true)][byte[]]$WireBody)
    return ,([byte[]](Join-NuwaTransportBytes -Parts @([byte[]](ConvertTo-NuwaUtf8Bytes -Value $Uuid), $WireBody)))
}

function Get-NuwaTransportResponseCandidates {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][byte[]]$ResponseBody, [Parameter(Mandatory = $true)][string]$ExpectedUuid, [Parameter(Mandatory = $true)][int]$UuidLength)
    if ($ResponseBody.Length -lt $UuidLength) { throw 'Transport response is shorter than its UUID route' }
    $route = ConvertFrom-NuwaUtf8Bytes -Bytes (Copy-NuwaTransportBytes -Bytes $ResponseBody -Offset 0 -Length $UuidLength)
    if ($route -cne $ExpectedUuid) { throw 'Transport response UUID does not match the expected route' }
    $wireBytes = Copy-NuwaTransportBytes -Bytes $ResponseBody -Offset $UuidLength -Length ($ResponseBody.Length - $UuidLength)
    return @(@{ Framing = 'raw-v1'; WireBody = [byte[]]$wireBytes; WireBytes = [byte[]]$wireBytes; Uuid = $route })
}
