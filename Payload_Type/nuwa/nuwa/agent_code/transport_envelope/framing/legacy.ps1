function Test-NuwaTransportFrameRoute {
    param([Parameter(Mandatory = $true)][byte[]]$Message, [Parameter(Mandatory = $true)][string]$Route)
    try { $frame = [byte[]](ConvertFrom-NuwaBase64String -Value (ConvertFrom-NuwaUtf8Bytes -Bytes $Message)) } catch { return $false }
    return $frame.Length -ge 36 -and (ConvertFrom-NuwaUtf8Bytes -Bytes (Copy-NuwaTransportBytes -Bytes $frame -Offset 0 -Length 36)) -ceq $Route
}

function New-NuwaTransportRequestBody {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Uuid, [Parameter(Mandatory = $true)][byte[]]$WireBody)
    $frame = [byte[]](Join-NuwaTransportBytes -Parts @([byte[]](ConvertTo-NuwaUtf8Bytes -Value $Uuid), $WireBody))
    return ,([byte[]](ConvertTo-NuwaUtf8Bytes -Value (ConvertTo-NuwaBase64String -Bytes $frame)))
}

function Get-NuwaTransportResponseCandidates {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][byte[]]$ResponseBody, [Parameter(Mandatory = $true)][string]$ExpectedUuid, [Parameter(Mandatory = $true)][int]$UuidLength)
    $frame = [byte[]](ConvertFrom-NuwaBase64String -Value (ConvertFrom-NuwaUtf8Bytes -Bytes $ResponseBody))
    if ($frame.Length -lt $UuidLength) { throw 'Transport response is shorter than its UUID route' }
    $route = ConvertFrom-NuwaUtf8Bytes -Bytes (Copy-NuwaTransportBytes -Bytes $frame -Offset 0 -Length $UuidLength)
    if ($route -cne $ExpectedUuid) { throw 'Transport response UUID does not match the expected route' }
    $wireBytes = Copy-NuwaTransportBytes -Bytes $frame -Offset $UuidLength -Length ($frame.Length - $UuidLength)
    return @(@{ Framing = 'legacy'; WireBody = [byte[]]$wireBytes; WireBytes = [byte[]]$wireBytes; Uuid = $route })
}
