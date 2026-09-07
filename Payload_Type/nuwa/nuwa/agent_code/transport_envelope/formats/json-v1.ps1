function Test-NuwaJsonV1Uuid {
    param([string]$Value)
    return $Value -cmatch '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
}

function Test-NuwaJsonV1Wrapper {
    param([object]$Wrapper, [string]$Direction)
    $allowed = @('message','sender_id','to_server','client_id','message_format','id','final')
    $names = @($Wrapper.PSObject.Properties.Name)
    if ($Wrapper -is [System.Collections.IDictionary]) { $names = @($Wrapper.Keys) }
    foreach ($name in $names) { if ($allowed -notcontains [string]$name) { return $false } }
    foreach ($required in @('message','sender_id','to_server')) { if ($names -notcontains $required) { return $false } }
    $message = Get-NuwaTransportEnvelopeProperty $Wrapper 'message'
    $sender = Get-NuwaTransportEnvelopeProperty $Wrapper 'sender_id'
    $toServer = Get-NuwaTransportEnvelopeProperty $Wrapper 'to_server'
    $client = Get-NuwaTransportEnvelopeProperty $Wrapper 'client_id'
    $format = Get-NuwaTransportEnvelopeProperty $Wrapper 'message_format'
    $id = Get-NuwaTransportEnvelopeProperty $Wrapper 'id'
    $final = Get-NuwaTransportEnvelopeProperty $Wrapper 'final'
    if ($message -isnot [string] -or $sender -isnot [string] -or -not (Test-NuwaJsonV1Uuid $sender) -or $toServer -isnot [bool]) { return $false }
    if ($null -ne $id -and (($id -isnot [int] -and $id -isnot [long]) -or $id -ne 1)) { return $false }
    if ($null -ne $final -and ($final -isnot [bool] -or -not $final)) { return $false }
    if ($null -ne $format -and ($format -isnot [string] -or $format -cne 'raw-v1')) { return $false }
    if ($Direction -eq 'agent-to-server') { if (-not $toServer -or $names -contains 'client_id') { return $false }; $route = $sender }
    elseif ($Direction -eq 'server-to-agent') { if ($toServer -or $client -isnot [string] -or -not (Test-NuwaJsonV1Uuid $client)) { return $false }; $route = $client }
    else { return $false }
    $messageBytes = [byte[]](ConvertTo-NuwaUtf8Bytes -Value $message)
    if ($format -ceq 'raw-v1') {
        if ($messageBytes.Length -lt 36) { return $false }
        if ((ConvertFrom-NuwaUtf8Bytes -Bytes (Copy-NuwaTransportBytes -Bytes $messageBytes -Offset 0 -Length 36)) -cne $route) { return $false }
    }
    return $true
}

function ConvertTo-NuwaTransportEnvelopeBytes {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$Wrapper, [Parameter(Mandatory = $true)][string]$Direction)
    $messageText = ConvertFrom-NuwaUtf8Bytes -Bytes ([byte[]]$Wrapper.message)
    $ordered = [ordered]@{ message = $messageText; sender_id = [string]$Wrapper.sender_id; to_server = [bool]$Wrapper.to_server }
    if ($Wrapper.ContainsKey('client_id')) { $ordered.client_id = [string]$Wrapper.client_id }
    if ($Wrapper.ContainsKey('message_format')) { $ordered.message_format = [string]$Wrapper.message_format }
    $ordered.id = 1; $ordered.final = $true
    if (-not (Test-NuwaJsonV1Wrapper -Wrapper $ordered -Direction $Direction)) { throw 'JSON transport wrapper is invalid' }
    return ,([byte[]](ConvertTo-NuwaUtf8Bytes -Value ($ordered | ConvertTo-Json -Compress -Depth 4)))
}

function ConvertFrom-NuwaTransportEnvelopeBytes {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][byte[]]$Bytes, [Parameter(Mandatory = $true)][string]$ExpectedDirection)
    $json = ConvertFrom-NuwaUtf8Bytes -Bytes $Bytes
    if ($json.Length -lt 2 -or $json[0] -cne '{' -or $json[$json.Length - 1] -cne '}') { throw 'JSON transport wrapper has invalid boundaries' }
    foreach ($field in @('message','sender_id','to_server','client_id','message_format','id','final')) {
        if ([regex]::Matches($json, ('"' + [regex]::Escape($field) + '"\s*:')).Count -gt 1) { throw 'JSON transport wrapper contains duplicate fields' }
    }
    $wrapper = $json | ConvertFrom-Json -ErrorAction Stop
    if (-not (Test-NuwaJsonV1Wrapper -Wrapper $wrapper -Direction $ExpectedDirection)) { throw 'JSON transport wrapper is invalid' }
    $result = @{ message = [byte[]](ConvertTo-NuwaUtf8Bytes -Value ([string]$wrapper.message)); sender_id = [string]$wrapper.sender_id; to_server = [bool]$wrapper.to_server; id = 1; final = $true }
    if ($null -ne $wrapper.client_id) { $result.client_id = [string]$wrapper.client_id }
    if ($null -ne $wrapper.message_format) { $result.message_format = [string]$wrapper.message_format }
    return $result
}
