$script:NuwaTransportEnvelopeMaximumDocumentBytes = 2097152
$script:NuwaTransportEnvelopeMaximumWrapperBytes = 524288

function Get-NuwaTransportEnvelopeProperty {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$Object,
        [Parameter(Mandatory = $true)]
        [string]$Name
    )
    if ($null -eq $Object) { return $null }
    if ($Object -is [System.Collections.IDictionary]) {
        if ($Object.Contains($Name)) { return $Object[$Name] }
        return $null
    }
    try { return $Object.$Name } catch { return $null }
}

function Join-NuwaTransportBytes {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][object[]]$Parts)
    [int64]$length = 0
    foreach ($part in $Parts) {
        if ($null -eq $part -or $part -isnot [byte[]]) { throw 'Transport byte part is invalid' }
        $length += $part.Length
        if ($length -gt $script:NuwaTransportEnvelopeMaximumDocumentBytes) {
            throw 'Transport envelope exceeds the byte limit'
        }
    }
    $result = New-Object byte[] ([int]$length)
    $offset = 0
    foreach ($part in $Parts) {
        for ($index = 0; $index -lt $part.Length; $index += 1) {
            $result[$offset + $index] = $part[$index]
        }
        $offset += $part.Length
    }
    return ,$result
}

function Copy-NuwaTransportBytes {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][byte[]]$Bytes,
        [Parameter(Mandatory = $true)][int]$Offset,
        [Parameter(Mandatory = $true)][int]$Length
    )
    if ($Offset -lt 0 -or $Length -lt 0 -or $Offset -gt $Bytes.Length -or $Length -gt ($Bytes.Length - $Offset)) {
        throw 'Transport byte slice is invalid'
    }
    $result = New-Object byte[] $Length
    for ($index = 0; $index -lt $Length; $index += 1) {
        $result[$index] = $Bytes[$Offset + $index]
    }
    return ,$result
}

function Get-NuwaTransportEntropy {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][int]$Count,
        [Parameter(Mandatory = $false)][hashtable]$Context = @{}
    )
    if ($Count -lt 0 -or $Count -gt 64) { throw 'Transport entropy length is invalid' }
    if ($null -ne $Context -and $Context.ContainsKey('entropy_bytes')) {
        $provided = [byte[]]$Context.entropy_bytes
        if ($provided.Length -ne $Count) { throw 'Transport test entropy length is invalid' }
        return ,(Copy-NuwaTransportBytes -Bytes $provided -Offset 0 -Length $provided.Length)
    }
    $result = New-Object byte[] $Count
    for ($index = 0; $index -lt $Count; $index += 1) {
        $result[$index] = [byte](Get-Random -Minimum 0 -Maximum 256)
    }
    return ,$result
}

function Get-NuwaTransportMasterKey {
    [CmdletBinding()]
    param()
    $key = [byte[]]$script:NuwaTransportEnvelopeState.MasterKey
    if ($null -eq $key -or $key.Length -ne 32) { throw 'Transport key is unavailable' }
    return ,$key
}

function Test-NuwaTransportWrapper {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][object]$Wrapper,
        [Parameter(Mandatory = $true)][string]$Direction
    )
    if ($Direction -notin @('agent-to-server', 'server-to-agent')) { return $false }
    $allowed = @('message','sender_id','to_server','client_id','message_format','id','final','envelope_version','envelope_codec')
    $names = @($Wrapper.PSObject.Properties.Name)
    if ($Wrapper -is [System.Collections.IDictionary]) { $names = @($Wrapper.Keys) }
    foreach ($name in $names) { if ($allowed -notcontains [string]$name) { return $false } }
    foreach ($required in @('message','sender_id','to_server','id','final','envelope_version','envelope_codec')) {
        if ($names -notcontains $required) { return $false }
    }
    $message = Get-NuwaTransportEnvelopeProperty $Wrapper 'message'
    $sender = Get-NuwaTransportEnvelopeProperty $Wrapper 'sender_id'
    $toServer = Get-NuwaTransportEnvelopeProperty $Wrapper 'to_server'
    $client = Get-NuwaTransportEnvelopeProperty $Wrapper 'client_id'
    $format = Get-NuwaTransportEnvelopeProperty $Wrapper 'message_format'
    $id = Get-NuwaTransportEnvelopeProperty $Wrapper 'id'
    $final = Get-NuwaTransportEnvelopeProperty $Wrapper 'final'
    $version = Get-NuwaTransportEnvelopeProperty $Wrapper 'envelope_version'
    $presentation = Get-NuwaTransportEnvelopeProperty $Wrapper 'envelope_codec'
    if ($message -isnot [string] -or $sender -isnot [string] -or $sender -cnotmatch '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$') { return $false }
    if ($toServer -isnot [bool] -or $id -ne 1 -or $final -isnot [bool] -or -not $final -or $version -ne 1) { return $false }
    if ($presentation -isnot [string] -or $presentation -cne [string]$script:NuwaConfig.TransportPresentation) { return $false }
    if ($null -ne $format -and ($format -isnot [string] -or $format -cne 'raw-v1')) { return $false }
    if ($Direction -eq 'agent-to-server') {
        if (-not $toServer -or $names -contains 'client_id') { return $false }
        $route = $sender
    } else {
        if ($toServer -or $client -isnot [string] -or $client -cnotmatch '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$') { return $false }
        $route = $client
    }
    if ($format -ceq 'raw-v1' -and ($message.Length -lt 36 -or $message.Substring(0, 36) -cne $route)) { return $false }
    return $true
}

function ConvertTo-NuwaTransportEnvelopeDocument {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][hashtable]$Wrapper,
        [Parameter(Mandatory = $true)][string]$Direction,
        [Parameter(Mandatory = $false)][hashtable]$Context = @{}
    )
    $ordered = [ordered]@{
        message = [string]$Wrapper.message
        sender_id = [string]$Wrapper.sender_id
        to_server = [bool]$Wrapper.to_server
    }
    if ($Wrapper.ContainsKey('client_id')) { $ordered.client_id = [string]$Wrapper.client_id }
    if ($Wrapper.ContainsKey('message_format')) { $ordered.message_format = [string]$Wrapper.message_format }
    $ordered.id = 1
    $ordered.final = $true
    $ordered.envelope_version = 1
    $ordered.envelope_codec = [string]$script:NuwaConfig.TransportPresentation
    if (-not (Test-NuwaTransportWrapper -Wrapper $ordered -Direction $Direction)) { throw 'Transport wrapper is invalid' }
    $json = $ordered | ConvertTo-Json -Compress -Depth 4
    $plain = [byte[]](ConvertTo-NuwaUtf8Bytes -Value $json)
    if ($plain.Length -gt $script:NuwaTransportEnvelopeMaximumWrapperBytes) { throw 'Transport wrapper exceeds the byte limit' }
    $packet = Protect-NuwaTransportEnvelopeBytes -Bytes $plain -Direction $Direction -Context $Context
    return ConvertTo-NuwaTransportPresentation -Bytes $packet
}

function ConvertFrom-NuwaTransportEnvelopeDocument {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Value,
        [Parameter(Mandatory = $true)][string]$Direction
    )
    $documentBytes = [byte[]](ConvertTo-NuwaUtf8Bytes -Value $Value)
    if ($documentBytes.Length -gt $script:NuwaTransportEnvelopeMaximumDocumentBytes) { throw 'Transport envelope exceeds the byte limit' }
    $packet = [byte[]](ConvertFrom-NuwaTransportPresentation -Value $Value)
    $plain = [byte[]](Unprotect-NuwaTransportEnvelopeBytes -Bytes $packet -Direction $Direction)
    if ($plain.Length -gt $script:NuwaTransportEnvelopeMaximumWrapperBytes) { throw 'Transport wrapper exceeds the byte limit' }
    $json = ConvertFrom-NuwaUtf8Bytes -Bytes $plain
    $wrapper = $json | ConvertFrom-Json -ErrorAction Stop
    if (-not (Test-NuwaTransportWrapper -Wrapper $wrapper -Direction $Direction)) { throw 'Transport wrapper is invalid' }
    return $wrapper
}
