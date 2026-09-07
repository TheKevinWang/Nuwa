$script:NuwaTransportEnvelopeMaximumDocumentBytes = 2097152
$script:NuwaTransportEnvelopeMaximumWrapperBytes = 524288

function Get-NuwaTransportEnvelopeProperty {
    [CmdletBinding()]
    param([AllowNull()][object]$Object, [Parameter(Mandatory = $true)][string]$Name)
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
        if ($length -gt $script:NuwaTransportEnvelopeMaximumDocumentBytes) { throw 'Transport envelope exceeds the byte limit' }
    }
    $result = New-Object byte[] ([int]$length)
    $offset = 0
    foreach ($part in $Parts) {
        for ($index = 0; $index -lt $part.Length; $index += 1) { $result[$offset + $index] = $part[$index] }
        $offset += $part.Length
    }
    return ,$result
}

function Copy-NuwaTransportBytes {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][byte[]]$Bytes, [Parameter(Mandatory = $true)][int]$Offset, [Parameter(Mandatory = $true)][int]$Length)
    if ($Offset -lt 0 -or $Length -lt 0 -or $Offset -gt $Bytes.Length -or $Length -gt ($Bytes.Length - $Offset)) { throw 'Transport byte slice is invalid' }
    $result = New-Object byte[] $Length
    for ($index = 0; $index -lt $Length; $index += 1) { $result[$index] = $Bytes[$Offset + $index] }
    return ,$result
}

function Get-NuwaTransportEntropy {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][int]$Count, [hashtable]$Context = @{})
    if ($Count -lt 0 -or $Count -gt 64) { throw 'Transport entropy length is invalid' }
    if ($null -ne $Context -and $Context.ContainsKey('entropy_bytes')) {
        $provided = [byte[]]$Context.entropy_bytes
        if ($provided.Length -ne $Count) { throw 'Transport test entropy length is invalid' }
        return ,(Copy-NuwaTransportBytes -Bytes $provided -Offset 0 -Length $provided.Length)
    }
    $result = New-Object byte[] $Count
    for ($index = 0; $index -lt $Count; $index += 1) { $result[$index] = [byte](Get-Random -Minimum 0 -Maximum 256) }
    return ,$result
}

function Get-NuwaTransportMasterKey {
    [CmdletBinding()]
    param()
    $key = [byte[]]$script:NuwaTransportEnvelopeState.MasterKey
    if ($null -eq $key -or $key.Length -ne 32) { throw 'Transport key is unavailable' }
    return ,$key
}

function ConvertTo-NuwaTransportDocument {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)
    return ConvertTo-NuwaTransportPresentation -Bytes $Bytes
}

function ConvertFrom-NuwaTransportDocument {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Document)
    if ($Document.Length -eq 0) { throw 'Transport envelope document is empty' }
    $first = [int][char]$Document[0]
    $last = [int][char]$Document[$Document.Length - 1]
    if ($first -in @(9,10,11,12,13,32) -or $last -in @(9,10,11,12,13,32)) { throw 'Transport envelope has boundary whitespace' }
    for ($index = 0; $index -lt $Document.Length; $index += 1) {
        $code = [int][char]$Document[$index]
        if ($code -eq 0 -or $code -lt 32 -or $code -eq 127) { throw 'Transport envelope contains control characters' }
    }
    if ((ConvertTo-NuwaUtf8Bytes -Value $Document).Length -gt $script:NuwaTransportEnvelopeMaximumDocumentBytes) { throw 'Transport envelope exceeds the byte limit' }
    return ,([byte[]](ConvertFrom-NuwaTransportPresentation -Value $Document))
}

function ConvertTo-NuwaTransportEnvelopeDocument {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$Wrapper, [Parameter(Mandatory = $true)][string]$Direction, [hashtable]$Context = @{})
    $plain = [byte[]](ConvertTo-NuwaTransportEnvelopeBytes -Wrapper $Wrapper -Direction $Direction)
    if ($plain.Length -gt $script:NuwaTransportEnvelopeMaximumWrapperBytes) { throw 'Transport wrapper exceeds the byte limit' }
    $packet = [byte[]](Protect-NuwaTransportEnvelopeBytes -Bytes $plain -Direction $Direction -Context $Context)
    return ConvertTo-NuwaTransportDocument -Bytes $packet
}

function ConvertFrom-NuwaTransportEnvelopeDocument {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Value, [Parameter(Mandatory = $true)][string]$Direction)
    $packet = [byte[]](ConvertFrom-NuwaTransportDocument -Document $Value)
    $plain = [byte[]](Unprotect-NuwaTransportEnvelopeBytes -Bytes $packet -Direction $Direction)
    if ($plain.Length -gt $script:NuwaTransportEnvelopeMaximumWrapperBytes) { throw 'Transport wrapper exceeds the byte limit' }
    return ConvertFrom-NuwaTransportEnvelopeBytes -Bytes $plain -ExpectedDirection $Direction
}
