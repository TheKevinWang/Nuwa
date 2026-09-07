$script:NuwaTransportXorSaltLength = 8

function Invoke-NuwaTransportXor {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][byte[]]$Bytes,
        [Parameter(Mandatory = $true)][byte[]]$Key,
        [Parameter(Mandatory = $true)][byte[]]$Salt
    )
    if ($Key.Length -ne 32 -or $Salt.Length -ne $script:NuwaTransportXorSaltLength) { throw 'Transport XOR input is invalid' }
    $result = New-Object byte[] $Bytes.Length
    for ($index = 0; $index -lt $Bytes.Length; $index += 1) {
        $saltByte = [int]$Salt[$index % $Salt.Length]
        $mask = ([int]$Key[($index + $saltByte) % 32]) -bxor $saltByte
        $result[$index] = [byte](([int]$Bytes[$index]) -bxor $mask)
    }
    return ,$result
}

function Protect-NuwaTransportEnvelopeBytes {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][byte[]]$Bytes,
        [Parameter(Mandatory = $true)][string]$Direction,
        [Parameter(Mandatory = $false)][hashtable]$Context = @{}
    )
    $salt = Get-NuwaTransportEntropy -Count $script:NuwaTransportXorSaltLength -Context $Context
    $body = Invoke-NuwaTransportXor -Bytes $Bytes -Key (Get-NuwaTransportDirectionKey $Direction) -Salt $salt
    return ,(Join-NuwaTransportBytes -Parts @([object]$salt, [object]$body))
}

function Unprotect-NuwaTransportEnvelopeBytes {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][byte[]]$Bytes,
        [Parameter(Mandatory = $true)][string]$Direction
    )
    if ($Bytes.Length -lt $script:NuwaTransportXorSaltLength) { throw 'Transport envelope is invalid' }
    $salt = Copy-NuwaTransportBytes $Bytes 0 $script:NuwaTransportXorSaltLength
    $body = Copy-NuwaTransportBytes $Bytes $script:NuwaTransportXorSaltLength ($Bytes.Length - $script:NuwaTransportXorSaltLength)
    return ,(Invoke-NuwaTransportXor -Bytes $body -Key (Get-NuwaTransportDirectionKey $Direction) -Salt $salt)
}
