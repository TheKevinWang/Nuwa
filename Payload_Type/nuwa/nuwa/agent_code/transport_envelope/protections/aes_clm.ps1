if ($null -eq $script:NuwaCryptoState) {
    $script:NuwaCryptoState = @{}
}

function Get-NuwaTransportAesSubkey {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][byte[]]$Root, [Parameter(Mandatory = $true)][string]$Label)
    $labelBytes = [byte[]](ConvertTo-NuwaUtf8Bytes $Label)
    $inputBytes = Join-NuwaTransportBytes -Parts @([object]$Root, [object]([byte[]]@(0)), [object]$labelBytes)
    return ,(Get-NuwaClmSha256Digest $inputBytes)
}

function Protect-NuwaTransportAesBytes {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][byte[]]$Bytes, [Parameter(Mandatory = $true)][byte[]]$Key, [Parameter(Mandatory = $true)][byte[]]$InitializationVector)
    return ,(Protect-NuwaClmAes256CbcBytes -Bytes $Bytes -Key $Key -InitializationVector $InitializationVector)
}

function Protect-NuwaTransportEnvelopeBytes {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][byte[]]$Bytes, [Parameter(Mandatory = $true)][string]$Direction, [Parameter(Mandatory = $false)][hashtable]$Context = @{})
    $root = Get-NuwaTransportDirectionKey $Direction
    $encryptionKey = Get-NuwaTransportAesSubkey $root 'aes256-hmac-v1/encryption'
    $authenticationKey = Get-NuwaTransportAesSubkey $root 'aes256-hmac-v1/authentication'
    $iv = Get-NuwaTransportEntropy -Count 16 -Context $Context
    $ciphertext = Protect-NuwaTransportAesBytes $Bytes $encryptionKey $iv
    $directionLabel = [byte[]](ConvertTo-NuwaUtf8Bytes ($Direction + [char]0))
    $authenticated = Join-NuwaTransportBytes -Parts @([object]$directionLabel, [object]$iv, [object]$ciphertext)
    $tag = Get-NuwaClmHmacSha256Tag -Key $authenticationKey -Bytes $authenticated
    return ,(Join-NuwaTransportBytes -Parts @([object]$iv, [object]$ciphertext, [object]$tag))
}

function Unprotect-NuwaTransportEnvelopeBytes {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][byte[]]$Bytes, [Parameter(Mandatory = $true)][string]$Direction)
    if ($Bytes.Length -lt 64 -or (($Bytes.Length - 48) % 16) -ne 0) { throw 'Transport envelope authentication failed' }
    $ciphertextLength = $Bytes.Length - 48
    $iv = Copy-NuwaTransportBytes $Bytes 0 16
    $ciphertext = Copy-NuwaTransportBytes $Bytes 16 $ciphertextLength
    $providedTag = Copy-NuwaTransportBytes $Bytes (16 + $ciphertextLength) 32
    $root = Get-NuwaTransportDirectionKey $Direction
    $encryptionKey = Get-NuwaTransportAesSubkey $root 'aes256-hmac-v1/encryption'
    $authenticationKey = Get-NuwaTransportAesSubkey $root 'aes256-hmac-v1/authentication'
    $directionLabel = [byte[]](ConvertTo-NuwaUtf8Bytes ($Direction + [char]0))
    $authenticated = Join-NuwaTransportBytes -Parts @([object]$directionLabel, [object]$iv, [object]$ciphertext)
    $expectedTag = Get-NuwaClmHmacSha256Tag -Key $authenticationKey -Bytes $authenticated
    if (-not (Test-NuwaFixedTimeEqual -Left $providedTag -Right $expectedTag)) { throw 'Transport envelope authentication failed' }
    try { return ,(Unprotect-NuwaClmAes256CbcBytes -Ciphertext $ciphertext -Key $encryptionKey -InitializationVector $iv) }
    catch { throw 'Transport envelope authentication failed' }
}
