function Get-NuwaTransportAesSha256 {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)
    $algorithm = $null
    try {
        $algorithm = [System.Security.Cryptography.SHA256]::Create()
        return ,([byte[]]$algorithm.ComputeHash($Bytes))
    } finally { if ($null -ne $algorithm) { $algorithm.Dispose() } }
}

function Get-NuwaTransportAesSubkey {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][byte[]]$Root, [Parameter(Mandatory = $true)][string]$Label)
    $labelBytes = [byte[]](ConvertTo-NuwaUtf8Bytes $Label)
    $inputBytes = Join-NuwaTransportBytes -Parts @([object]$Root, [object]([byte[]]@(0)), [object]$labelBytes)
    return ,(Get-NuwaTransportAesSha256 $inputBytes)
}

function Get-NuwaTransportAesTag {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][byte[]]$Key, [Parameter(Mandatory = $true)][byte[]]$Bytes)
    $algorithm = $null
    try {
        $algorithm = [System.Security.Cryptography.HMACSHA256]::new($Key)
        return ,([byte[]]$algorithm.ComputeHash($Bytes))
    } finally { if ($null -ne $algorithm) { $algorithm.Dispose() } }
}

function Test-NuwaTransportAesTag {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][byte[]]$Left, [Parameter(Mandatory = $true)][byte[]]$Right)
    if ($Left.Length -ne $Right.Length) { return $false }
    $difference = 0
    for ($index = 0; $index -lt $Left.Length; $index += 1) { $difference = $difference -bor ([int]$Left[$index] -bxor [int]$Right[$index]) }
    return $difference -eq 0
}

function Protect-NuwaTransportAesBytes {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][byte[]]$Bytes, [Parameter(Mandatory = $true)][byte[]]$Key, [Parameter(Mandatory = $true)][byte[]]$InitializationVector)
    $algorithm = $null
    $transform = $null
    try {
        $algorithm = [System.Security.Cryptography.Aes]::Create()
        $algorithm.KeySize = 256
        $algorithm.BlockSize = 128
        $algorithm.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $algorithm.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        $algorithm.Key = $Key
        $algorithm.IV = $InitializationVector
        $transform = $algorithm.CreateEncryptor()
        return ,([byte[]]$transform.TransformFinalBlock($Bytes, 0, $Bytes.Length))
    } finally {
        if ($null -ne $transform) { $transform.Dispose() }
        if ($null -ne $algorithm) { $algorithm.Dispose() }
    }
}

function Protect-NuwaTransportEnvelopeBytes {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][byte[]]$Bytes, [Parameter(Mandatory = $true)][string]$Direction, [Parameter(Mandatory = $false)][hashtable]$Context = @{})
    $root = Get-NuwaTransportDirectionKey $Direction
    $encryptionKey = Get-NuwaTransportAesSubkey $root 'aes256-hmac-v1/encryption'
    $authenticationKey = Get-NuwaTransportAesSubkey $root 'aes256-hmac-v1/authentication'
    $iv = Get-NuwaTransportEntropy -Count 16 -Context $Context
    $ciphertext = Protect-NuwaTransportAesBytes -Bytes $Bytes -Key $encryptionKey -InitializationVector $iv
    $directionLabel = [byte[]](ConvertTo-NuwaUtf8Bytes ($Direction + [char]0))
    $authenticated = Join-NuwaTransportBytes -Parts @([object]$directionLabel, [object]$iv, [object]$ciphertext)
    $tag = Get-NuwaTransportAesTag $authenticationKey $authenticated
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
    $expectedTag = Get-NuwaTransportAesTag $authenticationKey $authenticated
    if (-not (Test-NuwaTransportAesTag $providedTag $expectedTag)) { throw 'Transport envelope authentication failed' }
    $algorithm = $null
    $transform = $null
    try {
        $algorithm = [System.Security.Cryptography.Aes]::Create()
        $algorithm.KeySize = 256
        $algorithm.BlockSize = 128
        $algorithm.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $algorithm.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        $algorithm.Key = $encryptionKey
        $algorithm.IV = $iv
        $transform = $algorithm.CreateDecryptor()
        return ,([byte[]]$transform.TransformFinalBlock($ciphertext, 0, $ciphertext.Length))
    } catch { throw 'Transport envelope authentication failed' }
    finally {
        if ($null -ne $transform) { $transform.Dispose() }
        if ($null -ne $algorithm) { $algorithm.Dispose() }
    }
}
