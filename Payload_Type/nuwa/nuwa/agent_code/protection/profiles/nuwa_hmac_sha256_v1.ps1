function Get-NuwaProtectionProfileName {
    [CmdletBinding()]
    param()

    return 'nuwa_hmac_sha256_v1'
}

function Get-NuwaProtectionKey {
    [CmdletBinding()]
    param()

    $key = [byte[]]$script:NuwaCryptoState.Key
    if ($null -eq $key -or $key.Length -ne 32) {
        throw 'Nuwa protection key is unavailable'
    }
    return $key
}

function Test-NuwaFixedTimeEqual {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [byte[]]$Left,

        [Parameter(Mandatory = $true)]
        [byte[]]$Right
    )

    if ($Left.Length -ne $Right.Length) {
        return $false
    }
    $difference = 0
    for ($index = 0; $index -lt $Left.Length; $index += 1) {
        $difference = $difference -bor ([int]$Left[$index] -bxor [int]$Right[$index])
    }
    return $difference -eq 0
}

function Get-NuwaHmacTag {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [byte[]]$Key,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [byte[]]$Bytes
    )

    $algorithm = $null
    try {
        $algorithm = [System.Security.Cryptography.HMACSHA256]::new($Key)
        return [byte[]]$algorithm.ComputeHash($Bytes)
    } finally {
        if ($null -ne $algorithm) {
            $algorithm.Dispose()
        }
    }
}

function Protect-NuwaBytes {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [byte[]]$Bytes,

        [Parameter(Mandatory = $true)]
        [hashtable]$Context
    )

    $key = [byte[]](Get-NuwaProtectionKey)
    $tag = [byte[]](Get-NuwaHmacTag -Key $key -Bytes $Bytes)
    $result = [byte[]]::new($Bytes.Length + $tag.Length)
    [System.Array]::Copy($Bytes, 0, $result, 0, $Bytes.Length)
    [System.Array]::Copy($tag, 0, $result, $Bytes.Length, $tag.Length)
    return ,$result
}

function Unprotect-NuwaBytes {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [byte[]]$Bytes,

        [Parameter(Mandatory = $true)]
        [hashtable]$Context
    )

    if ($Bytes.Length -lt 32) {
        throw 'Nuwa protection authentication failed'
    }
    $payloadLength = $Bytes.Length - 32
    $payload = [byte[]]::new($payloadLength)
    $providedTag = [byte[]]::new(32)
    [System.Array]::Copy($Bytes, 0, $payload, 0, $payloadLength)
    [System.Array]::Copy($Bytes, $payloadLength, $providedTag, 0, 32)

    $key = [byte[]](Get-NuwaProtectionKey)
    $expectedTag = [byte[]](Get-NuwaHmacTag -Key $key -Bytes $payload)
    if (-not (Test-NuwaFixedTimeEqual -Left $providedTag -Right $expectedTag)) {
        throw 'Nuwa protection authentication failed'
    }
    return ,$payload
}
