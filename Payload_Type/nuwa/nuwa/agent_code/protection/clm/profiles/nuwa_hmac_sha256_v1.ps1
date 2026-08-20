function Get-NuwaProtectionProfileName {
    [CmdletBinding()]
    param()

    return 'nuwa_hmac_sha256_v1'
}

function Get-NuwaHmacTag {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [byte[]]$Key,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [byte[]]$Bytes
    )

    return ,(Get-NuwaClmHmacSha256Tag -Key $Key -Bytes $Bytes)
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

    $key = Get-NuwaProtectionKey
    $tag = Get-NuwaClmHmacSha256Tag -Key $key -Bytes $Bytes
    return ,(Join-NuwaClmBytes -Parts @([object]$Bytes, [object]$tag))
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
    $payload = Get-NuwaClmByteSlice -Source $Bytes -Offset 0 -Length $payloadLength
    $providedTag = Get-NuwaClmByteSlice -Source $Bytes -Offset $payloadLength -Length 32
    $key = Get-NuwaProtectionKey
    $expectedTag = Get-NuwaClmHmacSha256Tag -Key $key -Bytes $payload
    if (-not (Test-NuwaFixedTimeEqual -Left $providedTag -Right $expectedTag)) {
        throw 'Nuwa protection authentication failed'
    }
    return ,$payload
}
