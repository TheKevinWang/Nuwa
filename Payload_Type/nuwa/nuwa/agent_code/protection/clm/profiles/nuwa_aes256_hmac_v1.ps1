function Get-NuwaProtectionProfileName {
    [CmdletBinding()]
    param()

    return 'nuwa_aes256_hmac_v1'
}

function Get-NuwaAesHmacTag {
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

function ConvertTo-NuwaClmIvFromGuidStrings {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$GuidA,

        [Parameter(Mandatory = $true)]
        [string]$GuidB
    )

    if ($GuidA -ceq $GuidB) {
        throw 'Nuwa CLM GUID entropy is invalid'
    }
    foreach ($guidText in @($GuidA, $GuidB)) {
        if ($guidText -cnotmatch '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$') {
            throw 'Nuwa CLM GUID entropy is invalid'
        }
    }
    $guidAHex = $GuidA.Substring(0, 8) + $GuidA.Substring(9, 4) +
        $GuidA.Substring(14, 4) + $GuidA.Substring(19, 4) + $GuidA.Substring(24, 12)
    $guidBHex = $GuidB.Substring(0, 8) + $GuidB.Substring(9, 4) +
        $GuidB.Substring(14, 4) + $GuidB.Substring(19, 4) + $GuidB.Substring(24, 12)
    $entropy = Join-NuwaClmBytes -Parts @(
        [object](ConvertFrom-NuwaClmHex -Value $guidAHex),
        [object](ConvertFrom-NuwaClmHex -Value $guidBHex)
    )
    $digest = Get-NuwaClmSha256Digest -Bytes $entropy
    return ,(Get-NuwaClmByteSlice -Source $digest -Offset 0 -Length 16)
}

function New-NuwaClmInitializationVector {
    [CmdletBinding()]
    param()

    try {
        $guidA = [string][guid]::NewGuid()
        $guidB = [string][guid]::NewGuid()
    } catch {
        throw 'Nuwa CLM GUID entropy is invalid'
    }
    if ([string]::IsNullOrEmpty($guidA) -or [string]::IsNullOrEmpty($guidB) -or
        $guidA -ceq $guidB) {
        throw 'Nuwa CLM GUID entropy is invalid'
    }
    return ,(ConvertTo-NuwaClmIvFromGuidStrings -GuidA $guidA -GuidB $guidB)
}

function Protect-NuwaAesHmacBytes {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [byte[]]$Bytes,

        [Parameter(Mandatory = $true)]
        [byte[]]$Key,

        [Parameter(Mandatory = $true)]
        [byte[]]$InitializationVector
    )

    if ($Key.Length -ne 32 -or $InitializationVector.Length -ne 16) {
        throw 'Nuwa AES protection requires a 32-byte key and 16-byte IV'
    }
    $ciphertext = Protect-NuwaClmAes256CbcBytes -Bytes $Bytes -Key $Key -InitializationVector $InitializationVector
    $authenticated = Join-NuwaClmBytes -Parts @(
        [object]$InitializationVector,
        [object]$ciphertext
    )
    $tag = Get-NuwaClmHmacSha256Tag -Key $Key -Bytes $authenticated
    return ,(Join-NuwaClmBytes -Parts @([object]$authenticated, [object]$tag))
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
    $iv = New-NuwaClmInitializationVector
    return ,(Protect-NuwaAesHmacBytes -Bytes $Bytes -Key $key -InitializationVector $iv)
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

    if ($Bytes.Length -lt 64) {
        throw 'Nuwa protection authentication failed'
    }
    $authenticatedLength = $Bytes.Length - 32
    $ciphertextLength = $authenticatedLength - 16
    if ($ciphertextLength -lt 16 -or ($ciphertextLength % 16) -ne 0) {
        throw 'Nuwa protection authentication failed'
    }
    $authenticated = Get-NuwaClmByteSlice -Source $Bytes -Offset 0 -Length $authenticatedLength
    $providedTag = Get-NuwaClmByteSlice -Source $Bytes -Offset $authenticatedLength -Length 32
    $key = Get-NuwaProtectionKey
    $expectedTag = Get-NuwaClmHmacSha256Tag -Key $key -Bytes $authenticated
    if (-not (Test-NuwaFixedTimeEqual -Left $providedTag -Right $expectedTag)) {
        throw 'Nuwa protection authentication failed'
    }
    $iv = Get-NuwaClmByteSlice -Source $authenticated -Offset 0 -Length 16
    $ciphertext = Get-NuwaClmByteSlice -Source $authenticated -Offset 16 -Length $ciphertextLength
    try {
        return ,(Unprotect-NuwaClmAes256CbcBytes -Ciphertext $ciphertext -Key $key -InitializationVector $iv)
    } catch {
        throw 'Nuwa protection authentication failed'
    }
}
