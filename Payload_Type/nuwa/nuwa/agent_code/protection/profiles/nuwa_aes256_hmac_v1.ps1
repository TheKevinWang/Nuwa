function Get-NuwaProtectionProfileName {
    [CmdletBinding()]
    param()

    return 'nuwa_aes256_hmac_v1'
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

function Get-NuwaAesHmacTag {
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
        $ciphertext = [byte[]]$transform.TransformFinalBlock($Bytes, 0, $Bytes.Length)
    } finally {
        if ($null -ne $transform) {
            $transform.Dispose()
        }
        if ($null -ne $algorithm) {
            $algorithm.Dispose()
        }
    }

    $authenticated = [byte[]]::new($InitializationVector.Length + $ciphertext.Length)
    [System.Array]::Copy($InitializationVector, 0, $authenticated, 0, $InitializationVector.Length)
    [System.Array]::Copy($ciphertext, 0, $authenticated, $InitializationVector.Length, $ciphertext.Length)
    $tag = [byte[]](Get-NuwaAesHmacTag -Key $Key -Bytes $authenticated)
    $result = [byte[]]::new($authenticated.Length + $tag.Length)
    [System.Array]::Copy($authenticated, 0, $result, 0, $authenticated.Length)
    [System.Array]::Copy($tag, 0, $result, $authenticated.Length, $tag.Length)
    return ,$result
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
    $iv = [byte[]]::new(16)
    $random = $null
    try {
        $random = [System.Security.Cryptography.RandomNumberGenerator]::Create()
        $random.GetBytes($iv)
    } finally {
        if ($null -ne $random) {
            $random.Dispose()
        }
    }
    return Protect-NuwaAesHmacBytes `
        -Bytes $Bytes `
        -Key $key `
        -InitializationVector $iv
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

    $authenticated = [byte[]]::new($authenticatedLength)
    $providedTag = [byte[]]::new(32)
    [System.Array]::Copy($Bytes, 0, $authenticated, 0, $authenticatedLength)
    [System.Array]::Copy($Bytes, $authenticatedLength, $providedTag, 0, 32)
    $key = [byte[]](Get-NuwaProtectionKey)
    $expectedTag = [byte[]](Get-NuwaAesHmacTag -Key $key -Bytes $authenticated)
    if (-not (Test-NuwaFixedTimeEqual -Left $providedTag -Right $expectedTag)) {
        throw 'Nuwa protection authentication failed'
    }

    $iv = [byte[]]::new(16)
    $ciphertext = [byte[]]::new($ciphertextLength)
    [System.Array]::Copy($authenticated, 0, $iv, 0, 16)
    [System.Array]::Copy($authenticated, 16, $ciphertext, 0, $ciphertextLength)

    $algorithm = $null
    $transform = $null
    try {
        $algorithm = [System.Security.Cryptography.Aes]::Create()
        $algorithm.KeySize = 256
        $algorithm.BlockSize = 128
        $algorithm.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $algorithm.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        $algorithm.Key = $key
        $algorithm.IV = $iv
        $transform = $algorithm.CreateDecryptor()
        $plaintext = [byte[]]$transform.TransformFinalBlock(
            $ciphertext,
            0,
            $ciphertext.Length
        )
        return ,$plaintext
    } catch {
        throw 'Nuwa protection authentication failed'
    } finally {
        if ($null -ne $transform) {
            $transform.Dispose()
        }
        if ($null -ne $algorithm) {
            $algorithm.Dispose()
        }
    }
}
