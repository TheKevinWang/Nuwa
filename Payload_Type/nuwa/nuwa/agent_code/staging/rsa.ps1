function ConvertTo-NuwaDerLength {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [int]$Length
    )

    if ($Length -lt 0) {
        throw 'DER length cannot be negative'
    }
    if ($Length -lt 128) {
        return ,([byte[]]@([byte]$Length))
    }

    $encoded = [byte[]]::new(4)
    $remaining = [uint32]$Length
    for ($index = 3; $index -ge 0; $index -= 1) {
        $encoded[$index] = [byte]($remaining -band 0xFF)
        $remaining = $remaining -shr 8
    }
    $first = 0
    while ($first -lt 3 -and $encoded[$first] -eq 0) {
        $first += 1
    }
    $count = 4 - $first
    $result = [byte[]]::new(1 + $count)
    $result[0] = [byte](0x80 -bor $count)
    [System.Array]::Copy($encoded, $first, $result, 1, $count)
    return ,$result
}

function ConvertTo-NuwaDerPositiveInteger {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [byte[]]$Bytes
    )

    if ($Bytes.Length -eq 0) {
        throw 'DER positive integer cannot be empty'
    }
    $first = 0
    while ($first -lt ($Bytes.Length - 1) -and $Bytes[$first] -eq 0) {
        $first += 1
    }
    $valueLength = $Bytes.Length - $first
    $needsLeadingZero = ($Bytes[$first] -band 0x80) -ne 0
    $bodyLength = $valueLength + $(if ($needsLeadingZero) { 1 } else { 0 })
    $lengthBytes = [byte[]](ConvertTo-NuwaDerLength -Length $bodyLength)
    $result = [byte[]]::new(1 + $lengthBytes.Length + $bodyLength)
    $result[0] = 0x02
    [System.Array]::Copy($lengthBytes, 0, $result, 1, $lengthBytes.Length)
    $bodyOffset = 1 + $lengthBytes.Length
    if ($needsLeadingZero) {
        $result[$bodyOffset] = 0
        $bodyOffset += 1
    }
    [System.Array]::Copy($Bytes, $first, $result, $bodyOffset, $valueLength)
    return ,$result
}

function ConvertTo-NuwaRsaPublicKeyDer {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Security.Cryptography.RSAParameters]$Parameters
    )

    if (
        $null -eq $Parameters.Modulus -or $Parameters.Modulus.Length -eq 0 -or
        $null -eq $Parameters.Exponent -or $Parameters.Exponent.Length -eq 0
    ) {
        throw 'RSA public parameters are incomplete'
    }
    $modulus = [byte[]](ConvertTo-NuwaDerPositiveInteger -Bytes $Parameters.Modulus)
    $exponent = [byte[]](ConvertTo-NuwaDerPositiveInteger -Bytes $Parameters.Exponent)
    $contentLength = $modulus.Length + $exponent.Length
    $lengthBytes = [byte[]](ConvertTo-NuwaDerLength -Length $contentLength)
    $result = [byte[]]::new(1 + $lengthBytes.Length + $contentLength)
    $result[0] = 0x30
    [System.Array]::Copy($lengthBytes, 0, $result, 1, $lengthBytes.Length)
    $offset = 1 + $lengthBytes.Length
    [System.Array]::Copy($modulus, 0, $result, $offset, $modulus.Length)
    [System.Array]::Copy($exponent, 0, $result, $offset + $modulus.Length, $exponent.Length)
    return ,$result
}

function ConvertTo-NuwaRsaPublicKeyPem {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Security.Cryptography.RSAParameters]$Parameters
    )

    $der = [byte[]](ConvertTo-NuwaRsaPublicKeyDer -Parameters $Parameters)
    $encoded = [Convert]::ToBase64String($der)
    $lines = @()
    for ($offset = 0; $offset -lt $encoded.Length; $offset += 64) {
        $count = [Math]::Min(64, $encoded.Length - $offset)
        $lines += $encoded.Substring($offset, $count)
    }
    return (
        "-----BEGIN RSA PUBLIC KEY-----`n" +
        ($lines -join "`n") +
        "`n-----END RSA PUBLIC KEY-----`n"
    )
}

function ConvertTo-NuwaStagingPublicKey {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Security.Cryptography.RSAParameters]$Parameters
    )

    $pem = ConvertTo-NuwaRsaPublicKeyPem -Parameters $Parameters
    $pemBytes = [System.Text.Encoding]::ASCII.GetBytes($pem)
    return [Convert]::ToBase64String($pemBytes)
}

function New-NuwaStagingSessionId {
    [CmdletBinding()]
    param()

    $bytes = [byte[]]::new(20)
    $random = $null
    try {
        $random = [System.Security.Cryptography.RandomNumberGenerator]::Create()
        $random.GetBytes($bytes)
        return [System.BitConverter]::ToString($bytes).Replace('-', '').ToLowerInvariant()
    } finally {
        if ($null -ne $random) {
            $random.Dispose()
        }
        [System.Array]::Clear($bytes, 0, $bytes.Length)
    }
}

function New-NuwaRsaProvider {
    [CmdletBinding()]
    param()

    $provider = [System.Security.Cryptography.RSACryptoServiceProvider]::new(2048)
    $provider.PersistKeyInCsp = $false
    return $provider
}

function Test-NuwaStagingStringEqual {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Left,

        [Parameter(Mandatory = $true)]
        [string]$Right
    )

    $difference = $Left.Length -bxor $Right.Length
    $count = [Math]::Max($Left.Length, $Right.Length)
    for ($index = 0; $index -lt $count; $index += 1) {
        $leftValue = if ($index -lt $Left.Length) { [int][char]$Left[$index] } else { 0 }
        $rightValue = if ($index -lt $Right.Length) { [int][char]$Right[$index] } else { 0 }
        $difference = $difference -bor ($leftValue -bxor $rightValue)
    }
    return $difference -eq 0
}

function ConvertFrom-NuwaStrictBase64 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Value
    )

    if (
        [string]::IsNullOrEmpty($Value) -or
        ($Value.Length % 4) -ne 0 -or
        $Value -notmatch '^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$'
    ) {
        throw 'RSA staging session key must use strict Base64 encoding'
    }
    try {
        $decoded = [byte[]][Convert]::FromBase64String($Value)
    } catch {
        throw 'RSA staging session key must use strict Base64 encoding'
    }
    if ([Convert]::ToBase64String($decoded) -cne $Value) {
        [System.Array]::Clear($decoded, 0, $decoded.Length)
        throw 'RSA staging session key must use strict Base64 encoding'
    }
    return ,$decoded
}

function Resolve-NuwaRsaStagingResponse {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Response,

        [Parameter(Mandatory = $true)]
        [string]$ExpectedSessionId,

        [Parameter(Mandatory = $true)]
        [System.Security.Cryptography.RSACryptoServiceProvider]$Rsa
    )

    if ([string]$Response.action -cne 'staging_rsa') {
        throw 'RSA staging response action did not match'
    }
    if (-not (Test-NuwaStagingStringEqual -Left ([string]$Response.session_id) -Right $ExpectedSessionId)) {
        throw 'RSA staging response session identifier did not match'
    }

    $uuidText = [string]$Response.uuid
    $stagingGuid = [Guid]::Empty
    if (-not [Guid]::TryParseExact($uuidText, 'D', [ref]$stagingGuid)) {
        throw 'RSA staging response UUID was not canonical'
    }
    $canonicalUuid = $stagingGuid.ToString('D')
    if ($uuidText -cne $canonicalUuid) {
        throw 'RSA staging response UUID was not canonical'
    }
    if ($canonicalUuid.Equals([string]$script:NuwaConfig.PayloadUUID, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'RSA staging response UUID must differ from the payload UUID'
    }

    $ciphertext = [byte[]](ConvertFrom-NuwaStrictBase64 -Value ([string]$Response.session_key))
    $decrypted = $null
    try {
        try {
            $decrypted = [byte[]]$Rsa.Decrypt($ciphertext, $true)
        } catch {
            throw 'RSA staging response session key decryption failed'
        }
        if ($decrypted.Length -ne 32) {
            throw 'RSA staging response must decrypt to exactly one 32-byte key'
        }
        $candidateKey = [byte[]]::new(32)
        [System.Array]::Copy($decrypted, 0, $candidateKey, 0, 32)
        return @{
            OuterUuid = $canonicalUuid
            Key = $candidateKey
        }
    } finally {
        [System.Array]::Clear($ciphertext, 0, $ciphertext.Length)
        if ($null -ne $decrypted) {
            [System.Array]::Clear($decrypted, 0, $decrypted.Length)
        }
    }
}

function Invoke-NuwaRsaStaging {
    [CmdletBinding()]
    param()

    $retryDelaySeconds = [int]$script:NuwaConfig.CallbackInterval
    if ($retryDelaySeconds -lt 1) {
        $retryDelaySeconds = 1
    }

    for ($attempt = 1; $attempt -le 3; $attempt += 1) {
        $rsa = $null
        $candidateState = $null
        try {
            Write-NuwaDebug ("Starting RSA staging attempt {0}/3" -f $attempt)
            $rsa = New-NuwaRsaProvider
            $publicParameters = $rsa.ExportParameters($false)
            $publicKey = ConvertTo-NuwaStagingPublicKey -Parameters $publicParameters
            $sessionId = New-NuwaStagingSessionId
            $response = Invoke-NuwaSendMessage `
                -Uuid $script:NuwaCryptoState.OuterUuid `
                -Action 'staging_rsa' `
                -Body @{ pub_key = $publicKey; session_id = $sessionId }
            if ($null -eq $response) {
                throw 'RSA staging returned no response'
            }
            $candidateState = Resolve-NuwaRsaStagingResponse `
                -Response $response `
                -ExpectedSessionId $sessionId `
                -Rsa $rsa
        } catch {
            Write-NuwaDebug ("RSA staging attempt {0}/3 failed" -f $attempt)
        } finally {
            $publicParameters = $null
            $publicKey = $null
            $sessionId = $null
            $response = $null
            if ($null -ne $rsa) {
                $rsa.PersistKeyInCsp = $false
                $rsa.Dispose()
            }
        }

        if ($null -ne $candidateState) {
            Write-NuwaDebug 'RSA staging succeeded'
            $script:NuwaCryptoState = $candidateState
            return
        }
        if ($attempt -lt 3) {
            Start-Sleep -Seconds $retryDelaySeconds
        }
    }

    throw 'RSA staging failed after 3 attempts'
}
