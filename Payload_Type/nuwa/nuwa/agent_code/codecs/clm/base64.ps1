$script:NuwaBase64CodecAlphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'

function ConvertTo-NuwaRadix64Bytes {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [byte[]]$Bytes,

        [Parameter(Mandatory = $true)]
        [hashtable]$Context
    )

    $paddedLength = $Bytes.Length + 2
    $quartetCount = ($paddedLength - ($paddedLength % 3)) / 3
    $output = New-Object char[] ($quartetCount * 4)
    $outputIndex = 0
    for ($index = 0; $index -lt $Bytes.Length; $index += 3) {
        $remaining = $Bytes.Length - $index
        $first = [int]$Bytes[$index]
        $second = if ($remaining -gt 1) { [int]$Bytes[$index + 1] } else { 0 }
        $third = if ($remaining -gt 2) { [int]$Bytes[$index + 2] } else { 0 }
        $combined = ($first -shl 16) -bor ($second -shl 8) -bor $third

        $output[$outputIndex] = $script:NuwaBase64CodecAlphabet[($combined -shr 18) -band 63]
        $output[$outputIndex + 1] = $script:NuwaBase64CodecAlphabet[($combined -shr 12) -band 63]
        $output[$outputIndex + 2] = if ($remaining -gt 1) {
            $script:NuwaBase64CodecAlphabet[($combined -shr 6) -band 63]
        } else { '=' }
        $output[$outputIndex + 3] = if ($remaining -gt 2) {
            $script:NuwaBase64CodecAlphabet[$combined -band 63]
        } else { '=' }
        $outputIndex += 4
    }

    return ,(ConvertTo-NuwaUtf8Bytes -Value (-join $output))
}

function ConvertFrom-NuwaRadix64Bytes {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [byte[]]$Bytes,

        [Parameter(Mandatory = $true)]
        [hashtable]$Context
    )

    $value = ConvertFrom-NuwaUtf8Bytes -Bytes $Bytes
    if (($value.Length % 4) -ne 0) {
        throw 'Base64 payload length must be divisible by 4'
    }

    $paddingLength = 0
    if ($value.Length -gt 0 -and $value[$value.Length - 1] -eq '=') {
        $paddingLength = 1
        if ($value.Length -gt 1 -and $value[$value.Length - 2] -eq '=') {
            $paddingLength = 2
        }
    }
    $decodedLength = (($value.Length / 4) * 3) - $paddingLength
    $decoded = New-Object byte[] ([int]$decodedLength)
    $decodedIndex = 0

    for ($index = 0; $index -lt $value.Length; $index += 4) {
        $isFinal = $index -eq ($value.Length - 4)
        $characters = @(
            [char]$value[$index],
            [char]$value[$index + 1],
            [char]$value[$index + 2],
            [char]$value[$index + 3]
        )
        if ($characters[0] -eq '=' -or $characters[1] -eq '=') {
            throw 'Base64 payload has invalid padding'
        }
        if (($characters[2] -eq '=' -or $characters[3] -eq '=') -and -not $isFinal) {
            throw 'Base64 payload padding is allowed only in the final quartet'
        }
        if ($characters[2] -eq '=' -and $characters[3] -ne '=') {
            throw 'Base64 payload has invalid padding'
        }

        $values = @(0, 0, 0, 0)
        for ($position = 0; $position -lt 4; $position += 1) {
            if ($characters[$position] -eq '=') {
                $values[$position] = 0
                continue
            }
            $alphabetIndex = $script:NuwaBase64CodecAlphabet.IndexOf([string]$characters[$position])
            if ($alphabetIndex -lt 0) {
                throw 'Base64 payload contains an invalid character'
            }
            $values[$position] = $alphabetIndex
        }

        $combined = ($values[0] -shl 18) -bor ($values[1] -shl 12) -bor ($values[2] -shl 6) -bor $values[3]
        if ($decodedIndex -lt $decoded.Length) {
            $decoded[$decodedIndex] = [byte](($combined -shr 16) -band 255)
            $decodedIndex += 1
        }
        if ($decodedIndex -lt $decoded.Length) {
            $decoded[$decodedIndex] = [byte](($combined -shr 8) -band 255)
            $decodedIndex += 1
        }
        if ($decodedIndex -lt $decoded.Length) {
            $decoded[$decodedIndex] = [byte]($combined -band 255)
            $decodedIndex += 1
        }
    }

    $canonicalBytes = ConvertTo-NuwaRadix64Bytes -Bytes $decoded -Context $Context
    $canonical = ConvertFrom-NuwaUtf8Bytes -Bytes ([byte[]]$canonicalBytes)
    if ($canonical -cne $value) {
        throw 'Base64 payload is not canonical'
    }
    return ,$decoded
}
