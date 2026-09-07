function ConvertTo-NuwaBase64String {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [byte[]]$Bytes
    )

    $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
    $paddedLength = $Bytes.Length + 2
    $quartetCount = ($paddedLength - ($paddedLength % 3)) / 3
    $output = [char[]]::new($quartetCount * 4)
    $outputIndex = 0
    for ($index = 0; $index -lt $Bytes.Length; $index += 3) {
        $remaining = $Bytes.Length - $index
        $first = [int]$Bytes[$index]
        $second = if ($remaining -gt 1) { [int]$Bytes[$index + 1] } else { 0 }
        $third = if ($remaining -gt 2) { [int]$Bytes[$index + 2] } else { 0 }
        $combined = ($first -shl 16) -bor ($second -shl 8) -bor $third

        $output[$outputIndex] = $alphabet[($combined -shr 18) -band 0x3F]
        $outputIndex += 1
        $output[$outputIndex] = $alphabet[($combined -shr 12) -band 0x3F]
        $outputIndex += 1
        if ($remaining -gt 1) {
            $output[$outputIndex] = $alphabet[($combined -shr 6) -band 0x3F]
        } else {
            $output[$outputIndex] = '='
        }
        $outputIndex += 1
        if ($remaining -gt 2) {
            $output[$outputIndex] = $alphabet[$combined -band 0x3F]
        } else {
            $output[$outputIndex] = '='
        }
        $outputIndex += 1
    }

    return ($output -join '')
}

function ConvertFrom-NuwaBase64String {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Value
    )

    $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
    $normalized = ($Value -replace '\s', '')
    if (($normalized.Length % 4) -ne 0) {
        throw 'Base64 input length must be divisible by 4'
    }

    $paddingLength = 0
    if ($normalized.EndsWith('==')) {
        $paddingLength = 2
    } elseif ($normalized.EndsWith('=')) {
        $paddingLength = 1
    }

    $decodedLength = (($normalized.Length / 4) * 3) - $paddingLength
    $decoded = [byte[]]::new($decodedLength)
    $decodedIndex = 0
    for ($index = 0; $index -lt $normalized.Length; $index += 4) {
        $quartet = $normalized.Substring($index, 4)
        $padding = 0
        $values = @()

        foreach ($character in $quartet.ToCharArray()) {
            if ($character -eq '=') {
                $values += 0
                $padding += 1
            } else {
                $position = $alphabet.IndexOf([string]$character)
                if ($position -lt 0) {
                    throw 'Invalid base64 character'
                }
                $values += $position
            }
        }

        if ($padding -gt 2) {
            throw 'Invalid base64 padding'
        }
        if ($padding -gt 0 -and $index -ne ($normalized.Length - 4)) {
            throw 'Base64 padding can only appear in the final quartet'
        }

        $combined = ($values[0] -shl 18) -bor ($values[1] -shl 12) -bor ($values[2] -shl 6) -bor $values[3]
        $decoded[$decodedIndex] = (($combined -shr 16) -band 0xFF)
        $decodedIndex += 1
        if ($padding -lt 2) {
            $decoded[$decodedIndex] = (($combined -shr 8) -band 0xFF)
            $decodedIndex += 1
        }
        if ($padding -lt 1) {
            $decoded[$decodedIndex] = ($combined -band 0xFF)
            $decodedIndex += 1
        }
    }

    return $decoded
}

function ConvertTo-NuwaChunkData {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [byte[]]$Bytes
    )

    return ConvertTo-NuwaBase64String -Bytes $Bytes
}

function ConvertFrom-NuwaChunkData {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [object]$Value
    )

    return ConvertFrom-NuwaBase64String -Value ([string]$Value)
}

function Test-NuwaChunkDataPresent {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$Value
    )

    return $null -ne $Value -and -not [string]::IsNullOrEmpty([string]$Value)
}

function Get-NuwaFileChunkSize {
    [CmdletBinding()]
    param()

    $codecProfile = ([string]$script:NuwaConfig.CodecProfile).Trim().ToLowerInvariant()
    $transportPresentation = ([string]$script:NuwaConfig.TransportPresentation).Trim().ToLowerInvariant()
    $outerEmojiEnabled = (
        [bool]$script:NuwaConfig.TransportEnvelopeEnabled -and
        $transportPresentation -eq 'emoji'
    )
    if (
        $outerEmojiEnabled -and
        ([string]$script:NuwaConfig.PowerShellRuntime).Trim().ToLowerInvariant() -eq 'constrained-language'
    ) {
        return 51200
    }
    if ($outerEmojiEnabled) {
        return 384
    }
    if ($codecProfile -eq 'emoji') {
        return 384
    }

    return 51200
}
