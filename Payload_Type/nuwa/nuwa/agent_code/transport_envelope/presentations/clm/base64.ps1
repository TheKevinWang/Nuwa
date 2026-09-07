$script:NuwaTransportBase64Alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'

function ConvertTo-NuwaTransportPresentation {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][byte[]]$Bytes)

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

        $output[$outputIndex] = $script:NuwaTransportBase64Alphabet[($combined -shr 18) -band 63]
        $output[$outputIndex + 1] = $script:NuwaTransportBase64Alphabet[($combined -shr 12) -band 63]
        $output[$outputIndex + 2] = if ($remaining -gt 1) {
            $script:NuwaTransportBase64Alphabet[($combined -shr 6) -band 63]
        } else { '=' }
        $output[$outputIndex + 3] = if ($remaining -gt 2) {
            $script:NuwaTransportBase64Alphabet[$combined -band 63]
        } else { '=' }
        $outputIndex += 4
    }
    return (-join $output)
}

function ConvertFrom-NuwaTransportPresentation {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Value)

    if (($Value.Length % 4) -ne 0) {
        throw 'Transport Base64 document length must be divisible by 4'
    }
    $paddingLength = 0
    if ($Value.Length -gt 0 -and $Value[$Value.Length - 1] -eq '=') {
        $paddingLength = 1
        if ($Value.Length -gt 1 -and $Value[$Value.Length - 2] -eq '=') {
            $paddingLength = 2
        }
    }
    $decodedLength = (($Value.Length / 4) * 3) - $paddingLength
    $decoded = New-Object byte[] ([int]$decodedLength)
    $decodedIndex = 0

    for ($index = 0; $index -lt $Value.Length; $index += 4) {
        $isFinal = $index -eq ($Value.Length - 4)
        $characters = @(
            [char]$Value[$index],
            [char]$Value[$index + 1],
            [char]$Value[$index + 2],
            [char]$Value[$index + 3]
        )
        if ($characters[0] -eq '=' -or $characters[1] -eq '=') {
            throw 'Transport Base64 document has invalid padding'
        }
        if (($characters[2] -eq '=' -or $characters[3] -eq '=') -and -not $isFinal) {
            throw 'Transport Base64 padding is allowed only in the final quartet'
        }
        if ($characters[2] -eq '=' -and $characters[3] -ne '=') {
            throw 'Transport Base64 document has invalid padding'
        }

        $values = @(0, 0, 0, 0)
        for ($position = 0; $position -lt 4; $position += 1) {
            if ($characters[$position] -eq '=') {
                $values[$position] = 0
                continue
            }
            $alphabetIndex = $script:NuwaTransportBase64Alphabet.IndexOf([string]$characters[$position])
            if ($alphabetIndex -lt 0) {
                throw 'Transport Base64 document contains an invalid character'
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

    if ((ConvertTo-NuwaTransportPresentation -Bytes $decoded) -cne $Value) {
        throw 'Transport Base64 document is not canonical'
    }
    return ,$decoded
}
