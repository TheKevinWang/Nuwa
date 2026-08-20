function New-NuwaClmByteArray {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [int]$Length
    )

    if ($Length -lt 0 -or $Length -gt 67108864) {
        throw 'Nuwa CLM byte length is invalid'
    }
    $result = New-Object byte[] $Length
    return ,$result
}

function Copy-NuwaClmBytes {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [byte[]]$Source,

        [int]$Offset = 0,

        [int]$Length = -1
    )

    if ($Length -eq -1) {
        $Length = $Source.Length - $Offset
    }
    if ($Offset -lt 0 -or $Length -lt 0 -or $Offset -gt $Source.Length -or
        $Length -gt ($Source.Length - $Offset)) {
        throw 'Nuwa CLM byte slice is invalid'
    }

    $result = New-NuwaClmByteArray -Length $Length
    for ($index = 0; $index -lt $Length; $index += 1) {
        $result[$index] = $Source[$Offset + $index]
    }
    return ,$result
}

function Get-NuwaClmByteSlice {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [byte[]]$Source,

        [Parameter(Mandatory = $true)]
        [int]$Offset,

        [Parameter(Mandatory = $true)]
        [int]$Length
    )

    return ,(Copy-NuwaClmBytes -Source $Source -Offset $Offset -Length $Length)
}

function Join-NuwaClmBytes {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Parts
    )

    [int64]$totalLength = 0
    foreach ($part in $Parts) {
        if ($null -eq $part -or $part -isnot [byte[]]) {
            throw 'Nuwa CLM byte join requires byte arrays'
        }
        $totalLength += $part.Length
        if ($totalLength -gt 67108864) {
            throw 'Nuwa CLM byte length is invalid'
        }
    }

    $result = New-NuwaClmByteArray -Length ([int]$totalLength)
    $destinationOffset = 0
    foreach ($part in $Parts) {
        for ($index = 0; $index -lt $part.Length; $index += 1) {
            $result[$destinationOffset + $index] = $part[$index]
        }
        $destinationOffset += $part.Length
    }
    return ,$result
}

function ConvertFrom-NuwaClmHex {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Value
    )

    if (($Value.Length % 2) -ne 0) {
        throw 'Nuwa CLM hexadecimal text has an invalid length'
    }
    $result = New-NuwaClmByteArray -Length ([int]($Value.Length / 2))
    for ($index = 0; $index -lt $result.Length; $index += 1) {
        [int]$highCode = [int][char]$Value[$index * 2]
        [int]$lowCode = [int][char]$Value[($index * 2) + 1]
        [int]$high = -1
        [int]$low = -1
        if ($highCode -ge 48 -and $highCode -le 57) {
            $high = $highCode - 48
        } elseif ($highCode -ge 65 -and $highCode -le 70) {
            $high = $highCode - 55
        } elseif ($highCode -ge 97 -and $highCode -le 102) {
            $high = $highCode - 87
        }
        if ($lowCode -ge 48 -and $lowCode -le 57) {
            $low = $lowCode - 48
        } elseif ($lowCode -ge 65 -and $lowCode -le 70) {
            $low = $lowCode - 55
        } elseif ($lowCode -ge 97 -and $lowCode -le 102) {
            $low = $lowCode - 87
        }
        if ($high -lt 0 -or $low -lt 0) {
            throw 'Nuwa CLM hexadecimal text is invalid'
        }
        $result[$index] = [byte](($high -shl 4) -bor $low)
    }
    return ,$result
}

function Test-NuwaFixedTimeEqual {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [byte[]]$Left,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [byte[]]$Right
    )

    if ($Left.Length -ne $Right.Length) {
        return $false
    }
    [int]$difference = 0
    for ($index = 0; $index -lt $Left.Length; $index += 1) {
        $difference = $difference -bor ([int]$Left[$index] -bxor [int]$Right[$index])
    }
    return $difference -eq 0
}

function Get-NuwaProtectionKey {
    [CmdletBinding()]
    param()

    $key = [byte[]]$script:NuwaCryptoState.Key
    if ($null -eq $key -or $key.Length -ne 32) {
        throw 'Nuwa protection key is unavailable'
    }
    return ,$key
}
