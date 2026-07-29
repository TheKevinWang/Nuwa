function ConvertTo-NuwaDecimalBytes {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [byte[]]$Bytes,

        [Parameter(Mandatory = $true)]
        [hashtable]$Context
    )

    $encoded = [byte[]]::new($Bytes.Length * 3)
    $encodedIndex = 0
    for ($index = 0; $index -lt $Bytes.Length; $index += 1) {
        $value = [int]$Bytes[$index]
        $hundreds = ($value - ($value % 100)) / 100
        $tensValue = $value % 100
        $tens = ($tensValue - ($tensValue % 10)) / 10
        $ones = $value % 10
        $encoded[$encodedIndex] = 48 + $hundreds
        $encoded[$encodedIndex + 1] = 48 + $tens
        $encoded[$encodedIndex + 2] = 48 + $ones
        $encodedIndex += 3
    }

    return $encoded
}

function ConvertFrom-NuwaDecimalBytes {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [byte[]]$Bytes,

        [Parameter(Mandatory = $true)]
        [hashtable]$Context
    )

    if (($Bytes.Length % 3) -ne 0) {
        throw 'Decimal payload length must be divisible by 3'
    }

    $decodedLength = $Bytes.Length / 3
    $decoded = [byte[]]::new($decodedLength)
    $decodedIndex = 0
    for ($index = 0; $index -lt $Bytes.Length; $index += 3) {
        $digitA = [int]$Bytes[$index] - 48
        $digitB = [int]$Bytes[$index + 1] - 48
        $digitC = [int]$Bytes[$index + 2] - 48

        if ($digitA -lt 0 -or $digitA -gt 9 -or $digitB -lt 0 -or $digitB -gt 9 -or $digitC -lt 0 -or $digitC -gt 9) {
            throw 'Decimal payload must contain only digits'
        }

        $value = ($digitA * 100) + ($digitB * 10) + $digitC
        if ($value -lt 0 -or $value -gt 255) {
            throw 'Decimal group must decode to a byte in 0..255'
        }

        $decoded[$decodedIndex] = $value
        $decodedIndex += 1
    }

    return $decoded
}
