function ConvertTo-NuwaDiscordDecimalEnvelope {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [byte[]]$Bytes,

        [Parameter(Mandatory = $true)]
        [hashtable]$Context
    )

    $characters = [char[]]::new($Bytes.Length * 3)
    $outputIndex = 0
    for ($index = 0; $index -lt $Bytes.Length; $index += 1) {
        $value = [int]$Bytes[$index]
        $hundreds = ($value - ($value % 100)) / 100
        $tensValue = $value % 100
        $tens = ($tensValue - ($tensValue % 10)) / 10
        $characters[$outputIndex] = [char](48 + $hundreds)
        $characters[$outputIndex + 1] = [char](48 + $tens)
        $characters[$outputIndex + 2] = [char](48 + ($value % 10))
        $outputIndex += 3
    }
    return (-join $characters)
}

function ConvertFrom-NuwaDiscordDecimalEnvelope {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Value,

        [Parameter(Mandatory = $true)]
        [hashtable]$Context
    )

    if (($Value.Length % 3) -ne 0) {
        throw 'Decimal envelope length must be divisible by 3'
    }
    $bytes = [byte[]]::new($Value.Length / 3)
    $outputIndex = 0
    for ($index = 0; $index -lt $Value.Length; $index += 3) {
        $digitA = [int][char]$Value[$index] - 48
        $digitB = [int][char]$Value[$index + 1] - 48
        $digitC = [int][char]$Value[$index + 2] - 48
        if (
            $digitA -lt 0 -or $digitA -gt 9 -or
            $digitB -lt 0 -or $digitB -gt 9 -or
            $digitC -lt 0 -or $digitC -gt 9
        ) {
            throw 'Decimal envelope must contain only digits'
        }
        $decoded = ($digitA * 100) + ($digitB * 10) + $digitC
        if ($decoded -gt 255) {
            throw 'Decimal envelope group exceeds 255'
        }
        $bytes[$outputIndex] = [byte]$decoded
        $outputIndex += 1
    }
    return $bytes
}

Register-NuwaDiscordEnvelopeCodec `
    -Name 'decimal' `
    -Encode ${function:ConvertTo-NuwaDiscordDecimalEnvelope} `
    -Decode ${function:ConvertFrom-NuwaDiscordDecimalEnvelope} `
    -MaxExpansionNumerator 3 `
    -MaxExpansionDenominator 1 `
    -FixedOverheadBytes 0 `
    -UsesEntropy $false
