function ConvertTo-NuwaTransportDecimal {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][byte[]]$Bytes)
    $characters = New-Object char[] ($Bytes.Length * 3)
    $output = 0
    for ($index = 0; $index -lt $Bytes.Length; $index += 1) {
        $value = [int]$Bytes[$index]
        $characters[$output] = [char](48 + [int](($value - ($value % 100)) / 100))
        $characters[$output + 1] = [char](48 + [int]((($value % 100) - ($value % 10)) / 10))
        $characters[$output + 2] = [char](48 + ($value % 10))
        $output += 3
    }
    return (-join $characters)
}

function ConvertFrom-NuwaTransportDecimal {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Value)
    if (($Value.Length % 3) -ne 0) { throw 'Transport decimal length is invalid' }
    $bytes = New-Object byte[] ([int]($Value.Length / 3))
    for ($index = 0; $index -lt $Value.Length; $index += 3) {
        $a = [int][char]$Value[$index] - 48
        $b = [int][char]$Value[$index + 1] - 48
        $c = [int][char]$Value[$index + 2] - 48
        if ($a -lt 0 -or $a -gt 9 -or $b -lt 0 -or $b -gt 9 -or $c -lt 0 -or $c -gt 9) { throw 'Transport decimal contains a non-digit' }
        $decoded = ($a * 100) + ($b * 10) + $c
        if ($decoded -gt 255) { throw 'Transport decimal group exceeds 255' }
        $bytes[$index / 3] = [byte]$decoded
    }
    return ,$bytes
}

function ConvertTo-NuwaTransportPresentation {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][byte[]]$Bytes)
    return ConvertTo-NuwaTransportDecimal $Bytes
}

function ConvertFrom-NuwaTransportPresentation {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Value)
    return ,(ConvertFrom-NuwaTransportDecimal $Value)
}
