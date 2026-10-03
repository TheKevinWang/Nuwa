function Add-NuwaMessageMetadata {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$Message)
    return $Message
}

function ConvertTo-NuwaChunkData {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][byte[]]$Bytes)
    return ,([byte[]]$Bytes)
}

function ConvertFrom-NuwaChunkData {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][object]$Value)
    if ($Value -isnot [Array]) {
        throw (New-NuwaDiagnosticOutput -Code 1091)
    }
    $bytes = @(
        for ($index = 0; $index -lt $Value.Count; $index += 1) {
            $item = $Value[$index]
            $isInteger = (
                $item -is [byte] -or $item -is [sbyte] -or
                $item -is [int16] -or $item -is [uint16] -or
                $item -is [int32] -or $item -is [uint32] -or
                $item -is [int64] -or $item -is [uint64]
            )
            if (-not $isInteger -or [int64]$item -lt 0 -or [uint64]$item -gt 255) {
                throw (New-NuwaDiagnosticOutput -Code 1092 -Arguments @($index))
            }
            [byte]$item
        }
    )
    return ,([byte[]]$bytes)
}

function Test-NuwaChunkDataPresent {
    [CmdletBinding()]
    param([Parameter(Mandatory = $false)][AllowNull()][AllowEmptyCollection()][object]$Value)
    return $Value -is [Array]
}

function Get-NuwaFileChunkSize {
    [CmdletBinding()]
    param()
    return 16384
}
