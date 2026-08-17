function New-NuwaTransportRequestBody {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Uuid,

        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$WireBody
    )

    $body = $Uuid + $WireBody
    if ((ConvertTo-NuwaUtf8Bytes -Value $body).Length -gt 262144) {
        throw 'Raw transport request exceeds the 262144-byte limit'
    }
    return $body
}

function Get-NuwaTransportResponseCandidates {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ResponseBody,

        [Parameter(Mandatory = $true)]
        [string]$ExpectedUuid,

        [Parameter(Mandatory = $true)]
        [int]$UuidLength
    )

    return @(
        @{
            Framing = 'raw'
            WireBody = $ResponseBody
            WireBytes = ConvertTo-NuwaUtf8Bytes -Value $ResponseBody
            Uuid = $ExpectedUuid
        }
    )
}

function Add-NuwaMessageMetadata {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Message
    )

    $Message.nuwa_binary_format = 'byte_array'
    return $Message
}

function ConvertTo-NuwaChunkData {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [byte[]]$Bytes
    )

    $values = [int[]]::new($Bytes.Length)
    for ($index = 0; $index -lt $Bytes.Length; $index += 1) {
        $values[$index] = [int]$Bytes[$index]
    }
    return ,$values
}

function ConvertFrom-NuwaChunkData {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object]$Value
    )

    if ($Value -isnot [Array]) {
        throw 'Chunk data must be an array of byte values'
    }

    $bytes = [byte[]]::new($Value.Count)
    for ($index = 0; $index -lt $Value.Count; $index += 1) {
        $item = $Value[$index]
        $isInteger = (
            $item -is [byte] -or
            $item -is [sbyte] -or
            $item -is [int16] -or
            $item -is [uint16] -or
            $item -is [int32] -or
            $item -is [uint32] -or
            $item -is [int64] -or
            $item -is [uint64]
        )
        if (-not $isInteger -or [int64]$item -lt 0 -or [uint64]$item -gt 255) {
            throw ("Chunk data item {0} must be an integer from 0 through 255" -f $index)
        }
        $bytes[$index] = [byte]$item
    }
    return ,$bytes
}

function Test-NuwaChunkDataPresent {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [object]$Value
    )

    return $Value -is [Array]
}

function Get-NuwaFileChunkSize {
    [CmdletBinding()]
    param()

    return 16384
}
