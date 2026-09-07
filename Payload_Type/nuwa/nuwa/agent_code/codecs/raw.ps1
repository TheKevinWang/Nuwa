function Copy-NuwaRawBytes {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [byte[]]$Bytes
    )

    $result = [byte[]]::new($Bytes.Length)
    for ($index = 0; $index -lt $Bytes.Length; $index += 1) {
        $result[$index] = $Bytes[$index]
    }
    return $result
}

function ConvertTo-NuwaRawBytes {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [byte[]]$Bytes,

        [Parameter(Mandatory = $true)]
        [hashtable]$Context
    )

    return Copy-NuwaRawBytes -Bytes $Bytes
}

function ConvertFrom-NuwaRawBytes {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [byte[]]$Bytes,

        [Parameter(Mandatory = $true)]
        [hashtable]$Context
    )

    return Copy-NuwaRawBytes -Bytes $Bytes
}
