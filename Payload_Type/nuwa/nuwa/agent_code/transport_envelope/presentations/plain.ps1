function ConvertTo-NuwaTransportPresentation {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)
    return ConvertFrom-NuwaUtf8Bytes -Bytes $Bytes
}

function ConvertFrom-NuwaTransportPresentation {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Value)
    return ,([byte[]](ConvertTo-NuwaUtf8Bytes -Value $Value))
}
