function New-NuwaTransportRequestBody {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Uuid,

        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$WireBody
    )

    return ConvertTo-NuwaTransportEnvelope `
        -Uuid $Uuid `
        -MessageBytes (ConvertTo-NuwaUtf8Bytes -Value $WireBody)
}

function Add-NuwaMessageMetadata {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Message
    )

    return $Message
}
