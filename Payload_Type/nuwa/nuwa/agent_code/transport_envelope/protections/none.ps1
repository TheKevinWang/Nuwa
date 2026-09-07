function Protect-NuwaTransportEnvelopeBytes {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][byte[]]$Bytes,
        [Parameter(Mandatory = $true)][string]$Direction,
        [Parameter(Mandatory = $false)][hashtable]$Context = @{}
    )
    return ,(Copy-NuwaTransportBytes -Bytes $Bytes -Offset 0 -Length $Bytes.Length)
}

function Unprotect-NuwaTransportEnvelopeBytes {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][byte[]]$Bytes,
        [Parameter(Mandatory = $true)][string]$Direction
    )
    return ,(Copy-NuwaTransportBytes -Bytes $Bytes -Offset 0 -Length $Bytes.Length)
}
