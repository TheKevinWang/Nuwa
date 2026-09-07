function ConvertTo-NuwaTransportPresentation {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][byte[]]$Bytes)

    return [Convert]::ToBase64String($Bytes)
}

function ConvertFrom-NuwaTransportPresentation {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Value)

    try {
        $decoded = [byte[]][Convert]::FromBase64String($Value)
    } catch {
        throw 'Transport Base64 document is not valid canonical Base64'
    }
    if ([Convert]::ToBase64String($decoded) -cne $Value) {
        throw 'Transport Base64 document is not canonical'
    }
    return ,$decoded
}
