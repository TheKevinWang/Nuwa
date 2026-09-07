function ConvertTo-NuwaRadix64Bytes {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [byte[]]$Bytes,

        [Parameter(Mandatory = $true)]
        [hashtable]$Context
    )

    $encoded = [Convert]::ToBase64String($Bytes)
    return ,(ConvertTo-NuwaUtf8Bytes -Value $encoded)
}

function ConvertFrom-NuwaRadix64Bytes {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [byte[]]$Bytes,

        [Parameter(Mandatory = $true)]
        [hashtable]$Context
    )

    $value = ConvertFrom-NuwaUtf8Bytes -Bytes $Bytes
    try {
        $decoded = [byte[]][Convert]::FromBase64String($value)
    } catch {
        throw 'Base64 payload is not valid canonical Base64'
    }
    if ([Convert]::ToBase64String($decoded) -cne $value) {
        throw 'Base64 payload is not canonical'
    }
    return ,$decoded
}
