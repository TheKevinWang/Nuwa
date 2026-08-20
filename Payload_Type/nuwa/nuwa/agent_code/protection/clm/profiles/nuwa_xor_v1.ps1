function Get-NuwaProtectionProfileName {
    [CmdletBinding()]
    param()

    return 'nuwa_xor_v1'
}

function Protect-NuwaBytes {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [byte[]]$Bytes,

        [Parameter(Mandatory = $true)]
        [hashtable]$Context
    )

    $key = Get-NuwaProtectionKey
    $result = New-NuwaClmByteArray -Length $Bytes.Length
    for ($index = 0; $index -lt $Bytes.Length; $index += 1) {
        $result[$index] = $Bytes[$index] -bxor $key[$index % $key.Length]
    }
    return ,$result
}

function Unprotect-NuwaBytes {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [byte[]]$Bytes,

        [Parameter(Mandatory = $true)]
        [hashtable]$Context
    )

    return ,(Protect-NuwaBytes -Bytes $Bytes -Context $Context)
}
