function Get-NuwaProtectionProfileName {
    [CmdletBinding()]
    param()

    return 'nuwa_xor_v1'
}

function Get-NuwaProtectionKey {
    [CmdletBinding()]
    param()

    $key = [byte[]]$script:NuwaCryptoState.Key
    if ($null -eq $key -or $key.Length -ne 32) {
        throw 'Nuwa protection key is unavailable'
    }
    return $key
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

    $key = [byte[]](Get-NuwaProtectionKey)
    $result = [byte[]]::new($Bytes.Length)
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

    return Protect-NuwaBytes -Bytes $Bytes -Context $Context
}
