function Invoke-NuwaHostname {
    [CmdletBinding()]
    param()

    if ($env:COMPUTERNAME) {
        return $env:COMPUTERNAME
    }
    return $script:NuwaH_unknown_host
}
