function Invoke-NuwaHostname {
    [CmdletBinding()]
    param()

    if ($env:COMPUTERNAME) {
        return $env:COMPUTERNAME
    }
    return 'unknown-host'
}
