function Invoke-NuwaWhoami {
    [CmdletBinding()]
    param()

    if ($env:USERDOMAIN -and $env:USERNAME) {
        return ('{0}\{1}' -f $env:USERDOMAIN, $env:USERNAME)
    }
    if ($env:USERNAME) {
        return $env:USERNAME
    }
    return 'unknown'
}
