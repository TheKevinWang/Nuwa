function Invoke-NuwaExit {
    [CmdletBinding()]
    param()

    $script:NuwaState.ExitRequested = $true
    return 'Agent exiting'
}
