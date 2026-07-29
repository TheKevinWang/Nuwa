function Invoke-NuwaExit {
    [CmdletBinding()]
    param()

    $script:NuwaState.ExitRequested = $true
    return 'Nuwa exiting'
}
