function Invoke-NuwaExit {
    [CmdletBinding()]
    param()

    $script:NuwaState.ExitRequested = $true
    return ,(New-NuwaDiagnosticOutput -Code 1000)
}
