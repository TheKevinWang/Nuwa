function Invoke-NuwaCd {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Parameters
    )

    $target = [string]$Parameters.path
    if ([string]::IsNullOrWhiteSpace($target)) {
        throw 'cd requires a target path'
    }

    Push-Location -LiteralPath $script:NuwaState.CurrentDirectory
    try {
        Set-Location -LiteralPath $target
        $resolved = (Get-Location).ProviderPath
    } finally {
        Pop-Location
    }

    $script:NuwaState.CurrentDirectory = $resolved
    return $resolved
}
