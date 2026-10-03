function Invoke-NuwaSleep {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$Parameters)

    $script:NuwaConfig.CallbackInterval = [int]$Parameters.interval
    if ($Parameters.ContainsKey('jitter')) {
        $script:NuwaConfig.CallbackJitter = [int]$Parameters.jitter
    }

    $profileCode = if ([int]$script:NuwaConfig.C2Profile -eq $script:NuwaP_discordx) {
        $script:NuwaP_discordx
    } else {
        $script:NuwaP_http
    }
    $result = @{}
    $result[$script:NuwaF_interval] = [int]$script:NuwaConfig.CallbackInterval
    $result[$script:NuwaF_jitter] = [int]$script:NuwaConfig.CallbackJitter
    $result[$script:NuwaF_c2_profile] = [int]$profileCode
    return $result
}
