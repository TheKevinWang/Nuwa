function Set-NuwaProxyRequestOptions {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$InvokeParameters, [Parameter(Mandatory = $true)][hashtable]$RequestHeaders)
    if (-not [string]::IsNullOrWhiteSpace($script:NuwaConfig.ProxyHost)) { $InvokeParameters.Proxy = ('{0}:{1}' -f $script:NuwaConfig.ProxyHost, $script:NuwaConfig.ProxyPort) }
}
