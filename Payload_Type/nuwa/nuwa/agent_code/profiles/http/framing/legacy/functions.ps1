function Set-NuwaProxyRequestOptions {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$InvokeParameters,

        [Parameter(Mandatory = $true)]
        [hashtable]$RequestHeaders
    )

    if ([string]::IsNullOrWhiteSpace($script:NuwaConfig.ProxyHost)) {
        return
    }

    $InvokeParameters.Proxy = ('{0}:{1}' -f $script:NuwaConfig.ProxyHost, $script:NuwaConfig.ProxyPort)
    if ([string]::IsNullOrWhiteSpace($script:NuwaConfig.ProxyUser)) {
        return
    }

    $proxyCredentialBytes = ConvertTo-NuwaUtf8Bytes -Value ('{0}:{1}' -f $script:NuwaConfig.ProxyUser, $script:NuwaConfig.ProxyPass)
    $RequestHeaders['Proxy-Authorization'] = ('Basic {0}' -f (ConvertTo-NuwaBase64String -Bytes $proxyCredentialBytes))
}
