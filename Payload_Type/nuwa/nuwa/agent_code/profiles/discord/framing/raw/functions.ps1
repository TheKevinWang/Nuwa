function Add-NuwaDiscordMessageFormat {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Wrapper
    )

    $Wrapper.message_format = 'raw-v1'
    return $Wrapper
}

function Set-NuwaDiscordProxyInvokeParameters {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$InvokeParameters
    )

    if (-not [string]::IsNullOrWhiteSpace($script:NuwaConfig.ProxyHost)) {
        $InvokeParameters.Proxy = ('{0}:{1}' -f $script:NuwaConfig.ProxyHost, $script:NuwaConfig.ProxyPort)
    }
}
