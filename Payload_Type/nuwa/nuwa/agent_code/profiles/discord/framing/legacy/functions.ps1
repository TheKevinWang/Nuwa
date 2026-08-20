function Add-NuwaDiscordMessageFormat {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Wrapper
    )

    return $Wrapper
}

# The shared legacy fragment defines this same neutral operation for normal
# payload composition. Keeping it in the Discord legacy hook also lets this
# profile's transport be loaded independently by its narrow compatibility tests.
function New-NuwaTransportRequestBody {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Uuid,

        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$WireBody
    )

    return ConvertTo-NuwaTransportEnvelope `
        -Uuid $Uuid `
        -MessageBytes (ConvertTo-NuwaUtf8Bytes -Value $WireBody)
}

function Set-NuwaDiscordProxyInvokeParameters {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$InvokeParameters
    )

    if ([string]::IsNullOrWhiteSpace($script:NuwaConfig.ProxyHost)) {
        return
    }

    $InvokeParameters.Proxy = ('{0}:{1}' -f $script:NuwaConfig.ProxyHost, $script:NuwaConfig.ProxyPort)
    if ([string]::IsNullOrWhiteSpace($script:NuwaConfig.ProxyUser)) {
        return
    }

    if (-not $InvokeParameters.ContainsKey('Headers') -or $null -eq $InvokeParameters.Headers) {
        $InvokeParameters.Headers = @{}
    }
    $proxyCredentialBytes = ConvertTo-NuwaUtf8Bytes -Value ('{0}:{1}' -f $script:NuwaConfig.ProxyUser, $script:NuwaConfig.ProxyPass)
    $InvokeParameters.Headers['Proxy-Authorization'] = ('Basic {0}' -f (ConvertTo-NuwaBase64String -Bytes $proxyCredentialBytes))
}
