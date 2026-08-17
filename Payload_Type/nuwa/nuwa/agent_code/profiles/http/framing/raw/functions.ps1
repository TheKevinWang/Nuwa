function Set-NuwaProxyRequestOptions {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$InvokeParameters,

        [Parameter(Mandatory = $true)]
        [hashtable]$RequestHeaders
    )

    if (
        $RequestHeaders.ContainsKey('X-Mythic-Body-Format') -and
        [string]$RequestHeaders['X-Mythic-Body-Format'] -ne 'raw-v1'
    ) {
        throw 'The transport format header conflicts with raw-v1'
    }
    $RequestHeaders['X-Mythic-Body-Format'] = 'raw-v1'

    if (-not [string]::IsNullOrWhiteSpace($script:NuwaConfig.ProxyHost)) {
        $InvokeParameters.Proxy = ('{0}:{1}' -f $script:NuwaConfig.ProxyHost, $script:NuwaConfig.ProxyPort)
    }
}
