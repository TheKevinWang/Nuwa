function New-NuwaRequestDescriptor {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$CallbackHost,

        [Parameter(Mandatory = $true)]
        [string]$CallbackPort,

        [Parameter(Mandatory = $true)]
        [string]$PostUri,

        [Parameter(Mandatory = $true)]
        [hashtable]$Headers,

        [Parameter(Mandatory = $true)]
        [string]$Body
    )

    $baseHost = $CallbackHost.TrimEnd('/')
    $path = if ($PostUri.StartsWith('/')) { $PostUri } else { "/$PostUri" }
    return @{
        Method = 'POST'
        Uri = ('{0}:{1}{2}' -f $baseHost, $CallbackPort, $path)
        Headers = $Headers
        Body = $Body
    }
}

function ConvertFrom-NuwaHttpContent {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$Content
    )

    if ($null -eq $Content) {
        return ''
    }

    if ($Content -is [string]) {
        return [string]$Content
    }

    if ($Content -is [byte[]]) {
        return ConvertFrom-NuwaUtf8Bytes -Bytes $Content
    }

    if ($Content -is [Array]) {
        return ConvertFrom-NuwaUtf8Bytes -Bytes ([byte[]]$Content)
    }

    return [string]$Content
}

function Invoke-NuwaFullLanguageHttpRequest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][hashtable]$Request,
        [Parameter(Mandatory = $true)][hashtable]$InvokeParameters,
        [Parameter(Mandatory = $true)][hashtable]$RequestHeaders,
        [Parameter(Mandatory = $true)][byte[]]$BodyBytes
    )

    $webRequest = $null
    try {
        $webRequest = New-Object -ComObject WinHttp.WinHttpRequest.5.1
        $webRequest.Open([string]$Request.Method, [string]$Request.Uri, $false)
        if ($InvokeParameters.ContainsKey('Proxy')) {
            $webRequest.SetProxy(2, [string]$InvokeParameters.Proxy)
            if (-not [string]::IsNullOrWhiteSpace($script:NuwaConfig.ProxyUser)) {
                $webRequest.SetCredentials(
                    [string]$script:NuwaConfig.ProxyUser,
                    [string]$script:NuwaConfig.ProxyPass,
                    1
                )
            }
        }
        $hasContentType = $false
        foreach ($key in $RequestHeaders.Keys) {
            $name = [string]$key
            if (
                $name -ieq 'Connection' -or
                $name -ieq 'Content-Length' -or
                $name -ieq 'Transfer-Encoding'
            ) {
                continue
            }
            if ($name -ieq 'Content-Type') { $hasContentType = $true }
            $webRequest.SetRequestHeader($name, [string]$RequestHeaders[$key])
        }
        if (-not $hasContentType) {
            $webRequest.SetRequestHeader('Content-Type', 'application/octet-stream')
        }
        $webRequest.Send($BodyBytes)
        $responseBytes = [byte[]]$webRequest.ResponseBody
        return ConvertFrom-NuwaHttpContent -Content $responseBytes
    } finally {
        if ($null -ne $webRequest) {
            $null = [System.Runtime.InteropServices.Marshal]::FinalReleaseComObject($webRequest)
        }
    }
}

function Invoke-NuwaHttpRequest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Body
    )

    $request = New-NuwaRequestDescriptor `
        -CallbackHost $script:NuwaConfig.CallbackHost `
        -CallbackPort $script:NuwaConfig.CallbackPort `
        -PostUri $script:NuwaConfig.PostUri `
        -Headers $script:NuwaConfig.Headers `
        -Body $Body

    $bodyBytes = [byte[]](ConvertTo-NuwaUtf8Bytes -Value ([string]$request.Body))
    $invokeParameters = @{
        Uri = $request.Uri
        Method = $request.Method
        Body = $bodyBytes
        UseBasicParsing = $true
    }
    $requestHeaders = @{}
    foreach ($key in $request.Headers.Keys) {
        $requestHeaders[$key] = $request.Headers[$key]
    }
    Set-NuwaProxyRequestOptions -InvokeParameters $invokeParameters -RequestHeaders $requestHeaders
    $invokeParameters.Headers = $requestHeaders
    if ($script:NuwaConfig.TransportEnvelopeEnabled) {
        $invokeParameters.DisableKeepAlive = $true
        if ($ExecutionContext.SessionState.LanguageMode -eq 'FullLanguage') {
            Write-NuwaDebug "POST $($request.Uri)"
            return Invoke-NuwaFullLanguageHttpRequest `
                -Request $request `
                -InvokeParameters $invokeParameters `
                -RequestHeaders $requestHeaders `
                -BodyBytes $bodyBytes
        }
    }

    Write-NuwaDebug "POST $($request.Uri)"
    $response = Invoke-WebRequest @invokeParameters
    return ConvertFrom-NuwaHttpContent -Content $response.Content
}

# NUWA_HTTP_FIXED_TRANSPORT_BEGIN
function Invoke-NuwaTransport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Uuid,

        [Parameter(Mandatory = $true)]
        [string]$Action,

        [Parameter(Mandatory = $true)]
        [string]$WireBody
    )

    $body = New-NuwaTransportRequestBody -Uuid $Uuid -WireBody $WireBody
    # NUWA_TRANSPORT_ENVELOPE_BEGIN
    if (-not $script:NuwaConfig.TransportEnvelopeEnabled) {
        return Invoke-NuwaHttpRequest -Body $body
    }

    $wrapper = @{
        message = $body
        sender_id = $Uuid
        to_server = $true
        id = 1
        final = $true
    }
    if ([string]$script:NuwaConfig.TransportMessageFormat -eq 'raw-v1') {
        $wrapper.message_format = 'raw-v1'
    }
    $document = ConvertTo-NuwaTransportEnvelopeDocument `
        -Wrapper $wrapper `
        -Direction 'agent-to-server'
    $responseDocument = Invoke-NuwaHttpRequest -Body $document
    try {
        $responseWrapper = ConvertFrom-NuwaTransportEnvelopeDocument `
            -Value $responseDocument `
            -Direction 'server-to-agent'
        if ([string]$responseWrapper.client_id -cne $Uuid) {
            throw 'Transport response route is invalid'
        }
        if (
            -not [string]::IsNullOrEmpty([string]$responseWrapper.message_format) -and
            [string]$responseWrapper.message_format -cne 'raw-v1'
        ) {
            throw 'Transport response format is invalid'
        }
        return [string]$responseWrapper.message
    } catch {
        throw 'Transport response is invalid'
    }
    # NUWA_TRANSPORT_ENVELOPE_END
}
# NUWA_HTTP_FIXED_TRANSPORT_END
