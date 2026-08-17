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

    $invokeParameters = @{
        Uri = $request.Uri
        Method = $request.Method
        Body = $request.Body
        UseBasicParsing = $true
    }
    $requestHeaders = @{}
    foreach ($key in $request.Headers.Keys) {
        $requestHeaders[$key] = $request.Headers[$key]
    }
    Set-NuwaProxyRequestOptions -InvokeParameters $invokeParameters -RequestHeaders $requestHeaders
    $invokeParameters.Headers = $requestHeaders

    Write-NuwaDebug "POST $($request.Uri)"
    $response = Invoke-WebRequest @invokeParameters
    return ConvertFrom-NuwaHttpContent -Content $response.Content
}

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
    return Invoke-NuwaHttpRequest -Body $body
}
