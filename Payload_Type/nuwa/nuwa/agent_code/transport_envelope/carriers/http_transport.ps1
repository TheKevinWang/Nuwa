function Invoke-NuwaTransport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Uuid,

        [Parameter(Mandatory = $true)]
        [string]$Action,

        [Parameter(Mandatory = $true)]
        [byte[]]$WireBody
    )

    [byte[]]$body = New-NuwaTransportRequestBody -Uuid $Uuid -WireBody $WireBody
    $wrapper = @{
        message = $body
        sender_id = $Uuid
        to_server = $true
        id = 1
        final = $true
        message_format = 'raw-v1'
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
        if ([string]$responseWrapper.message_format -cne 'raw-v1') {
            throw 'Transport response format is invalid'
        }
        return ,([byte[]]$responseWrapper.message)
    } catch {
        if ([bool]$script:NuwaConfig.DebugLogging) {
            Write-NuwaDebug ("HTTP envelope decode failed: {0}" -f $_.Exception.Message)
        }
        throw 'Transport response is invalid'
    }
}
