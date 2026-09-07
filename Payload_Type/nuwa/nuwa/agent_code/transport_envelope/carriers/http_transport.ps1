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
}
