function ConvertTo-NuwaDiscordMessageWrapper {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [byte[]]$Message,

        [Parameter(Mandatory = $true)]
        [string]$SenderId,

        [Parameter(Mandatory = $true)]
        [bool]$ToServer
    )

    $wrapper = @{
        message = $Message
        sender_id = $SenderId
        to_server = $ToServer
        id = 1
        final = $true
    }
    $wrapper = Add-NuwaDiscordMessageFormat -Wrapper $wrapper
    return ConvertTo-NuwaTransportEnvelopeDocument `
        -Wrapper $wrapper `
        -Direction 'agent-to-server'
}
