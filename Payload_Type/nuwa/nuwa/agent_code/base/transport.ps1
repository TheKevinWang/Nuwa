function ConvertTo-NuwaTransportEnvelope {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Uuid,

        [Parameter(Mandatory = $true)]
        [byte[]]$MessageBytes
    )

    $envelopeBytes = @()
    $envelopeBytes += ConvertTo-NuwaUtf8Bytes -Value $Uuid
    $envelopeBytes += $MessageBytes
    return ConvertTo-NuwaBase64String -Bytes ([byte[]]$envelopeBytes)
}

function ConvertFrom-NuwaTransportEnvelope {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Envelope,

        [Parameter(Mandatory = $true)]
        [int]$UuidLength
    )

    $decoded = ConvertFrom-NuwaBase64String -Value $Envelope
    if ($decoded.Length -lt $UuidLength) {
        throw 'Decoded transport envelope is shorter than the UUID prefix'
    }

    $uuidBytes = $decoded[0..($UuidLength - 1)]
    $messageBytes = if ($decoded.Length -gt $UuidLength) {
        $decoded[$UuidLength..($decoded.Length - 1)]
    } else {
        [byte[]]@()
    }

    return @{
        uuid = ConvertFrom-NuwaUtf8Bytes -Bytes ([byte[]]$uuidBytes)
        message_bytes = [byte[]]$messageBytes
    }
}
