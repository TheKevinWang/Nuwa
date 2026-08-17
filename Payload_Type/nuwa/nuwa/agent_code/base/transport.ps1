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

function Get-NuwaTransportResponseCandidates {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ResponseBody,

        [Parameter(Mandatory = $true)]
        [string]$ExpectedUuid,

        [Parameter(Mandatory = $true)]
        [int]$UuidLength
    )

    $candidates = @(
        @{
            Framing = 'raw'
            WireBody = $ResponseBody
            WireBytes = ConvertTo-NuwaUtf8Bytes -Value $ResponseBody
            Uuid = $ExpectedUuid
        }
    )

    try {
        $decodedEnvelope = ConvertFrom-NuwaTransportEnvelope -Envelope $ResponseBody -UuidLength $UuidLength
        if (
            [string]::IsNullOrWhiteSpace($ExpectedUuid) -or
            [string]$decodedEnvelope.uuid -eq $ExpectedUuid
        ) {
            $candidates += @{
                Framing = 'uuid-envelope'
                WireBody = ConvertFrom-NuwaUtf8Bytes -Bytes ([byte[]]$decodedEnvelope.message_bytes)
                WireBytes = [byte[]]$decodedEnvelope.message_bytes
                Uuid = [string]$decodedEnvelope.uuid
            }
        }
    } catch {
    }

    return $candidates
}
