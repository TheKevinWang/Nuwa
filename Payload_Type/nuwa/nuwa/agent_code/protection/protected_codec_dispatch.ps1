function Get-NuwaCodecProfile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Context
    )

    $profile = [string]$Context.codec_profile
    if ([string]::IsNullOrWhiteSpace($profile)) {
        return 'decimal'
    }
    return $profile.ToLowerInvariant()
}

function Get-NuwaDecodeCodecProfiles {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Context
    )

    $configuredProfiles = @()
    foreach ($contextProfile in @($Context.decode_codec_profiles)) {
        if (-not [string]::IsNullOrWhiteSpace([string]$contextProfile)) {
            $configuredProfiles += [string]$contextProfile
        }
    }
    if ($configuredProfiles.Count -eq 0) {
        foreach ($configProfile in @($script:NuwaConfig.DecodeCodecProfiles)) {
            if (-not [string]::IsNullOrWhiteSpace([string]$configProfile)) {
                $configuredProfiles += [string]$configProfile
            }
        }
    }
    if ($configuredProfiles.Count -eq 0) {
        $configuredProfiles = @('decimal')
    }

    $profiles = @()
    foreach ($configuredProfile in $configuredProfiles) {
        $profile = ([string]$configuredProfile).Trim().ToLowerInvariant()
        if ([string]::IsNullOrWhiteSpace($profile) -or ($profiles -contains $profile)) {
            continue
        }
        $profiles += $profile
    }
    return $profiles
}

function ConvertTo-NuwaInner {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [byte[]]$Bytes,

        [Parameter(Mandatory = $true)]
        [hashtable]$Context
    )

    switch (Get-NuwaCodecProfile -Context $Context) {
        'decimal' {
            return ConvertTo-NuwaDecimalBytes -Bytes $Bytes -Context $Context
        }
        default {
            throw ("Unsupported codec profile '{0}'" -f (Get-NuwaCodecProfile -Context $Context))
        }
    }
}

function ConvertFrom-NuwaInner {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [byte[]]$Bytes,

        [Parameter(Mandatory = $true)]
        [hashtable]$Context
    )

    switch (Get-NuwaCodecProfile -Context $Context) {
        'decimal' {
            return ConvertFrom-NuwaDecimalBytes -Bytes $Bytes -Context $Context
        }
        default {
            throw ("Unsupported codec profile '{0}'" -f (Get-NuwaCodecProfile -Context $Context))
        }
    }
}

function ConvertTo-NuwaWireBytes {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$MessageJson,

        [Parameter(Mandatory = $true)]
        [hashtable]$Context
    )

    $messageBytes = ConvertTo-NuwaUtf8Bytes -Value $MessageJson
    $protectedBytes = [byte[]](Protect-NuwaBytes -Bytes $messageBytes -Context $Context)
    return ConvertTo-NuwaInner -Bytes $protectedBytes -Context $Context
}

function Get-NuwaWireDecodeCandidates {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [byte[]]$WireBytes,

        [Parameter(Mandatory = $true)]
        [hashtable]$Context
    )

    $candidates = @()
    foreach ($codecProfile in @(Get-NuwaDecodeCodecProfiles -Context $Context)) {
        $attemptContext = @{}
        foreach ($contextKey in $Context.Keys) {
            $attemptContext[$contextKey] = $Context[$contextKey]
        }
        $attemptContext.codec_profile = $codecProfile

        try {
            $decodedBytes = [byte[]](
                ConvertFrom-NuwaInner -Bytes $WireBytes -Context $attemptContext
            )
            $messageBytes = [byte[]](
                Unprotect-NuwaBytes -Bytes $decodedBytes -Context $attemptContext
            )
            $json = ConvertFrom-NuwaUtf8Bytes -Bytes $messageBytes
            $trimmedJson = $json.Trim()
            if (-not $trimmedJson.StartsWith('{')) {
                continue
            }
            $null = $trimmedJson | ConvertFrom-Json -ErrorAction Stop
        } catch {
            continue
        }

        $candidates += @{
            Json = $json
            CodecProfile = $codecProfile
        }
    }
    return $candidates
}

function Resolve-NuwaWireBytes {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [byte[]]$WireBytes,

        [Parameter(Mandatory = $true)]
        [hashtable]$Context
    )

    $candidates = @(Get-NuwaWireDecodeCandidates -WireBytes $WireBytes -Context $Context)
    if ($candidates.Count -eq 0) {
        throw 'No Nuwa codec accepted the wire payload'
    }
    if ($candidates.Count -gt 1) {
        $matchingProfiles = (($candidates | ForEach-Object { [string]$_.CodecProfile }) -join ', ')
        throw ("Ambiguous Nuwa wire payload: {0}" -f $matchingProfiles)
    }
    return $candidates[0]
}

function ConvertFrom-NuwaWireBytes {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [byte[]]$WireBytes,

        [Parameter(Mandatory = $true)]
        [hashtable]$Context
    )

    $resolved = Resolve-NuwaWireBytes -WireBytes $WireBytes -Context $Context
    return [string]$resolved.Json
}
