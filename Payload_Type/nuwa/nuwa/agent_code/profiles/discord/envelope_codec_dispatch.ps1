$script:NuwaDiscordEnvelopeCodecRegistry = @{}
$script:NuwaDiscordEnvelopeMaximumEncodedUtf8Bytes = 2097152
$script:NuwaDiscordEnvelopeMaximumDecodedUtf8Bytes = 524288
$script:NuwaDiscordEnvelopeMaximumRawMessageUtf8Bytes = 262144

function Register-NuwaDiscordEnvelopeCodec {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [scriptblock]$Encode,

        [Parameter(Mandatory = $true)]
        [scriptblock]$Decode,

        [Parameter(Mandatory = $true)]
        [int]$MaxExpansionNumerator,

        [Parameter(Mandatory = $true)]
        [int]$MaxExpansionDenominator,

        [Parameter(Mandatory = $true)]
        [int]$FixedOverheadBytes,

        [Parameter(Mandatory = $true)]
        [bool]$UsesEntropy
    )

    $normalized = $Name.Trim().ToLowerInvariant()
    if ($normalized -eq 'legacy-json' -or $normalized -notmatch '^[a-z0-9][a-z0-9_-]{0,31}$') {
        throw "Invalid or reserved Discord envelope codec name"
    }
    if ($script:NuwaDiscordEnvelopeCodecRegistry.ContainsKey($normalized)) {
        throw ("Duplicate Discord envelope codec '{0}'" -f $normalized)
    }
    if ($MaxExpansionNumerator -le 0 -or $MaxExpansionDenominator -le 0 -or $FixedOverheadBytes -lt 0) {
        throw "Invalid Discord envelope codec resource declaration"
    }

    $script:NuwaDiscordEnvelopeCodecRegistry[$normalized] = @{
        Name = $normalized
        Encode = $Encode
        Decode = $Decode
        MaxExpansionNumerator = $MaxExpansionNumerator
        MaxExpansionDenominator = $MaxExpansionDenominator
        FixedOverheadBytes = $FixedOverheadBytes
        UsesEntropy = $UsesEntropy
    }
}

function Copy-NuwaDiscordEnvelopeContext {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [hashtable]$Context = @{}
    )

    $copy = @{}
    if ($null -ne $Context) {
        foreach ($key in $Context.Keys) {
            $copy[$key] = $Context[$key]
        }
    }
    return $copy
}

function Test-NuwaDiscordEnvelopeSafeText {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Value
    )

    if ($Value.Length -gt 0 -and (
        [char]::IsWhiteSpace($Value[0]) -or
        [char]::IsWhiteSpace($Value[$Value.Length - 1])
    )) {
        return $false
    }
    for ($index = 0; $index -lt $Value.Length; $index += 1) {
        $unit = [int][char]$Value[$index]
        if ($unit -eq 0 -or $unit -lt 32 -or $unit -eq 127) {
            return $false
        }
        if ($unit -ge 0xD800 -and $unit -le 0xDBFF) {
            if ($index + 1 -ge $Value.Length) {
                return $false
            }
            $low = [int][char]$Value[$index + 1]
            if ($low -lt 0xDC00 -or $low -gt 0xDFFF) {
                return $false
            }
            $index += 1
        } elseif ($unit -ge 0xDC00 -and $unit -le 0xDFFF) {
            return $false
        }
    }
    return $true
}

function Get-NuwaDiscordEnvelopeProperty {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$Object,

        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    if ($null -eq $Object) {
        return $null
    }
    if ($Object -is [hashtable]) {
        if ($Object.ContainsKey($Name)) {
            return $Object[$Name]
        }
        return $null
    }
    try {
        return $Object.$Name
    } catch {
        return $null
    }
}

function Test-NuwaDiscordLegacyEnvelopeWrapper {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Wrapper
    )

    $names = @($Wrapper.PSObject.Properties.Name)
    if ($names -contains 'envelope_version' -or $names -contains 'envelope_codec') {
        return $false
    }
    if ($names -notcontains 'message' -or $names -notcontains 'sender_id' -or $names -notcontains 'to_server') {
        return $false
    }
    return (
        (Get-NuwaDiscordEnvelopeProperty -Object $Wrapper -Name 'message') -is [string] -and
        (Get-NuwaDiscordEnvelopeProperty -Object $Wrapper -Name 'sender_id') -is [string] -and
        (Get-NuwaDiscordEnvelopeProperty -Object $Wrapper -Name 'to_server') -is [bool]
    )
}

function Test-NuwaDiscordEncodedEnvelopeWrapper {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Wrapper,

        [Parameter(Mandatory = $true)]
        [string]$CodecProfile
    )

    $allowed = @(
        'message', 'sender_id', 'to_server', 'client_id', 'message_format',
        'id', 'final', 'envelope_version', 'envelope_codec'
    )
    $names = @($Wrapper.PSObject.Properties.Name)
    foreach ($name in $names) {
        if ($allowed -notcontains $name) {
            return $false
        }
    }
    foreach ($required in @('message', 'sender_id', 'to_server', 'id', 'final', 'envelope_version', 'envelope_codec')) {
        if ($names -notcontains $required) {
            return $false
        }
    }

    $message = Get-NuwaDiscordEnvelopeProperty -Object $Wrapper -Name 'message'
    $senderId = Get-NuwaDiscordEnvelopeProperty -Object $Wrapper -Name 'sender_id'
    $toServer = Get-NuwaDiscordEnvelopeProperty -Object $Wrapper -Name 'to_server'
    $clientId = Get-NuwaDiscordEnvelopeProperty -Object $Wrapper -Name 'client_id'
    $messageFormat = Get-NuwaDiscordEnvelopeProperty -Object $Wrapper -Name 'message_format'
    $id = Get-NuwaDiscordEnvelopeProperty -Object $Wrapper -Name 'id'
    $final = Get-NuwaDiscordEnvelopeProperty -Object $Wrapper -Name 'final'
    $envelopeVersion = Get-NuwaDiscordEnvelopeProperty -Object $Wrapper -Name 'envelope_version'
    $envelopeCodec = Get-NuwaDiscordEnvelopeProperty -Object $Wrapper -Name 'envelope_codec'
    if (
        $message -isnot [string] -or
        $senderId -isnot [string] -or
        $senderId -cnotmatch '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' -or
        $toServer -isnot [bool] -or
        -not (Test-NuwaDiscordEnvelopeIntegerOne -Value $id) -or
        $final -isnot [bool] -or
        $final -ne $true -or
        -not (Test-NuwaDiscordEnvelopeIntegerOne -Value $envelopeVersion) -or
        $envelopeCodec -isnot [string] -or
        $envelopeCodec -cne $CodecProfile
    ) {
        return $false
    }
    if ($toServer) {
        if ($names -contains 'client_id') {
            return $false
        }
    } else {
        if (
            $clientId -isnot [string] -or
            $clientId -cnotmatch '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
        ) {
            return $false
        }
    }
    if ($null -ne $messageFormat -and (
        $messageFormat -isnot [string] -or
        $messageFormat -cne 'raw-v1'
    )) {
        return $false
    }
    if ($messageFormat -ceq 'raw-v1') {
        if (
            $message.Length -lt 36 -or
            $message.Substring(0, 36) -cne $senderId -or
            (ConvertTo-NuwaUtf8Bytes -Value $message).Length -gt $script:NuwaDiscordEnvelopeMaximumRawMessageUtf8Bytes
        ) {
            return $false
        }
    }
    return $true
}

function Test-NuwaDiscordEnvelopeIntegerOne {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$Value
    )

    if (
        $Value -isnot [sbyte] -and
        $Value -isnot [byte] -and
        $Value -isnot [int16] -and
        $Value -isnot [uint16] -and
        $Value -isnot [int32] -and
        $Value -isnot [uint32] -and
        $Value -isnot [int64] -and
        $Value -isnot [uint64]
    ) {
        return $false
    }
    return ($Value -eq 1)
}

function ConvertTo-NuwaDiscordEnvelopeText {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Wrapper,

        [Parameter(Mandatory = $true)]
        [string]$CodecProfile,

        [Parameter(Mandatory = $false)]
        [hashtable]$Context = @{}
    )

    $profile = $CodecProfile.Trim().ToLowerInvariant()
    if (-not $script:NuwaDiscordEnvelopeCodecRegistry.ContainsKey($profile)) {
        throw ("Unsupported Discord envelope codec '{0}'" -f $profile)
    }
    $encodedWrapper = @{}
    foreach ($key in $Wrapper.Keys) {
        $encodedWrapper[$key] = $Wrapper[$key]
    }
    $encodedWrapper.envelope_version = 1
    $encodedWrapper.envelope_codec = $profile
    $json = $encodedWrapper | ConvertTo-Json -Compress -Depth 10
    $jsonBytes = ConvertTo-NuwaUtf8Bytes -Value $json
    if ($jsonBytes.Length -gt $script:NuwaDiscordEnvelopeMaximumDecodedUtf8Bytes) {
        throw 'Discord envelope decoded wrapper exceeds the UTF-8 byte limit'
    }

    $registration = $script:NuwaDiscordEnvelopeCodecRegistry[$profile]
    $maximumDeclared = [int](
        (($jsonBytes.Length * [int64]$registration.MaxExpansionNumerator) / [int64]$registration.MaxExpansionDenominator) +
        [int64]$registration.FixedOverheadBytes
    )
    $attemptContext = Copy-NuwaDiscordEnvelopeContext -Context $Context
    $attemptContext.envelope_codec = $profile
    $attemptContext.envelope_version = 1
    $text = [string](& $registration.Encode ([byte[]]$jsonBytes) $attemptContext)
    $encodedLength = (ConvertTo-NuwaUtf8Bytes -Value $text).Length
    if ($encodedLength -gt $maximumDeclared) {
        throw 'Discord envelope codec exceeded its declared expansion'
    }
    if ($encodedLength -gt $script:NuwaDiscordEnvelopeMaximumEncodedUtf8Bytes) {
        throw 'Discord envelope document exceeds the UTF-8 byte limit'
    }
    if (-not (Test-NuwaDiscordEnvelopeSafeText -Value $text)) {
        throw 'Discord envelope codec returned unsafe text'
    }
    return $text
}

function Resolve-NuwaDiscordEnvelopeText {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Value,

        [Parameter(Mandatory = $false)]
        [hashtable]$Context = @{}
    )

    if ((ConvertTo-NuwaUtf8Bytes -Value $Value).Length -gt $script:NuwaDiscordEnvelopeMaximumEncodedUtf8Bytes) {
        throw 'Discord envelope document exceeds the UTF-8 byte limit'
    }
    $candidates = @()
    try {
        $legacy = $Value | ConvertFrom-Json -ErrorAction Stop
        if (Test-NuwaDiscordLegacyEnvelopeWrapper -Wrapper $legacy) {
            $candidates += @{
                Wrapper = $legacy
                CodecProfile = 'legacy-json'
                IsEncoded = $false
            }
        }
    } catch {
    }

    foreach ($profile in @($script:NuwaConfig.DiscordEnvelopeDecodeCodecs)) {
        $normalized = ([string]$profile).Trim().ToLowerInvariant()
        if (-not $script:NuwaDiscordEnvelopeCodecRegistry.ContainsKey($normalized)) {
            continue
        }
        $registration = $script:NuwaDiscordEnvelopeCodecRegistry[$normalized]
        $attemptContext = Copy-NuwaDiscordEnvelopeContext -Context $Context
        $attemptContext.envelope_codec = $normalized
        $attemptContext.envelope_version = 1
        try {
            $decodedBytes = [byte[]](& $registration.Decode $Value $attemptContext)
            if ($decodedBytes.Length -gt $script:NuwaDiscordEnvelopeMaximumDecodedUtf8Bytes) {
                continue
            }
            $json = ConvertFrom-NuwaUtf8Bytes -Bytes $decodedBytes
            $wrapper = $json | ConvertFrom-Json -ErrorAction Stop
            if (-not (Test-NuwaDiscordEncodedEnvelopeWrapper -Wrapper $wrapper -CodecProfile $normalized)) {
                continue
            }
            $candidates += @{
                Wrapper = $wrapper
                CodecProfile = $normalized
                IsEncoded = $true
            }
        } catch {
            continue
        }
    }

    if ($candidates.Count -eq 0) {
        throw 'No Discord envelope codec accepted the channel document'
    }
    if ($candidates.Count -gt 1) {
        throw 'Ambiguous Discord envelope channel document'
    }
    return $candidates[0]
}
