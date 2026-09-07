function Get-NuwaCodecProfile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Context
    )

    $profile = [string]$Context.codec_profile
    if ([string]::IsNullOrWhiteSpace($profile)) {
        return 'raw'
    }

    return $profile.ToLowerInvariant()
}

function ConvertTo-NuwaInner {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [byte[]]$Bytes,

        [Parameter(Mandatory = $true)]
        [hashtable]$Context
    )

    $profile = Get-NuwaCodecProfile -Context $Context
    if ($profile -eq ('base' + '64')) {
        return ConvertTo-NuwaRadix64Bytes -Bytes $Bytes -Context $Context
    }
    switch ($profile) {
        'raw' {
            return ConvertTo-NuwaRawBytes -Bytes $Bytes -Context $Context
        }
        'decimal' {
            return ConvertTo-NuwaDecimalBytes -Bytes $Bytes -Context $Context
        }
        'emoji' {
            return ConvertTo-NuwaEmojiBytes -Bytes $Bytes -Context $Context
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

    $profile = Get-NuwaCodecProfile -Context $Context
    if ($profile -eq ('base' + '64')) {
        return ConvertFrom-NuwaRadix64Bytes -Bytes $Bytes -Context $Context
    }
    switch ($profile) {
        'raw' {
            return ConvertFrom-NuwaRawBytes -Bytes $Bytes -Context $Context
        }
        'decimal' {
            return ConvertFrom-NuwaDecimalBytes -Bytes $Bytes -Context $Context
        }
        'emoji' {
            return ConvertFrom-NuwaEmojiBytes -Bytes $Bytes -Context $Context
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
    return ConvertTo-NuwaInner -Bytes $messageBytes -Context $Context
}

function ConvertFrom-NuwaWireBytes {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [byte[]]$WireBytes,

        [Parameter(Mandatory = $true)]
        [hashtable]$Context
    )

    $decodedBytes = ConvertFrom-NuwaInner -Bytes $WireBytes -Context $Context
    $json = ConvertFrom-NuwaUtf8Bytes -Bytes ([byte[]]$decodedBytes)
    $parsed = $json | ConvertFrom-Json -ErrorAction Stop
    if ($null -eq $parsed -or -not $json.Trim().StartsWith('{')) {
        throw 'Nuwa wire message must be a JSON object'
    }
    return [string]$json
}
