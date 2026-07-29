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

function Get-NuwaWireMarker {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Context
    )

    return ('NW1:{0}:' -f (Get-NuwaCodecProfile -Context $Context))
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
    $innerBytes = ConvertTo-NuwaInner -Bytes $messageBytes -Context $Context
    $wireText = (Get-NuwaWireMarker -Context $Context) + (ConvertFrom-NuwaUtf8Bytes -Bytes $innerBytes)
    return ConvertTo-NuwaUtf8Bytes -Value $wireText
}

function ConvertFrom-NuwaWireBytes {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [byte[]]$WireBytes,

        [Parameter(Mandatory = $true)]
        [hashtable]$Context
    )

    $wireText = ConvertFrom-NuwaUtf8Bytes -Bytes $WireBytes
    $marker = Get-NuwaWireMarker -Context $Context
    if (-not $wireText.StartsWith($marker)) {
        throw ("Malformed Nuwa wire marker, expected prefix '{0}'" -f $marker)
    }

    $innerText = $wireText.Substring($marker.Length)
    $innerBytes = ConvertTo-NuwaUtf8Bytes -Value $innerText
    $decodedBytes = ConvertFrom-NuwaInner -Bytes $innerBytes -Context $Context
    return ConvertFrom-NuwaUtf8Bytes -Bytes $decodedBytes
}
