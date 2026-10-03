# Nuwa v3 uses the v2 byte buffer helpers and payload-selected primitive tags.
function Compare-NuwaV3MapKeys {
    param([object]$Left, [object]$Right)
    $leftText = $Left -is [string]
    $rightText = $Right -is [string]
    if ($leftText -and -not $rightText) { return 1 }
    if ($rightText -and -not $leftText) { return -1 }
    if (-not $leftText) {
        if ([uint64]$Left -lt [uint64]$Right) { return -1 }
        if ([uint64]$Left -gt [uint64]$Right) { return 1 }
        return 0
    }
    return Compare-NuwaBinaryKeys (ConvertTo-NuwaUtf8Bytes -Value $Left) (ConvertTo-NuwaUtf8Bytes -Value $Right)
}

function Add-NuwaV3Value {
    param([hashtable]$State, [object]$Value, [int]$Depth)
    if ($Depth -gt 20) { throw 'Binary v3 nesting exceeds 20' }
    if ($null -eq $Value) { Add-NuwaBinaryByte $State ([byte]$script:NuwaV3Tag_null); return }
    if ($Value -is [bool]) {
        $tag = if ($Value) { $script:NuwaV3Tag_true } else { $script:NuwaV3Tag_false }
        Add-NuwaBinaryByte $State ([byte]$tag); return
    }
    if ($Value -is [byte[]]) {
        Add-NuwaBinaryByte $State ([byte]$script:NuwaV3Tag_bytes)
        Add-NuwaBinaryUvarint $State ([uint64]$Value.Length)
        Add-NuwaBinaryBytes $State $Value
    } elseif ($Value -is [string]) {
        $raw = [byte[]](ConvertTo-NuwaUtf8Bytes -Value $Value)
        Add-NuwaBinaryByte $State ([byte]$script:NuwaV3Tag_text)
        Add-NuwaBinaryUvarint $State ([uint64]$raw.Length)
        Add-NuwaBinaryBytes $State $raw
    } elseif ($Value -is [sbyte] -or $Value -is [int16] -or $Value -is [int32] -or $Value -is [int64] -or
              $Value -is [byte] -or $Value -is [uint16] -or $Value -is [uint32] -or $Value -is [uint64]) {
        if ($Value -lt 0) {
            Add-NuwaBinaryByte $State ([byte]$script:NuwaV3Tag_negative_integer)
            [uint64]$magnitude = [uint64](-([int64]$Value + 1))
            Add-NuwaBinaryUvarint $State ([uint64](($magnitude -shl 1) -bor 1))
        } else {
            Add-NuwaBinaryByte $State ([byte]$script:NuwaV3Tag_unsigned_integer)
            Add-NuwaBinaryUvarint $State ([uint64]$Value)
        }
    } elseif ($Value -is [double] -or $Value -is [float] -or $Value -is [decimal]) {
        Add-NuwaBinaryByte $State ([byte]$script:NuwaV3Tag_float)
        $bits = ConvertTo-NuwaBinaryDoubleBits -Value ([double]$Value)
        for ($index = 7; $index -ge 0; $index--) {
            Add-NuwaBinaryByte $State ([byte](($bits -shr ($index * 8)) -band 255))
        }
    } elseif ($Value -is [System.Collections.IDictionary]) {
        $entries = @()
        foreach ($key in $Value.Keys) {
            if ($key -is [string]) {
                if ($key -cnotmatch '^[A-Za-z][A-Za-z0-9_-]{0,63}$') { throw 'Binary v3 map string key is invalid' }
            } elseif ($key -isnot [int] -and $key -isnot [long] -and $key -isnot [uint64]) {
                throw 'Binary v3 map key type is invalid'
            } elseif ([uint64]$key -lt 1 -or [uint64]$key -gt 65535) {
                throw 'Binary v3 field ID is invalid'
            }
            $entries += ,@($key, $Value[$key])
        }
        for ($index = 1; $index -lt $entries.Count; $index++) {
            $candidate = $entries[$index]
            $cursor = $index - 1
            while ($cursor -ge 0 -and (Compare-NuwaV3MapKeys $candidate[0] $entries[$cursor][0]) -lt 0) {
                $entries[$cursor + 1] = $entries[$cursor]
                $cursor--
            }
            $entries[$cursor + 1] = $candidate
        }
        Add-NuwaBinaryByte $State ([byte]$script:NuwaV3Tag_map)
        Add-NuwaBinaryUvarint $State ([uint64]$entries.Count)
        foreach ($entry in $entries) {
            Add-NuwaV3Value $State $entry[0] ($Depth + 1)
            Add-NuwaV3Value $State $entry[1] ($Depth + 1)
        }
    } elseif ($Value -is [array] -or $Value -is [System.Collections.IList]) {
        Add-NuwaBinaryByte $State ([byte]$script:NuwaV3Tag_array)
        Add-NuwaBinaryUvarint $State ([uint64]$Value.Count)
        foreach ($item in $Value) { Add-NuwaV3Value $State $item ($Depth + 1) }
    } else {
        throw 'Unsupported binary v3 value'
    }
}

function Read-NuwaV3Value {
    param([hashtable]$State, [int]$Depth)
    if ($Depth -gt 20) { throw 'Binary v3 nesting exceeds 20' }
    $tag = (Read-NuwaBinaryBytes $State 1)[0]
    if ($tag -eq $script:NuwaV3Tag_null) { return $null }
    if ($tag -eq $script:NuwaV3Tag_false) { return $false }
    if ($tag -eq $script:NuwaV3Tag_true) { return $true }
    if ($tag -eq $script:NuwaV3Tag_negative_integer) {
        $encoded = Read-NuwaBinaryUvarint $State
        if (($encoded -band 1) -eq 0) { throw 'Noncanonical binary v3 negative integer' }
        if ($encoded -eq [uint64]::MaxValue) { return [long]::MinValue }
        return (-([long]($encoded -shr 1)) - 1)
    }
    if ($tag -eq $script:NuwaV3Tag_unsigned_integer) { return (Read-NuwaBinaryUvarint $State) }
    if ($tag -eq $script:NuwaV3Tag_float) {
        $raw = Read-NuwaBinaryBytes $State 8
        [uint64]$bits = 0
        foreach ($item in $raw) { $bits = ($bits -shl 8) -bor [uint64]$item }
        return (ConvertFrom-NuwaBinaryDoubleBits $bits)
    }
    if ($tag -eq $script:NuwaV3Tag_text -or $tag -eq $script:NuwaV3Tag_bytes) {
        $raw = Read-NuwaBinaryBytes $State (Read-NuwaBinaryUvarint $State)
        if ($tag -eq $script:NuwaV3Tag_bytes) { return ,([byte[]]$raw) }
        if ($raw.Length -eq 0) { return '' }
        return (ConvertFrom-NuwaUtf8Bytes -Bytes $raw)
    }
    if ($tag -eq $script:NuwaV3Tag_array) {
        $count = Read-NuwaBinaryUvarint $State
        if ($count -gt ($State[$script:NuwaB_Bytes].Length - $State[$script:NuwaB_Offset])) {
            throw 'Binary v3 array count exceeds remaining bytes'
        }
        $result = [object[]]::new([int]$count)
        for ($index = 0; $index -lt $count; $index++) { $result[$index] = Read-NuwaV3Value $State ($Depth + 1) }
        return ,$result
    }
    if ($tag -eq $script:NuwaV3Tag_map) {
        $count = Read-NuwaBinaryUvarint $State
        if ($count -gt (($State[$script:NuwaB_Bytes].Length - $State[$script:NuwaB_Offset]) -shr 1)) {
            throw 'Binary v3 map count exceeds remaining bytes'
        }
        $result = @{}
        $previous = $null
        for ($index = 0; $index -lt $count; $index++) {
            $key = Read-NuwaV3Value $State ($Depth + 1)
            if ($key -is [string]) {
                if ($key -cnotmatch '^[A-Za-z][A-Za-z0-9_-]{0,63}$') { throw 'Binary v3 map string key is invalid' }
            } elseif ($key -isnot [int] -and $key -isnot [long] -and $key -isnot [uint64]) {
                throw 'Binary v3 map key type is invalid'
            } elseif ([uint64]$key -lt 1 -or [uint64]$key -gt 65535) {
                throw 'Binary v3 field ID is invalid'
            }
            if ($null -ne $previous -and (Compare-NuwaV3MapKeys $key $previous) -le 0) {
                throw 'Binary v3 map keys are duplicate or unsorted'
            }
            if ($result.ContainsKey($key)) { throw 'Duplicate binary v3 map key' }
            $result[$key] = Read-NuwaV3Value $State ($Depth + 1)
            $previous = $key
        }
        return $result
    }
    throw 'Unsupported binary v3 tag'
}

# The selected artifact keeps the v2 runtime's call sites, with v3 bodies.
function ConvertTo-NuwaBinaryV2Bytes {
    param([Parameter(Mandatory = $true)][System.Collections.IDictionary]$Message)
    $state = @{
        ($script:NuwaB_Buffer) = [byte[]]::new(524288)
        ($script:NuwaB_Offset) = 0
    }
    Add-NuwaBinaryByte $state ([byte]$script:NuwaV3Marker_first)
    Add-NuwaBinaryByte $state ([byte]$script:NuwaV3Marker_second)
    Add-NuwaV3Value $state $Message 0
    $output = [byte[]]::new($state[$script:NuwaB_Offset])
    for ($index = 0; $index -lt $output.Length; $index++) { $output[$index] = $state[$script:NuwaB_Buffer][$index] }
    return ,$output
}

function ConvertFrom-NuwaBinaryV2Bytes {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)
    if ($Bytes.Length -gt 524288) { throw 'Binary v3 document exceeds 524288 bytes' }
    if ($Bytes.Length -lt 3 -or $Bytes[0] -ne $script:NuwaV3Marker_first -or
        $Bytes[1] -ne $script:NuwaV3Marker_second) { throw 'Binary v3 marker mismatch' }
    $state = @{
        ($script:NuwaB_Bytes) = $Bytes
        ($script:NuwaB_Offset) = 2
    }
    $value = Read-NuwaV3Value $state 0
    if ($value -isnot [System.Collections.IDictionary]) { throw 'Binary v3 root must be a map' }
    if ($state[$script:NuwaB_Offset] -ne $Bytes.Length) { throw 'Binary v3 document has trailing bytes' }
    return $value
}
