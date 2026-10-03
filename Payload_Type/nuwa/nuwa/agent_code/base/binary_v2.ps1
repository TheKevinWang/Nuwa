# Binary v2 serializer using core PowerShell arrays and arithmetic only.
function Add-NuwaBinaryByte {
    param([hashtable]$State, [byte]$Value)
    if ($State.Offset -ge 524288) { throw 'Binary v2 document exceeds 524288 bytes' }
    $State.Buffer[$State.Offset] = $Value
    $State.Offset++
}

function Add-NuwaBinaryBytes {
    param([hashtable]$State, [byte[]]$Value)
    if ($Value.Length -gt (524288 - $State.Offset)) { throw 'Binary v2 document exceeds 524288 bytes' }
    for ($index = 0; $index -lt $Value.Length; $index++) {
        $State.Buffer[$State.Offset] = $Value[$index]
        $State.Offset++
    }
}

function Add-NuwaBinaryUvarint {
    param([hashtable]$State, [uint64]$Value)
    while ($Value -ge 128) {
        Add-NuwaBinaryByte -State $State -Value ([byte](($Value -band 127) -bor 128))
        $Value = $Value -shr 7
    }
    Add-NuwaBinaryByte -State $State -Value ([byte]$Value)
}

function Compare-NuwaBinaryKeys {
    param([byte[]]$Left, [byte[]]$Right)
    $length = $Left.Length
    if ($Right.Length -lt $length) { $length = $Right.Length }
    for ($index = 0; $index -lt $length; $index++) {
        if ($Left[$index] -lt $Right[$index]) { return -1 }
        if ($Left[$index] -gt $Right[$index]) { return 1 }
    }
    if ($Left.Length -lt $Right.Length) { return -1 }
    if ($Left.Length -gt $Right.Length) { return 1 }
    return 0
}

function ConvertTo-NuwaBinaryDoubleBits {
    param([double]$Value)
    if ($Value -ne $Value -or $Value -eq [double]::PositiveInfinity -or $Value -eq [double]::NegativeInfinity) {
        throw 'Nonfinite binary v2 float'
    }
    [uint64]$sign = 0
    if ($Value -lt 0) { $sign = 1; $Value = -$Value }
    if ($Value -eq 0) { return [uint64]($sign -shl 63) }
    [int]$exponent = 0
    $normalized = $Value
    while ($normalized -ge 2) { $normalized /= 2; $exponent++ }
    while ($normalized -lt 1 -and $exponent -gt -1022) { $normalized *= 2; $exponent-- }
    if ($normalized -ge 1) {
        [uint64]$mantissa = [uint64](($normalized - 1) * 4503599627370496.0)
        return [uint64](($sign -shl 63) -bor ([uint64]($exponent + 1023) -shl 52) -bor $mantissa)
    }
    $subnormalValue = $Value
    for ($index = 0; $index -lt 1074; $index++) { $subnormalValue *= 2 }
    [uint64]$subnormal = [uint64]$subnormalValue
    return [uint64](($sign -shl 63) -bor $subnormal)
}

function ConvertFrom-NuwaBinaryDoubleBits {
    param([uint64]$Bits)
    $negative = ($Bits -band ([uint64]1 -shl 63)) -ne 0
    $exponent = [int](($Bits -shr 52) -band 2047)
    [uint64]$mantissa = $Bits -band 4503599627370495
    if ($exponent -eq 2047) { throw 'Nonfinite binary v2 float' }
    if ($exponent -eq 0) {
        [double]$result = [double]$mantissa
        for ($index = 0; $index -lt 1074; $index++) { $result /= 2 }
    } else {
        [double]$result = 1.0 + ([double]$mantissa / 4503599627370496.0)
        $power = $exponent - 1023
        if ($power -ge 0) {
            for ($index = 0; $index -lt $power; $index++) { $result *= 2 }
        } else {
            for ($index = 0; $index -lt (-$power); $index++) { $result /= 2 }
        }
    }
    if ($negative) { return (-$result) }
    return $result
}

function Add-NuwaBinaryValue {
    param([hashtable]$State, [object]$Value, [int]$Depth)
    if ($Depth -gt 20) { throw 'Binary v2 nesting exceeds 20' }
    if ($null -eq $Value) { Add-NuwaBinaryByte $State 0; return }
    if ($Value -is [bool]) { $tag = if ($Value) { 2 } else { 1 }; Add-NuwaBinaryByte $State ([byte]$tag); return }
    if ($Value -is [byte[]]) {
        Add-NuwaBinaryByte $State 7
        Add-NuwaBinaryUvarint $State ([uint64]$Value.Length)
        Add-NuwaBinaryBytes $State $Value
    } elseif ($Value -is [string]) {
        $encoded = [byte[]](ConvertTo-NuwaUtf8Bytes -Value $Value)
        Add-NuwaBinaryByte $State 6
        Add-NuwaBinaryUvarint $State ([uint64]$encoded.Length)
        Add-NuwaBinaryBytes $State $encoded
    } elseif ($Value -is [sbyte] -or $Value -is [int16] -or $Value -is [int32] -or $Value -is [int64] -or
              $Value -is [byte] -or $Value -is [uint16] -or $Value -is [uint32] -or $Value -is [uint64]) {
        if ($Value -lt 0) {
            Add-NuwaBinaryByte $State 3
            [uint64]$magnitude = [uint64](-([int64]$Value + 1))
            Add-NuwaBinaryUvarint $State ([uint64](($magnitude -shl 1) -bor 1))
        } else {
            Add-NuwaBinaryByte $State 4
            Add-NuwaBinaryUvarint $State ([uint64]$Value)
        }
    } elseif ($Value -is [double] -or $Value -is [float] -or $Value -is [decimal]) {
        Add-NuwaBinaryByte $State 5
        $bits = ConvertTo-NuwaBinaryDoubleBits -Value ([double]$Value)
        for ($index = 7; $index -ge 0; $index--) {
            Add-NuwaBinaryByte $State ([byte](($bits -shr ($index * 8)) -band 255))
        }
    } elseif ($Value -is [System.Collections.IDictionary]) {
        $entries = @()
        foreach ($key in $Value.Keys) {
            if (($key -isnot [byte]) -and ($key -isnot [int16]) -and ($key -isnot [int32]) -and
                ($key -isnot [int64]) -and ($key -isnot [uint16]) -and ($key -isnot [uint32]) -and
                ($key -isnot [uint64])) { throw 'Binary v2 map keys must be integers' }
            if ([uint64]$key -lt 1 -or [uint64]$key -gt 65535) { throw 'Binary v2 field ID is invalid' }
            $entries += ,@{ Key = [int]$key; Item = $Value[$key] }
        }
        for ($index = 1; $index -lt $entries.Count; $index++) {
            $candidate = $entries[$index]
            $cursor = $index - 1
            while ($cursor -ge 0 -and $candidate.Key -lt $entries[$cursor].Key) {
                $entries[$cursor + 1] = $entries[$cursor]
                $cursor--
            }
            $entries[$cursor + 1] = $candidate
        }
        Add-NuwaBinaryByte $State 10
        Add-NuwaBinaryUvarint $State ([uint64]$entries.Count)
        foreach ($entry in $entries) {
            Add-NuwaBinaryUvarint $State ([uint64]$entry.Key)
            Add-NuwaBinaryValue $State $entry.Item ($Depth + 1)
        }
    } elseif ($Value -is [array] -or $Value -is [System.Collections.IList]) {
        Add-NuwaBinaryByte $State 8
        Add-NuwaBinaryUvarint $State ([uint64]$Value.Count)
        foreach ($item in $Value) { Add-NuwaBinaryValue $State $item ($Depth + 1) }
    } else {
        throw 'Unsupported binary v2 value'
    }
}

function Read-NuwaBinaryBytes {
    param([hashtable]$State, [uint64]$Length)
    if ($Length -gt ($State.Bytes.Length - $State.Offset)) { throw 'Truncated binary v2 document' }
    $value = [byte[]]::new([int]$Length)
    for ($index = 0; $index -lt $Length; $index++) { $value[$index] = $State.Bytes[$State.Offset + $index] }
    $State.Offset += [int]$Length
    return ,$value
}

function Read-NuwaBinaryUvarint {
    param([hashtable]$State)
    [uint64]$result = 0
    for ($index = 0; $index -lt 10; $index++) {
        $current = (Read-NuwaBinaryBytes $State 1)[0]
        if ($index -eq 9 -and $current -gt 1) { throw 'Binary v2 varint overflow' }
        $result = $result -bor ([uint64]($current -band 127) -shl (7 * $index))
        if ($current -lt 128) {
            $minimum = @{ Buffer = [byte[]]::new(10); Offset = 0 }
            Add-NuwaBinaryUvarint $minimum $result
            if ($minimum.Offset -ne ($index + 1)) { throw 'Nonminimal binary v2 varint' }
            return $result
        }
    }
    throw 'Binary v2 varint is too long'
}

function Read-NuwaBinaryValue {
    param([hashtable]$State, [int]$Depth)
    if ($Depth -gt 20) { throw 'Binary v2 nesting exceeds 20' }
    $tag = (Read-NuwaBinaryBytes $State 1)[0]
    switch ($tag) {
        0 { return $null }
        1 { return $false }
        2 { return $true }
        3 {
            $encoded = Read-NuwaBinaryUvarint $State
            if (($encoded -band 1) -eq 0) { throw 'Noncanonical binary v2 negative integer' }
            if ($encoded -eq [uint64]::MaxValue) { return [long]::MinValue }
            return (-([long]($encoded -shr 1)) - 1)
        }
        4 { return (Read-NuwaBinaryUvarint $State) }
        5 {
            $raw = Read-NuwaBinaryBytes $State 8
            [uint64]$bits = 0
            foreach ($item in $raw) { $bits = ($bits -shl 8) -bor [uint64]$item }
            return (ConvertFrom-NuwaBinaryDoubleBits $bits)
        }
        { $_ -eq 6 -or $_ -eq 7 } {
            $value = Read-NuwaBinaryBytes $State (Read-NuwaBinaryUvarint $State)
            if ($tag -eq 7) { return ,([byte[]]$value) }
            if ($value.Length -eq 0) { return '' }
            return (ConvertFrom-NuwaUtf8Bytes -Bytes $value)
        }
        8 {
            $count = Read-NuwaBinaryUvarint $State
            if ($count -gt ($State.Bytes.Length - $State.Offset)) { throw 'Binary v2 array count exceeds remaining bytes' }
            $result = [object[]]::new([int]$count)
            for ($index = 0; $index -lt $count; $index++) { $result[$index] = Read-NuwaBinaryValue $State ($Depth + 1) }
            return ,$result
        }
        10 {
            $count = Read-NuwaBinaryUvarint $State
            if ($count -gt (($State.Bytes.Length - $State.Offset) -shr 1)) { throw 'Binary v2 map count exceeds remaining bytes' }
            $result = @{}
            [uint64]$previous = 0
            for ($index = 0; $index -lt $count; $index++) {
                [uint64]$key = Read-NuwaBinaryUvarint $State
                if ($key -lt 1 -or $key -gt 65535 -or $key -le $previous) { throw 'Unsorted or duplicate binary v2 map key' }
                $result[[int]$key] = Read-NuwaBinaryValue $State ($Depth + 1)
                $previous = $key
            }
            return $result
        }
        default { throw 'Unsupported binary v2 tag' }
    }
}

function Assert-NuwaBinarySocksFields {
    param([System.Collections.IDictionary]$Message)
    $hasSocks = $Message.Contains([int]34)
    $hasBatch = $Message.Contains([int]35)
    $records = if ($hasSocks) { @($Message[[int]34]) } else { @() }
    if ($hasSocks -and $records.Count -eq 0) { throw 'socks must be a nonempty array' }
    if (($records.Count -gt 0) -ne $hasBatch) { throw 'Binary v2 batch ID requires records' }
    if ($hasBatch -and ($Message[[int]35] -isnot [byte[]] -or $Message[[int]35].Length -ne 16)) { throw 'Binary v2 batch ID must be 16 bytes' }
    if ($Message.Contains([int]36)) {
        $ack = @($Message[[int]36])
        if ($ack.Count -eq 0) { throw 'socks_ack must be nonempty' }
        foreach ($item in $ack) { if ($item -isnot [byte[]] -or $item.Length -ne 16) { throw 'Binary v2 ack entry must be 16 bytes' } }
    }
}

function ConvertTo-NuwaBinaryV2Bytes {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][System.Collections.IDictionary]$Message)
    Assert-NuwaBinarySocksFields $Message
    $state = @{ Buffer = [byte[]]::new(524288); Offset = 0 }
    Add-NuwaBinaryByte $state 242
    Add-NuwaBinaryByte $state 2
    Add-NuwaBinaryValue $state $Message 0
    $output = [byte[]]::new($state.Offset)
    for ($index = 0; $index -lt $state.Offset; $index++) { $output[$index] = $state.Buffer[$index] }
    return ,$output
}

function ConvertFrom-NuwaBinaryV2Bytes {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)
    if ($Bytes.Length -gt 524288) { throw 'Binary v2 document exceeds 524288 bytes' }
    if ($Bytes.Length -lt 3 -or $Bytes[0] -ne 242 -or $Bytes[1] -ne 2) { throw 'Binary v2 version prefix is invalid' }
    $state = @{ Bytes = $Bytes; Offset = 2 }
    $value = Read-NuwaBinaryValue $state 0
    if ($value -isnot [System.Collections.IDictionary]) { throw 'Binary v2 root must be a map' }
    if ($state.Offset -ne $Bytes.Length) { throw 'Binary v2 document has trailing bytes' }
    Assert-NuwaBinarySocksFields $value
    return $value
}
