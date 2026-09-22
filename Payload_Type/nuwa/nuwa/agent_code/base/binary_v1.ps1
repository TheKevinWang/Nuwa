# Canonical Nuwa inner v1. All lengths and counts are minimal unsigned LEB128.
function Add-NuwaBinaryUvarint {
    param([System.Collections.Generic.List[byte]]$Buffer, [uint64]$Value)
    while ($Value -ge 128) {
        $Buffer.Add([byte](($Value -band 127) -bor 128))
        $Value = $Value -shr 7
    }
    $Buffer.Add([byte]$Value)
}

function Compare-NuwaBinaryKeys {
    param([byte[]]$Left, [byte[]]$Right)
    $length = [Math]::Min($Left.Length, $Right.Length)
    for ($index = 0; $index -lt $length; $index++) {
        if ($Left[$index] -lt $Right[$index]) { return -1 }
        if ($Left[$index] -gt $Right[$index]) { return 1 }
    }
    if ($Left.Length -lt $Right.Length) { return -1 }
    if ($Left.Length -gt $Right.Length) { return 1 }
    return 0
}

function Add-NuwaBinaryValue {
    param([System.Collections.Generic.List[byte]]$Buffer, [object]$Value, [int]$Depth)
    if ($Depth -gt 20) { throw 'Binary v1 nesting exceeds 20' }
    if ($null -eq $Value) { $Buffer.Add(0); return }
    if ($Value -is [bool]) { $tag = if ($Value) { 2 } else { 1 }; $Buffer.Add([byte]$tag); return }
    if ($Value -is [byte[]]) {
        $Buffer.Add(7)
        Add-NuwaBinaryUvarint -Buffer $Buffer -Value ([uint64]$Value.Length)
        $Buffer.AddRange([byte[]]$Value)
    } elseif ($Value -is [string]) {
        $encoded = [System.Text.Encoding]::UTF8.GetBytes([string]$Value)
        if ([System.Text.Encoding]::UTF8.GetString($encoded) -cne $Value) { throw 'Invalid UTF-8 string' }
        $Buffer.Add(6)
        Add-NuwaBinaryUvarint -Buffer $Buffer -Value ([uint64]$encoded.Length)
        $Buffer.AddRange([byte[]]$encoded)
    } elseif ($Value -is [sbyte] -or $Value -is [int16] -or $Value -is [int32] -or $Value -is [int64] -or
              $Value -is [byte] -or $Value -is [uint16] -or $Value -is [uint32] -or $Value -is [uint64]) {
        if ($Value -lt 0) {
            $Buffer.Add(3)
            $magnitude = [uint64](-([int64]$Value + 1))
            Add-NuwaBinaryUvarint -Buffer $Buffer -Value ([uint64](($magnitude -shl 1) -bor 1))
        } else {
            $Buffer.Add(4)
            Add-NuwaBinaryUvarint -Buffer $Buffer -Value ([uint64]$Value)
        }
    } elseif ($Value -is [float] -or $Value -is [double] -or $Value -is [decimal]) {
        $number = [double]$Value
        if ([double]::IsNaN($number) -or [double]::IsInfinity($number)) { throw 'Nonfinite binary v1 float' }
        $Buffer.Add(5)
        $bits = [BitConverter]::GetBytes($number)
        if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($bits) }
        $Buffer.AddRange([byte[]]$bits)
    } elseif ($Value -is [System.Collections.IDictionary] -or $Value -is [pscustomobject]) {
        $entries = [System.Collections.Generic.List[object]]::new()
        if ($Value -is [System.Collections.IDictionary]) {
            foreach ($key in $Value.Keys) {
                if ($key -isnot [string]) { throw 'Binary v1 map keys must be strings' }
                $encoded = [System.Text.Encoding]::UTF8.GetBytes([string]$key)
                $entries.Add(@{ Key = [string]$key; Bytes = [byte[]]$encoded; Item = $Value[$key] })
            }
        } else {
            foreach ($property in $Value.PSObject.Properties) {
                $encoded = [System.Text.Encoding]::UTF8.GetBytes([string]$property.Name)
                $entries.Add(@{ Key = [string]$property.Name; Bytes = [byte[]]$encoded; Item = $property.Value })
            }
        }
        for ($index = 1; $index -lt $entries.Count; $index++) {
            $candidate = $entries[$index]
            $cursor = $index - 1
            while ($cursor -ge 0 -and (Compare-NuwaBinaryKeys -Left $candidate.Bytes -Right $entries[$cursor].Bytes) -lt 0) {
                $entries[$cursor + 1] = $entries[$cursor]
                $cursor--
            }
            $entries[$cursor + 1] = $candidate
        }
        $Buffer.Add(9)
        Add-NuwaBinaryUvarint -Buffer $Buffer -Value ([uint64]$entries.Count)
        foreach ($entry in $entries) {
            Add-NuwaBinaryUvarint -Buffer $Buffer -Value ([uint64]$entry.Bytes.Length)
            $Buffer.AddRange([byte[]]$entry.Bytes)
            Add-NuwaBinaryValue -Buffer $Buffer -Value $entry.Item -Depth ($Depth + 1)
        }
    } elseif ($Value -is [array] -or $Value -is [System.Collections.IList]) {
        $Buffer.Add(8)
        Add-NuwaBinaryUvarint -Buffer $Buffer -Value ([uint64]$Value.Count)
        foreach ($item in $Value) { Add-NuwaBinaryValue -Buffer $Buffer -Value $item -Depth ($Depth + 1) }
    } else {
        throw ("Unsupported binary v1 value: {0}" -f $Value.GetType().FullName)
    }
    if ($Buffer.Count -gt 524288) { throw 'Binary v1 document exceeds 524288 bytes' }
}

function Read-NuwaBinaryBytes {
    param([hashtable]$State, [uint64]$Length)
    if ($Length -gt ($State.Bytes.Length - $State.Offset)) { throw 'Truncated binary v1 document' }
    $value = [byte[]]::new([int]$Length)
    if ($Length -gt 0) { [Array]::Copy($State.Bytes, $State.Offset, $value, 0, [int]$Length) }
    $State.Offset += [int]$Length
    return ,$value
}

function Read-NuwaBinaryUvarint {
    param([hashtable]$State)
    [uint64]$result = 0
    for ($index = 0; $index -lt 10; $index++) {
        $current = (Read-NuwaBinaryBytes -State $State -Length 1)[0]
        if ($index -eq 9 -and $current -gt 1) { throw 'Binary v1 varint overflow' }
        $result = $result -bor ([uint64]($current -band 127) -shl (7 * $index))
        if ($current -lt 128) {
            $minimum = [System.Collections.Generic.List[byte]]::new()
            Add-NuwaBinaryUvarint -Buffer $minimum -Value $result
            if ($minimum.Count -ne ($index + 1)) { throw 'Nonminimal binary v1 varint' }
            return $result
        }
    }
    throw 'Binary v1 varint is too long'
}

function Read-NuwaBinaryValue {
    param([hashtable]$State, [int]$Depth)
    if ($Depth -gt 20) { throw 'Binary v1 nesting exceeds 20' }
    $tag = (Read-NuwaBinaryBytes -State $State -Length 1)[0]
    switch ($tag) {
        0 { return $null }
        1 { return $false }
        2 { return $true }
        3 {
            $encoded = Read-NuwaBinaryUvarint -State $State
            if (($encoded -band 1) -eq 0) { throw 'Noncanonical binary v1 negative integer' }
            if ($encoded -eq [uint64]::MaxValue) { return [long]::MinValue }
            return (-([long]($encoded -shr 1)) - 1)
        }
        4 { return (Read-NuwaBinaryUvarint -State $State) }
        5 {
            $bits = Read-NuwaBinaryBytes -State $State -Length 8
            if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($bits) }
            $number = [BitConverter]::ToDouble($bits, 0)
            if ([double]::IsNaN($number) -or [double]::IsInfinity($number)) { throw 'Nonfinite binary v1 float' }
            return $number
        }
        { $_ -eq 6 -or $_ -eq 7 } {
            $length = Read-NuwaBinaryUvarint -State $State
            $value = Read-NuwaBinaryBytes -State $State -Length $length
            if ($tag -eq 7) { return ,([byte[]]$value) }
            $decoded = [System.Text.Encoding]::UTF8.GetString($value)
            if (-not [System.Linq.Enumerable]::SequenceEqual([byte[]]$value, [byte[]][System.Text.Encoding]::UTF8.GetBytes($decoded))) {
                throw 'Malformed binary v1 UTF-8'
            }
            return $decoded
        }
        8 {
            $count = Read-NuwaBinaryUvarint -State $State
            if ($count -gt ($State.Bytes.Length - $State.Offset)) { throw 'Binary v1 array count exceeds remaining bytes' }
            $result = [System.Collections.Generic.List[object]]::new()
            for ([uint64]$index = 0; $index -lt $count; $index++) {
                $result.Add((Read-NuwaBinaryValue -State $State -Depth ($Depth + 1)))
            }
            return ,($result.ToArray())
        }
        9 {
            $count = Read-NuwaBinaryUvarint -State $State
            if ($count -gt [uint64][Math]::Floor(($State.Bytes.Length - $State.Offset) / 2)) { throw 'Binary v1 map count exceeds remaining bytes' }
            $result = [hashtable]::new([StringComparer]::Ordinal)
            $previous = $null
            for ([uint64]$index = 0; $index -lt $count; $index++) {
                $keyBytes = Read-NuwaBinaryBytes -State $State -Length (Read-NuwaBinaryUvarint -State $State)
                if ($null -ne $previous -and (Compare-NuwaBinaryKeys -Left $previous -Right $keyBytes) -ge 0) {
                    throw 'Unsorted or duplicate binary v1 map key'
                }
                $key = [System.Text.Encoding]::UTF8.GetString($keyBytes)
                if (-not [System.Linq.Enumerable]::SequenceEqual([byte[]]$keyBytes, [byte[]][System.Text.Encoding]::UTF8.GetBytes($key))) { throw 'Malformed binary v1 map key' }
                $result[$key] = Read-NuwaBinaryValue -State $State -Depth ($Depth + 1)
                $previous = $keyBytes
            }
            return $result
        }
        default { throw ("Unsupported binary v1 tag {0}" -f $tag) }
    }
}

function Assert-NuwaBinarySocksFields {
    param([System.Collections.IDictionary]$Message)
    $hasSocks = $Message.Contains('socks')
    $hasBatch = $Message.Contains('socks_batch_id')
    $records = if ($hasSocks) { @($Message['socks']) } else { @() }
    if ($hasSocks -and $records.Count -eq 0) { throw 'socks must be a nonempty array' }
    if (($records.Count -gt 0) -ne $hasBatch) { throw 'socks_batch_id requires nonempty socks' }
    if ($hasBatch -and ($Message['socks_batch_id'] -isnot [byte[]] -or $Message['socks_batch_id'].Length -ne 16)) { throw 'socks_batch_id must be 16 bytes' }
    if ($Message.Contains('socks_ack')) {
        $ack = @($Message['socks_ack'])
        if ($ack.Count -eq 0) { throw 'socks_ack must be nonempty' }
        foreach ($item in $ack) { if ($item -isnot [byte[]] -or $item.Length -ne 16) { throw 'socks_ack entry must be 16 bytes' } }
    }
}

function ConvertTo-NuwaBinaryV1Bytes {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][System.Collections.IDictionary]$Message)
    Assert-NuwaBinarySocksFields -Message $Message
    $buffer = [System.Collections.Generic.List[byte]]::new()
    Add-NuwaBinaryValue -Buffer $buffer -Value $Message -Depth 0
    return ,([byte[]]$buffer.ToArray())
}

function ConvertFrom-NuwaBinaryV1Bytes {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)
    if ($Bytes.Length -gt 524288) { throw 'Binary v1 document exceeds 524288 bytes' }
    $state = @{ Bytes = $Bytes; Offset = 0 }
    $value = Read-NuwaBinaryValue -State $state -Depth 0
    if ($value -isnot [System.Collections.IDictionary]) { throw 'Binary v1 root must be a map' }
    if ($state.Offset -ne $Bytes.Length) { throw 'Binary v1 document has trailing bytes' }
    Assert-NuwaBinarySocksFields -Message $value
    return $value
}
