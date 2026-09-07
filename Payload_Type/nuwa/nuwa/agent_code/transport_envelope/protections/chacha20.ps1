function ConvertTo-NuwaChaChaUInt32 {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][uint64]$Value)
    return [uint32]($Value -band [uint64]4294967295)
}

function Add-NuwaChaChaUInt32 {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][uint32]$Left, [Parameter(Mandatory = $true)][uint32]$Right)
    return ConvertTo-NuwaChaChaUInt32 ([uint64]$Left + [uint64]$Right)
}

function RotateLeft-NuwaChaChaUInt32 {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][uint32]$Value, [Parameter(Mandatory = $true)][int]$Count)
    [uint64]$left = ([uint64]$Value -shl $Count) -band [uint64]4294967295
    [uint64]$right = [uint64]$Value -shr (32 - $Count)
    return ConvertTo-NuwaChaChaUInt32 ($left -bor $right)
}

function Invoke-NuwaChaChaQuarterRound {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][uint32[]]$State, [int]$A, [int]$B, [int]$C, [int]$D)
    [uint64]$mask = 4294967295

    $State[$A] = [uint32](([uint64]$State[$A] + [uint64]$State[$B]) -band $mask)
    [uint64]$value = [uint64]($State[$D] -bxor $State[$A])
    $State[$D] = [uint32]((($value -shl 16) -band $mask) -bor ($value -shr 16))
    $State[$C] = [uint32](([uint64]$State[$C] + [uint64]$State[$D]) -band $mask)
    $value = [uint64]($State[$B] -bxor $State[$C])
    $State[$B] = [uint32]((($value -shl 12) -band $mask) -bor ($value -shr 20))
    $State[$A] = [uint32](([uint64]$State[$A] + [uint64]$State[$B]) -band $mask)
    $value = [uint64]($State[$D] -bxor $State[$A])
    $State[$D] = [uint32]((($value -shl 8) -band $mask) -bor ($value -shr 24))
    $State[$C] = [uint32](([uint64]$State[$C] + [uint64]$State[$D]) -band $mask)
    $value = [uint64]($State[$B] -bxor $State[$C])
    $State[$B] = [uint32]((($value -shl 7) -band $mask) -bor ($value -shr 25))
}

function ConvertFrom-NuwaChaChaLittleEndianWord {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][byte[]]$Bytes, [Parameter(Mandatory = $true)][int]$Offset)
    return [uint32](([uint64]$Bytes[$Offset]) -bor ([uint64]$Bytes[$Offset + 1] -shl 8) -bor ([uint64]$Bytes[$Offset + 2] -shl 16) -bor ([uint64]$Bytes[$Offset + 3] -shl 24))
}

function Invoke-NuwaChaCha20Block {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][byte[]]$Key,
        [Parameter(Mandatory = $true)][byte[]]$Nonce,
        [Parameter(Mandatory = $true)][uint32]$Counter
    )
    if ($Key.Length -ne 32 -or $Nonce.Length -ne 12) { throw 'ChaCha20 input is invalid' }
    $initial = [uint32[]]@(
        0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
        (ConvertFrom-NuwaChaChaLittleEndianWord $Key 0), (ConvertFrom-NuwaChaChaLittleEndianWord $Key 4),
        (ConvertFrom-NuwaChaChaLittleEndianWord $Key 8), (ConvertFrom-NuwaChaChaLittleEndianWord $Key 12),
        (ConvertFrom-NuwaChaChaLittleEndianWord $Key 16), (ConvertFrom-NuwaChaChaLittleEndianWord $Key 20),
        (ConvertFrom-NuwaChaChaLittleEndianWord $Key 24), (ConvertFrom-NuwaChaChaLittleEndianWord $Key 28),
        $Counter,
        (ConvertFrom-NuwaChaChaLittleEndianWord $Nonce 0), (ConvertFrom-NuwaChaChaLittleEndianWord $Nonce 4),
        (ConvertFrom-NuwaChaChaLittleEndianWord $Nonce 8)
    )
    $working = New-Object 'uint32[]' 16
    for ($index = 0; $index -lt 16; $index += 1) { $working[$index] = $initial[$index] }
    for ($round = 0; $round -lt 10; $round += 1) {
        Invoke-NuwaChaChaQuarterRound $working 0 4 8 12
        Invoke-NuwaChaChaQuarterRound $working 1 5 9 13
        Invoke-NuwaChaChaQuarterRound $working 2 6 10 14
        Invoke-NuwaChaChaQuarterRound $working 3 7 11 15
        Invoke-NuwaChaChaQuarterRound $working 0 5 10 15
        Invoke-NuwaChaChaQuarterRound $working 1 6 11 12
        Invoke-NuwaChaChaQuarterRound $working 2 7 8 13
        Invoke-NuwaChaChaQuarterRound $working 3 4 9 14
    }
    $output = New-Object byte[] 64
    for ($wordIndex = 0; $wordIndex -lt 16; $wordIndex += 1) {
        [uint32]$word = [uint32](([uint64]$working[$wordIndex] + [uint64]$initial[$wordIndex]) -band [uint64]4294967295)
        $output[$wordIndex * 4] = [byte]([uint64]$word -band 255)
        $output[($wordIndex * 4) + 1] = [byte](([uint64]$word -shr 8) -band 255)
        $output[($wordIndex * 4) + 2] = [byte](([uint64]$word -shr 16) -band 255)
        $output[($wordIndex * 4) + 3] = [byte](([uint64]$word -shr 24) -band 255)
    }
    return ,$output
}

function Invoke-NuwaChaCha20 {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][byte[]]$Bytes, [Parameter(Mandatory = $true)][byte[]]$Key, [Parameter(Mandatory = $true)][byte[]]$Nonce)
    [uint64]$blockCount = [uint64](($Bytes.Length + 63) / 64)
    if ($blockCount -gt [uint64]4294967295) { throw 'ChaCha20 counter would wrap' }
    $result = New-Object byte[] $Bytes.Length
    for ([uint64]$blockIndex = 0; $blockIndex -lt $blockCount; $blockIndex += 1) {
        [uint64]$counterValue = 1 + $blockIndex
        if ($counterValue -gt [uint64]4294967295) { throw 'ChaCha20 counter would wrap' }
        $stream = Invoke-NuwaChaCha20Block -Key $Key -Nonce $Nonce -Counter ([uint32]$counterValue)
        $offset = [int]($blockIndex * 64)
        $take = $Bytes.Length - $offset
        if ($take -gt 64) { $take = 64 }
        for ($index = 0; $index -lt $take; $index += 1) { $result[$offset + $index] = [byte](([int]$Bytes[$offset + $index]) -bxor ([int]$stream[$index])) }
    }
    return ,$result
}

function Protect-NuwaTransportEnvelopeBytes {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][byte[]]$Bytes, [Parameter(Mandatory = $true)][string]$Direction, [Parameter(Mandatory = $false)][hashtable]$Context = @{})
    $nonce = Get-NuwaTransportEntropy -Count 12 -Context $Context
    $ciphertext = Invoke-NuwaChaCha20 -Bytes $Bytes -Key (Get-NuwaTransportDirectionKey $Direction) -Nonce $nonce
    return ,(Join-NuwaTransportBytes -Parts @([object]$nonce, [object]$ciphertext))
}

function Unprotect-NuwaTransportEnvelopeBytes {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][byte[]]$Bytes, [Parameter(Mandatory = $true)][string]$Direction)
    if ($Bytes.Length -lt 12) { throw 'Transport envelope is invalid' }
    $nonce = Copy-NuwaTransportBytes $Bytes 0 12
    $ciphertext = Copy-NuwaTransportBytes $Bytes 12 ($Bytes.Length - 12)
    return ,(Invoke-NuwaChaCha20 -Bytes $ciphertext -Key (Get-NuwaTransportDirectionKey $Direction) -Nonce $nonce)
}
