function ConvertTo-NuwaClmUInt32 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [uint64]$Value
    )

    return [uint32]($Value -band [uint64]4294967295)
}

function Add-NuwaClmUInt32 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [uint32[]]$Values
    )

    [uint64]$sum = 0
    foreach ($value in $Values) {
        $sum += [uint64]$value
    }
    return ConvertTo-NuwaClmUInt32 -Value $sum
}

function RotateRight-NuwaClmUInt32 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [uint32]$Value,

        [Parameter(Mandatory = $true)]
        [int]$Count
    )

    $Count = $Count % 32
    if ($Count -eq 0) {
        return $Value
    }
    [uint64]$right = ([uint64]$Value -shr $Count)
    [uint64]$left = ([uint64]$Value -shl (32 - $Count))
    return ConvertTo-NuwaClmUInt32 -Value ($right -bor $left)
}

function Get-NuwaClmSha256Digest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [byte[]]$Bytes
    )

    if ($Bytes.Length -gt 67108855) {
        throw 'Nuwa CLM SHA-256 input is too large'
    }
    if ($null -eq $script:NuwaClmSha256Initial) {
        $script:NuwaClmSha256Initial = [uint32[]]@(
            1779033703, 3144134277, 1013904242, 2773480762,
            1359893119, 2600822924, 528734635, 1541459225
        )
        $script:NuwaClmSha256Rounds = [uint32[]]@(
            1116352408, 1899447441, 3049323471, 3921009573,
            961987163, 1508970993, 2453635748, 2870763221,
            3624381080, 310598401, 607225278, 1426881987,
            1925078388, 2162078206, 2614888103, 3248222580,
            3835390401, 4022224774, 264347078, 604807628,
            770255983, 1249150122, 1555081692, 1996064986,
            2554220882, 2821834349, 2952996808, 3210313671,
            3336571891, 3584528711, 113926993, 338241895,
            666307205, 773529912, 1294757372, 1396182291,
            1695183700, 1986661051, 2177026350, 2456956037,
            2730485921, 2820302411, 3259730800, 3345764771,
            3516065817, 3600352804, 4094571909, 275423344,
            430227734, 506948616, 659060556, 883997877,
            958139571, 1322822218, 1537002063, 1747873779,
            1955562222, 2024104815, 2227730452, 2361852424,
            2428436474, 2756734187, 3204031479, 3329325298
        )
    }

    [int]$messageLength = $Bytes.Length
    [int]$zeroBytes = (64 - (($messageLength + 1 + 8) % 64)) % 64
    $padded = New-NuwaClmByteArray -Length ($messageLength + 1 + $zeroBytes + 8)
    for ($index = 0; $index -lt $messageLength; $index += 1) {
        $padded[$index] = $Bytes[$index]
    }
    $padded[$messageLength] = 128
    [uint64]$bitLength = [uint64]$messageLength * 8
    for ($index = 0; $index -lt 8; $index += 1) {
        $padded[$padded.Length - 8 + $index] = [byte](
            ($bitLength -shr ((7 - $index) * 8)) -band 255
        )
    }

    [uint32]$hashA = $script:NuwaClmSha256Initial[0]
    [uint32]$hashB = $script:NuwaClmSha256Initial[1]
    [uint32]$hashC = $script:NuwaClmSha256Initial[2]
    [uint32]$hashD = $script:NuwaClmSha256Initial[3]
    [uint32]$hashE = $script:NuwaClmSha256Initial[4]
    [uint32]$hashF = $script:NuwaClmSha256Initial[5]
    [uint32]$hashG = $script:NuwaClmSha256Initial[6]
    [uint32]$hashH = $script:NuwaClmSha256Initial[7]
    [uint64]$mask32 = 4294967295

    for ($offset = 0; $offset -lt $padded.Length; $offset += 64) {
        $words = New-Object uint32[] 64
        for ($wordIndex = 0; $wordIndex -lt 16; $wordIndex += 1) {
            $wordOffset = $offset + ($wordIndex * 4)
            $words[$wordIndex] = ConvertTo-NuwaClmUInt32 -Value (
                (([uint64]$padded[$wordOffset]) -shl 24) -bor
                (([uint64]$padded[$wordOffset + 1]) -shl 16) -bor
                (([uint64]$padded[$wordOffset + 2]) -shl 8) -bor
                ([uint64]$padded[$wordOffset + 3])
            )
        }
        for ($wordIndex = 16; $wordIndex -lt 64; $wordIndex += 1) {
            [uint32]$word15 = $words[$wordIndex - 15]
            [uint32]$word2 = $words[$wordIndex - 2]
            [uint32]$small0 = ([uint32]((([uint64]$word15 -shr 7) -bor (([uint64]$word15 -shl 25))) -band $mask32)) -bxor
                ([uint32]((([uint64]$word15 -shr 18) -bor (([uint64]$word15 -shl 14))) -band $mask32)) -bxor
                ($word15 -shr 3)
            [uint32]$small1 = ([uint32]((([uint64]$word2 -shr 17) -bor (([uint64]$word2 -shl 15))) -band $mask32)) -bxor
                ([uint32]((([uint64]$word2 -shr 19) -bor (([uint64]$word2 -shl 13))) -band $mask32)) -bxor
                ($word2 -shr 10)
            $words[$wordIndex] = [uint32]((
                [uint64]$words[$wordIndex - 16] + [uint64]$small0 +
                [uint64]$words[$wordIndex - 7] + [uint64]$small1
            ) -band $mask32)
        }

        [uint32]$a = $hashA
        [uint32]$b = $hashB
        [uint32]$c = $hashC
        [uint32]$d = $hashD
        [uint32]$e = $hashE
        [uint32]$f = $hashF
        [uint32]$g = $hashG
        [uint32]$h = $hashH
        for ($round = 0; $round -lt 64; $round += 1) {
            [uint32]$big1 = ([uint32]((([uint64]$e -shr 6) -bor (([uint64]$e -shl 26))) -band $mask32)) -bxor
                ([uint32]((([uint64]$e -shr 11) -bor (([uint64]$e -shl 21))) -band $mask32)) -bxor
                ([uint32]((([uint64]$e -shr 25) -bor (([uint64]$e -shl 7))) -band $mask32))
            [uint32]$choice = ($e -band $f) -bxor (($e -bxor [uint32]4294967295) -band $g)
            [uint32]$temp1 = [uint32]((
                [uint64]$h + [uint64]$big1 + [uint64]$choice +
                [uint64]$script:NuwaClmSha256Rounds[$round] + [uint64]$words[$round]
            ) -band $mask32)
            [uint32]$big0 = ([uint32]((([uint64]$a -shr 2) -bor (([uint64]$a -shl 30))) -band $mask32)) -bxor
                ([uint32]((([uint64]$a -shr 13) -bor (([uint64]$a -shl 19))) -band $mask32)) -bxor
                ([uint32]((([uint64]$a -shr 22) -bor (([uint64]$a -shl 10))) -band $mask32))
            [uint32]$majority = ($a -band $b) -bxor ($a -band $c) -bxor ($b -band $c)
            [uint32]$temp2 = [uint32](([uint64]$big0 + [uint64]$majority) -band $mask32)
            $h = $g
            $g = $f
            $f = $e
            $e = [uint32](([uint64]$d + [uint64]$temp1) -band $mask32)
            $d = $c
            $c = $b
            $b = $a
            $a = [uint32](([uint64]$temp1 + [uint64]$temp2) -band $mask32)
        }
        $hashA = [uint32](([uint64]$hashA + [uint64]$a) -band $mask32)
        $hashB = [uint32](([uint64]$hashB + [uint64]$b) -band $mask32)
        $hashC = [uint32](([uint64]$hashC + [uint64]$c) -band $mask32)
        $hashD = [uint32](([uint64]$hashD + [uint64]$d) -band $mask32)
        $hashE = [uint32](([uint64]$hashE + [uint64]$e) -band $mask32)
        $hashF = [uint32](([uint64]$hashF + [uint64]$f) -band $mask32)
        $hashG = [uint32](([uint64]$hashG + [uint64]$g) -band $mask32)
        $hashH = [uint32](([uint64]$hashH + [uint64]$h) -band $mask32)
    }

    $digest = New-NuwaClmByteArray -Length 32
    $hashes = [uint32[]]@($hashA, $hashB, $hashC, $hashD, $hashE, $hashF, $hashG, $hashH)
    for ($hashIndex = 0; $hashIndex -lt 8; $hashIndex += 1) {
        for ($byteIndex = 0; $byteIndex -lt 4; $byteIndex += 1) {
            $digest[($hashIndex * 4) + $byteIndex] = [byte](
                ([uint64]$hashes[$hashIndex] -shr ((3 - $byteIndex) * 8)) -band 255
            )
        }
    }
    return ,$digest
}

function Initialize-NuwaClmHmacState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [byte[]]$Key
    )

    $cachedKey = [byte[]]$script:NuwaCryptoState.ClmHmacKey
    if ($null -ne $cachedKey -and (Test-NuwaFixedTimeEqual -Left $cachedKey -Right $Key)) {
        return
    }
    $normalized = New-NuwaClmByteArray -Length 64
    $keyMaterial = if ($Key.Length -gt 64) {
        [byte[]](Get-NuwaClmSha256Digest -Bytes $Key)
    } else {
        $Key
    }
    for ($index = 0; $index -lt $keyMaterial.Length; $index += 1) {
        $normalized[$index] = $keyMaterial[$index]
    }
    $innerPad = New-NuwaClmByteArray -Length 64
    $outerPad = New-NuwaClmByteArray -Length 64
    for ($index = 0; $index -lt 64; $index += 1) {
        $innerPad[$index] = $normalized[$index] -bxor 54
        $outerPad[$index] = $normalized[$index] -bxor 92
    }
    $script:NuwaCryptoState.ClmHmacKey = Copy-NuwaClmBytes -Source $Key
    $script:NuwaCryptoState.ClmHmacInnerPad = $innerPad
    $script:NuwaCryptoState.ClmHmacOuterPad = $outerPad
}

function Get-NuwaClmHmacSha256Tag {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [byte[]]$Key,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [byte[]]$Bytes
    )

    Initialize-NuwaClmHmacState -Key $Key
    $innerInput = Join-NuwaClmBytes -Parts @(
        [object]$script:NuwaCryptoState.ClmHmacInnerPad,
        [object]$Bytes
    )
    $innerDigest = Get-NuwaClmSha256Digest -Bytes $innerInput
    $outerInput = Join-NuwaClmBytes -Parts @(
        [object]$script:NuwaCryptoState.ClmHmacOuterPad,
        [object]$innerDigest
    )
    return ,(Get-NuwaClmSha256Digest -Bytes $outerInput)
}
