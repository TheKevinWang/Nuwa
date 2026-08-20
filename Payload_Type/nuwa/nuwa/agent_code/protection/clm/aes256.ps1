function Initialize-NuwaClmAesTables {
    [CmdletBinding()]
    param()

    if ($null -ne $script:NuwaClmAesSbox) {
        return
    }
    $script:NuwaClmAesSbox = [byte[]]@(
        99,124,119,123,242,107,111,197,48,1,103,43,254,215,171,118,
        202,130,201,125,250,89,71,240,173,212,162,175,156,164,114,192,
        183,253,147,38,54,63,247,204,52,165,229,241,113,216,49,21,
        4,199,35,195,24,150,5,154,7,18,128,226,235,39,178,117,
        9,131,44,26,27,110,90,160,82,59,214,179,41,227,47,132,
        83,209,0,237,32,252,177,91,106,203,190,57,74,76,88,207,
        208,239,170,251,67,77,51,133,69,249,2,127,80,60,159,168,
        81,163,64,143,146,157,56,245,188,182,218,33,16,255,243,210,
        205,12,19,236,95,151,68,23,196,167,126,61,100,93,25,115,
        96,129,79,220,34,42,144,136,70,238,184,20,222,94,11,219,
        224,50,58,10,73,6,36,92,194,211,172,98,145,149,228,121,
        231,200,55,109,141,213,78,169,108,86,244,234,101,122,174,8,
        186,120,37,46,28,166,180,198,232,221,116,31,75,189,139,138,
        112,62,181,102,72,3,246,14,97,53,87,185,134,193,29,158,
        225,248,152,17,105,217,142,148,155,30,135,233,206,85,40,223,
        140,161,137,13,191,230,66,104,65,153,45,15,176,84,187,22
    )
    $script:NuwaClmAesInverseSbox = [byte[]]@(
        82,9,106,213,48,54,165,56,191,64,163,158,129,243,215,251,
        124,227,57,130,155,47,255,135,52,142,67,68,196,222,233,203,
        84,123,148,50,166,194,35,61,238,76,149,11,66,250,195,78,
        8,46,161,102,40,217,36,178,118,91,162,73,109,139,209,37,
        114,248,246,100,134,104,152,22,212,164,92,204,93,101,182,146,
        108,112,72,80,253,237,185,218,94,21,70,87,167,141,157,132,
        144,216,171,0,140,188,211,10,247,228,88,5,184,179,69,6,
        208,44,30,143,202,63,15,2,193,175,189,3,1,19,138,107,
        58,145,17,65,79,103,220,234,151,242,207,206,240,180,230,115,
        150,172,116,34,231,173,53,133,226,249,55,232,28,117,223,110,
        71,241,26,113,29,41,197,137,111,183,98,14,170,24,190,27,
        252,86,62,75,198,210,121,32,154,219,192,254,120,205,90,244,
        31,221,168,51,136,7,199,49,177,18,16,89,39,128,236,95,
        96,81,127,169,25,181,74,13,45,229,122,159,147,201,156,239,
        160,224,59,77,174,42,245,176,200,235,187,60,131,83,153,97,
        23,43,4,126,186,119,214,38,225,105,20,99,85,33,12,125
    )
    $script:NuwaClmAesRcon = [byte[]]@(1,2,4,8,16,32,64,128,27,54,108,216,171,77,154)
    $script:NuwaClmAesMul2 = New-NuwaClmByteArray -Length 256
    $script:NuwaClmAesMul3 = New-NuwaClmByteArray -Length 256
    $script:NuwaClmAesMul9 = New-NuwaClmByteArray -Length 256
    $script:NuwaClmAesMul11 = New-NuwaClmByteArray -Length 256
    $script:NuwaClmAesMul13 = New-NuwaClmByteArray -Length 256
    $script:NuwaClmAesMul14 = New-NuwaClmByteArray -Length 256
    $script:NuwaClmAesEncryptTable0 = New-Object uint32[] 256
    $script:NuwaClmAesEncryptTable1 = New-Object uint32[] 256
    $script:NuwaClmAesEncryptTable2 = New-Object uint32[] 256
    $script:NuwaClmAesEncryptTable3 = New-Object uint32[] 256
    $script:NuwaClmAesDecryptTable0 = New-Object uint32[] 256
    $script:NuwaClmAesDecryptTable1 = New-Object uint32[] 256
    $script:NuwaClmAesDecryptTable2 = New-Object uint32[] 256
    $script:NuwaClmAesDecryptTable3 = New-Object uint32[] 256
    for ($index = 0; $index -lt 256; $index += 1) {
        $value = [byte]$index
        $script:NuwaClmAesMul2[$index] = Multiply-NuwaClmAesByte -Left $value -Right 2
        $script:NuwaClmAesMul3[$index] = Multiply-NuwaClmAesByte -Left $value -Right 3
        $script:NuwaClmAesMul9[$index] = Multiply-NuwaClmAesByte -Left $value -Right 9
        $script:NuwaClmAesMul11[$index] = Multiply-NuwaClmAesByte -Left $value -Right 11
        $script:NuwaClmAesMul13[$index] = Multiply-NuwaClmAesByte -Left $value -Right 13
        $script:NuwaClmAesMul14[$index] = Multiply-NuwaClmAesByte -Left $value -Right 14
        [byte]$substituted = $script:NuwaClmAesSbox[$index]
        [byte]$inverseSubstituted = $script:NuwaClmAesInverseSbox[$index]
        $script:NuwaClmAesEncryptTable0[$index] = ConvertTo-NuwaClmUInt32 -Value (
            (([uint64]$script:NuwaClmAesMul2[$substituted]) -shl 24) -bor
            (([uint64]$substituted) -shl 16) -bor (([uint64]$substituted) -shl 8) -bor
            ([uint64]$script:NuwaClmAesMul3[$substituted])
        )
        $script:NuwaClmAesEncryptTable1[$index] = ConvertTo-NuwaClmUInt32 -Value (
            (([uint64]$script:NuwaClmAesMul3[$substituted]) -shl 24) -bor
            (([uint64]$script:NuwaClmAesMul2[$substituted]) -shl 16) -bor
            (([uint64]$substituted) -shl 8) -bor ([uint64]$substituted)
        )
        $script:NuwaClmAesEncryptTable2[$index] = ConvertTo-NuwaClmUInt32 -Value (
            (([uint64]$substituted) -shl 24) -bor
            (([uint64]$script:NuwaClmAesMul3[$substituted]) -shl 16) -bor
            (([uint64]$script:NuwaClmAesMul2[$substituted]) -shl 8) -bor ([uint64]$substituted)
        )
        $script:NuwaClmAesEncryptTable3[$index] = ConvertTo-NuwaClmUInt32 -Value (
            (([uint64]$substituted) -shl 24) -bor (([uint64]$substituted) -shl 16) -bor
            (([uint64]$script:NuwaClmAesMul3[$substituted]) -shl 8) -bor
            ([uint64]$script:NuwaClmAesMul2[$substituted])
        )
        $script:NuwaClmAesDecryptTable0[$index] = ConvertTo-NuwaClmUInt32 -Value (
            (([uint64]$script:NuwaClmAesMul14[$inverseSubstituted]) -shl 24) -bor
            (([uint64]$script:NuwaClmAesMul9[$inverseSubstituted]) -shl 16) -bor
            (([uint64]$script:NuwaClmAesMul13[$inverseSubstituted]) -shl 8) -bor
            ([uint64]$script:NuwaClmAesMul11[$inverseSubstituted])
        )
        $script:NuwaClmAesDecryptTable1[$index] = ConvertTo-NuwaClmUInt32 -Value (
            (([uint64]$script:NuwaClmAesMul11[$inverseSubstituted]) -shl 24) -bor
            (([uint64]$script:NuwaClmAesMul14[$inverseSubstituted]) -shl 16) -bor
            (([uint64]$script:NuwaClmAesMul9[$inverseSubstituted]) -shl 8) -bor
            ([uint64]$script:NuwaClmAesMul13[$inverseSubstituted])
        )
        $script:NuwaClmAesDecryptTable2[$index] = ConvertTo-NuwaClmUInt32 -Value (
            (([uint64]$script:NuwaClmAesMul13[$inverseSubstituted]) -shl 24) -bor
            (([uint64]$script:NuwaClmAesMul11[$inverseSubstituted]) -shl 16) -bor
            (([uint64]$script:NuwaClmAesMul14[$inverseSubstituted]) -shl 8) -bor
            ([uint64]$script:NuwaClmAesMul9[$inverseSubstituted])
        )
        $script:NuwaClmAesDecryptTable3[$index] = ConvertTo-NuwaClmUInt32 -Value (
            (([uint64]$script:NuwaClmAesMul9[$inverseSubstituted]) -shl 24) -bor
            (([uint64]$script:NuwaClmAesMul13[$inverseSubstituted]) -shl 16) -bor
            (([uint64]$script:NuwaClmAesMul11[$inverseSubstituted]) -shl 8) -bor
            ([uint64]$script:NuwaClmAesMul14[$inverseSubstituted])
        )
    }
    for ($index = 0; $index -lt 256; $index += 1) {
        [byte]$substituted = $script:NuwaClmAesSbox[$index]
        [byte]$inverseSubstituted = $script:NuwaClmAesInverseSbox[$index]
        $script:NuwaClmAesEncryptTable0[$index] = ConvertTo-NuwaClmUInt32 -Value ((([uint64]$script:NuwaClmAesMul2[$substituted]) -shl 24) -bor (([uint64]$substituted) -shl 16) -bor (([uint64]$substituted) -shl 8) -bor ([uint64]$script:NuwaClmAesMul3[$substituted]))
        $script:NuwaClmAesEncryptTable1[$index] = ConvertTo-NuwaClmUInt32 -Value ((([uint64]$script:NuwaClmAesMul3[$substituted]) -shl 24) -bor (([uint64]$script:NuwaClmAesMul2[$substituted]) -shl 16) -bor (([uint64]$substituted) -shl 8) -bor ([uint64]$substituted))
        $script:NuwaClmAesEncryptTable2[$index] = ConvertTo-NuwaClmUInt32 -Value ((([uint64]$substituted) -shl 24) -bor (([uint64]$script:NuwaClmAesMul3[$substituted]) -shl 16) -bor (([uint64]$script:NuwaClmAesMul2[$substituted]) -shl 8) -bor ([uint64]$substituted))
        $script:NuwaClmAesEncryptTable3[$index] = ConvertTo-NuwaClmUInt32 -Value ((([uint64]$substituted) -shl 24) -bor (([uint64]$substituted) -shl 16) -bor (([uint64]$script:NuwaClmAesMul3[$substituted]) -shl 8) -bor ([uint64]$script:NuwaClmAesMul2[$substituted]))
        $script:NuwaClmAesDecryptTable0[$index] = ConvertTo-NuwaClmUInt32 -Value ((([uint64]$script:NuwaClmAesMul14[$inverseSubstituted]) -shl 24) -bor (([uint64]$script:NuwaClmAesMul9[$inverseSubstituted]) -shl 16) -bor (([uint64]$script:NuwaClmAesMul13[$inverseSubstituted]) -shl 8) -bor ([uint64]$script:NuwaClmAesMul11[$inverseSubstituted]))
        $script:NuwaClmAesDecryptTable1[$index] = ConvertTo-NuwaClmUInt32 -Value ((([uint64]$script:NuwaClmAesMul11[$inverseSubstituted]) -shl 24) -bor (([uint64]$script:NuwaClmAesMul14[$inverseSubstituted]) -shl 16) -bor (([uint64]$script:NuwaClmAesMul9[$inverseSubstituted]) -shl 8) -bor ([uint64]$script:NuwaClmAesMul13[$inverseSubstituted]))
        $script:NuwaClmAesDecryptTable2[$index] = ConvertTo-NuwaClmUInt32 -Value ((([uint64]$script:NuwaClmAesMul13[$inverseSubstituted]) -shl 24) -bor (([uint64]$script:NuwaClmAesMul11[$inverseSubstituted]) -shl 16) -bor (([uint64]$script:NuwaClmAesMul14[$inverseSubstituted]) -shl 8) -bor ([uint64]$script:NuwaClmAesMul9[$inverseSubstituted]))
        $script:NuwaClmAesDecryptTable3[$index] = ConvertTo-NuwaClmUInt32 -Value ((([uint64]$script:NuwaClmAesMul9[$inverseSubstituted]) -shl 24) -bor (([uint64]$script:NuwaClmAesMul13[$inverseSubstituted]) -shl 16) -bor (([uint64]$script:NuwaClmAesMul11[$inverseSubstituted]) -shl 8) -bor ([uint64]$script:NuwaClmAesMul14[$inverseSubstituted]))
    }
}

function Initialize-NuwaClmAes256State {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [byte[]]$Key
    )

    if ($Key.Length -ne 32) {
        throw 'Nuwa AES protection requires a 32-byte key and 16-byte IV'
    }
    Initialize-NuwaClmAesTables
    $cachedKey = [byte[]]$script:NuwaCryptoState.ClmAesKey
    if ($null -ne $cachedKey -and
        (Test-NuwaFixedTimeEqual -Left $cachedKey -Right $Key) -and
        $null -ne $script:NuwaCryptoState.ClmAesRoundKeys -and
        $null -ne $script:NuwaCryptoState.ClmAesRoundWords) {
        return
    }

    $roundKeys = New-NuwaClmByteArray -Length 240
    for ($index = 0; $index -lt 32; $index += 1) {
        $roundKeys[$index] = $Key[$index]
    }
    for ($word = 8; $word -lt 60; $word += 1) {
        [byte]$t0 = $roundKeys[(($word - 1) * 4)]
        [byte]$t1 = $roundKeys[(($word - 1) * 4) + 1]
        [byte]$t2 = $roundKeys[(($word - 1) * 4) + 2]
        [byte]$t3 = $roundKeys[(($word - 1) * 4) + 3]
        if (($word % 8) -eq 0) {
            [byte]$oldT0 = $t0
            $t0 = $script:NuwaClmAesSbox[$t1]
            $t1 = $script:NuwaClmAesSbox[$t2]
            $t2 = $script:NuwaClmAesSbox[$t3]
            $t3 = $script:NuwaClmAesSbox[$oldT0]
            $t0 = $t0 -bxor $script:NuwaClmAesRcon[([int]($word / 8)) - 1]
        } elseif (($word % 8) -eq 4) {
            $t0 = $script:NuwaClmAesSbox[$t0]
            $t1 = $script:NuwaClmAesSbox[$t1]
            $t2 = $script:NuwaClmAesSbox[$t2]
            $t3 = $script:NuwaClmAesSbox[$t3]
        }
        $base = $word * 4
        $previousBase = ($word - 8) * 4
        $roundKeys[$base] = $roundKeys[$previousBase] -bxor $t0
        $roundKeys[$base + 1] = $roundKeys[$previousBase + 1] -bxor $t1
        $roundKeys[$base + 2] = $roundKeys[$previousBase + 2] -bxor $t2
        $roundKeys[$base + 3] = $roundKeys[$previousBase + 3] -bxor $t3
    }
    $roundWords = New-Object uint32[] 60
    for ($word = 0; $word -lt 60; $word += 1) {
        $base = $word * 4
        $roundWords[$word] = ConvertTo-NuwaClmUInt32 -Value (
            (([uint64]$roundKeys[$base]) -shl 24) -bor
            (([uint64]$roundKeys[$base + 1]) -shl 16) -bor
            (([uint64]$roundKeys[$base + 2]) -shl 8) -bor
            ([uint64]$roundKeys[$base + 3])
        )
    }
    $decryptRoundWords = New-Object uint32[] 60
    for ($word = 0; $word -lt 60; $word += 1) {
        $decryptRoundWords[$word] = $roundWords[$word]
    }
    for ($word = 4; $word -lt 56; $word += 1) {
        $base = $word * 4
        [byte]$b0 = $roundKeys[$base]
        [byte]$b1 = $roundKeys[$base + 1]
        [byte]$b2 = $roundKeys[$base + 2]
        [byte]$b3 = $roundKeys[$base + 3]
        [byte]$d0 = $script:NuwaClmAesMul14[$b0] -bxor $script:NuwaClmAesMul11[$b1] -bxor $script:NuwaClmAesMul13[$b2] -bxor $script:NuwaClmAesMul9[$b3]
        [byte]$d1 = $script:NuwaClmAesMul9[$b0] -bxor $script:NuwaClmAesMul14[$b1] -bxor $script:NuwaClmAesMul11[$b2] -bxor $script:NuwaClmAesMul13[$b3]
        [byte]$d2 = $script:NuwaClmAesMul13[$b0] -bxor $script:NuwaClmAesMul9[$b1] -bxor $script:NuwaClmAesMul14[$b2] -bxor $script:NuwaClmAesMul11[$b3]
        [byte]$d3 = $script:NuwaClmAesMul11[$b0] -bxor $script:NuwaClmAesMul13[$b1] -bxor $script:NuwaClmAesMul9[$b2] -bxor $script:NuwaClmAesMul14[$b3]
        $decryptRoundWords[$word] = ConvertTo-NuwaClmUInt32 -Value ((([uint64]$d0) -shl 24) -bor (([uint64]$d1) -shl 16) -bor (([uint64]$d2) -shl 8) -bor ([uint64]$d3))
    }
    $script:NuwaCryptoState.ClmAesKey = Copy-NuwaClmBytes -Source $Key
    $script:NuwaCryptoState.ClmAesRoundKeys = $roundKeys
    $script:NuwaCryptoState.ClmAesRoundWords = $roundWords
    $script:NuwaCryptoState.ClmAesDecryptRoundWords = $decryptRoundWords
}

function Add-NuwaClmAesRoundKey {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [byte[]]$State,

        [Parameter(Mandatory = $true)]
        [int]$Round
    )

    $keyOffset = $Round * 16
    for ($index = 0; $index -lt 16; $index += 1) {
        $State[$index] = $State[$index] -bxor $script:NuwaCryptoState.ClmAesRoundKeys[$keyOffset + $index]
    }
}

function Invoke-NuwaClmAesSubBytes {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [byte[]]$State,

        [switch]$Inverse
    )

    $table = if ($Inverse) { $script:NuwaClmAesInverseSbox } else { $script:NuwaClmAesSbox }
    for ($index = 0; $index -lt 16; $index += 1) {
        $State[$index] = $table[$State[$index]]
    }
}

function Invoke-NuwaClmAesShiftRows {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [byte[]]$State,

        [switch]$Inverse
    )

    [byte]$t1 = $State[1]
    [byte]$t5 = $State[5]
    [byte]$t9 = $State[9]
    [byte]$t13 = $State[13]
    if ($Inverse) {
        $State[1] = $t13; $State[5] = $t1; $State[9] = $t5; $State[13] = $t9
    } else {
        $State[1] = $t5; $State[5] = $t9; $State[9] = $t13; $State[13] = $t1
    }
    [byte]$t2 = $State[2]
    [byte]$t6 = $State[6]
    [byte]$t10 = $State[10]
    [byte]$t14 = $State[14]
    $State[2] = $t10; $State[6] = $t14; $State[10] = $t2; $State[14] = $t6
    [byte]$t3 = $State[3]
    [byte]$t7 = $State[7]
    [byte]$t11 = $State[11]
    [byte]$t15 = $State[15]
    if ($Inverse) {
        $State[3] = $t7; $State[7] = $t11; $State[11] = $t15; $State[15] = $t3
    } else {
        $State[3] = $t15; $State[7] = $t3; $State[11] = $t7; $State[15] = $t11
    }
}

function Multiply-NuwaClmAesByte {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [byte]$Left,

        [Parameter(Mandatory = $true)]
        [byte]$Right
    )

    [int]$leftValue = $Left
    [int]$rightValue = $Right
    [int]$result = 0
    while ($rightValue -gt 0) {
        if (($rightValue -band 1) -ne 0) {
            $result = $result -bxor $leftValue
        }
        [bool]$highBit = ($leftValue -band 128) -ne 0
        $leftValue = ($leftValue -shl 1) -band 255
        if ($highBit) {
            $leftValue = $leftValue -bxor 27
        }
        $rightValue = $rightValue -shr 1
    }
    return [byte]$result
}

function Invoke-NuwaClmAesMixColumns {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [byte[]]$State,

        [switch]$Inverse
    )

    for ($offset = 0; $offset -lt 16; $offset += 4) {
        [byte]$a0 = $State[$offset]
        [byte]$a1 = $State[$offset + 1]
        [byte]$a2 = $State[$offset + 2]
        [byte]$a3 = $State[$offset + 3]
        if ($Inverse) {
            $State[$offset] = $script:NuwaClmAesMul14[$a0] -bxor $script:NuwaClmAesMul11[$a1] -bxor $script:NuwaClmAesMul13[$a2] -bxor $script:NuwaClmAesMul9[$a3]
            $State[$offset + 1] = $script:NuwaClmAesMul9[$a0] -bxor $script:NuwaClmAesMul14[$a1] -bxor $script:NuwaClmAesMul11[$a2] -bxor $script:NuwaClmAesMul13[$a3]
            $State[$offset + 2] = $script:NuwaClmAesMul13[$a0] -bxor $script:NuwaClmAesMul9[$a1] -bxor $script:NuwaClmAesMul14[$a2] -bxor $script:NuwaClmAesMul11[$a3]
            $State[$offset + 3] = $script:NuwaClmAesMul11[$a0] -bxor $script:NuwaClmAesMul13[$a1] -bxor $script:NuwaClmAesMul9[$a2] -bxor $script:NuwaClmAesMul14[$a3]
        } else {
            $State[$offset] = $script:NuwaClmAesMul2[$a0] -bxor $script:NuwaClmAesMul3[$a1] -bxor $a2 -bxor $a3
            $State[$offset + 1] = $a0 -bxor $script:NuwaClmAesMul2[$a1] -bxor $script:NuwaClmAesMul3[$a2] -bxor $a3
            $State[$offset + 2] = $a0 -bxor $a1 -bxor $script:NuwaClmAesMul2[$a2] -bxor $script:NuwaClmAesMul3[$a3]
            $State[$offset + 3] = $script:NuwaClmAesMul3[$a0] -bxor $a1 -bxor $a2 -bxor $script:NuwaClmAesMul2[$a3]
        }
    }
}

function Protect-NuwaClmAes256Block {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [byte[]]$Block
    )

    if ($Block.Length -ne 16 -or $null -eq $script:NuwaCryptoState.ClmAesRoundWords) {
        throw 'Nuwa CLM AES state is unavailable'
    }
    $roundWords = [uint32[]]$script:NuwaCryptoState.ClmAesRoundWords
    $table0 = [uint32[]]$script:NuwaClmAesEncryptTable0
    $table1 = [uint32[]]$script:NuwaClmAesEncryptTable1
    $table2 = [uint32[]]$script:NuwaClmAesEncryptTable2
    $table3 = [uint32[]]$script:NuwaClmAesEncryptTable3
    $sbox = [byte[]]$script:NuwaClmAesSbox
    [uint32]$state0 = ConvertTo-NuwaClmUInt32 -Value (
        (([uint64]$Block[0]) -shl 24) -bor (([uint64]$Block[1]) -shl 16) -bor
        (([uint64]$Block[2]) -shl 8) -bor ([uint64]$Block[3])
    )
    [uint32]$state1 = ConvertTo-NuwaClmUInt32 -Value (
        (([uint64]$Block[4]) -shl 24) -bor (([uint64]$Block[5]) -shl 16) -bor
        (([uint64]$Block[6]) -shl 8) -bor ([uint64]$Block[7])
    )
    [uint32]$state2 = ConvertTo-NuwaClmUInt32 -Value (
        (([uint64]$Block[8]) -shl 24) -bor (([uint64]$Block[9]) -shl 16) -bor
        (([uint64]$Block[10]) -shl 8) -bor ([uint64]$Block[11])
    )
    [uint32]$state3 = ConvertTo-NuwaClmUInt32 -Value (
        (([uint64]$Block[12]) -shl 24) -bor (([uint64]$Block[13]) -shl 16) -bor
        (([uint64]$Block[14]) -shl 8) -bor ([uint64]$Block[15])
    )
    $state0 = $state0 -bxor $roundWords[0]
    $state1 = $state1 -bxor $roundWords[1]
    $state2 = $state2 -bxor $roundWords[2]
    $state3 = $state3 -bxor $roundWords[3]
    for ($round = 1; $round -lt 14; $round += 1) {
        $keyOffset = $round * 4
        [uint32]$next0 = $table0[$state0 -shr 24] -bxor $table1[(($state1 -shr 16) -band 255)] -bxor $table2[(($state2 -shr 8) -band 255)] -bxor $table3[($state3 -band 255)] -bxor $roundWords[$keyOffset]
        [uint32]$next1 = $table0[$state1 -shr 24] -bxor $table1[(($state2 -shr 16) -band 255)] -bxor $table2[(($state3 -shr 8) -band 255)] -bxor $table3[($state0 -band 255)] -bxor $roundWords[$keyOffset + 1]
        [uint32]$next2 = $table0[$state2 -shr 24] -bxor $table1[(($state3 -shr 16) -band 255)] -bxor $table2[(($state0 -shr 8) -band 255)] -bxor $table3[($state1 -band 255)] -bxor $roundWords[$keyOffset + 2]
        [uint32]$next3 = $table0[$state3 -shr 24] -bxor $table1[(($state0 -shr 16) -band 255)] -bxor $table2[(($state1 -shr 8) -band 255)] -bxor $table3[($state2 -band 255)] -bxor $roundWords[$keyOffset + 3]
        $state0 = $next0; $state1 = $next1; $state2 = $next2; $state3 = $next3
    }
    [uint32]$final0 = ConvertTo-NuwaClmUInt32 -Value (
        (([uint64]$sbox[$state0 -shr 24]) -shl 24) -bor
        (([uint64]$sbox[(($state1 -shr 16) -band 255)]) -shl 16) -bor
        (([uint64]$sbox[(($state2 -shr 8) -band 255)]) -shl 8) -bor
        ([uint64]$sbox[($state3 -band 255)])
    )
    [uint32]$final1 = ConvertTo-NuwaClmUInt32 -Value ((([uint64]$sbox[$state1 -shr 24]) -shl 24) -bor (([uint64]$sbox[(($state2 -shr 16) -band 255)]) -shl 16) -bor (([uint64]$sbox[(($state3 -shr 8) -band 255)]) -shl 8) -bor ([uint64]$sbox[($state0 -band 255)]))
    [uint32]$final2 = ConvertTo-NuwaClmUInt32 -Value ((([uint64]$sbox[$state2 -shr 24]) -shl 24) -bor (([uint64]$sbox[(($state3 -shr 16) -band 255)]) -shl 16) -bor (([uint64]$sbox[(($state0 -shr 8) -band 255)]) -shl 8) -bor ([uint64]$sbox[($state1 -band 255)]))
    [uint32]$final3 = ConvertTo-NuwaClmUInt32 -Value ((([uint64]$sbox[$state3 -shr 24]) -shl 24) -bor (([uint64]$sbox[(($state0 -shr 16) -band 255)]) -shl 16) -bor (([uint64]$sbox[(($state1 -shr 8) -band 255)]) -shl 8) -bor ([uint64]$sbox[($state2 -band 255)]))
    $final0 = $final0 -bxor $roundWords[56]; $final1 = $final1 -bxor $roundWords[57]
    $final2 = $final2 -bxor $roundWords[58]; $final3 = $final3 -bxor $roundWords[59]
    $result = New-NuwaClmByteArray -Length 16
    $words = [uint32[]]@($final0, $final1, $final2, $final3)
    for ($wordIndex = 0; $wordIndex -lt 4; $wordIndex += 1) {
        for ($byteIndex = 0; $byteIndex -lt 4; $byteIndex += 1) {
            $result[($wordIndex * 4) + $byteIndex] = [byte](([uint64]$words[$wordIndex] -shr ((3 - $byteIndex) * 8)) -band 255)
        }
    }
    return ,$result
}

function Unprotect-NuwaClmAes256Block {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [byte[]]$Block
    )

    if ($Block.Length -ne 16 -or $null -eq $script:NuwaCryptoState.ClmAesRoundWords) {
        throw 'Nuwa CLM AES state is unavailable'
    }
    $roundWords = [uint32[]]$script:NuwaCryptoState.ClmAesDecryptRoundWords
    $inverseSbox = [byte[]]$script:NuwaClmAesInverseSbox
    $table0 = [uint32[]]$script:NuwaClmAesDecryptTable0
    $table1 = [uint32[]]$script:NuwaClmAesDecryptTable1
    $table2 = [uint32[]]$script:NuwaClmAesDecryptTable2
    $table3 = [uint32[]]$script:NuwaClmAesDecryptTable3
    [uint32]$state0 = ConvertTo-NuwaClmUInt32 -Value ((([uint64]$Block[0]) -shl 24) -bor (([uint64]$Block[1]) -shl 16) -bor (([uint64]$Block[2]) -shl 8) -bor ([uint64]$Block[3]))
    [uint32]$state1 = ConvertTo-NuwaClmUInt32 -Value ((([uint64]$Block[4]) -shl 24) -bor (([uint64]$Block[5]) -shl 16) -bor (([uint64]$Block[6]) -shl 8) -bor ([uint64]$Block[7]))
    [uint32]$state2 = ConvertTo-NuwaClmUInt32 -Value ((([uint64]$Block[8]) -shl 24) -bor (([uint64]$Block[9]) -shl 16) -bor (([uint64]$Block[10]) -shl 8) -bor ([uint64]$Block[11]))
    [uint32]$state3 = ConvertTo-NuwaClmUInt32 -Value ((([uint64]$Block[12]) -shl 24) -bor (([uint64]$Block[13]) -shl 16) -bor (([uint64]$Block[14]) -shl 8) -bor ([uint64]$Block[15]))
    $state0 = $state0 -bxor $roundWords[56]
    $state1 = $state1 -bxor $roundWords[57]
    $state2 = $state2 -bxor $roundWords[58]
    $state3 = $state3 -bxor $roundWords[59]
    for ($round = 13; $round -gt 0; $round -= 1) {
        $keyOffset = $round * 4
        [uint32]$next0 = $table0[$state0 -shr 24] -bxor $table1[(($state3 -shr 16) -band 255)] -bxor $table2[(($state2 -shr 8) -band 255)] -bxor $table3[($state1 -band 255)] -bxor $roundWords[$keyOffset]
        [uint32]$next1 = $table0[$state1 -shr 24] -bxor $table1[(($state0 -shr 16) -band 255)] -bxor $table2[(($state3 -shr 8) -band 255)] -bxor $table3[($state2 -band 255)] -bxor $roundWords[$keyOffset + 1]
        [uint32]$next2 = $table0[$state2 -shr 24] -bxor $table1[(($state1 -shr 16) -band 255)] -bxor $table2[(($state0 -shr 8) -band 255)] -bxor $table3[($state3 -band 255)] -bxor $roundWords[$keyOffset + 2]
        [uint32]$next3 = $table0[$state3 -shr 24] -bxor $table1[(($state2 -shr 16) -band 255)] -bxor $table2[(($state1 -shr 8) -band 255)] -bxor $table3[($state0 -band 255)] -bxor $roundWords[$keyOffset + 3]
        $state0 = $next0; $state1 = $next1; $state2 = $next2; $state3 = $next3
    }
    [uint32]$final0 = ConvertTo-NuwaClmUInt32 -Value ((([uint64]$inverseSbox[$state0 -shr 24]) -shl 24) -bor (([uint64]$inverseSbox[(($state3 -shr 16) -band 255)]) -shl 16) -bor (([uint64]$inverseSbox[(($state2 -shr 8) -band 255)]) -shl 8) -bor ([uint64]$inverseSbox[($state1 -band 255)]))
    [uint32]$final1 = ConvertTo-NuwaClmUInt32 -Value ((([uint64]$inverseSbox[$state1 -shr 24]) -shl 24) -bor (([uint64]$inverseSbox[(($state0 -shr 16) -band 255)]) -shl 16) -bor (([uint64]$inverseSbox[(($state3 -shr 8) -band 255)]) -shl 8) -bor ([uint64]$inverseSbox[($state2 -band 255)]))
    [uint32]$final2 = ConvertTo-NuwaClmUInt32 -Value ((([uint64]$inverseSbox[$state2 -shr 24]) -shl 24) -bor (([uint64]$inverseSbox[(($state1 -shr 16) -band 255)]) -shl 16) -bor (([uint64]$inverseSbox[(($state0 -shr 8) -band 255)]) -shl 8) -bor ([uint64]$inverseSbox[($state3 -band 255)]))
    [uint32]$final3 = ConvertTo-NuwaClmUInt32 -Value ((([uint64]$inverseSbox[$state3 -shr 24]) -shl 24) -bor (([uint64]$inverseSbox[(($state2 -shr 16) -band 255)]) -shl 16) -bor (([uint64]$inverseSbox[(($state1 -shr 8) -band 255)]) -shl 8) -bor ([uint64]$inverseSbox[($state0 -band 255)]))
    $final0 = $final0 -bxor $roundWords[0]; $final1 = $final1 -bxor $roundWords[1]
    $final2 = $final2 -bxor $roundWords[2]; $final3 = $final3 -bxor $roundWords[3]
    $result = New-NuwaClmByteArray -Length 16
    $words = [uint32[]]@($final0, $final1, $final2, $final3)
    for ($wordIndex = 0; $wordIndex -lt 4; $wordIndex += 1) {
        for ($byteIndex = 0; $byteIndex -lt 4; $byteIndex += 1) {
            $result[($wordIndex * 4) + $byteIndex] = [byte](([uint64]$words[$wordIndex] -shr ((3 - $byteIndex) * 8)) -band 255)
        }
    }
    return ,$result
}

function Protect-NuwaClmAes256CbcBytes {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [byte[]]$Bytes,

        [Parameter(Mandatory = $true)]
        [byte[]]$Key,

        [Parameter(Mandatory = $true)]
        [byte[]]$InitializationVector
    )

    if ($InitializationVector.Length -ne 16) {
        throw 'Nuwa AES protection requires a 32-byte key and 16-byte IV'
    }
    Initialize-NuwaClmAes256State -Key $Key
    [int]$paddingLength = 16 - ($Bytes.Length % 16)
    $padded = New-NuwaClmByteArray -Length ($Bytes.Length + $paddingLength)
    for ($index = 0; $index -lt $Bytes.Length; $index += 1) {
        $padded[$index] = $Bytes[$index]
    }
    for ($index = $Bytes.Length; $index -lt $padded.Length; $index += 1) {
        $padded[$index] = [byte]$paddingLength
    }
    $ciphertext = New-NuwaClmByteArray -Length $padded.Length
    $previous = Copy-NuwaClmBytes -Source $InitializationVector
    for ($offset = 0; $offset -lt $padded.Length; $offset += 16) {
        $block = New-NuwaClmByteArray -Length 16
        for ($index = 0; $index -lt 16; $index += 1) {
            $block[$index] = $padded[$offset + $index] -bxor $previous[$index]
        }
        $encrypted = Protect-NuwaClmAes256Block -Block $block
        for ($index = 0; $index -lt 16; $index += 1) {
            $ciphertext[$offset + $index] = $encrypted[$index]
        }
        $previous = $encrypted
    }
    return ,$ciphertext
}

function Unprotect-NuwaClmAes256CbcBytes {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [byte[]]$Ciphertext,

        [Parameter(Mandatory = $true)]
        [byte[]]$Key,

        [Parameter(Mandatory = $true)]
        [byte[]]$InitializationVector
    )

    if ($InitializationVector.Length -ne 16 -or $Ciphertext.Length -lt 16 -or
        ($Ciphertext.Length % 16) -ne 0) {
        throw 'Nuwa protection authentication failed'
    }
    Initialize-NuwaClmAes256State -Key $Key
    $padded = New-NuwaClmByteArray -Length $Ciphertext.Length
    $previous = Copy-NuwaClmBytes -Source $InitializationVector
    for ($offset = 0; $offset -lt $Ciphertext.Length; $offset += 16) {
        $block = Get-NuwaClmByteSlice -Source $Ciphertext -Offset $offset -Length 16
        $decrypted = Unprotect-NuwaClmAes256Block -Block $block
        for ($index = 0; $index -lt 16; $index += 1) {
            $padded[$offset + $index] = $decrypted[$index] -bxor $previous[$index]
        }
        $previous = $block
    }
    [int]$paddingLength = $padded[$padded.Length - 1]
    if ($paddingLength -lt 1 -or $paddingLength -gt 16 -or $paddingLength -gt $padded.Length) {
        throw 'Nuwa protection authentication failed'
    }
    for ($index = $padded.Length - $paddingLength; $index -lt $padded.Length; $index += 1) {
        if ($padded[$index] -ne $paddingLength) {
            throw 'Nuwa protection authentication failed'
        }
    }
    return ,(Get-NuwaClmByteSlice -Source $padded -Offset 0 -Length ($padded.Length - $paddingLength))
}
