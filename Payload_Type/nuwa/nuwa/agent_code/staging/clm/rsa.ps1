# This file is deliberately composed only into constrained-language staged
# payloads.  It must remain independent of the Full Language RSA provider.

$script:NuwaClmRsaMillerRabinRounds = 24
$script:NuwaClmRsaMaxWitnessDraws = 128
$script:NuwaClmRsaMaxPrimeCandidates = 4096
$script:NuwaClmRsaMaxKeyPairAttempts = 8

function ConvertTo-NuwaClmRsaBigInteger {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [byte[]]$Bytes
    )

    [bigint]$value = 0
    for ($index = 0; $index -lt $Bytes.Length; $index += 1) {
        $value = ($value * [bigint]256) + [bigint]$Bytes[$index]
    }
    return $value
}

function ConvertFrom-NuwaClmRsaBigInteger {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [bigint]$Value,

        [Parameter(Mandatory = $true)]
        [int]$Length
    )

    if ($Value -lt [bigint]0 -or $Length -lt 1 -or $Length -gt 4096) {
        throw 'Nuwa CLM RSA integer conversion failed'
    }
    [bigint]$limit = 1
    for ($index = 0; $index -lt $Length; $index += 1) {
        $limit *= [bigint]256
    }
    if ($Value -ge $limit) {
        throw 'Nuwa CLM RSA integer conversion failed'
    }
    $result = New-NuwaClmByteArray -Length $Length
    [bigint]$remaining = $Value
    for ($index = $Length - 1; $index -ge 0; $index -= 1) {
        $result[$index] = [byte]($remaining % [bigint]256)
        $remaining /= [bigint]256
    }
    return ,$result
}

function Get-NuwaClmRsaModulusByteLength {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [bigint]$Modulus
    )

    if ($Modulus -le [bigint]1) {
        throw 'Nuwa CLM RSA modulus is invalid'
    }
    [int]$length = 0
    [bigint]$remaining = $Modulus
    while ($remaining -gt [bigint]0) {
        $length += 1
        $remaining /= [bigint]256
    }
    return $length
}

function Invoke-NuwaClmRsaModularPower {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [bigint]$Representative,

        [Parameter(Mandatory = $true)]
        [bigint]$Exponent,

        [Parameter(Mandatory = $true)]
        [bigint]$Modulus
    )

    if ($Modulus -le [bigint]1 -or $Exponent -le [bigint]0 -or
        $Representative -lt [bigint]0 -or $Representative -ge $Modulus) {
        throw 'Nuwa CLM RSA representative is invalid'
    }
    return [bigint]::ModPow($Representative, $Exponent, $Modulus)
}

function Invoke-NuwaClmRsaPrivate {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [bigint]$Representative,

        [Parameter(Mandatory = $true)]
        [bigint]$PrivateExponent,

        [Parameter(Mandatory = $true)]
        [bigint]$Modulus
    )

    return Invoke-NuwaClmRsaModularPower -Representative $Representative `
        -Exponent $PrivateExponent -Modulus $Modulus
}

function ConvertTo-NuwaClmRsaUInt32 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [uint64]$Value
    )

    return [uint32]($Value -band [uint64]4294967295)
}

function RotateLeft-NuwaClmRsaUInt32 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [uint32]$Value,

        [Parameter(Mandatory = $true)]
        [int]$Count
    )

    if ($Count -lt 1 -or $Count -gt 31) {
        throw 'Nuwa CLM SHA-1 rotation is invalid'
    }
    [uint64]$wide = [uint64]$Value
    return ConvertTo-NuwaClmRsaUInt32 -Value (
        (($wide -shl $Count) -bor ($wide -shr (32 - $Count))) -band [uint64]4294967295
    )
}

function Get-NuwaClmSha1Digest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [byte[]]$Bytes
    )

    if ($Bytes.Length -gt 67108855) {
        throw 'Nuwa CLM SHA-1 input is too large'
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

    [uint32]$hashA = 1732584193
    [uint32]$hashB = 4023233417
    [uint32]$hashC = 2562383102
    [uint32]$hashD = 271733878
    [uint32]$hashE = 3285377520
    [uint64]$mask32 = 4294967295
    for ($offset = 0; $offset -lt $padded.Length; $offset += 64) {
        $words = New-Object uint32[] 80
        for ($wordIndex = 0; $wordIndex -lt 16; $wordIndex += 1) {
            $wordOffset = $offset + ($wordIndex * 4)
            $words[$wordIndex] = ConvertTo-NuwaClmRsaUInt32 -Value (
                (([uint64]$padded[$wordOffset]) -shl 24) -bor
                (([uint64]$padded[$wordOffset + 1]) -shl 16) -bor
                (([uint64]$padded[$wordOffset + 2]) -shl 8) -bor
                ([uint64]$padded[$wordOffset + 3])
            )
        }
        for ($wordIndex = 16; $wordIndex -lt 80; $wordIndex += 1) {
            [uint32]$mixed = $words[$wordIndex - 3] -bxor $words[$wordIndex - 8] -bxor
                $words[$wordIndex - 14] -bxor $words[$wordIndex - 16]
            $words[$wordIndex] = RotateLeft-NuwaClmRsaUInt32 -Value $mixed -Count 1
        }

        [uint32]$a = $hashA
        [uint32]$b = $hashB
        [uint32]$c = $hashC
        [uint32]$d = $hashD
        [uint32]$e = $hashE
        for ($round = 0; $round -lt 80; $round += 1) {
            [uint32]$f = 0
            [uint32]$constant = 0
            if ($round -lt 20) {
                $f = ($b -band $c) -bor (($b -bxor [uint32]4294967295) -band $d)
                $constant = 1518500249
            } elseif ($round -lt 40) {
                $f = $b -bxor $c -bxor $d
                $constant = 1859775393
            } elseif ($round -lt 60) {
                $f = ($b -band $c) -bor ($b -band $d) -bor ($c -band $d)
                $constant = 2400959708
            } else {
                $f = $b -bxor $c -bxor $d
                $constant = 3395469782
            }
            [uint32]$temporary = [uint32](
                ([uint64](RotateLeft-NuwaClmRsaUInt32 -Value $a -Count 5) +
                [uint64]$f + [uint64]$e + [uint64]$constant + [uint64]$words[$round]) -band $mask32
            )
            $e = $d
            $d = $c
            $c = RotateLeft-NuwaClmRsaUInt32 -Value $b -Count 30
            $b = $a
            $a = $temporary
        }
        $hashA = [uint32](([uint64]$hashA + [uint64]$a) -band $mask32)
        $hashB = [uint32](([uint64]$hashB + [uint64]$b) -band $mask32)
        $hashC = [uint32](([uint64]$hashC + [uint64]$c) -band $mask32)
        $hashD = [uint32](([uint64]$hashD + [uint64]$d) -band $mask32)
        $hashE = [uint32](([uint64]$hashE + [uint64]$e) -band $mask32)
    }

    $digest = New-NuwaClmByteArray -Length 20
    $hashes = [uint32[]]@($hashA, $hashB, $hashC, $hashD, $hashE)
    for ($hashIndex = 0; $hashIndex -lt 5; $hashIndex += 1) {
        for ($byteIndex = 0; $byteIndex -lt 4; $byteIndex += 1) {
            $digest[($hashIndex * 4) + $byteIndex] = [byte](
                ([uint64]$hashes[$hashIndex] -shr ((3 - $byteIndex) * 8)) -band 255
            )
        }
    }
    return ,$digest
}

function Get-NuwaClmRsaRandomBytes {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [int]$Length
    )

    if ($Length -lt 1 -or $Length -gt 4096) {
        throw 'Nuwa CLM RSA entropy request is invalid'
    }
    $result = New-NuwaClmByteArray -Length $Length
    [int]$written = 0
    while ($written -lt $Length) {
        try {
            $guidText = [guid]::NewGuid().ToString('D')
        } catch {
            throw 'Nuwa CLM RSA entropy failed'
        }
        if ($guidText -cnotmatch '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$') {
            throw 'Nuwa CLM RSA entropy failed'
        }
        $guidBytes = ConvertFrom-NuwaClmHex -Value ($guidText.Replace('-', ''))
        [int]$count = $guidBytes.Length
        if ($count -gt ($Length - $written)) {
            $count = $Length - $written
        }
        for ($index = 0; $index -lt $count; $index += 1) {
            $result[$written + $index] = $guidBytes[$index]
        }
        $written += $count
    }
    return ,$result
}

function Get-NuwaClmMgf1Sha1Mask {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [byte[]]$Seed,

        [Parameter(Mandatory = $true)]
        [int]$MaskLength
    )

    if ($MaskLength -lt 0 -or $MaskLength -gt 67108864) {
        throw 'Nuwa CLM MGF1 length is invalid'
    }
    $mask = New-NuwaClmByteArray -Length $MaskLength
    [int]$written = 0
    [uint64]$counterValue = 0
    while ($written -lt $MaskLength) {
        $counter = New-NuwaClmByteArray -Length 4
        for ($index = 0; $index -lt 4; $index += 1) {
            $counter[$index] = [byte](($counterValue -shr ((3 - $index) * 8)) -band 255)
        }
        $input = Join-NuwaClmBytes -Parts @([object]$Seed, [object]$counter)
        $digest = Get-NuwaClmSha1Digest -Bytes $input
        [int]$count = $digest.Length
        if ($count -gt ($MaskLength - $written)) {
            $count = $MaskLength - $written
        }
        for ($index = 0; $index -lt $count; $index += 1) {
            $mask[$written + $index] = $digest[$index]
        }
        $written += $count
        $counterValue += 1
    }
    return ,$mask
}

function Get-NuwaClmRsaXorBytes {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [byte[]]$Left,

        [Parameter(Mandatory = $true)]
        [byte[]]$Right
    )

    if ($Left.Length -ne $Right.Length) {
        throw 'Nuwa CLM RSA bytes are invalid'
    }
    $result = New-NuwaClmByteArray -Length $Left.Length
    for ($index = 0; $index -lt $result.Length; $index += 1) {
        $result[$index] = [byte]($Left[$index] -bxor $Right[$index])
    }
    return ,$result
}

function Unprotect-NuwaClmRsaOaepSha1 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [byte[]]$Ciphertext,

        [Parameter(Mandatory = $true)]
        [bigint]$PrivateExponent,

        [Parameter(Mandatory = $true)]
        [bigint]$Modulus
    )

    try {
        [int]$hashLength = 20
        [int]$modulusLength = Get-NuwaClmRsaModulusByteLength -Modulus $Modulus
        if ($modulusLength -ne 256 -or $Ciphertext.Length -ne $modulusLength) {
            throw 'invalid'
        }
        $ciphertextRepresentative = ConvertTo-NuwaClmRsaBigInteger -Bytes $Ciphertext
        $encodedRepresentative = Invoke-NuwaClmRsaPrivate -Representative $ciphertextRepresentative `
            -PrivateExponent $PrivateExponent -Modulus $Modulus
        $encodedMessage = ConvertFrom-NuwaClmRsaBigInteger -Value $encodedRepresentative -Length $modulusLength
        [int]$dataBlockLength = $modulusLength - $hashLength - 1
        $maskedSeed = Copy-NuwaClmBytes -Source $encodedMessage -Offset 1 -Length $hashLength
        $maskedDataBlock = Copy-NuwaClmBytes -Source $encodedMessage -Offset ($hashLength + 1) -Length $dataBlockLength
        $seedMask = Get-NuwaClmMgf1Sha1Mask -Seed $maskedDataBlock -MaskLength $hashLength
        $seed = Get-NuwaClmRsaXorBytes -Left $maskedSeed -Right $seedMask
        $dataBlockMask = Get-NuwaClmMgf1Sha1Mask -Seed $seed -MaskLength $dataBlockLength
        $dataBlock = Get-NuwaClmRsaXorBytes -Left $maskedDataBlock -Right $dataBlockMask
        $labelHash = Get-NuwaClmSha1Digest -Bytes ([byte[]]@())
        [int]$invalid = 0
        if ($encodedMessage[0] -ne 0) {
            $invalid = 1
        }
        for ($index = 0; $index -lt $hashLength; $index += 1) {
            $invalid = $invalid -bor ([int]$dataBlock[$index] -bxor [int]$labelHash[$index])
        }
        [int]$separatorIndex = -1
        for ($index = $hashLength; $index -lt $dataBlock.Length; $index += 1) {
            if ($separatorIndex -lt 0) {
                if ($dataBlock[$index] -eq 1) {
                    $separatorIndex = $index
                } elseif ($dataBlock[$index] -ne 0) {
                    $invalid = 1
                }
            }
        }
        if ($separatorIndex -lt 0) {
            $invalid = 1
            $separatorIndex = $dataBlock.Length - 1
        }
        [int]$plaintextLength = $dataBlock.Length - $separatorIndex - 1
        if ($invalid -ne 0 -or $plaintextLength -ne 32) {
            throw 'invalid'
        }
        return ,(Copy-NuwaClmBytes -Source $dataBlock -Offset ($separatorIndex + 1) -Length $plaintextLength)
    } catch {
        throw 'RSA staging response session key decryption failed'
    }
}

function Get-NuwaClmRsaGreatestCommonDivisor {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [bigint]$Left,

        [Parameter(Mandatory = $true)]
        [bigint]$Right
    )

    [bigint]$a = $Left
    [bigint]$b = $Right
    while ($b -ne [bigint]0) {
        [bigint]$remainder = $a % $b
        $a = $b
        $b = $remainder
    }
    if ($a -lt [bigint]0) {
        $a = -$a
    }
    return $a
}

function Get-NuwaClmRsaModularInverse {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [bigint]$Value,

        [Parameter(Mandatory = $true)]
        [bigint]$Modulus
    )

    if ($Modulus -le [bigint]1) {
        throw 'Nuwa CLM RSA key generation failed'
    }
    [bigint]$oldRemainder = $Modulus
    [bigint]$remainder = $Value % $Modulus
    [bigint]$oldCoefficient = 0
    [bigint]$coefficient = 1
    while ($remainder -ne [bigint]0) {
        [bigint]$quotient = $oldRemainder / $remainder
        [bigint]$nextRemainder = $oldRemainder - ($quotient * $remainder)
        $oldRemainder = $remainder
        $remainder = $nextRemainder
        [bigint]$nextCoefficient = $oldCoefficient - ($quotient * $coefficient)
        $oldCoefficient = $coefficient
        $coefficient = $nextCoefficient
    }
    if ($oldRemainder -ne [bigint]1) {
        throw 'Nuwa CLM RSA key generation failed'
    }
    if ($oldCoefficient -lt [bigint]0) {
        $oldCoefficient += $Modulus
    }
    return $oldCoefficient
}

function Get-NuwaClmRsaRandomBigIntegerBelow {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [bigint]$UpperExclusive
    )

    if ($UpperExclusive -le [bigint]1) {
        throw 'Nuwa CLM RSA key generation failed'
    }
    [int]$byteLength = Get-NuwaClmRsaModulusByteLength -Modulus ($UpperExclusive - [bigint]1)
    for ($draw = 0; $draw -lt $script:NuwaClmRsaMaxWitnessDraws; $draw += 1) {
        $candidate = ConvertTo-NuwaClmRsaBigInteger -Bytes (Get-NuwaClmRsaRandomBytes -Length $byteLength)
        if ($candidate -lt $UpperExclusive) {
            return $candidate
        }
    }
    throw 'Nuwa CLM RSA key generation failed'
}

function Test-NuwaClmRsaProbablePrime {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [bigint]$Value
    )

    if ($Value -lt [bigint]2) {
        return $false
    }
    $smallPrimes = [int[]]@(2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47)
    foreach ($prime in $smallPrimes) {
        if ($Value -eq [bigint]$prime) {
            return $true
        }
        if (($Value % [bigint]$prime) -eq [bigint]0) {
            return $false
        }
    }
    [bigint]$oddPart = $Value - [bigint]1
    [int]$powersOfTwo = 0
    while (($oddPart % [bigint]2) -eq [bigint]0) {
        $oddPart /= [bigint]2
        $powersOfTwo += 1
    }
    for ($round = 0; $round -lt $script:NuwaClmRsaMillerRabinRounds; $round += 1) {
        [bigint]$witness = (Get-NuwaClmRsaRandomBigIntegerBelow -UpperExclusive ($Value - [bigint]3)) + [bigint]2
        [bigint]$power = Invoke-NuwaClmRsaModularPower -Representative $witness -Exponent $oddPart -Modulus $Value
        if ($power -eq [bigint]1 -or $power -eq ($Value - [bigint]1)) {
            continue
        }
        [bool]$composite = $true
        for ($index = 1; $index -lt $powersOfTwo; $index += 1) {
            $power = Invoke-NuwaClmRsaModularPower -Representative $power -Exponent ([bigint]2) -Modulus $Value
            if ($power -eq ($Value - [bigint]1)) {
                $composite = $false
                break
            }
        }
        if ($composite) {
            return $false
        }
    }
    return $true
}

function New-NuwaClmRsaProbablePrime {
    [CmdletBinding()]
    param()

    for ($candidateIndex = 0; $candidateIndex -lt $script:NuwaClmRsaMaxPrimeCandidates; $candidateIndex += 1) {
        $candidateBytes = Get-NuwaClmRsaRandomBytes -Length 128
        $candidateBytes[0] = [byte](($candidateBytes[0] -band 63) -bor 192)
        $candidateBytes[$candidateBytes.Length - 1] = [byte]($candidateBytes[$candidateBytes.Length - 1] -bor 1)
        [bigint]$candidate = ConvertTo-NuwaClmRsaBigInteger -Bytes $candidateBytes
        if (Test-NuwaClmRsaProbablePrime -Value $candidate) {
            return $candidate
        }
    }
    throw 'Nuwa CLM RSA key generation failed'
}

function New-NuwaClmRsaKeyPair {
    [CmdletBinding()]
    param()

    [bigint]$publicExponent = 65537
    for ($attempt = 0; $attempt -lt $script:NuwaClmRsaMaxKeyPairAttempts; $attempt += 1) {
        [bigint]$primeP = New-NuwaClmRsaProbablePrime
        [bigint]$primeQ = New-NuwaClmRsaProbablePrime
        if ($primeP -eq $primeQ) {
            continue
        }
        [bigint]$modulus = $primeP * $primeQ
        if ((Get-NuwaClmRsaModulusByteLength -Modulus $modulus) -ne 256) {
            continue
        }
        [bigint]$pMinusOne = $primeP - [bigint]1
        [bigint]$qMinusOne = $primeQ - [bigint]1
        [bigint]$lambda = ($pMinusOne / (Get-NuwaClmRsaGreatestCommonDivisor -Left $pMinusOne -Right $qMinusOne)) * $qMinusOne
        if ((Get-NuwaClmRsaGreatestCommonDivisor -Left $publicExponent -Right $lambda) -ne [bigint]1) {
            continue
        }
        [bigint]$privateExponent = Get-NuwaClmRsaModularInverse -Value $publicExponent -Modulus $lambda
        return @{
            Modulus = $modulus
            PublicExponent = $publicExponent
            PrivateExponent = $privateExponent
        }
    }
    throw 'Nuwa CLM RSA key generation failed'
}

function ConvertTo-NuwaClmDerLength {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [int]$Length
    )

    if ($Length -lt 0 -or $Length -gt 4096) {
        throw 'Nuwa CLM RSA DER encoding failed'
    }
    if ($Length -lt 128) {
        return ,([byte[]]@([byte]$Length))
    }
    [int]$width = 1
    [int]$remaining = $Length
    while ($remaining -gt 255) {
        $width += 1
        $remaining = $remaining -shr 8
    }
    $result = New-NuwaClmByteArray -Length ($width + 1)
    $result[0] = [byte](128 -bor $width)
    for ($index = 0; $index -lt $width; $index += 1) {
        $result[$width - $index] = [byte](($Length -shr ($index * 8)) -band 255)
    }
    return ,$result
}

function ConvertTo-NuwaClmDerPositiveInteger {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [byte[]]$Bytes
    )

    if ($Bytes.Length -eq 0) {
        throw 'Nuwa CLM RSA DER encoding failed'
    }
    [int]$first = 0
    while ($first -lt ($Bytes.Length - 1) -and $Bytes[$first] -eq 0) {
        $first += 1
    }
    [int]$valueLength = $Bytes.Length - $first
    [bool]$leadingZero = ($Bytes[$first] -band 128) -ne 0
    [int]$bodyLength = $valueLength + $(if ($leadingZero) { 1 } else { 0 })
    $lengthBytes = ConvertTo-NuwaClmDerLength -Length $bodyLength
    $result = New-NuwaClmByteArray -Length (1 + $lengthBytes.Length + $bodyLength)
    $result[0] = 2
    for ($index = 0; $index -lt $lengthBytes.Length; $index += 1) {
        $result[1 + $index] = $lengthBytes[$index]
    }
    [int]$offset = 1 + $lengthBytes.Length
    if ($leadingZero) {
        $result[$offset] = 0
        $offset += 1
    }
    for ($index = 0; $index -lt $valueLength; $index += 1) {
        $result[$offset + $index] = $Bytes[$first + $index]
    }
    return ,$result
}

function ConvertTo-NuwaClmRsaPublicKeyDer {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$KeyPair
    )

    $modulus = ConvertFrom-NuwaClmRsaBigInteger -Value ([bigint]$KeyPair.Modulus) -Length 256
    $exponent = ConvertFrom-NuwaClmRsaBigInteger -Value ([bigint]$KeyPair.PublicExponent) -Length 3
    $modulusDer = ConvertTo-NuwaClmDerPositiveInteger -Bytes $modulus
    $exponentDer = ConvertTo-NuwaClmDerPositiveInteger -Bytes $exponent
    $body = Join-NuwaClmBytes -Parts @([object]$modulusDer, [object]$exponentDer)
    $length = ConvertTo-NuwaClmDerLength -Length $body.Length
    return ,(Join-NuwaClmBytes -Parts @([object]([byte[]]@(48)), [object]$length, [object]$body))
}

function ConvertTo-NuwaClmStagingBase64 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [byte[]]$Bytes
    )

    $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
    [string]$output = ''
    for ($offset = 0; $offset -lt $Bytes.Length; $offset += 3) {
        [int]$remaining = $Bytes.Length - $offset
        [int]$one = [int]$Bytes[$offset]
        [int]$two = if ($remaining -gt 1) { [int]$Bytes[$offset + 1] } else { 0 }
        [int]$three = if ($remaining -gt 2) { [int]$Bytes[$offset + 2] } else { 0 }
        $output += $alphabet[($one -shr 2) -band 63]
        $output += $alphabet[(($one -band 3) -shl 4) -bor ($two -shr 4)]
        $output += if ($remaining -gt 1) { $alphabet[(($two -band 15) -shl 2) -bor ($three -shr 6)] } else { '=' }
        $output += if ($remaining -gt 2) { $alphabet[$three -band 63] } else { '=' }
    }
    return $output
}

function Get-NuwaClmStagingBase64Value {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [char]$Character
    )

    [int]$code = [int]$Character
    if ($code -ge 65 -and $code -le 90) { return $code - 65 }
    if ($code -ge 97 -and $code -le 122) { return $code - 71 }
    if ($code -ge 48 -and $code -le 57) { return $code + 4 }
    if ($code -eq 43) { return 62 }
    if ($code -eq 47) { return 63 }
    return -1
}

function ConvertFrom-NuwaClmStagingStrictBase64 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Value
    )

    if ($Value.Length -eq 0 -or ($Value.Length % 4) -ne 0) {
        throw 'RSA staging session key must use strict Base64 encoding'
    }
    [int]$padding = 0
    if ($Value[$Value.Length - 1] -eq '=') { $padding += 1 }
    if ($Value[$Value.Length - 2] -eq '=') { $padding += 1 }
    for ($index = 0; $index -lt ($Value.Length - $padding); $index += 1) {
        if ((Get-NuwaClmStagingBase64Value -Character $Value[$index]) -lt 0) {
            throw 'RSA staging session key must use strict Base64 encoding'
        }
    }
    for ($index = $Value.Length - $padding; $index -lt $Value.Length; $index += 1) {
        if ($Value[$index] -ne '=') {
            throw 'RSA staging session key must use strict Base64 encoding'
        }
    }
    if ($padding -gt 2) {
        throw 'RSA staging session key must use strict Base64 encoding'
    }
    $result = New-NuwaClmByteArray -Length ((($Value.Length / 4) * 3) - $padding)
    [int]$written = 0
    for ($offset = 0; $offset -lt $Value.Length; $offset += 4) {
        [int]$first = Get-NuwaClmStagingBase64Value -Character $Value[$offset]
        [int]$second = Get-NuwaClmStagingBase64Value -Character $Value[$offset + 1]
        [int]$third = if ($Value[$offset + 2] -eq '=') { 0 } else { Get-NuwaClmStagingBase64Value -Character $Value[$offset + 2] }
        [int]$fourth = if ($Value[$offset + 3] -eq '=') { 0 } else { Get-NuwaClmStagingBase64Value -Character $Value[$offset + 3] }
        if ($first -lt 0 -or $second -lt 0 -or $third -lt 0 -or $fourth -lt 0) {
            throw 'RSA staging session key must use strict Base64 encoding'
        }
        $result[$written] = [byte]((($first -shl 2) -bor ($second -shr 4)) -band 255)
        $written += 1
        if ($written -lt $result.Length) {
            $result[$written] = [byte]((($second -shl 4) -bor ($third -shr 2)) -band 255)
            $written += 1
        }
        if ($written -lt $result.Length) {
            $result[$written] = [byte]((($third -shl 6) -bor $fourth) -band 255)
            $written += 1
        }
    }
    if ((ConvertTo-NuwaClmStagingBase64 -Bytes $result) -cne $Value) {
        throw 'RSA staging session key must use strict Base64 encoding'
    }
    return ,$result
}

function ConvertTo-NuwaClmRsaPublicKeyPem {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$KeyPair
    )

    $encoded = ConvertTo-NuwaClmStagingBase64 -Bytes (ConvertTo-NuwaClmRsaPublicKeyDer -KeyPair $KeyPair)
    [string[]]$lines = @('-----BEGIN RSA PUBLIC KEY-----')
    for ($offset = 0; $offset -lt $encoded.Length; $offset += 64) {
        [int]$count = 64
        if (($encoded.Length - $offset) -lt $count) {
            $count = $encoded.Length - $offset
        }
        $lines += $encoded.Substring($offset, $count)
    }
    $lines += '-----END RSA PUBLIC KEY-----'
    return (($lines -join "`n") + "`n")
}

function ConvertTo-NuwaClmStagingPublicKey {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$KeyPair
    )

    $pem = ConvertTo-NuwaClmRsaPublicKeyPem -KeyPair $KeyPair
    return ConvertTo-NuwaClmStagingBase64 -Bytes (ConvertTo-NuwaUtf8Bytes -Value $pem)
}

function New-NuwaClmStagingSessionId {
    [CmdletBinding()]
    param()

    $bytes = Get-NuwaClmRsaRandomBytes -Length 20
    [string]$result = ''
    for ($index = 0; $index -lt $bytes.Length; $index += 1) {
        $result += $bytes[$index].ToString('x2')
    }
    return $result
}

function Test-NuwaClmStagingStringEqual {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Left,

        [Parameter(Mandatory = $true)]
        [string]$Right
    )

    [int]$difference = $Left.Length -bxor $Right.Length
    [int]$count = $Left.Length
    if ($Right.Length -gt $count) {
        $count = $Right.Length
    }
    for ($index = 0; $index -lt $count; $index += 1) {
        [int]$leftValue = if ($index -lt $Left.Length) { [int][char]$Left[$index] } else { 0 }
        [int]$rightValue = if ($index -lt $Right.Length) { [int][char]$Right[$index] } else { 0 }
        $difference = $difference -bor ($leftValue -bxor $rightValue)
    }
    return $difference -eq 0
}

function Resolve-NuwaClmRsaStagingResponse {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Response,

        [Parameter(Mandatory = $true)]
        [string]$ExpectedSessionId,

        [Parameter(Mandatory = $true)]
        [hashtable]$KeyPair
    )

    if ([string]$Response.action -cne 'staging_rsa') {
        throw 'RSA staging response action did not match'
    }
    if (-not (Test-NuwaClmStagingStringEqual -Left ([string]$Response.session_id) -Right $ExpectedSessionId)) {
        throw 'RSA staging response session identifier did not match'
    }
    $uuidText = [string]$Response.uuid
    if ($uuidText -cnotmatch '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$') {
        throw 'RSA staging response UUID was not canonical'
    }
    if ($uuidText.ToLowerInvariant() -ceq ([string]$script:NuwaConfig.PayloadUUID).ToLowerInvariant()) {
        throw 'RSA staging response UUID must differ from the payload UUID'
    }
    $ciphertext = ConvertFrom-NuwaClmStagingStrictBase64 -Value ([string]$Response.session_key)
    $candidateKey = Unprotect-NuwaClmRsaOaepSha1 -Ciphertext $ciphertext `
        -PrivateExponent ([bigint]$KeyPair.PrivateExponent) -Modulus ([bigint]$KeyPair.Modulus)
    if ($candidateKey.Length -ne 32) {
        throw 'RSA staging response session key decryption failed'
    }
    return @{
        OuterUuid = $uuidText
        Key = [byte[]]$candidateKey
    }
}

function Invoke-NuwaRsaStaging {
    [CmdletBinding()]
    param()

    [int]$retryDelaySeconds = [int]$script:NuwaConfig.CallbackInterval
    if ($retryDelaySeconds -lt 1) {
        $retryDelaySeconds = 1
    }
    for ($attempt = 1; $attempt -le 3; $attempt += 1) {
        $keyPair = $null
        $candidateState = $null
        try {
            Write-NuwaDebug ("Starting RSA staging attempt {0}/3" -f $attempt)
            $keyPair = New-NuwaClmRsaKeyPair
            $publicKey = ConvertTo-NuwaClmStagingPublicKey -KeyPair $keyPair
            $sessionId = New-NuwaClmStagingSessionId
            $response = Invoke-NuwaSendMessage -Uuid $script:NuwaCryptoState.OuterUuid `
                -Action 'staging_rsa' -Body @{ pub_key = $publicKey; session_id = $sessionId }
            if ($null -eq $response) {
                throw 'RSA staging returned no response'
            }
            $candidateState = Resolve-NuwaClmRsaStagingResponse -Response $response `
                -ExpectedSessionId $sessionId -KeyPair $keyPair
        } catch {
            Write-NuwaDebug ("RSA staging attempt {0}/3 failed" -f $attempt)
        } finally {
            $publicKey = $null
            $sessionId = $null
            $response = $null
            $keyPair = $null
        }
        if ($null -ne $candidateState) {
            Write-NuwaDebug 'RSA staging succeeded'
            $script:NuwaCryptoState = $candidateState
            return
        }
        if ($attempt -lt 3) {
            Start-Sleep -Seconds $retryDelaySeconds
        }
    }
    throw 'RSA staging failed after 3 attempts'
}
