function ConvertTo-NuwaUtf8Bytes {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Value
    )

    $allAscii = $true
    for ($asciiIndex = 0; $asciiIndex -lt $Value.Length; $asciiIndex += 1) {
        if ([int][char]$Value[$asciiIndex] -gt 0x7F) {
            $allAscii = $false
            break
        }
    }

    if ($allAscii) {
        $asciiBytes = [byte[]]::new($Value.Length)
        for ($asciiIndex = 0; $asciiIndex -lt $Value.Length; $asciiIndex += 1) {
            $asciiBytes[$asciiIndex] = [byte][char]$Value[$asciiIndex]
        }
        return $asciiBytes
    }

    $bytes = @()
    $index = 0
    while ($index -lt $Value.Length) {
        $codePoint = [int][char]$Value[$index]
        if ($codePoint -ge 0xD800 -and $codePoint -le 0xDBFF) {
            if ($index + 1 -ge $Value.Length) {
                throw "Incomplete surrogate pair in UTF-16 input"
            }

            $lowSurrogate = [int][char]$Value[$index + 1]
            if ($lowSurrogate -lt 0xDC00 -or $lowSurrogate -gt 0xDFFF) {
                throw "Invalid surrogate pair in UTF-16 input"
            }

            $codePoint = 0x10000 + (($codePoint - 0xD800) * 0x400) + ($lowSurrogate - 0xDC00)
            $index += 1
        } elseif ($codePoint -ge 0xDC00 -and $codePoint -le 0xDFFF) {
            throw "Unexpected low surrogate in UTF-16 input"
        }

        if ($codePoint -le 0x7F) {
            $bytes += $codePoint
        } elseif ($codePoint -le 0x7FF) {
            $bytes += (0xC0 -bor ($codePoint -shr 6))
            $bytes += (0x80 -bor ($codePoint -band 0x3F))
        } elseif ($codePoint -le 0xFFFF) {
            $bytes += (0xE0 -bor ($codePoint -shr 12))
            $bytes += (0x80 -bor (($codePoint -shr 6) -band 0x3F))
            $bytes += (0x80 -bor ($codePoint -band 0x3F))
        } elseif ($codePoint -le 0x10FFFF) {
            $bytes += (0xF0 -bor ($codePoint -shr 18))
            $bytes += (0x80 -bor (($codePoint -shr 12) -band 0x3F))
            $bytes += (0x80 -bor (($codePoint -shr 6) -band 0x3F))
            $bytes += (0x80 -bor ($codePoint -band 0x3F))
        } else {
            throw "Unicode code point outside UTF-8 range"
        }

        $index += 1
    }

    return [byte[]]$bytes
}

function ConvertFrom-NuwaUtf8Bytes {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [byte[]]$Bytes
    )

    $allAscii = $true
    for ($asciiIndex = 0; $asciiIndex -lt $Bytes.Length; $asciiIndex += 1) {
        if ($Bytes[$asciiIndex] -gt 0x7F) {
            $allAscii = $false
            break
        }
    }

    if ($allAscii) {
        $asciiCharacters = [char[]]::new($Bytes.Length)
        for ($asciiIndex = 0; $asciiIndex -lt $Bytes.Length; $asciiIndex += 1) {
            $asciiCharacters[$asciiIndex] = [char]$Bytes[$asciiIndex]
        }
        return (-join $asciiCharacters)
    }

    $characters = @()
    $index = 0
    while ($index -lt $Bytes.Length) {
        $first = [int]$Bytes[$index]

        if ($first -le 0x7F) {
            $codePoint = $first
            $width = 1
        } elseif ($first -ge 0xC2 -and $first -le 0xDF) {
            $width = 2
            if ($index + $width -gt $Bytes.Length) {
                throw "Truncated UTF-8 sequence"
            }

            $second = [int]$Bytes[$index + 1]
            if ($second -lt 0x80 -or $second -gt 0xBF) {
                throw "Invalid UTF-8 continuation byte"
            }

            $codePoint = (($first -band 0x1F) -shl 6) -bor ($second -band 0x3F)
        } elseif ($first -ge 0xE0 -and $first -le 0xEF) {
            $width = 3
            if ($index + $width -gt $Bytes.Length) {
                throw "Truncated UTF-8 sequence"
            }

            $second = [int]$Bytes[$index + 1]
            $third = [int]$Bytes[$index + 2]
            if ($second -lt 0x80 -or $second -gt 0xBF -or $third -lt 0x80 -or $third -gt 0xBF) {
                throw "Invalid UTF-8 continuation byte"
            }

            $codePoint = (($first -band 0x0F) -shl 12) -bor (($second -band 0x3F) -shl 6) -bor ($third -band 0x3F)
            if ($codePoint -lt 0x800 -or ($codePoint -ge 0xD800 -and $codePoint -le 0xDFFF)) {
                throw "Invalid UTF-8 code point"
            }
        } elseif ($first -ge 0xF0 -and $first -le 0xF4) {
            $width = 4
            if ($index + $width -gt $Bytes.Length) {
                throw "Truncated UTF-8 sequence"
            }

            $second = [int]$Bytes[$index + 1]
            $third = [int]$Bytes[$index + 2]
            $fourth = [int]$Bytes[$index + 3]
            if (
                $second -lt 0x80 -or $second -gt 0xBF -or
                $third -lt 0x80 -or $third -gt 0xBF -or
                $fourth -lt 0x80 -or $fourth -gt 0xBF
            ) {
                throw "Invalid UTF-8 continuation byte"
            }

            $codePoint = (($first -band 0x07) -shl 18) -bor (($second -band 0x3F) -shl 12) -bor (($third -band 0x3F) -shl 6) -bor ($fourth -band 0x3F)
            if ($codePoint -lt 0x10000 -or $codePoint -gt 0x10FFFF) {
                throw "Invalid UTF-8 code point"
            }
        } else {
            throw "Invalid UTF-8 leading byte"
        }

        if ($codePoint -le 0xFFFF) {
            $characters += [string][char]$codePoint
        } else {
            $surrogateValue = $codePoint - 0x10000
            $high = 0xD800 + ($surrogateValue -shr 10)
            $low = 0xDC00 + ($surrogateValue -band 0x3FF)
            $characters += [string][char]$high
            $characters += [string][char]$low
        }

        $index += $width
    }

    return ($characters -join '')
}
