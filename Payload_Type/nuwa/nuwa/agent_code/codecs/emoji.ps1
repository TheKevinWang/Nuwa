$script:NuwaEmojiAlphabet = @(
    "$([char]0xD83D)$([char]0xDE01)",
    "$([char]0xD83D)$([char]0xDE02)",
    "$([char]0xD83D)$([char]0xDE05)",
    "$([char]0xD83D)$([char]0xDE33)",
    "$([char]0xD83E)$([char]0xDD7A)",
    "$([char]0xD83D)$([char]0xDE44)",
    "$([char]0xD83E)$([char]0xDD17)",
    "$([char]0xD83D)$([char]0xDE2B)",
    "$([char]0xD83E)$([char]0xDD70)",
    "$([char]0xD83D)$([char]0xDE0F)",
    "$([char]0xD83E)$([char]0xDD2D)",
    "$([char]0xD83D)$([char]0xDE09)",
    "$([char]0xD83D)$([char]0xDE03)",
    "$([char]0xD83D)$([char]0xDE28)",
    "$([char]0xD83D)$([char]0xDE30)",
    "$([char]0xD83E)$([char]0xDD11)"
)

function ConvertTo-NuwaEmojiBytes {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [byte[]]$Bytes,

        [Parameter(Mandatory = $true)]
        [hashtable]$Context
    )

    $tokens = [string[]]::new($Bytes.Length * 2)
    $tokenIndex = 0
    for ($index = 0; $index -lt $Bytes.Length; $index += 1) {
        $value = [int]$Bytes[$index]
        $tokens[$tokenIndex] = [string]$script:NuwaEmojiAlphabet[($value -shr 4) -band 0x0F]
        $tokens[$tokenIndex + 1] = [string]$script:NuwaEmojiAlphabet[$value -band 0x0F]
        $tokenIndex += 2
    }

    return ConvertTo-NuwaUtf8Bytes -Value (-join $tokens)
}

function ConvertFrom-NuwaEmojiBytes {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [byte[]]$Bytes,

        [Parameter(Mandatory = $true)]
        [hashtable]$Context
    )

    $payload = ConvertFrom-NuwaUtf8Bytes -Bytes $Bytes
    $nibbles = [int[]]::new($payload.Length)
    $nibbleCount = 0
    $cursor = 0
    while ($cursor -lt $payload.Length) {
        $matched = $false
        for ($nibble = 0; $nibble -lt $script:NuwaEmojiAlphabet.Length; $nibble += 1) {
            $token = [string]$script:NuwaEmojiAlphabet[$nibble]
            if (
                ($cursor + $token.Length) -le $payload.Length -and
                [string]::Equals(
                    $payload.Substring($cursor, $token.Length),
                    $token,
                    [System.StringComparison]::Ordinal
                )
            ) {
                $nibbles[$nibbleCount] = $nibble
                $nibbleCount += 1
                $cursor += $token.Length
                $matched = $true
                break
            }
        }

        if (-not $matched) {
            throw 'Emoji payload contains a noncanonical token'
        }
    }

    if (($nibbleCount % 2) -ne 0) {
        throw 'Emoji payload must contain an even number of tokens'
    }

    $decoded = [byte[]]::new($nibbleCount / 2)
    for ($index = 0; $index -lt $nibbleCount; $index += 2) {
        $decoded[$index / 2] = ($nibbles[$index] -shl 4) -bor $nibbles[$index + 1]
    }

    return $decoded
}
