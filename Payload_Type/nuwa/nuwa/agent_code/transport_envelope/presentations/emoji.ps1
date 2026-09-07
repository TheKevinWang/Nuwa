$script:NuwaTransportEmojiAlphabet = @(
    "$([char]0xD83D)$([char]0xDE01)", "$([char]0xD83D)$([char]0xDE02)",
    "$([char]0xD83D)$([char]0xDE05)", "$([char]0xD83D)$([char]0xDE33)",
    "$([char]0xD83E)$([char]0xDD7A)", "$([char]0xD83D)$([char]0xDE44)",
    "$([char]0xD83E)$([char]0xDD17)", "$([char]0xD83D)$([char]0xDE2B)",
    "$([char]0xD83E)$([char]0xDD70)", "$([char]0xD83D)$([char]0xDE0F)",
    "$([char]0xD83E)$([char]0xDD2D)", "$([char]0xD83D)$([char]0xDE09)",
    "$([char]0xD83D)$([char]0xDE03)", "$([char]0xD83D)$([char]0xDE28)",
    "$([char]0xD83D)$([char]0xDE30)", "$([char]0xD83E)$([char]0xDD11)"
)
$script:NuwaTransportEmojiDecode = @{}
for ($index = 0; $index -lt $script:NuwaTransportEmojiAlphabet.Length; $index += 1) {
    $token = [string]$script:NuwaTransportEmojiAlphabet[$index]
    $key = (([int][char]$token[0]) -shl 16) -bor ([int][char]$token[1])
    $script:NuwaTransportEmojiDecode[$key] = $index
}

function ConvertTo-NuwaTransportPresentation {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][byte[]]$Bytes)
    $tokens = New-Object string[] ($Bytes.Length * 2)
    $output = 0
    for ($index = 0; $index -lt $Bytes.Length; $index += 1) {
        $tokens[$output] = $script:NuwaTransportEmojiAlphabet[([int]$Bytes[$index] -shr 4) -band 15]
        $tokens[$output + 1] = $script:NuwaTransportEmojiAlphabet[[int]$Bytes[$index] -band 15]
        $output += 2
    }
    return (-join $tokens)
}

function ConvertFrom-NuwaTransportPresentation {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Value)
    if (($Value.Length % 4) -ne 0) { throw 'Transport emoji length is invalid' }
    $bytes = New-Object byte[] ([int]($Value.Length / 4))
    for ($index = 0; $index -lt $bytes.Length; $index += 1) {
        $cursor = $index * 4
        $key = (([int][char]$Value[$cursor]) -shl 16) -bor ([int][char]$Value[$cursor + 1])
        if (-not $script:NuwaTransportEmojiDecode.ContainsKey($key)) { throw 'Transport emoji token is invalid' }
        $high = [int]$script:NuwaTransportEmojiDecode[$key]
        $key = (([int][char]$Value[$cursor + 2]) -shl 16) -bor ([int][char]$Value[$cursor + 3])
        if (-not $script:NuwaTransportEmojiDecode.ContainsKey($key)) { throw 'Transport emoji token is invalid' }
        $low = [int]$script:NuwaTransportEmojiDecode[$key]
        $bytes[$index] = [byte](($high -shl 4) -bor $low)
    }
    return ,$bytes
}
