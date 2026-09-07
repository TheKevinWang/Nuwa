function Get-NuwaTransportSha256 {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)
    $algorithm = $null
    try {
        $algorithm = [System.Security.Cryptography.SHA256]::Create()
        return ,([byte[]]$algorithm.ComputeHash($Bytes))
    } finally { if ($null -ne $algorithm) { $algorithm.Dispose() } }
}

function Get-NuwaTransportDirectionKey {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Direction)
    if ($Direction -notin @('agent-to-server', 'server-to-agent')) { throw 'Transport direction is invalid' }
    $label = [byte[]](ConvertTo-NuwaUtf8Bytes -Value $Direction)
    $inputBytes = Join-NuwaTransportBytes -Parts @([object](Get-NuwaTransportMasterKey), [object]([byte[]]@(0)), [object]$label)
    return ,(Get-NuwaTransportSha256 -Bytes $inputBytes)
}
