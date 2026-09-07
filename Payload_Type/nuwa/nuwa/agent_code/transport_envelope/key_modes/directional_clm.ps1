function Get-NuwaTransportDirectionKey {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Direction)
    if ($Direction -notin @('agent-to-server', 'server-to-agent')) { throw 'Transport direction is invalid' }
    $label = [byte[]](ConvertTo-NuwaUtf8Bytes -Value $Direction)
    $inputBytes = Join-NuwaTransportBytes -Parts @([object](Get-NuwaTransportMasterKey), [object]([byte[]]@(0)), [object]$label)
    return ,(Get-NuwaClmSha256Digest -Bytes $inputBytes)
}
