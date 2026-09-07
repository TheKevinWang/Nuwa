function Get-NuwaTransportDirectionKey {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Direction)
    if ($Direction -notin @('agent-to-server', 'server-to-agent')) { throw 'Transport direction is invalid' }
    return ,(Get-NuwaTransportMasterKey)
}
