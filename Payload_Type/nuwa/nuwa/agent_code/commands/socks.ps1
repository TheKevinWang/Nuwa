function Invoke-NuwaSocks {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$Parameters)

    $action = [string]$Parameters.action
    $port = [int]$Parameters.port
    Write-NuwaDebug ('SOCKS command entered action={0} port={1}' -f $action, $port)
    if ($port -lt 1 -or $port -gt 65535) {
        throw 'SOCKS port must be between 1 and 65535'
    }
    if ($action -eq 'start') {
        Write-NuwaDebug 'SOCKS command starting runtime'
        Start-NuwaSocksRuntime -Port $port
        Write-NuwaDebug 'SOCKS command runtime started'
        return ('SOCKS5 Gateway ready for Mythic port {0}' -f $port)
    }
    if ($action -eq 'stop') {
        Stop-NuwaSocksRuntime -Port $port
        return ('SOCKS5 Gateway stopped for Mythic port {0}' -f $port)
    }
    throw 'SOCKS action must be start or stop'
}
