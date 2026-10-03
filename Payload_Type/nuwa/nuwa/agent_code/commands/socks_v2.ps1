function Invoke-NuwaSocks {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$Parameters)

    $action = $Parameters.action
    $port = [int]$Parameters.port
    Write-NuwaDebug ('SOCKS command entered action={0} port={1}' -f $action, $port)
    if ($port -lt 1 -or $port -gt 65535) {
        throw (New-NuwaDiagnosticOutput -Code 1087)
    }
    if ($action -eq $script:NuwaV_start) {
        Write-NuwaDebug 'SOCKS command starting runtime'
        Start-NuwaSocksRuntime -Port $port
        Write-NuwaDebug 'SOCKS command runtime started'
        return ,(New-NuwaDiagnosticOutput -Code 1089 -Arguments @($port))
    }
    if ($action -eq $script:NuwaV_stop) {
        Stop-NuwaSocksRuntime -Port $port
        return ,(New-NuwaDiagnosticOutput -Code 1090 -Arguments @($port))
    }
    throw (New-NuwaDiagnosticOutput -Code 1088)
}
