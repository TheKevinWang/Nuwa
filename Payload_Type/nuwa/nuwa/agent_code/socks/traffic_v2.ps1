function Add-NuwaSocksOutboundRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][hashtable]$Worker,
        [Parameter(Mandatory = $true)][uint32]$ServerId,
        [Parameter(Mandatory = $true)][int]$Port,
        [Parameter(Mandatory = $false)][byte[]]$Data = @(),
        [Parameter(Mandatory = $false)][bool]$Exit = $false
    )

    $queuedBytes = 0
    foreach ($item in $Worker.Outbound) { $queuedBytes += ([byte[]]$item[$script:NuwaF_data]).Length }
    if ($Data.Length -gt 49152 -or $queuedBytes + $Data.Length -gt 524288 -or
        $Worker.Outbound.Count -ge 512) {
        throw 'SOCKS outbound queue is full'
    }
    if ($Worker.Outbound.Count -eq 0) {
        $Worker.FirstOutboundAt = [DateTimeOffset]::UtcNow
    }
    $Worker.LastOutboundAt = [DateTimeOffset]::UtcNow
    $record = @{}
    $record[$script:NuwaF_server_id] = [uint64]$ServerId
    $record[$script:NuwaF_port] = $Port
    $record[$script:NuwaF_data] = [byte[]]$Data
    $record[$script:NuwaF_exit] = $Exit
    $Worker.Outbound.Add($record)
}

function Close-NuwaSocksConnection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][hashtable]$Worker,
        [Parameter(Mandatory = $true)][uint32]$ServerId,
        [Parameter(Mandatory = $false)][bool]$ReportExit = $true
    )

    $key = [string]$ServerId
    if (-not $Worker.Connections.ContainsKey($key)) { return }
    $connection = $Worker.Connections[$key]
    try { if ($null -ne $connection.Client) { $connection.Client.Dispose() } } catch { }
    [void]$Worker.Connections.Remove($key)
    if ($ReportExit) {
        try {
            Add-NuwaSocksOutboundRecord -Worker $Worker -ServerId $ServerId `
                -Port ([int]$connection.Port) -Exit $true
        } catch {
            Write-NuwaDebug ('SOCKS close report failed for {0}: {1}' -f $ServerId, $_.Exception.Message)
        }
    }
}

function Close-NuwaSocksAllConnections {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$Worker)

    foreach ($key in @($Worker.Connections.Keys)) {
        Close-NuwaSocksConnection -Worker $Worker -ServerId ([uint32]$key)
    }
}

function Add-NuwaSocksServerRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][hashtable]$Worker,
        [Parameter(Mandatory = $true)][object]$Record
    )

    [uint32]$serverId = [uint32]$Record[$script:NuwaF_server_id]
    $key = [string]$serverId
    $port = [int]$Record[$script:NuwaF_port]
    [byte[]]$data = if ($null -ne $Record[$script:NuwaF_data]) { [byte[]]$Record[$script:NuwaF_data] } else { [byte[]]@() }
    $remoteExit = ($Record[$script:NuwaF_exit] -eq $true)
    if ($Worker.Connections.ContainsKey($key)) {
        $connection = $Worker.Connections[$key]
        if ($port -ne 0 -and $port -ne $connection.Port) {
            throw 'SOCKS server_id changed listener port'
        }
    } else {
        if ($remoteExit) { return }
        if (-not $Worker.Shared.Ports.ContainsKey($port)) {
            throw 'SOCKS record names an inactive listener port'
        }
        if ($Worker.Connections.Count -ge 64) {
            throw 'SOCKS connection limit reached'
        }
        $connection = @{
            ServerId = $serverId
            Port = $port
            State = 'request'
            Initial = [System.Collections.Generic.List[byte]]::new()
            Client = $null
            Stream = $null
            ConnectTask = $null
            ReadTask = $null
            ReadBuffer = [byte[]]::new(16384)
            WriteTask = $null
            WriteQueue = [System.Collections.Generic.Queue[byte[]]]::new()
            BufferedBytes = 0
            LastActivity = [DateTimeOffset]::UtcNow
        }
        $Worker.Connections[$key] = $connection
    }
    $connection.LastActivity = [DateTimeOffset]::UtcNow
    if ($remoteExit) {
        Close-NuwaSocksConnection -Worker $Worker -ServerId $serverId -ReportExit $false
        return
    }
    if ($data.Length -eq 0) { return }

    if ($connection.State -eq 'request') {
        if ($connection.Initial.Count + $data.Length -gt 65536) {
            Close-NuwaSocksConnection -Worker $Worker -ServerId $serverId
            throw 'SOCKS initial request exceeded limit'
        }
        $connection.Initial.AddRange($data)
        $request = Read-NuwaSocksConnectRequest -Bytes $connection.Initial.ToArray()
        if (-not $request.Complete) { return }
        if ([int]$request.ReplyCode -ne 0) {
            Add-NuwaSocksOutboundRecord -Worker $Worker -ServerId $serverId -Port $port `
                -Data (New-NuwaSocksReplyBytes -ReplyCode ([byte]$request.ReplyCode))
            Close-NuwaSocksConnection -Worker $Worker -ServerId $serverId
            return
        }
        try {
            $connection.Client = [System.Net.Sockets.TcpClient]::new()
            $connection.State = 'connecting'
            $connection.ConnectStartedAt = [DateTimeOffset]::UtcNow
            $connection.ConnectTask = $connection.Client.ConnectAsync([string]$request.Host, [int]$request.Port)
        } catch {
            Add-NuwaSocksOutboundRecord -Worker $Worker -ServerId $serverId -Port $port `
                -Data (New-NuwaSocksReplyBytes -ReplyCode 4)
            Close-NuwaSocksConnection -Worker $Worker -ServerId $serverId
            return
        }
        if ($connection.Initial.Count -gt [int]$request.Consumed) {
            $initial = [byte[]]$connection.Initial.ToArray()
            [byte[]]$remaining = [byte[]]::new($initial.Length - [int]$request.Consumed)
            [Array]::Copy($initial, [int]$request.Consumed, $remaining, 0, $remaining.Length)
            $connection.WriteQueue.Enqueue($remaining)
            $connection.BufferedBytes += $remaining.Length
        }
        $connection.Initial.Clear()
        return
    }
    if ($connection.BufferedBytes + $data.Length -gt 524288) {
        Close-NuwaSocksConnection -Worker $Worker -ServerId $serverId
        throw 'SOCKS destination write queue is full'
    }
    $connection.WriteQueue.Enqueue($data)
    $connection.BufferedBytes += $data.Length
}

function Update-NuwaSocksConnections {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$Worker)

    $now = [DateTimeOffset]::UtcNow
    foreach ($key in @($Worker.Connections.Keys)) {
        if (-not $Worker.Connections.ContainsKey($key)) { continue }
        $connection = $Worker.Connections[$key]
        [uint32]$serverId = [uint32]$connection.ServerId
        if (-not $Worker.Shared.Ports.ContainsKey([int]$connection.Port) -or
            $now - $connection.LastActivity -gt [TimeSpan]::FromMinutes(5)) {
            Close-NuwaSocksConnection -Worker $Worker -ServerId $serverId
            continue
        }
        if ($connection.State -eq 'connecting') {
            if ($now - $connection.ConnectStartedAt -gt [TimeSpan]::FromSeconds(10)) {
                Add-NuwaSocksOutboundRecord -Worker $Worker -ServerId $serverId -Port $connection.Port `
                    -Data (New-NuwaSocksReplyBytes -ReplyCode 4)
                Close-NuwaSocksConnection -Worker $Worker -ServerId $serverId
                continue
            }
            if (-not $connection.ConnectTask.IsCompleted) { continue }
            try {
                $connection.ConnectTask.GetAwaiter().GetResult()
                $connection.Stream = $connection.Client.GetStream()
                $connection.State = 'connected'
                Add-NuwaSocksOutboundRecord -Worker $Worker -ServerId $serverId -Port $connection.Port `
                    -Data (New-NuwaSocksReplyBytes -ReplyCode 0 `
                        -BoundEndpoint $connection.Client.Client.LocalEndPoint)
            } catch {
                Add-NuwaSocksOutboundRecord -Worker $Worker -ServerId $serverId -Port $connection.Port `
                    -Data (New-NuwaSocksReplyBytes -ReplyCode 5)
                Close-NuwaSocksConnection -Worker $Worker -ServerId $serverId
                continue
            }
        }
        if ($connection.State -ne 'connected') { continue }
        try {
            if ($null -ne $connection.WriteTask -and $connection.WriteTask.IsCompleted) {
                $connection.WriteTask.GetAwaiter().GetResult()
                $sent = $connection.WriteQueue.Dequeue()
                $connection.BufferedBytes -= $sent.Length
                $connection.WriteTask = $null
                $connection.LastActivity = $now
            }
            if ($null -eq $connection.WriteTask -and $connection.WriteQueue.Count -gt 0) {
                [byte[]]$next = $connection.WriteQueue.Peek()
                $connection.WriteTask = $connection.Stream.WriteAsync($next, 0, $next.Length)
            }
            if ($null -ne $connection.ReadTask -and $connection.ReadTask.IsCompleted) {
                $length = [int]$connection.ReadTask.GetAwaiter().GetResult()
                $connection.ReadTask = $null
                if ($length -eq 0) {
                    Close-NuwaSocksConnection -Worker $Worker -ServerId $serverId
                    continue
                }
                [byte[]]$received = [byte[]]::new($length)
                [Array]::Copy($connection.ReadBuffer, 0, $received, 0, $length)
                Add-NuwaSocksOutboundRecord -Worker $Worker -ServerId $serverId -Port $connection.Port `
                    -Data $received
                $connection.LastActivity = $now
            }
            if ($null -eq $connection.ReadTask) {
                $connection.ReadTask = $connection.Stream.ReadAsync(
                    $connection.ReadBuffer, 0, $connection.ReadBuffer.Length)
            }
        } catch {
            Close-NuwaSocksConnection -Worker $Worker -ServerId $serverId
        }
    }
}

function ConvertFrom-NuwaSocksServerFrame {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][object]$Parsed)

    $callbackUuid = [string]$script:NuwaState.CallbackUUID
    $targetUuid = [string](Get-NuwaDiscordObjectProperty -Object $Parsed -Name 'client_id')
    if ($targetUuid -ne $callbackUuid) { return $null }
    [byte[]]$frame = [byte[]](Get-NuwaDiscordObjectProperty -Object $Parsed -Name 'message')
    if ($frame.Length -le 36) { return $null }
    if ([System.Text.Encoding]::ASCII.GetString($frame, 0, 36) -ne $callbackUuid) { return $null }
    [byte[]]$inner = [byte[]]$frame[36..($frame.Length - 1)]
    if ($script:NuwaConfig.ProtectionProfile -and
        [string]$script:NuwaConfig.ProtectionProfile -ne 'none') {
        $inner = [byte[]](Unprotect-NuwaBytes -Bytes $inner -Context @{})
    }
    return ConvertFrom-NuwaBinaryV2Bytes -Bytes $inner
}

function Invoke-NuwaSocksInboundMessage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][object]$Message,
        [Parameter(Mandatory = $true)][hashtable]$Worker
    )

    $channelId = [string](Get-NuwaDiscordObjectProperty -Object $Message -Name 'channel_id')
    $messageId = [string](Get-NuwaDiscordObjectProperty -Object $Message -Name 'id')
    $author = Get-NuwaDiscordObjectProperty -Object $Message -Name 'author'
    $authorId = [string](Get-NuwaDiscordObjectProperty -Object $author -Name 'id')
    if ($channelId -ne [string]$script:NuwaConfig.SocksChannel -or
        $authorId -ne [string]$Worker.BotId -or -not $messageId) { return }
    if ($Worker.SeenMessages.Contains($messageId)) { return }
    $numericMessageId = ConvertTo-NuwaDiscordUnsignedDecimal -Value $messageId
    if ($null -eq $numericMessageId) { return }
    $parsed = ConvertFrom-NuwaDiscordMessage -Message $Message
    if ($null -eq $parsed) { return }
    if ($parsed.to_server) {
        [void]$Worker.SeenMessages.Add($messageId)
        $Worker.SeenMessageOrder.Enqueue($messageId)
        if ($Worker.SeenMessageOrder.Count -gt 4096) {
            $old = $Worker.SeenMessageOrder.Dequeue()
            [void]$Worker.SeenMessages.Remove($old)
        }
        return
    }
    $body = ConvertFrom-NuwaSocksServerFrame -Parsed $parsed
    if ($null -eq $body -or [int]$body[$script:NuwaF_action] -ne $script:NuwaA_post_response) { return }

    if ($body.ContainsKey($script:NuwaF_socks_ack)) {
        foreach ($ack in @($body[$script:NuwaF_socks_ack])) {
            if ($ack -isnot [byte[]] -or $ack.Length -ne 16) { throw 'Malformed SOCKS acknowledgment' }
            $ackHex = [BitConverter]::ToString([byte[]]$ack).Replace('-', '')
            if ($null -ne $Worker.Pending -and $Worker.Pending.Id -eq $ackHex) {
                $Worker.Pending = $null
            }
        }
    }

    if ($null -ne $body[$script:NuwaF_socks_batch_id]) {
        [byte[]]$batchId = [byte[]]$body[$script:NuwaF_socks_batch_id]
        if ($batchId.Length -ne 16) { throw 'Malformed SOCKS batch ID' }
        $batchHex = [BitConverter]::ToString($batchId).Replace('-', '')
        if ($Worker.FailedBatchIds.Contains($batchHex)) { return }
        if (-not $Worker.SeenBatchIds.Contains($batchHex)) {
            if ($numericMessageId -lt $Worker.LastMessageId) {
                throw 'Unseen SOCKS batch fell outside the ordered recovery window'
            }
            $records = @($body[$script:NuwaF_socks])
            if ($records.Count -eq 0 -or $records.Count -gt 64) { throw 'SOCKS batch record count is invalid' }
            $total = 0
            foreach ($record in $records) {
                $total += ([byte[]]$record[$script:NuwaF_data]).Length
                if ($total -gt 49152) { throw 'SOCKS batch exceeds data ceiling' }
                $port = [int]$record[$script:NuwaF_port]
                if ($port -ne 0 -and -not $Worker.Shared.Ports.ContainsKey($port)) {
                    throw 'SOCKS batch names an inactive listener port'
                }
            }
            [void]$Worker.SeenBatchIds.Add($batchHex)
            $Worker.SeenBatchOrder.Enqueue($batchHex)
            try {
                foreach ($record in $records) {
                    Add-NuwaSocksServerRecord -Worker $Worker -Record $record
                }
            } catch {
                [void]$Worker.FailedBatchIds.Add($batchHex)
                foreach ($record in $records) {
                    Close-NuwaSocksConnection -Worker $Worker -ServerId ([uint32]$record[$script:NuwaF_server_id])
                }
                Write-NuwaDebug ('SOCKS batch retained after affected connections closed: {0}' -f $_.Exception.Message)
                return
            }
            if ($Worker.SeenBatchOrder.Count -gt 4096) {
                $old = $Worker.SeenBatchOrder.Dequeue()
                [void]$Worker.SeenBatchIds.Remove($old)
            }
        }
    }
    [void]$Worker.SeenMessages.Add($messageId)
    $Worker.SeenMessageOrder.Enqueue($messageId)
    if ($numericMessageId -gt $Worker.LastMessageId) {
        $Worker.LastMessageId = $numericMessageId
    }
    if ($Worker.SeenMessageOrder.Count -gt 4096) {
        $old = $Worker.SeenMessageOrder.Dequeue()
        [void]$Worker.SeenMessages.Remove($old)
    }
    if ($Worker.Cleanup.Count -ge 1024) { throw 'SOCKS cleanup queue is full' }
    $Worker.Cleanup.Add($messageId)
    $timestamp = Get-NuwaDiscordObjectProperty -Object $Message -Name 'timestamp'
    try {
        $Worker.CleanupTimestamps[$messageId] = [DateTimeOffset]::Parse([string]$timestamp)
    } catch {
        $Worker.CleanupTimestamps[$messageId] = [DateTimeOffset]::MinValue
    }
}

function Update-NuwaSocksWorker {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$Worker)

    Update-NuwaSocksConnections -Worker $Worker
    Update-NuwaSocksOutbound -Worker $Worker
    Update-NuwaSocksCleanup -Worker $Worker
}
