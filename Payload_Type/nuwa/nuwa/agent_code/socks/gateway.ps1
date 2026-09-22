function New-NuwaSocksHttpClient {
    [CmdletBinding()]
    param()

    $client = [System.Net.Http.HttpClient]::new()
    $client.Timeout = [TimeSpan]::FromSeconds(20)
    $client.DefaultRequestHeaders.Authorization =
        [System.Net.Http.Headers.AuthenticationHeaderValue]::new(
            'Bot', [string]$script:NuwaConfig.DiscordToken)
    $client.DefaultRequestHeaders.UserAgent.ParseAdd('Nuwa/1.0')
    return $client
}

function Invoke-NuwaSocksRestGet {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][System.Net.Http.HttpClient]$Client,
        [Parameter(Mandatory = $true)][string]$Path
    )

    $uri = Get-NuwaDiscordApiUri -Path $Path
    for ($attempt = 0; $attempt -lt 4; $attempt += 1) {
        $response = $Client.GetAsync($uri).GetAwaiter().GetResult()
        try {
            if ([int]$response.StatusCode -eq 429 -and $attempt -lt 3) {
                $delay = 1100
                if ($null -ne $response.Headers.RetryAfter -and
                    $null -ne $response.Headers.RetryAfter.Delta) {
                    $delay = [int][Math]::Ceiling(
                        $response.Headers.RetryAfter.Delta.TotalMilliseconds)
                }
            } elseif (-not $response.IsSuccessStatusCode) {
                throw ('Discord GET failed with HTTP {0}' -f [int]$response.StatusCode)
            } else {
                $json = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
                return ($json | ConvertFrom-Json)
            }
        } finally {
            $response.Dispose()
        }
        Start-Sleep -Milliseconds ([Math]::Min(60000, [Math]::Max(100, $delay)))
    }
}

function Send-NuwaSocksGatewayJson {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][System.Net.WebSockets.ClientWebSocket]$Socket,
        [Parameter(Mandatory = $true)][object]$Message
    )

    $json = $Message | ConvertTo-Json -Compress -Depth 12
    [byte[]]$bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
    $segment = [ArraySegment[byte]]::new($bytes)
    $Socket.SendAsync(
        $segment, [System.Net.WebSockets.WebSocketMessageType]::Text,
        $true, [System.Threading.CancellationToken]::None
    ).GetAwaiter().GetResult()
}

function Receive-NuwaSocksGatewayJson {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][System.Net.WebSockets.ClientWebSocket]$Socket,
        [Parameter(Mandatory = $true)][hashtable]$Gateway,
        [Parameter(Mandatory = $true)][hashtable]$Worker,
        [Parameter(Mandatory = $false)][System.Threading.Tasks.Task]$UntilTask = $null
    )

    if ($null -eq $Gateway.ReceiveBuffer) {
        $Gateway.ReceiveBuffer = [byte[]]::new(65536)
        $Gateway.ReceiveParts = [System.Collections.Generic.List[byte]]::new()
    }
    $segment = [ArraySegment[byte]]::new([byte[]]$Gateway.ReceiveBuffer)
    while (-not $Worker.Shared.Stop.WaitOne(0)) {
        Update-NuwaSocksWorker -Worker $Worker
        $now = [DateTimeOffset]::UtcNow
        if ($Gateway.HeartbeatMilliseconds -gt 0 -and $now -ge $Gateway.NextHeartbeatAt) {
            if ($Gateway.RequireHeartbeatAck -and $Gateway.AwaitingHeartbeatAck) {
                throw 'Discord Gateway heartbeat acknowledgment missed'
            }
            Send-NuwaSocksGatewayJson -Socket $Socket -Message @{ op = 1; d = $Gateway.Sequence }
            $Gateway.AwaitingHeartbeatAck = $Gateway.RequireHeartbeatAck
            $Gateway.NextHeartbeatAt = $now.AddMilliseconds($Gateway.HeartbeatMilliseconds)
        }
        if ($null -eq $Gateway.ReceiveTask) {
            $Gateway.ReceiveTask = $Socket.ReceiveAsync(
                $segment, [System.Threading.CancellationToken]::None)
        }
        if ($null -ne $UntilTask -and $UntilTask.IsCompleted) { return $null }
        if (-not $Gateway.ReceiveTask.Wait(50)) {
            continue
        }
        $result = $Gateway.ReceiveTask.GetAwaiter().GetResult()
        $Gateway.ReceiveTask = $null
        if ($result.MessageType -eq [System.Net.WebSockets.WebSocketMessageType]::Close) {
            throw 'Discord Gateway closed the WebSocket'
        }
        if ($result.MessageType -ne [System.Net.WebSockets.WebSocketMessageType]::Text) {
            throw 'Discord Gateway sent a non-text frame'
        }
        for ($index = 0; $index -lt $result.Count; $index += 1) {
            $Gateway.ReceiveParts.Add($Gateway.ReceiveBuffer[$index])
        }
        if ($Gateway.ReceiveParts.Count -gt 2097152) {
            throw 'Discord Gateway frame exceeded the bounded size'
        }
        if ($result.EndOfMessage) {
            $json = [System.Text.Encoding]::UTF8.GetString($Gateway.ReceiveParts.ToArray())
            $Gateway.ReceiveParts.Clear()
            return ($json | ConvertFrom-Json)
        }
    }
    return $null
}

function Wait-NuwaSocksGatewayTask {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][System.Threading.Tasks.Task]$Task,
        [Parameter(Mandatory = $true)][System.Net.WebSockets.ClientWebSocket]$Socket,
        [Parameter(Mandatory = $true)][hashtable]$Gateway,
        [Parameter(Mandatory = $true)][hashtable]$Worker,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()]
        [System.Collections.Generic.List[object]]$Live
    )

    while (-not $Task.IsCompleted -and -not $Worker.Shared.Stop.WaitOne(0)) {
        $event = Receive-NuwaSocksGatewayJson -Socket $Socket -Gateway $Gateway `
            -Worker $Worker -UntilTask $Task
        if ($null -eq $event) { continue }
        if ($null -ne $event.s) { $Gateway.Sequence = [int64]$event.s }
        if ([int]$event.op -eq 11) {
            $Gateway.AwaitingHeartbeatAck = $false
        } elseif ([int]$event.op -eq 1) {
            Send-NuwaSocksGatewayJson -Socket $Socket -Message @{ op = 1; d = $Gateway.Sequence }
        } elseif ([int]$event.op -in @(7, 9)) {
            throw 'Discord Gateway interrupted SOCKS recovery'
        } elseif ([int]$event.op -eq 0 -and [string]$event.t -eq 'MESSAGE_CREATE') {
            $message = $event.d
            if ([string]$message.channel_id -eq [string]$script:NuwaConfig.SocksChannel -and
                [string]$message.author.id -eq [string]$Worker.BotId) {
                if ($Live.Count -ge 4096) { throw 'SOCKS recovery live-event buffer is full' }
                $Live.Add($message)
            }
        }
    }
}

function Get-NuwaSocksRecoveryMessages {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][System.Net.WebSockets.ClientWebSocket]$Socket,
        [Parameter(Mandatory = $true)][hashtable]$Gateway,
        [Parameter(Mandatory = $true)][hashtable]$Worker
    )

    $messages = [System.Collections.Generic.List[object]]::new()
    $live = [System.Collections.Generic.List[object]]::new()
    $channelId = [string]$script:NuwaConfig.SocksChannel
    $botId = [string]$Worker.BotId
    $before = ''
    $complete = $false
    for ($page = 0; $page -lt 50; $page += 1) {
        $path = 'channels/{0}/messages?limit=100' -f $channelId
        if ($before) { $path += '&before=' + $before }
        $uri = Get-NuwaDiscordApiUri -Path $path
        $attempt = 0
        while ($true) {
            $request = $Worker.Http.GetAsync($uri)
            Wait-NuwaSocksGatewayTask -Task $request -Socket $Socket `
                -Gateway $Gateway -Worker $Worker -Live $live
            $response = $request.GetAwaiter().GetResult()
            try {
                $status = [int]$response.StatusCode
                if ($status -eq 429) {
                    $attempt += 1
                    if ($attempt -ge 4) { throw 'Discord recovery GET exceeded rate-limit retries' }
                    $delay = 1100
                    if ($null -ne $response.Headers.RetryAfter -and
                        $null -ne $response.Headers.RetryAfter.Delta) {
                        $delay = [int][Math]::Ceiling(
                            $response.Headers.RetryAfter.Delta.TotalMilliseconds)
                    }
                    $delay = [Math]::Min(60000, [Math]::Max(100, $delay))
                } elseif (-not $response.IsSuccessStatusCode) {
                    throw ('Discord recovery GET failed with HTTP {0}' -f $status)
                } else {
                    $json = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
                    $batch = @($json | ConvertFrom-Json)
                }
            } finally {
                $response.Dispose()
            }
            if ($status -ne 429) { break }
            $delayTask = [System.Threading.Tasks.Task]::Delay($delay)
            Wait-NuwaSocksGatewayTask -Task $delayTask -Socket $Socket `
                -Gateway $Gateway -Worker $Worker -Live $live
        }
        if ($batch.Count -eq 0) { $complete = $true; break }
        foreach ($message in $batch) {
            if ([string]$message.channel_id -eq $channelId -and
                [string]$message.author.id -eq $botId) {
                $messages.Add($message)
            }
        }
        $before = [string]$batch[-1].id
        if ($batch.Count -lt 100) { $complete = $true; break }
    }
    if (-not $complete) { throw 'SOCKS recovery exceeded its 5000-message history window' }
    $merged = @{}
    foreach ($message in $messages) { $merged[[string]$message.id] = $message }
    foreach ($message in $live) { $merged[[string]$message.id] = $message }
    return @($merged.Values | Sort-Object { [decimal]$_.id })
}

function Invoke-NuwaSocksSafeInboundMessage {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][object]$Message,
          [Parameter(Mandatory = $true)][hashtable]$Worker)

    try {
        Invoke-NuwaSocksInboundMessage -Message $Message -Worker $Worker
    } catch {
        # A partial or uncertain socket write is not replayed. The source
        # Discord message remains available for diagnosis and recovery.
        Close-NuwaSocksAllConnections -Worker $Worker
        Write-NuwaDebug ('SOCKS inbound message retained: {0}' -f $_.Exception.Message)
    }
}

function Invoke-NuwaSocksGatewayLoop {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$Shared)

    $http = $null
    try {
        $http = New-NuwaSocksHttpClient
        $me = Invoke-NuwaSocksRestGet -Client $http -Path 'users/@me'
        $botId = [string]$me.id
        if (-not $botId) { throw 'Discord bot identity is unavailable' }
        $gatewayResult = Invoke-NuwaSocksRestGet -Client $http -Path 'gateway/bot'
        $gatewayUrl = [string]$gatewayResult.url
        $configuredGateway = [string]$script:NuwaConfig.DiscordGatewayOrigin
        if (-not [string]::IsNullOrWhiteSpace($configuredGateway)) {
            $gatewayUrl = $configuredGateway
        }
        $gatewayUri = [Uri]$gatewayUrl
        if (-not $gatewayUri.IsAbsoluteUri -or $gatewayUri.PathAndQuery -ne '/' -or
            $gatewayUri.Fragment -or $gatewayUri.UserInfo -or
            $gatewayUri.Scheme -notin @('wss', 'ws')) {
            throw 'Discord Gateway URL is invalid'
        }
        if ([string]::IsNullOrWhiteSpace($configuredGateway) -and
            $gatewayUri.Scheme -ne 'wss') {
            throw 'Discovered Discord Gateway must use wss'
        }
        $gatewayUrl = $gatewayUri.GetLeftPart([System.UriPartial]::Authority)

        $gateway = @{
            Sequence = $null
            SessionId = ''
            ResumeUrl = ''
            HeartbeatMilliseconds = 0
            NextHeartbeatAt = [DateTimeOffset]::MaxValue
            AwaitingHeartbeatAck = $false
            # Keep Discord's strict ACK failure behavior. Explicit custom
            # Gateways are local compatibility providers; continue sending
            # heartbeats and let their server-side timeout own liveness.
            RequireHeartbeatAck = [string]::IsNullOrWhiteSpace($configuredGateway)
            ReceiveTask = $null
            ReceiveBuffer = $null
            ReceiveParts = $null
        }
        $epoch = [byte[]]::new(8)
        [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($epoch)
        $worker = @{
            Shared = $Shared
            Http = $http
            BotId = $botId
            SeenMessages = [System.Collections.Generic.HashSet[string]]::new()
            SeenMessageOrder = [System.Collections.Generic.Queue[string]]::new()
            LastMessageId = [UInt64]0
            SeenBatchIds = [System.Collections.Generic.HashSet[string]]::new()
            FailedBatchIds = [System.Collections.Generic.HashSet[string]]::new()
            SeenBatchOrder = [System.Collections.Generic.Queue[string]]::new()
            Connections = @{}
            Outbound = [System.Collections.Generic.List[object]]::new()
            Cleanup = [System.Collections.Generic.List[string]]::new()
            CleanupFailures = @{}
            CleanupTimestamps = @{}
            CleanupTask = $null
            CleanupAt = [DateTimeOffset]::MinValue
            CleanupBulkDenied = $false
            CleanupBulkFailures = 0
            Pending = $null
            ActivePost = $null
            Epoch = $epoch
            Sequence = [UInt64]0
            FirstOutboundAt = [DateTimeOffset]::MaxValue
            LastOutboundAt = [DateTimeOffset]::MinValue
        }
        $gatewayFailures = 0
        while (-not $Shared.Stop.WaitOne(0)) {
            $socket = [System.Net.WebSockets.ClientWebSocket]::new()
            try {
                $gateway.ReceiveTask = $null
                $gateway.ReceiveBuffer = $null
                $gateway.ReceiveParts = $null
                $url = if ($gateway.ResumeUrl) { $gateway.ResumeUrl } else { $gatewayUrl }
                $uri = [Uri]($url.TrimEnd('/') + '/?v=10&encoding=json')
                $socket.ConnectAsync($uri, [System.Threading.CancellationToken]::None).GetAwaiter().GetResult()
                $hello = Receive-NuwaSocksGatewayJson -Socket $socket -Gateway $gateway -Worker $worker
                if ($null -eq $hello -or [int]$hello.op -ne 10) { throw 'Discord Gateway did not send HELLO' }
                $gatewayFailures = 0
                $gateway.HeartbeatMilliseconds = [int]$hello.d.heartbeat_interval
                if ($gateway.HeartbeatMilliseconds -lt 1000) { throw 'Discord Gateway heartbeat interval is invalid' }
                $gateway.NextHeartbeatAt = [DateTimeOffset]::UtcNow.AddMilliseconds($gateway.HeartbeatMilliseconds)
                $gateway.AwaitingHeartbeatAck = $false
                if ($gateway.SessionId -and $gateway.Sequence -ne $null) {
                    Send-NuwaSocksGatewayJson -Socket $socket -Message @{
                        op = 6
                        d = @{ token = [string]$script:NuwaConfig.DiscordToken;
                               session_id = $gateway.SessionId; seq = $gateway.Sequence }
                    }
                } else {
                    Send-NuwaSocksGatewayJson -Socket $socket -Message @{
                        op = 2
                        d = @{ token = [string]$script:NuwaConfig.DiscordToken;
                               intents = 33280;
                               properties = @{ os = 'windows'; browser = 'Nuwa'; device = 'Nuwa' } }
                    }
                }

                while (-not $Shared.Stop.WaitOne(0)) {
                    $event = Receive-NuwaSocksGatewayJson -Socket $socket -Gateway $gateway -Worker $worker
                    if ($null -eq $event) { break }
                    if ($null -ne $event.s) { $gateway.Sequence = [int64]$event.s }
                    if ([int]$event.op -eq 11) {
                        $gateway.AwaitingHeartbeatAck = $false
                        continue
                    }
                    if ([int]$event.op -eq 1) {
                        Send-NuwaSocksGatewayJson -Socket $socket -Message @{ op = 1; d = $gateway.Sequence }
                        continue
                    }
                    if ([int]$event.op -eq 7) { break }
                    if ([int]$event.op -eq 9) {
                        $gateway.SessionId = ''
                        $gateway.Sequence = $null
                        $gateway.ResumeUrl = ''
                        Close-NuwaSocksAllConnections -Worker $worker
                        break
                    }
                    if ([int]$event.op -ne 0) { continue }
                    if ([string]$event.t -eq 'READY') {
                        $gateway.SessionId = [string]$event.d.session_id
                        $gateway.ResumeUrl = [string]$event.d.resume_gateway_url
                        Close-NuwaSocksAllConnections -Worker $worker
                        $recovered = @(Get-NuwaSocksRecoveryMessages -Socket $socket `
                            -Gateway $gateway -Worker $worker)
                        foreach ($message in $recovered) {
                            Invoke-NuwaSocksSafeInboundMessage -Message $message -Worker $worker
                        }
                        [void]$Shared.Ready.Set()
                        continue
                    }
                    if ([string]$event.t -eq 'RESUMED') {
                        [void]$Shared.Ready.Set()
                        continue
                    }
                    if ([string]$event.t -eq 'MESSAGE_CREATE') {
                        Invoke-NuwaSocksSafeInboundMessage -Message $event.d -Worker $worker
                    }
                }
            } catch {
                $gatewayFailures += 1
                Write-NuwaDebug ('SOCKS Gateway reconnecting: {0}' -f $_.Exception.Message)
                if ($gatewayFailures -ge 3) {
                    $gateway.SessionId = ''
                    $gateway.Sequence = $null
                    $gateway.ResumeUrl = ''
                    Close-NuwaSocksAllConnections -Worker $worker
                    $gatewayFailures = 0
                }
            } finally {
                try { $socket.Dispose() } catch { }
            }
            if (-not $Shared.Stop.WaitOne(0)) { Start-Sleep -Milliseconds 500 }
        }
        Close-NuwaSocksAllConnections -Worker $worker
    } catch {
        $Shared.Error = $_.Exception.Message
        [void]$Shared.Ready.Set()
        Write-NuwaDebug ('SOCKS Gateway stopped: {0}' -f $_.Exception.Message)
    } finally {
        if ($null -ne $http) { $http.Dispose() }
    }
}
