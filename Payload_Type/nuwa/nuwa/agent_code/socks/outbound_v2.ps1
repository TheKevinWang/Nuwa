function New-NuwaSocksBatchId {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$Worker)

    if ($Worker.Sequence -eq [UInt64]::MaxValue) { throw 'SOCKS batch sequence exhausted' }
    $Worker.Sequence = [UInt64]($Worker.Sequence + 1)
    [byte[]]$sequence = [BitConverter]::GetBytes([UInt64]$Worker.Sequence)
    if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($sequence) }
    [byte[]]$result = [byte[]]::new(16)
    [Array]::Copy([byte[]]$Worker.Epoch, 0, $result, 0, 8)
    [Array]::Copy($sequence, 0, $result, 8, 8)
    return ,$result
}

function New-NuwaSocksOutboundDocument {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$Message)

    $uuid = [string]$script:NuwaState.CallbackUUID
    if (-not (Test-NuwaCanonicalUuid -Value $uuid)) {
        throw 'SOCKS callback route is unavailable'
    }
    [byte[]]$wire = ConvertTo-NuwaWireBytes -Message $Message -Context @{}
    [byte[]]$frame = New-NuwaTransportRequestBody -Uuid $uuid -WireBody $wire
    $document = ConvertTo-NuwaDiscordMessageWrapper -Message $frame -SenderId $uuid -ToServer $true
    if ([System.Text.Encoding]::UTF8.GetByteCount($document) -gt 2097152) {
        throw 'SOCKS Discord document exceeds the byte ceiling'
    }
    return $document
}

function New-NuwaSocksOutboundBatch {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$Worker)

    $records = [System.Collections.Generic.List[object]]::new()
    $servers = [System.Collections.Generic.HashSet[string]]::new()
    $round = [System.Collections.Generic.HashSet[string]]::new()
    $bytes = 0
    while ($Worker.Outbound.Count -gt 0 -and $records.Count -lt 64) {
        $selected = -1
        for ($index = 0; $index -lt $Worker.Outbound.Count; $index += 1) {
            $candidate = $Worker.Outbound[$index]
            $key = [string]$candidate[$script:NuwaF_server_id]
            if ($round.Contains($key)) { continue }
            if ($records.Count -gt 0 -and $bytes + ([byte[]]$candidate[$script:NuwaF_data]).Length -gt 49152) {
                continue
            }
            $selected = $index
            break
        }
        if ($selected -lt 0) {
            if ($round.Count -eq 0) { break }
            $round.Clear()
            continue
        }
        $record = $Worker.Outbound[$selected]
        $Worker.Outbound.RemoveAt($selected)
        $records.Add($record)
        [void]$servers.Add([string]$record[$script:NuwaF_server_id])
        [void]$round.Add([string]$record[$script:NuwaF_server_id])
        $bytes += ([byte[]]$record[$script:NuwaF_data]).Length
    }
    if ($records.Count -eq 0) { throw 'SOCKS outbound batch could not fit a record' }
    if ($Worker.Outbound.Count -eq 0) {
        $Worker.FirstOutboundAt = [DateTimeOffset]::MaxValue
    } else {
        $Worker.LastOutboundAt = $Worker.FirstOutboundAt
    }
    [byte[]]$batchId = New-NuwaSocksBatchId -Worker $Worker
    $message = @{}
    $message[$script:NuwaF_action] = $script:NuwaA_post_response
    $message[$script:NuwaF_socks] = $records.ToArray()
    $message[$script:NuwaF_socks_batch_id] = $batchId
    $document = New-NuwaSocksOutboundDocument -Message $message
    return @{
        Id = [BitConverter]::ToString($batchId).Replace('-', '')
        Document = $document
        Servers = @($servers)
        Attempts = 0
        Due = [DateTimeOffset]::UtcNow
        Deadline = [DateTimeOffset]::UtcNow.AddSeconds(45)
    }
}

function Start-NuwaSocksPost {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$Worker,
          [Parameter(Mandatory = $true)][hashtable]$Batch)

    $uri = Get-NuwaDiscordApiUri -Path (
        'channels/' + [string]$script:NuwaConfig.SocksChannel + '/messages')
    $document = [string]$Batch.Document
    $payload = @{ content = $document } | ConvertTo-Json -Compress
    if ($document.Length -le 1900) {
        $content = [System.Net.Http.StringContent]::new(
            $payload, [System.Text.Encoding]::UTF8, 'application/json')
    } else {
        $content = [System.Net.Http.MultipartFormDataContent]::new()
        $metadata = [System.Net.Http.StringContent]::new('{"content":""}', [System.Text.Encoding]::UTF8)
        $content.Add($metadata, 'payload_json')
        $file = [System.Net.Http.ByteArrayContent]::new([System.Text.Encoding]::UTF8.GetBytes($document))
        $file.Headers.ContentType = [System.Net.Http.Headers.MediaTypeHeaderValue]::new('text/plain')
        $content.Add($file, 'files[0]', 'message.txt')
    }
    $Batch.Attempts += 1
    try {
        $Worker.ActivePost = @{
            Batch = $Batch
            Content = $content
            Task = $Worker.Http.PostAsync($uri, $content)
        }
    } catch {
        $content.Dispose()
        throw
    }
}

function Stop-NuwaSocksFailedBatch {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$Worker,
          [Parameter(Mandatory = $true)][hashtable]$Batch)

    foreach ($key in @($Batch.Servers)) {
        Close-NuwaSocksConnection -Worker $Worker -ServerId ([uint32]$key)
    }
    if ($null -ne $Worker.Pending -and $Worker.Pending.Id -eq $Batch.Id) {
        $Worker.Pending = $null
    }
    Write-NuwaDebug 'SOCKS batch exceeded its bounded Discord POST retries'
}

function Update-NuwaSocksOutbound {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$Worker)

    $now = [DateTimeOffset]::UtcNow
    if ($null -ne $Worker.ActivePost -and $Worker.ActivePost.Task.IsCompleted) {
        $active = $Worker.ActivePost
        $Worker.ActivePost = $null
        $batch = $active.Batch
        $status = 0
        $retryMilliseconds = 1100
        try {
            $response = $active.Task.GetAwaiter().GetResult()
            try {
                $status = [int]$response.StatusCode
                if ($status -eq 429 -and $null -ne $response.Headers.RetryAfter -and
                    $null -ne $response.Headers.RetryAfter.Delta) {
                    $retryMilliseconds = [int][Math]::Ceiling($response.Headers.RetryAfter.Delta.TotalMilliseconds)
                }
            } finally { $response.Dispose() }
        } catch {
            Write-NuwaDebug ('SOCKS Discord POST failed: {0}' -f $_.Exception.Message)
        } finally { $active.Content.Dispose() }

        if ($status -ge 200 -and $status -lt 300) {
            # The channel accepted this immutable batch. The ingress
            # ledger still suppresses duplicates if a recovery later replays it.
            if ($null -ne $Worker.Pending -and $Worker.Pending.Id -eq $batch.Id) {
                $Worker.Pending = $null
            }
        } else {
            if ($status -eq 429) {
                $batch.Attempts -= 1
                $batch.Due = $now.AddMilliseconds([Math]::Min(60000, [Math]::Max(100, $retryMilliseconds)))
            } else {
                $batch.Due = $now.AddMilliseconds(500)
            }
            if ($batch.Attempts -ge 3) { Stop-NuwaSocksFailedBatch -Worker $Worker -Batch $batch }
        }
    }

    if ($null -eq $Worker.Pending -and $Worker.Outbound.Count -gt 0 -and
        ($Worker.Outbound.Count -ge 64 -or
         $now - $Worker.LastOutboundAt -ge [TimeSpan]::FromMilliseconds(20) -or
         $now - $Worker.FirstOutboundAt -ge [TimeSpan]::FromMilliseconds(200))) {
        $Worker.Pending = New-NuwaSocksOutboundBatch -Worker $Worker
        $Worker.Pending.Due = $now
    }
    if ($null -ne $Worker.ActivePost) { return }
    foreach ($batch in @($Worker.Pending)) {
        if ($null -eq $batch) { continue }
        if ($null -ne $batch.Deadline -and $now -ge $batch.Deadline) {
            Stop-NuwaSocksFailedBatch -Worker $Worker -Batch $batch
            continue
        }
        if ($batch.Attempts -ge 3) {
            Stop-NuwaSocksFailedBatch -Worker $Worker -Batch $batch
            continue
        }
        if ($now -lt $batch.Due) { continue }
        Start-NuwaSocksPost -Worker $Worker -Batch $batch
        break
    }
}

function Update-NuwaSocksCleanup {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$Worker)

    if ($null -ne $Worker.CleanupTask) {
        if (-not $Worker.CleanupTask.Task.IsCompleted) { return }
        $active = $Worker.CleanupTask
        $Worker.CleanupTask = $null
        $status = 0
        $retryMilliseconds = 1000
        try {
            $response = $active.Task.GetAwaiter().GetResult()
            try {
                $status = [int]$response.StatusCode
                if ($status -eq 429 -and $null -ne $response.Headers.RetryAfter -and
                    $null -ne $response.Headers.RetryAfter.Delta) {
                    $retryMilliseconds = [int][Math]::Ceiling($response.Headers.RetryAfter.Delta.TotalMilliseconds)
                }
            } finally { $response.Dispose() }
        } catch {
            Write-NuwaDebug ('SOCKS cleanup failed: {0}' -f $_.Exception.Message)
        } finally {
            if ($null -ne $active.Content) { $active.Content.Dispose() }
        }
        if ($status -ge 200 -and $status -lt 300 -or $status -eq 404) {
            foreach ($id in $active.Ids) {
                [void]$Worker.Cleanup.Remove($id)
                [void]$Worker.CleanupFailures.Remove($id)
                [void]$Worker.CleanupTimestamps.Remove($id)
            }
        } elseif ($active.Bulk -and $status -in @(400, 403)) {
            $Worker.CleanupBulkDenied = $true
        } elseif ($status -eq 429) {
            # Keep accepted IDs queued and honor the server's retry delay.
        } elseif ($active.Bulk) {
            $Worker.CleanupBulkFailures += 1
            if ($Worker.CleanupBulkFailures -ge 3) { $Worker.CleanupBulkDenied = $true }
        } else {
            foreach ($id in $active.Ids) {
                $Worker.CleanupFailures[$id] = [int]$Worker.CleanupFailures[$id] + 1
                if ($status -in @(401, 403) -or $Worker.CleanupFailures[$id] -ge 3) {
                    [void]$Worker.Cleanup.Remove($id)
                    [void]$Worker.CleanupFailures.Remove($id)
                    [void]$Worker.CleanupTimestamps.Remove($id)
                    Write-NuwaDebug ('SOCKS source message retained after cleanup failure {0}' -f $status)
                }
            }
        }
        $Worker.CleanupAt = [DateTimeOffset]::UtcNow.AddMilliseconds(
            [Math]::Min(60000, [Math]::Max(1000, $retryMilliseconds)))
        return
    }
    if ($Worker.Cleanup.Count -eq 0 -or [DateTimeOffset]::UtcNow -lt $Worker.CleanupAt) { return }
    $channel = [string]$script:NuwaConfig.SocksChannel
    $base = Get-NuwaDiscordApiUri -Path ('channels/' + $channel + '/messages')
    $bulkEligible = @($Worker.Cleanup | Where-Object {
        $Worker.CleanupTimestamps[$_] -gt [DateTimeOffset]::UtcNow.AddDays(-13.9)
    } | Select-Object -First 100)
    if (-not $Worker.CleanupBulkDenied -and $bulkEligible.Count -ge 2) {
        $ids = $bulkEligible
        $body = @{ messages = $ids } | ConvertTo-Json -Compress
        $content = [System.Net.Http.StringContent]::new(
            $body, [System.Text.Encoding]::UTF8, 'application/json')
        $task = $Worker.Http.PostAsync($base + '/bulk-delete', $content)
        $Worker.CleanupTask = @{ Task = $task; Content = $content; Ids = $ids; Bulk = $true }
    } else {
        $id = [string]$Worker.Cleanup[0]
        $task = $Worker.Http.DeleteAsync($base + '/' + $id)
        $Worker.CleanupTask = @{ Task = $task; Content = $null; Ids = @($id); Bulk = $false }
    }
}
