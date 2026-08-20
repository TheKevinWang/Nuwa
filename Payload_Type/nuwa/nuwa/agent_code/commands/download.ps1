function Get-NuwaFileChunks {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [int]$ChunkSize
    )

    [byte[]]$fileBytes = Get-Content -LiteralPath $Path -Encoding Byte
    if ($fileBytes.Length -eq 0) {
        Write-Output -NoEnumerate @([byte[]]@())
        return
    }

    $chunks = @()
    for ($offset = 0; $offset -lt $fileBytes.Length; $offset += $ChunkSize) {
        $remaining = $fileBytes.Length - $offset
        $count = if ($remaining -lt $ChunkSize) { $remaining } else { $ChunkSize }
        if ($count -eq 1) {
            $chunkBytes = [byte[]]@($fileBytes[$offset])
        } else {
            $chunkBytes = [byte[]]$fileBytes[$offset..($offset + $count - 1)]
        }
        $chunks += ,$chunkBytes
    }

    Write-Output -NoEnumerate $chunks
}

function Invoke-NuwaDownload {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TaskId,

        [Parameter(Mandatory = $true)]
        [hashtable]$Parameters
    )

    $sourcePath = Resolve-NuwaPath -Path ([string]$Parameters.path)
    $file = Get-Item -LiteralPath $sourcePath -Force
    if ($file.PSIsContainer) {
        throw 'download requires a file path'
    }

    $chunkSize = Get-NuwaFileChunkSize
    $requestAttempts = 3
    $chunks = Get-NuwaFileChunks -Path $sourcePath -ChunkSize $chunkSize
    if ($chunks -is [byte[]]) {
        $chunks = ,([byte[]]$chunks)
    } elseif ($null -eq $chunks) {
        $chunks = @()
    }
    $totalChunks = $chunks.Count
    if ($totalChunks -lt 1) {
        $totalChunks = 1
    }

    $initialDownload = @{
        total_chunks = $totalChunks
        full_path = $sourcePath
        chunk_size = $chunkSize
    }
    if ($chunks.Count -eq 1) {
        $initialDownload.chunk_num = 1
        $initialDownload.chunk_data = ConvertTo-NuwaChunkData -Bytes $chunks[0]
    }

    $initialResponse = $null
    for ($attempt = 0; $attempt -lt $requestAttempts; $attempt += 1) {
        $initialResponse = Invoke-NuwaSendMessage -Uuid $script:NuwaState.CallbackUUID -Action 'post_response' -Body @{
            responses = @(
                @{
                    task_id = $TaskId
                    download = $initialDownload
                }
            )
        }
        $initialResponseItems = $null
        if ($null -ne $initialResponse) {
            if ($initialResponse -is [hashtable]) {
                if ($initialResponse.ContainsKey('responses')) {
                    $initialResponseItems = $initialResponse.responses
                }
            } else {
                try {
                    $initialResponseItems = $initialResponse.responses
                } catch {
                    $initialResponseItems = $null
                }
            }
        }
        if ($initialResponseItems -and @($initialResponseItems).Count -gt 0) {
            break
        }
        if (($attempt + 1) -lt $requestAttempts) {
            Start-Sleep -Seconds 1
        }
    }
    if ($null -eq $initialResponseItems -or @($initialResponseItems).Count -eq 0) {
        throw 'Download metadata request did not return a file ID'
    }
    $fileId = [string](@($initialResponseItems)[0].file_id)
    $chunkStartIndex = 0
    $chunkNumber = 1
    if ($chunks.Count -eq 1) {
        $chunkStartIndex = 1
        $chunkNumber = 2
    }

    for ($chunkIndex = $chunkStartIndex; $chunkIndex -lt $chunks.Count; $chunkIndex += 1) {
        $chunkBytes = $chunks[$chunkIndex]
        $chunkAcknowledged = $false
        for ($attempt = 0; $attempt -lt $requestAttempts; $attempt += 1) {
            $chunkResponse = Invoke-NuwaSendMessage -Uuid $script:NuwaState.CallbackUUID -Action 'post_response' -Body @{
                responses = @(
                    @{
                        task_id = $TaskId
                        download = @{
                            chunk_num = $chunkNumber
                            file_id = $fileId
                            chunk_data = ConvertTo-NuwaChunkData -Bytes $chunkBytes
                        }
                    }
                )
            }
            $chunkResponseItems = $null
            if ($null -ne $chunkResponse) {
                if ($chunkResponse -is [hashtable]) {
                    if ($chunkResponse.ContainsKey('responses')) {
                        $chunkResponseItems = $chunkResponse.responses
                    }
                } else {
                    try {
                        $chunkResponseItems = $chunkResponse.responses
                    } catch {
                        $chunkResponseItems = $null
                    }
                }
            }
            if ($chunkResponseItems -and @($chunkResponseItems).Count -gt 0) {
                $chunkAcknowledged = $true
                break
            }
            if (($attempt + 1) -lt $requestAttempts) {
                Start-Sleep -Seconds 1
            }
        }
        if (-not $chunkAcknowledged) {
            throw ("Download chunk upload was not acknowledged for chunk {0}" -f $chunkNumber)
        }
        $chunkNumber += 1
    }

    return (@{ agent_file_id = $fileId } | ConvertTo-Json -Compress)
}
