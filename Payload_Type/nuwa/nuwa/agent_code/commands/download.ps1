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
    $totalChunks = [int][Math]::Ceiling($file.Length / [double]$chunkSize)
    if ($totalChunks -lt 1) {
        $totalChunks = 1
    }
    $chunks = Get-NuwaFileChunks -Path $sourcePath -ChunkSize $chunkSize
    if ($chunks -is [byte[]]) {
        $chunks = ,([byte[]]$chunks)
    } elseif ($null -eq $chunks) {
        $chunks = @()
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
        if (
            $null -ne $initialResponse -and
            (
                ($initialResponse -is [hashtable] -and $initialResponse.ContainsKey('responses') -and $initialResponse.responses -and $initialResponse.responses.Count -gt 0) -or
                ($initialResponse.PSObject.Properties.Match('responses').Count -gt 0 -and $initialResponse.responses -and $initialResponse.responses.Count -gt 0)
            )
        ) {
            break
        }
        if (($attempt + 1) -lt $requestAttempts) {
            Start-Sleep -Seconds 1
        }
    }
    if (
        $null -eq $initialResponse -or
        (
            ($initialResponse -is [hashtable] -and (-not $initialResponse.ContainsKey('responses') -or -not $initialResponse.responses -or $initialResponse.responses.Count -eq 0)) -or
            ($initialResponse -isnot [hashtable] -and ($initialResponse.PSObject.Properties.Match('responses').Count -eq 0 -or -not $initialResponse.responses -or $initialResponse.responses.Count -eq 0))
        )
    ) {
        throw 'Download metadata request did not return a file ID'
    }
    $fileId = [string]$initialResponse.responses[0].file_id
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
            if (
                $null -ne $chunkResponse -and
                (
                    ($chunkResponse -is [hashtable] -and $chunkResponse.ContainsKey('responses') -and $chunkResponse.responses -and $chunkResponse.responses.Count -gt 0) -or
                    ($chunkResponse.PSObject.Properties.Match('responses').Count -gt 0 -and $chunkResponse.responses -and $chunkResponse.responses.Count -gt 0)
                )
            ) {
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
