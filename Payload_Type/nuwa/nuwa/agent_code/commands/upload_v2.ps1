function Invoke-NuwaUpload {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TaskId,

        [Parameter(Mandatory = $true)]
        [hashtable]$Parameters
    )

    $targetPath = Resolve-NuwaPath -Path ([string]$Parameters.remote_path)
    $chunkSize = Get-NuwaFileChunkSize
    $chunkRequestAttempts = 3
    $chunkNumber = 1
    $totalChunks = 1

    if (Test-Path -LiteralPath $targetPath) {
        Remove-Item -LiteralPath $targetPath -Force
    }

    while ($chunkNumber -le $totalChunks) {
        $uploadResponse = $null
        for ($attempt = 0; $attempt -lt $chunkRequestAttempts; $attempt += 1) {
            $upload = @{}
            $upload[$script:NuwaF_chunk_size] = $chunkSize
            $upload[$script:NuwaF_file_id] = [string]$Parameters.file
            $upload[$script:NuwaF_chunk_num] = $chunkNumber
            $upload[$script:NuwaF_full_path] = $targetPath
            $entry = @{}
            $entry[$script:NuwaF_task_id] = $TaskId
            $entry[$script:NuwaF_upload] = $upload
            $body = @{}
            $body[$script:NuwaF_responses] = @($entry)
            $response = Invoke-NuwaSendMessage -Uuid $script:NuwaState.CallbackUUID -Action $script:NuwaA_post_response -Body $body

            $responseItems = if ($null -ne $response) { $response[$script:NuwaF_responses] } else { $null }
            if ($responseItems -and @($responseItems).Count -gt 0) {
                $uploadResponse = @($responseItems)[0]
                $chunkData = $uploadResponse[$script:NuwaF_chunk_data]
                $hasChunkData = Test-NuwaChunkDataPresent -Value $chunkData
                if ($hasChunkData) {
                    break
                }
                $uploadResponse = $null
            }

            if (($attempt + 1) -lt $chunkRequestAttempts) {
                Start-Sleep -Seconds 1
            }
        }
        if ($null -eq $uploadResponse) {
            throw (New-NuwaDiagnosticOutput -Code 1075 -Arguments @($chunkNumber))
        }

        $totalChunks = [int]$uploadResponse[$script:NuwaF_total_chunks]
        $chunkBytes = ConvertFrom-NuwaChunkData -Value $uploadResponse[$script:NuwaF_chunk_data]
        if ($chunkNumber -eq 1) {
            Set-Content -LiteralPath $targetPath -Value $chunkBytes -Encoding Byte
        } else {
            Add-Content -LiteralPath $targetPath -Value $chunkBytes -Encoding Byte
        }
        $chunkNumber += 1
    }

    $result = @{}
    $result[$script:NuwaF_completed] = $true
    $result[$script:NuwaF_user_output] = New-NuwaDiagnosticOutput -Code 1076 -Arguments @($targetPath)
    return $result
}
