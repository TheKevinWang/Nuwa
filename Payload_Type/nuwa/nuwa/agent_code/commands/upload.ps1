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

            if (
                $null -ne $response -and
                (
                    ($response -is [hashtable] -and $response.ContainsKey('responses') -and $response.responses -and $response.responses.Count -gt 0) -or
                    ($response.PSObject.Properties.Match('responses').Count -gt 0 -and $response.responses -and $response.responses.Count -gt 0)
                )
            ) {
                $uploadResponse = $response.responses[0]
                $hasChunkData = $false
                if (
                    ($uploadResponse -is [hashtable] -and $uploadResponse.ContainsKey('chunk_data')) -or
                    ($uploadResponse -isnot [hashtable] -and $uploadResponse.PSObject.Properties.Match('chunk_data').Count -gt 0)
                ) {
                    $hasChunkData = Test-NuwaChunkDataPresent -Value $uploadResponse.chunk_data
                }
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
        upload = @{
            file_id = [string]$Parameters.file
            full_path = $targetPath
        }
    }
}
