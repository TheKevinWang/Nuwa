function Invoke-NuwaShell {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Parameters
    )

    $command = [string]$Parameters.command
    $priorPreference = $ErrorActionPreference
    $locationPushed = $false
    $ErrorActionPreference = 'Stop'
    try {
        if ($script:NuwaState -and -not [string]::IsNullOrWhiteSpace($script:NuwaState.CurrentDirectory)) {
            Push-Location -LiteralPath $script:NuwaState.CurrentDirectory
            $locationPushed = $true
        }
        $global:LASTEXITCODE = 0
        $output = Invoke-Expression $command 2>&1 | Out-String
        $exitCode = if ($null -ne $LASTEXITCODE) { [int]$LASTEXITCODE } else { 0 }
        $process = @{}
        $process[$script:NuwaF_exit_code] = $exitCode
        $result = @{}
        $result[$script:NuwaF_user_output] = [string]$output
        $result[$script:NuwaF_process_response] = $process
        return $result
    } catch {
        $process = @{}
        $process[$script:NuwaF_exit_code] = if ($null -ne $LASTEXITCODE) { [int]$LASTEXITCODE } else { 1 }
        $result = @{}
        $result[$script:NuwaF_user_output] = [string]($_ | Out-String)
        $result[$script:NuwaF_process_response] = $process
        return $result
    } finally {
        if ($locationPushed) {
            Pop-Location
        }
        $ErrorActionPreference = $priorPreference
    }
}
