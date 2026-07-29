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
        return @{
            user_output = [string]$output
            process_response = @{
                exit_code = $exitCode
            }
        }
    } catch {
        return @{
            user_output = [string]($_ | Out-String)
            process_response = @{
                exit_code = if ($null -ne $LASTEXITCODE) { [int]$LASTEXITCODE } else { 1 }
            }
        }
    } finally {
        if ($locationPushed) {
            Pop-Location
        }
        $ErrorActionPreference = $priorPreference
    }
}
