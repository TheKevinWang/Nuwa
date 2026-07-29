function Invoke-NuwaLs {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Parameters
    )

    $requestedPath = [string]$Parameters.path
    if ([string]::IsNullOrWhiteSpace($requestedPath) -or $requestedPath -eq '.') {
        $requestedPath = $script:NuwaState.CurrentDirectory
    }

    Push-Location -LiteralPath $script:NuwaState.CurrentDirectory
    try {
        $item = Get-Item -LiteralPath $requestedPath -Force
        $resolved = $item.FullName
        $files = @()
        if ($item.PSIsContainer) {
            foreach ($child in (Get-ChildItem -LiteralPath $resolved -Force)) {
                $files += @{
                    name = $child.Name
                    is_file = (-not $child.PSIsContainer)
                    size = if ($child.PSIsContainer) { 0 } else { [int64]$child.Length }
                }
            }
        } else {
            $files += @{
                name = $item.Name
                is_file = $true
                size = [int64]$item.Length
            }
        }

        return (@{
            files = $files
            parent_path = $resolved
            name = $item.Name
        } | ConvertTo-Json -Compress -Depth 5)
    } finally {
        Pop-Location
    }
}
