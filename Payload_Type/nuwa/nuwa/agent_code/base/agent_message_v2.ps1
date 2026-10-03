# Rebuild integer-key records after Windows PowerShell's JSON conversion.
function ConvertTo-NuwaAgentJsonValue {
    [CmdletBinding()]
    param([Parameter(Mandatory = $false)][AllowNull()][object]$Value)

    if ($null -eq $Value) { return $null }
    if ($Value -is [System.Collections.IDictionary]) {
        $result = @{}
        foreach ($key in $Value.Keys) {
            if ($key -isnot [int] -or [int]$key -lt 1 -or [int]$key -gt 65535) {
                throw 'Numeric agent field is invalid'
            }
            $result[[string]$key] = ConvertTo-NuwaAgentJsonValue -Value $Value[$key]
        }
        return $result
    }
    if ($Value -is [array]) {
        $items = [object[]]::new($Value.Length)
        for ($index = 0; $index -lt $Value.Length; $index++) {
            $items[$index] = ConvertTo-NuwaAgentJsonValue -Value $Value[$index]
        }
        return ,$items
    }
    return $Value
}

function ConvertFrom-NuwaAgentJsonValue {
    [CmdletBinding()]
    param([Parameter(Mandatory = $false)][AllowNull()][object]$Value)

    if ($null -eq $Value) { return $null }
    if ($Value -is [System.Collections.IDictionary] -or $Value -is [pscustomobject]) {
        $record = @{}
        if ($Value -is [System.Collections.IDictionary]) {
            foreach ($name in $Value.Keys) {
                try { [int]$field = [int]$name } catch { throw 'Numeric agent field is invalid' }
                if ($field -lt 1 -or $field -gt 65535 -or $record.ContainsKey($field)) { throw 'Numeric agent field is invalid' }
                $record[$field] = ConvertFrom-NuwaAgentJsonValue -Value $Value[$name]
            }
        } else {
            foreach ($property in $Value.PSObject.Properties) {
                try { [int]$field = [int]$property.Name } catch { throw 'Numeric agent field is invalid' }
                if ($field -lt 1 -or $field -gt 65535 -or $record.ContainsKey($field)) { throw 'Numeric agent field is invalid' }
                $record[$field] = ConvertFrom-NuwaAgentJsonValue -Value $property.Value
            }
        }
        return $record
    }
    if ($Value -is [array]) {
        $items = [object[]]::new($Value.Length)
        for ($index = 0; $index -lt $Value.Length; $index++) {
            $items[$index] = ConvertFrom-NuwaAgentJsonValue -Value $Value[$index]
        }
        return ,$items
    }
    return $Value
}

function New-NuwaDiagnosticOutput {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][int]$Code,
          [Parameter(Mandatory = $false)][object[]]$Arguments = @())

    $record = @($null, $null, $null, $null)
    $record[0] = [int]20053
    $record[1] = [int]1
    $record[2] = $Code
    $record[3] = [object[]]$Arguments
    return ,([object[]]$record)
}
