# v3 records keep their payload-selected integer or ASCII string keys.
function ConvertTo-NuwaAgentJsonValue {
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [System.Collections.IDictionary]) {
        $result = @{}
        foreach ($key in $Value.Keys) {
            $result[[string]$key] = ConvertTo-NuwaAgentJsonValue -Value $Value[$key]
        }
        return $result
    }
    if ($Value -is [array] -and $Value -isnot [byte[]]) {
        $items = [object[]]::new($Value.Length)
        for ($index = 0; $index -lt $Value.Length; $index++) {
            $items[$index] = ConvertTo-NuwaAgentJsonValue -Value $Value[$index]
        }
        return ,$items
    }
    return $Value
}

function ConvertFrom-NuwaAgentJsonValue {
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [System.Collections.IDictionary] -or $Value -is [pscustomobject]) {
        $result = @{}
        $entries = if ($Value -is [System.Collections.IDictionary]) { $Value.GetEnumerator() } else { $Value.PSObject.Properties }
        foreach ($entry in $entries) {
            $name = if ($Value -is [System.Collections.IDictionary]) { [string]$entry.Key } else { [string]$entry.Name }
            $key = $null
            if ($name -match '^[1-9][0-9]{0,4}$') {
                $number = [int]$name
                if ($number -gt 65535) { throw 'v3 agent field ID is invalid' }
                $key = $number
            } elseif ($name -cmatch '^[A-Za-z][A-Za-z0-9_-]{0,63}$') {
                $key = $name
            } else {
                throw 'v3 agent field name is invalid'
            }
            if ($result.ContainsKey($key)) { throw 'Duplicate v3 agent field' }
            $result[$key] = ConvertFrom-NuwaAgentJsonValue -Value $entry.Value
        }
        return $result
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
    param([Parameter(Mandatory = $true)][object]$Code,
          [object[]]$Arguments = @())
    $record = [object[]]::new(4)
    $record[$script:NuwaV3DiagPos_tag] = $script:NuwaV3DiagHeader_tag
    $record[$script:NuwaV3DiagPos_version] = $script:NuwaV3DiagHeader_version
    $record[$script:NuwaV3DiagPos_code] = $Code
    $record[$script:NuwaV3DiagPos_arguments] = [object[]]$Arguments
    return ,$record
}
