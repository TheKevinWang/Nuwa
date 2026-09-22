function Read-NuwaSocksConnectRequest {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)

    if ($Bytes.Length -lt 4) {
        return @{ Complete = $false }
    }
    if ($Bytes[0] -ne 5 -or $Bytes[2] -ne 0) {
        return @{ Complete = $true; ReplyCode = [byte]1 }
    }
    if ($Bytes[1] -ne 1) {
        return @{ Complete = $true; ReplyCode = [byte]7 }
    }

    $addressType = [int]$Bytes[3]
    $offset = 4
    $addressLength = 0
    if ($addressType -eq 1) {
        $addressLength = 4
    } elseif ($addressType -eq 4) {
        $addressLength = 16
    } elseif ($addressType -eq 3) {
        if ($Bytes.Length -lt 5) {
            return @{ Complete = $false }
        }
        $addressLength = [int]$Bytes[4]
        $offset = 5
        if ($addressLength -eq 0) {
            return @{ Complete = $true; ReplyCode = [byte]4 }
        }
    } else {
        return @{ Complete = $true; ReplyCode = [byte]8 }
    }

    $needed = $offset + $addressLength + 2
    if ($Bytes.Length -lt $needed) {
        return @{ Complete = $false }
    }
    [byte[]]$address = [byte[]]$Bytes[$offset..($offset + $addressLength - 1)]
    $targetHost = ''
    if ($addressType -eq 3) {
        foreach ($item in $address) {
            if ($item -lt 33 -or $item -gt 126) {
                return @{ Complete = $true; ReplyCode = [byte]4 }
            }
        }
        $targetHost = [System.Text.Encoding]::ASCII.GetString($address)
    } else {
        $targetHost = ([System.Net.IPAddress]::new($address)).ToString()
    }
    $port = ([int]$Bytes[$needed - 2] -shl 8) -bor [int]$Bytes[$needed - 1]
    if ($port -le 0) {
        return @{ Complete = $true; ReplyCode = [byte]4 }
    }
    return @{
        Complete = $true
        ReplyCode = [byte]0
        AddressType = [byte]$addressType
        Host = $targetHost
        Port = $port
        Consumed = $needed
    }
}

function New-NuwaSocksReplyBytes {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][byte]$ReplyCode,
        [Parameter(Mandatory = $false)][AllowNull()][System.Net.EndPoint]$BoundEndpoint = $null
    )

    [byte[]]$address = [byte[]]@(0, 0, 0, 0)
    [byte]$addressType = 1
    $port = 0
    if ($null -ne $BoundEndpoint -and $BoundEndpoint -is [System.Net.IPEndPoint]) {
        [byte[]]$address = [byte[]]$BoundEndpoint.Address.GetAddressBytes()
        $addressType = if ($address.Length -eq 16) { [byte]4 } else { [byte]1 }
        $port = [int]$BoundEndpoint.Port
    }
    [byte[]]$reply = [byte[]]::new(4 + $address.Length + 2)
    $reply[0] = 5
    $reply[1] = $ReplyCode
    $reply[2] = 0
    $reply[3] = $addressType
    [Array]::Copy($address, 0, $reply, 4, $address.Length)
    $reply[$reply.Length - 2] = [byte](($port -shr 8) -band 255)
    $reply[$reply.Length - 1] = [byte]($port -band 255)
    return ,$reply
}
