function ConvertFrom-NuwaDiscordMessage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Message
    )

    $value = ''
    if ($Message -is [string]) {
        $value = $Message
    }

    $content = Get-NuwaDiscordObjectProperty -Object $Message -Name 'content'
    $attachments = Get-NuwaDiscordObjectProperty -Object $Message -Name 'attachments'
    if ([string]::IsNullOrWhiteSpace($value) -and -not [string]::IsNullOrWhiteSpace([string]$content)) {
        $value = [string]$content
    }
    if ([string]::IsNullOrWhiteSpace($value) -and $attachments) {
        $attachment = @($attachments)[0]
        $attachmentUrl = Get-NuwaDiscordObjectProperty -Object $attachment -Name 'url'
        $attachmentSize = Get-NuwaDiscordObjectProperty -Object $attachment -Name 'size'
        if ([string]::IsNullOrWhiteSpace([string]$attachmentUrl) -or $null -eq $attachmentSize) {
            return $null
        }
        $attachmentSizeText = [string]$attachmentSize
        if ($attachmentSizeText -notmatch '^[0-9]+$') {
            return $null
        }
        try {
            $declaredSize = [long]$attachmentSizeText
        } catch {
            return $null
        }
        if ($declaredSize -gt 2097152) {
            return $null
        }
        $value = Get-NuwaDiscordAttachmentContent -Url ([string]$attachmentUrl) -DeclaredSize $declaredSize
    }
    if ([string]::IsNullOrWhiteSpace($value)) {
        return $null
    }

    try {
        $parsed = ConvertFrom-NuwaTransportEnvelopeDocument `
            -Value $value `
            -Direction 'server-to-agent'
        return $parsed
    } catch {
        Write-NuwaDebug ('Discord envelope rejected: {0}' -f $_.Exception.Message)
        return $null
    }
}
