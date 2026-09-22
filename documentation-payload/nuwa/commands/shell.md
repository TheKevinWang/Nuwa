+++
title = "shell"
chapter = false
weight = 105
hidden = false
+++

## Summary

Runs one PowerShell command with `Invoke-Expression` in Nuwa's logical current
directory. It merges the error stream into output and reports
`$LASTEXITCODE` in `process_response.exit_code`.

## Usage

```text
shell <powershell command>
```

The command remains subject to the host's PowerShell language mode and
application-control policy.
