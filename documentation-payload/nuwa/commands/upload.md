+++
title = "upload"
chapter = false
weight = 107
hidden = false
+++

## Summary

Uploads a Mythic-hosted file to the target. Nuwa removes an existing
destination before requesting the first acknowledged chunk and retries each
request up to three times.

## Usage

```text
upload
```

Use Mythic's upload dialog or named `file` and `remote_path` arguments.
Binary-v1 HTTP and DiscordX use 16,384-byte chunks carried as raw bytes inside
the inner message.
