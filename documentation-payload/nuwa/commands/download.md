+++
title = "download"
chapter = false
weight = 101
hidden = false
+++

## Summary

Downloads a file from the target through Mythic's file-transfer workflow. Nuwa
creates file metadata, sends acknowledged chunks, and retries each request up
to three times.

## Usage

```text
download <path>
```

Binary-v1 HTTP and DiscordX use 16,384-byte chunks. The inner message carries
chunk contents as raw bytes; the selected outer presentation controls the
channel text or HTTP body.
