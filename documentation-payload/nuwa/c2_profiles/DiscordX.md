+++
title = "DiscordX"
chapter = false
weight = 22
+++

## Summary

Nuwa uses the `discordx` C2 profile as a synchronous Discord REST poller. It
embeds `discord_token`, `bot_channel`, `message_checks`, and
`time_between_checks`; the token is sensitive payload material.
Set `user_agent` to control the complete User-Agent header on Nuwa's Discord API
requests. Its default is
`DiscordBot (https://github.com/discord-net/Discord.Net, v3.20.1)`.

## Fixed channel contract

The saved C2 configuration fixes `transport_envelope_format` as `json-v1` or
`binary-v1`, and `transport_presentation` as `plain`, `base64`, `decimal`, or
`emoji`. The payload and listener must use that same saved format,
presentation, protection, key mode, key, and `use_base64` framing choice. They
do not negotiate or probe alternate settings in the channel.

New DiscordX instances default to `binary-v1`, raw-v1 framing, Base64 outer
presentation, directional ChaCha20 outer protection, and no inner protection;
Nuwa's inner codec independently defaults to `raw`. `binary-v1` uses a flags
byte, a canonical 36-byte routing UUID, and arbitrary message bytes. ChaCha20
provides confidentiality but not integrity. The readable-development bundle is
`json-v1` with `plain` presentation and no outer protection. Raw-v1 inside
`json-v1` requires a text-producing inner codec when protection is enabled.

The complete envelope may independently use outer
`transport_protection` (`none`, XOR, ChaCha20, or AES/HMAC) and a `single` or
`directional` `transport_key_mode`. Presentation only changes how bytes appear
in Discord; it is not confidentiality, integrity, or authentication.

Documents up to 1,900 UTF-16 code units are sent inline. Larger documents use a
neutral `message.txt` attachment. Presented and decoded-envelope limits are
2,097,152 and 524,288 UTF-8 bytes respectively.
