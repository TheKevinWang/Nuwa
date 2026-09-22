+++
title = "Nuwa"
chapter = false
weight = 5
+++

## Summary

Nuwa is a small Windows agent written for Windows PowerShell 5.1. A payload
contains exactly one build-time-selected C2 transport (`http` or `discordx`)
and only the commands selected in the payload workflow. It does not dynamically
load commands.

Nuwa uses a companion translation container because its canonical binary-v1
inner message is not native Mythic JSON. File chunks and SOCKS records carry
raw bytes inside that message. The fixed HTTP or DiscordX outer envelope
applies one configured presentation and optional protection. See
[Configuration](/agents/nuwa/configuration/) for the message pipeline and
runtime choices.

## Supported C2 profiles

- [HTTP](/agents/nuwa/c2_profiles/http/)
- [DiscordX](/agents/nuwa/c2_profiles/discordx/)

## Commands

Nuwa provides `cd`, `download`, `exit`, `hostname`, `ls`, `shell`, `sleep`,
`upload`, and `whoami`. See the [command reference](/agents/nuwa/commands/).

## Important security boundaries

An inner codec or outer presentation is encoding, not encryption. Prefer HTTPS
for HTTP, and use `nuwa_aes256_hmac_v1` when application-layer confidentiality
and authentication are required. Static keys and Discord bot credentials are
embedded in generated payloads and should be treated as sensitive.
