+++
title = "C2 Profiles"
chapter = true
weight = 20
pre = "<b>2. </b>"
+++

# Supported C2 profiles

Nuwa supports one build-time-selected profile per payload:

- [HTTP](/agents/nuwa/c2_profiles/http/)
- [DiscordX](/agents/nuwa/c2_profiles/discordx/)

Both expose raw or historical Base64 UUID framing through `use_base64` and
separate listener-owned outer transport presentation/protection settings.
