+++
title = "HTTP"
chapter = false
weight = 21
+++

## Summary

Nuwa HTTP uses POST for check-in, task polling, responses, and file transfer.
The endpoint is formed from `callback_host`, `callback_port`, and `post_uri`.

## Framing

`use_base64=true` (including an omitted value) uses the historical Base64
envelope: `Base64(ASCII UUID || wire message)`. `use_base64=false` uses raw-v1:
`ASCII UUID || wire message`, with `X-Agent-Body-Format: raw-v1`. The HTTP
profile also accepts the previous `X-Mythic-Body-Format` selector during the
transition and rejects requests that provide conflicting selectors. The two
choices are outer framing and are independent of the selected inner codec and
`AESPSK` protection.

Raw requests are limited to 262,144 UTF-8 bytes by Nuwa and reject credentialed
proxy settings. Historical framing retains credentialed-proxy compatibility.

## Protection

`AESPSK` selects Nuwa's inner message protection, not the HTTP listener's outer
Transport Protection. Raw-v1 protected bytes require a text-producing inner
codec: `base64`, `decimal`, or `emoji`; historical Base64 framing can carry
protected `raw`. `require_https=true` validates the callback URL at build time;
HTTPS and `nuwa_aes256_hmac_v1` protect different boundaries and are normally
used together.

The HTTP listener can independently use `transport_presentation`,
`transport_protection`, `transport_key_mode`, `transport_key`, and
`transport_nonce_strategy`. Reuse the same named saved C2 instance for the
listener and payload so randomized outer keys remain identical.
