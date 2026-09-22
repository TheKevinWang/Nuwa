+++
title = "Configuration"
chapter = false
weight = 10
pre = "<b>1. </b>"
+++

## Payload build options

| Option | Values | Default | Purpose |
| --- | --- | --- | --- |
| `codec_profile` | `binary-v1` | `binary-v1` | Uses the canonical binary inner map with raw file and SOCKS bytes. |
| `debug_logging` | Boolean | `false` | Enables agent-side status diagnostics. Treat debug output as sensitive. |
| `require_https` | Boolean | `false` | Rejects an HTTP build unless `callback_host` is a valid HTTPS URL. |
| `powershell_runtime` | `full-language`, `constrained-language` | `full-language` | Statically selects the normal .NET-backed implementation or the tested pure-PowerShell Constrained Language implementation. |

Each build must select exactly one C2 profile. HTTP and DiscordX code are
isolated at build time, so an HTTP artifact does not contain DiscordX transport
code or credentials and a DiscordX artifact does not contain HTTP endpoint
configuration.

## Supported configurations

Treat each row as one complete saved C2 instance and reuse that same instance
for its listener and payloads. The slash-separated stack is `codec_profile` /
UUID framing / outer serializer / outer presentation / outer protection / outer
key mode. The outer serializer, protection, and presentation are applied in
that order even though the table groups them by setting.

| Configuration | Stack | Inner protection | Use |
| --- | --- | --- | --- |
| **DiscordX default** | `binary-v1` / `raw-v1` / `binary-v1` / `base64` / `chacha20-v1` / `directional` | `none`, exchange off | Binary inner bytes in the existing 37-byte outer header. ChaCha20 does not authenticate modifications. |
| **Authenticated DiscordX** | `binary-v1` / `raw-v1` / `binary-v1` / `base64` / `aes256-hmac-v1` / `directional` | `none`, exchange off | Adds authenticated outer encryption. |
| **Layered DiscordX** | `binary-v1` / `raw-v1` / `binary-v1` / `base64` / `aes256-hmac-v1` / `directional` | `nuwa_aes256_hmac_v1`, staging on | Adds per-callback inner protection beneath the listener-wide outer layer. |
| **HTTP development** | `binary-v1` / `raw-v1` / `binary-v1` / `decimal` / `none` / `single` | `none`, exchange off | Requires explicitly selecting the fixed binary HTTP envelope on the listener. |

For every row, `raw-v1` means `use_base64=false`. The outer presentation is
independent of inner bytes. New DiscordX instances select the first row by
default, including a randomized outer key. HTTP listeners must explicitly
select `transport_envelope_format=binary-v1` and a supported outer presentation.
Install matching Nuwa, translation, and C2 revisions together because binary
inner v1 intentionally replaces the earlier JSON wire representation.

## Inner message pipeline

Nuwa encodes one canonical binary map. Text fields are UTF-8; file chunks and
SOCKS data use raw byte-string values. The translation container converts only
the known Mythic dictionary boundaries to and from Base64 text. The binary map
may receive optional inner protection, then one UUID frame, the selected fixed
binary outer envelope, optional outer protection, and exactly one outer
presentation. The decoder rejects JSON wire messages and noncanonical binary
maps. Ordinary messages contain no SOCKS-only batch or acknowledgment key.

## Inner protection and staging

The shared `AESPSK` parameter is the legacy Mythic parameter name. For Nuwa it
selects `none`, `nuwa_xor_v1`, `nuwa_hmac_sha256_v1`, or
`nuwa_aes256_hmac_v1`; it is separate from outer transport protection. XOR is
obfuscation only, HMAC adds integrity without confidentiality, and AES/HMAC is
the preferred protected option.

Keep `encrypted_exchange_check=false` for HTTP or `F` for DiscordX when using a
static key. RSA staging is supported only with `nuwa_aes256_hmac_v1`; enable it
with `true` for HTTP or `T` for DiscordX. The staged exchange uses Mythic's
RSA-OAEP-SHA1 compatibility protocol, fails closed, and retains internal Base64
for its public-key and session-key fields even when the outer framing is raw.

## Runtime selection

`full-language` remains the default. `constrained-language` compiles in the
tested Constrained Language-safe codec, protection, and RSA implementations.
This selection does not bypass host policy: commands invoked through `shell`
remain subject to the target's CLM, AppLocker, or WDAC restrictions.

## Optional SOCKS5 over DiscordX

To build a SOCKS-capable payload, select the `socks` command, select DiscordX,
set a numeric `socks_channel` different from the normal `bot_channel`, and use
`powershell_runtime=full-language`. Nuwa bundles the Gateway and TCP helpers
only for that build. HTTP and Constrained Language builds with `socks` are
rejected; an ordinary build without `socks` has no SOCKS helper or channel
requirement. Install matching Mythic core, DiscordX, Nuwa, and translation
revisions before starting a listener.

Task `socks start <port>` on the callback to create a Mythic-hosted SOCKS5
listener on that local port. The task reports when Nuwa's Discord Gateway is
ready. Connect a SOCKS5 client to the Mythic port; this implementation supports
TCP `CONNECT` to IPv4, IPv6, or domain destinations. `BIND` and UDP are not
supported. Task `socks stop <port>` to close that listener and its connections;
Nuwa closes the Gateway after the last SOCKS listener stops. Normal DiscordX
tasking continues to poll its normal channel throughout.

The SOCKS channel is shared by callbacks and carries the existing protected
binary outer envelope. Per-callback inner protection is recommended when the
channel is shared. Nuwa deletes accepted server messages in safe batches when
the bot has `MANAGE_MESSAGES`, with single-delete fallback; failed messages
remain available for recovery.

## Active listener

The **Active listener** field in the Create Payload C2 step lists running HTTP
and DiscordX listeners. Selecting one copies its listener-owned settings into
the current form. It preserves payload-owned callback host, redirector, URI,
and timing fields. The selection is local until the normal payload form is
submitted; a named saved C2 instance remains the durable configuration source.
