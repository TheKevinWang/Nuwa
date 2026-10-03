+++
title = "Configuration"
chapter = false
weight = 10
pre = "<b>1. </b>"
+++

## Payload build options

| Option | Values | Default | Purpose |
| --- | --- | --- | --- |
| `control_id_mode` | `default`, `custom`, `random` | `default` | Selects the legacy IDs, an uploaded v3 map, or a reproducible v3 map derived from the payload UUID. |
| `control_id_file` | uploaded JSON file ID | empty | Required for `custom`; must be empty for other modes. |
| `codec_profile` | `binary-v1`, `binary-v2` | `binary-v2` | Uses the canonical numeric inner map with raw file and SOCKS bytes; v1 is retained for explicit migration builds. |
| `debug_logging` | Boolean | `false` | Enables agent-side status diagnostics. Treat debug output as sensitive. |
| `require_https` | Boolean | `false` | Rejects an HTTP build unless `callback_host` is a valid HTTPS URL. |
| `powershell_runtime` | `full-language`, `constrained-language` | `full-language` | Statically selects the normal .NET-backed implementation or the tested pure-PowerShell Constrained Language implementation. |

## Per-payload control identifiers

`default` preserves the existing v1/v2 inner wire format and all its frozen
fixtures. `custom` and `random` select inner binary v3. Keep
`codec_profile=binary-v2` when selecting either v3 mode; the v2 option supplies
Nuwa's numeric runtime, while the selected profile supplies the v3 IDs and
bytes. The translation container finds the original payload UUID through
Mythic for each payload, staging, or callback route, then recovers the same map
after a restart. Existing v3 payloads built with the previous 18-byte header
need to be rebuilt for this wire format.

The v3 document begins with the two selected marker bytes, followed directly
by a typed map.
Integer keys sort in ascending numeric order before ASCII string keys, which
sort by byte value. Encoders use shortest unsigned varints and UTF-8 text;
decoders reject duplicate or unsorted keys, nonminimal varints, unknown field
IDs, trailing bytes, nesting beyond 20 levels, and documents above 524,288
bytes.

For `custom`, upload one UTF-8 JSON file in Mythic's payload form. The file has
`{"version":3,"namespaces":{...}}`. Namespace names and entry names match `control_identifiers_v3_default.json`
shipped with the payload builder and translation container; omitted entries
retain their defaults. [This example](control-identifiers-v3-example.json) changes wire
fields, an action, a command, a diagnostic, a local slot, and a byte tag.
Unknown names, duplicate JSON names, duplicate assigned values, Boolean IDs,
non-ASCII strings, and out-of-range integers fail the build with the namespace
and entry named in the error. A partial numeric override that takes an
occupied default value swaps the previous owner to the overridden entry's old
value. Explicit overrides that collide with each other fail.

Semantic fields, enum values, diagnostics, and dictionary-backed local record
keys may be integers or ASCII identifiers matching
`[A-Za-z][A-Za-z0-9_-]{0,63}`. Numeric wire field IDs are 1 through 65535.
Primitive tags and marker bytes are integers 0 through 255. Numeric array
slots and diagnostic record positions must be complete permutations of their
default index sets; string local keys make that record dictionary-backed.
The uploaded file is limited to 65,536 bytes and the fully expanded profile
to 262,144 bytes. The builder reports an error if Mythic cannot retrieve the
uploaded file. The translation container reports that error again after a
restart rather than using a default map.

`random` assigns each namespace independently from SHA-256 counter bytes
seeded by the payload UUID. New builds always use compact IDs: command IDs
are 1–10, most other namespaces stay below 100, and the 165 diagnostic IDs
use 1–165 because they must be distinct. Array slots remain permutations of
their legal indexes. An internal, hidden marker distinguishes new builds from
historical random payloads, which continue to resolve with their original
wide assignments after a translator restart.
Rebuilding the same UUID under the same mapping produces the same map;
different payload UUIDs produce distinct maps. This map is not a secret. Mythic-side command
names and visible task results stay the same in
all three modes. Deleting a callback removes its route immediately and clears
Mythic's UUID cache. Deleting a payload file marks that payload deleted, so
new payload and staging routes stop resolving; existing callback rows may
continue using their original payload configuration. An uploaded custom file
remains a normal Mythic file until removed through Mythic's file controls.

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
| **DiscordX default** | `binary-v2` / `raw-v1` / `binary-v1` / `base64` / `chacha20-v1` / `directional` | `none`, exchange off | Numeric inner bytes in the existing 37-byte outer header. ChaCha20 does not authenticate modifications. |
| **Authenticated DiscordX** | `binary-v2` / `raw-v1` / `binary-v1` / `base64` / `aes256-hmac-v1` / `directional` | `none`, exchange off | Adds authenticated outer encryption. |
| **Layered DiscordX** | `binary-v2` / `raw-v1` / `binary-v1` / `base64` / `aes256-hmac-v1` / `directional` | `nuwa_aes256_hmac_v1`, staging on | Adds per-callback inner protection beneath the listener-wide outer layer. |
| **HTTP development** | `binary-v2` / `raw-v1` / `binary-v1` / `decimal` / `none` / `single` | `none`, exchange off | Requires explicitly selecting the fixed binary HTTP envelope on the listener. |

For every row, `raw-v1` means `use_base64=false`. The outer presentation is
independent of inner bytes. New DiscordX instances select the first row by
default, including a randomized outer key. HTTP listeners must explicitly
select `transport_envelope_format=binary-v1` and a supported outer presentation.
Install matching Nuwa, translation, and C2 revisions together because binary
inner v2 uses numeric IDs; the translation container still reads v1 agent messages.

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
listeners and healthy DiscordX logical listeners in the current operation.
Selecting DiscordX loads its named saved C2 instance's nonsecret settings and
keeps listener-owned fields read-only. Tokens and transport keys stay
write-only: Mythic resolves them on the server when building the payload and
checks that the selected generation remains active and synchronized.

The selector preserves payload-owned callback host, redirector, URI, timing,
and target proxy fields. The selection is local until the normal payload form
is submitted; a named saved C2 instance remains the durable configuration
source. Use **Refresh listeners** after creating or changing a listener under
C2 Profiles. A running DiscordX service without a configured saved listener
shows an explanatory message and contributes no active listener option.
