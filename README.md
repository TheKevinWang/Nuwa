# Nuwa

Nuwa is a Windows PowerShell 5.1 agent for
Mythic v3.4, designed for evasion through simplicity and rapid iteration. It
supports a minimal payload with a pluggable codec system designed to make custom
encodings easy to add. The [DiscordX](https://github.com/TheKevinWang/discordx) (`discordx`) C2 profile also supports
encryption and custom encoding of the routing envelope.

Optional inner message encryption uses AES-256-CBC with HMAC-SHA256
(`nuwa_aes256_hmac_v1`). Other inner protection options are HMAC-SHA256
authentication without encryption (`nuwa_hmac_sha256_v1`), XOR obfuscation
(`nuwa_xor_v1`), and no protection (`none`). HTTP and DiscordX also support
independent routing-envelope encryption with ChaCha20 (`chacha20-v1`, without
authentication) or AES-256-CBC with HMAC-SHA256 (`aes256-hmac-v1`), alongside
XOR obfuscation, no protection, and custom envelope encoding.

Use Nuwa only on systems you own or are explicitly authorized to test.

## Installation

Install the agent from the Mythic directory, using an absolute path to this
directory:

```shell
./mythic-cli install folder /absolute/path/to/Mythic_Agents/Nuwa -f
```

The payload type and translation container are separate services. A healthy
installation therefore requires both `nuwa` and `nuwa_translation` to be
running, in addition to the selected shared C2 profile.

## Architecture and payload construction

Nuwa has three execution domains:

1. The Python payload container registers the payload type and command
   definitions with Mythic and renders the final script.
2. The generated PowerShell script owns callback state, command execution,
   codec dispatch, and its selected transport.
3. The Python translation container converts between Mythic JSON objects and
   Nuwa's custom wire representation.

### Why the translation container exists

The translation container is not required by CLM. It exists because Nuwa
deliberately uses a non-native, pluggable wire format. With
`mythic_encrypts = false`, Mythic can use its native unencrypted JSON path
without a translation container; Nuwa instead sends markerless custom codec
messages, so `nuwa_translation` must convert between Mythic message objects
and those custom bytes. If the custom codec layer were removed, Nuwa could use
the native path and keep only its CLM-safe serialization and transport helpers.

CLM constrains the PowerShell implementation, not the server-side service
topology. Windows PowerShell 5.1 CLM blocks the usual static .NET calls used by
PowerShell agents for byte and Base64 conversion, including
`[System.Text.Encoding]::UTF8.GetBytes(...)` and
`[Convert]::ToBase64String(...)`. Nuwa implements UTF-8 with CLM-safe script
primitives. Legacy HTTP and legacy Discord builds also include a CLM-safe Base64
implementation. Plaintext and static-protected raw HTTP and raw Discord builds
whose selected inner and outer presentations are not Base64 omit that
implementation and every identifier, call, and comment containing `base64` or
`b64`. A staged raw build is the deliberate exception because the
standard Mythic staging JSON contains Base64 text fields even though its outer
framing remains raw.

Custom codecs are an extension point shared by the agent and translation
container. They control message representation independently of transport and
encryption; encoding alone provides no confidentiality or authentication.

The builder requires exactly one C2 profile per payload. It rejects a build
with zero profiles, multiple profiles, or a profile other than `http` or
`discordx`. It then emits an uncompressed UTF-8 `.ps1` by concatenating these
sections in order:

```text
generated configuration and runtime state
UTF-8 helpers
exactly one raw or legacy framing/helper set
runtime timing and response helpers
direct dispatch for exactly one selected inner codec
exactly one selected C2 transport
the selected command implementations
an optional staged-only RSA helper
the static or staged check-in and task-loop entry point
```

This is static composition, not a runtime branch or dynamic loading. An HTTP build contains no
Discord transport implementation or Discord credentials; a Discord build
contains no HTTP endpoint configuration or HTTP transport implementation. The
legacy selection includes the established UUID envelope, file-string, and
credentialed-proxy helpers. The raw selection includes only direct request
framing, byte-array file helpers, and unauthenticated proxy support. The script
starts immediately because the last emitted statement is `Start-Nuwa`.

The builder exposes four Nuwa-specific parameters:

| Parameter | Values | Default | Effect |
| --- | --- | --- | --- |
| `codec_profile` | Registered codec names | `raw` | Selects the one inner message representation compiled into the payload; custom codecs extend the available choices. |
| `debug_logging` | Boolean | `false` | Enables neutral `[Status]` host messages. Plaintext builds retain their existing diagnostics; protected builds never log message bodies or key material. |
| `require_https` | Boolean | `false` | Rejects an HTTP build unless `callback_host` has an HTTPS scheme and nonempty host. It is a non-emitting build policy; Discord already uses HTTPS. |
| `powershell_runtime` | `full-language`, `constrained-language` | `full-language` | Statically selects the optimized .NET-backed Full Language implementation or the CLM-compatible pure-PowerShell protection and staged-RSA implementation. It is build composition only and is not emitted as runtime configuration. |

### Build-time option validation

Nuwa validates the complete submitted option stack before rendering an
artifact. Invalid submissions return one build error containing every
independent problem found and an empty payload; token, password, and key values
are never included in the error. This server-side check applies to both UI and
API payload creation.

The builder enforces the exposed value types and choices, required transport
fields, numeric ranges, proxy consistency, and these cross-option boundaries:

- exactly one `http` or `discordx` C2 profile is required, and a new DiscordX
  payload requires that instance's `wire_protocol` to be `fixed`;
- `encrypted_exchange_check` can be enabled only with keyed
  `nuwa_aes256_hmac_v1`; the historical keyless `aes256_hmac` compatibility
  value is accepted only with exchange disabled;
- protected inner `raw` bytes are invalid over HTTP; DiscordX accepts them with
  `binary-v1`, or with `json-v1` only when historical Base64 UUID framing makes
  the complete inner frame text-safe;
- DiscordX `plain` outer presentation requires unprotected `json-v1`, while
  HTTP `legacy-http` requires outer protection `none`;
- every protected outer mode requires one canonical Base64 32-byte key; an
  auto-materialized key is safely discarded when outer protection is `none`;
- raw UUID framing rejects credentialed proxies and a conflicting
  `X-Mythic-Body-Format` header.

Recommended and release-qualified configurations are a smaller set than valid
configurations. The validator does not reject a mechanically supported stack
merely because it is not recommended or has not completed a release gate.

### Recommended configurations

Treat each row as one complete saved C2 instance and reuse that same instance
for its listener and payloads. The slash-separated stack is `codec_profile` /
UUID framing / outer serializer / outer presentation / outer protection / outer
key mode. The outer serializer, protection, and presentation are applied in
that order even though the table groups them by setting.

| Configuration | Stack | Inner protection | Use |
| --- | --- | --- | --- |
| **Default third-party C2** | `raw` / `raw-v1` / `binary-v1` / `base64` / `chacha20-v1` / `directional` | `none`, exchange off | Default for new DiscordX instances and the baseline for future text-backed third-party transports. ChaCha20 provides confidentiality but not integrity, so use the next row when modification detection matters. |
| **Authenticated outer** | `raw` / `raw-v1` / `binary-v1` / `base64` / `aes256-hmac-v1` / `directional` | `none`, exchange off | Keeps inner messages compact while adding authenticated confidentiality to the listener-shared outer wrapper. |
| **Layered authenticated** | `raw` / `raw-v1` / `binary-v1` / `base64` / `aes256-hmac-v1` / `directional` | `nuwa_aes256_hmac_v1`, staging on | Adds per-execution inner keys beneath authenticated outer protection. Keep distinct inner and outer keys. |
| **Readable development** | `raw` / `raw-v1` / `json-v1` / `plain` / `none` / `single` | `none`, exchange off | Human-readable local diagnostics only; it provides no confidentiality or integrity. |
| **Historical framing compatibility** | `raw` / historical Base64 / `json-v1` / `base64` / `none` / `single` | `none`, exchange off | Compatibility testing for the historical UUID envelope; do not choose it for a new deployment. |

For these rows, `raw-v1` means `use_base64=false`; historical Base64 means
`use_base64=true`. `base64` in the outer-presentation column is independent of
that inner framing switch. New DiscordX instances materialize the first row by
default, including a randomized outer key. Save the instance before starting
the listener or building payloads so both sides retain that same key.

Keep `raw` (recommended) for ordinary plaintext messages. It leaves compact
UTF-8 JSON unchanged and avoids redundant inner expansion when the complete
transport envelope already has its own text presentation. Select another codec
when a different representation is needed. Inner protection produces arbitrary
binary bytes. HTTP requires a text-producing codec for those bytes. DiscordX
`json-v1` requires a text-producing codec or historical Base64 UUID framing;
`binary-v1` can carry protected `raw` bytes directly. Full Language Base64 uses
PowerShell's standard
`[Convert]::ToBase64String` and `[Convert]::FromBase64String` methods. A
constrained-language build statically substitutes a CLM-safe arithmetic
implementation that emits and requires the same canonical padded text.

The shared profiles also expose `AESPSK` and `encrypted_exchange_check` as C2
parameters. Nuwa narrows `AESPSK` to `none`, `nuwa_xor_v1`,
`nuwa_hmac_sha256_v1`, and `nuwa_aes256_hmac_v1`, with `none` as its default.
Despite the shared parameter name, it selects exactly one Nuwa protection
profile rather than always selecting AES. `encrypted_exchange_check` remains
at its no-exchange value for static protection: Boolean `false` for HTTP and
`F` for Discord. An operator may instead enable RSA staging only with
`nuwa_aes256_hmac_v1`: Boolean `true` for HTTP or `T` for Discord. Staging is a
keying mode for that one profile, not another protection layer.

### Fixed outer transport envelope

HTTP and Discord listeners can protect the complete routing wrapper before it
is presented as text. Discord independently selects `json-v1` or `binary-v1`
and a text presentation. Each transport exposes its supported presentations
through the C2 profile. This outer layer is listener-owned and
separate from Nuwa's `AESPSK` inner message protection. The outer key must be
available before Mythic can inspect a payload or callback UUID; the inner key
is selected only after that routing step. Enabling one does not implicitly
enable the other, and the keys must not be reused between layers.

The common C2 parameters are `transport_presentation`,
`transport_protection`, `transport_key_mode`, and `transport_key`. HTTP also
retains its `transport_nonce_strategy` setting; Discord does not expose one and
additionally requires `transport_envelope_format`. Each selected Discord
protection version owns its salt, nonce, or IV construction and uses the
implementation's one internal byte source. `plain` is valid only for
unprotected `json-v1`; other valid configurations use an encoded text
presentation with exactly one of `none`, `xor-obfuscation-v1`, `chacha20-v1`, or
`aes256-hmac-v1`. Presentation changes appearance and transport encoding only;
it does not encrypt or authenticate traffic. The payload contains only that
format, presentation, protection, and
`single` or `directional` key path. It contains no registry, format probe,
clear selector, or alternate outer implementation. Nuwa no longer exposes a
separate Discord envelope build parameter. The saved Discord C2 configuration
is authoritative, so the payload and listener cannot silently select different
channel formats.

Always save and name the C2 instance, then reuse that same saved instance for
the running listener and every payload assigned to it. Mythic persists the
instance's randomized `transport_key`; separate unsaved defaults materialize
different values and cannot communicate. Protected modes require canonical
Base64 for exactly 32 bytes. Mythic can still auto-materialize that conditional
field when protection is `none`; the profile and builder discard it, and no
key bytes enter the generated payload.

The matching Mythic UI exposes an **Active listener** selector in Nuwa's C2
configuration step. It inspects only running, online HTTP and Discord profiles
through Mythic's authorized container-file action and copies the current
listener-owned values into the normal C2 form. For Discord this includes the
channel and credential plus `transport_envelope_format`, presentation,
protection, key mode, key, and legacy Base64 switch. For HTTP it lists each
configured internal port and copies the port and transport-envelope values.
HTTP callback hosts, redirector ports, URIs, timing, and other agent-owned
values are deliberately left unchanged because they cannot be inferred from
an internal listener. Selecting a listener changes only the local form until
the payload is submitted; the named saved instance remains the durable source
for recovery and reuse.

The Discord outer pipeline is `selected envelope serializer -> selected
protection -> selected presentation`. The reverse path invokes exactly the configured
operations and rejects a mismatch without trying plaintext or another codec.
`plain` posts unprotected JSON directly; other presentations encode the
complete envelope as text.
`single` uses the same outer root in both directions. `directional` derives
distinct `agent-to-server` and `server-to-agent` roots. Both exposed nonce
strategies generate a fresh 8-byte XOR salt, 12-byte ChaCha20 nonce, or 16-byte
AES IV in version 1; the byte source is an internal implementation detail, not
another payload option.

| Outer profile | Packet before presentation | Security boundary |
| --- | --- | --- |
| `none` | strict wrapper UTF-8 | Encoding only; no confidentiality or integrity. |
| `xor-obfuscation-v1` | `8-byte salt || XOR body` | Small obfuscation only; known-plaintext and modification attacks remain possible. |
| `chacha20-v1` | `12-byte nonce || IETF ChaCha20 ciphertext` | Confidentiality only when the shared key/nonce stream is not reused. It has no tag and is malleable. |
| `aes256-hmac-v1` | `16-byte IV || AES-256-CBC-PKCS7 ciphertext || 32-byte HMAC-SHA256` | Authenticated confidentiality. The direction is authenticated and the tag is checked before decryption. |

The outer listener key is shared by all matching agents. It hides routing
fields from channel or HTTP-body observers but does not provide per-agent
isolation. Per-agent contents remain isolated only when independent inner
protection is enabled. None of the outer profiles provides replay prevention.
Random ChaCha20 nonce collision risk and endpoint key extraction remain; XOR
and ChaCha20 cannot reliably reject a targeted modification that still forms a
valid wrapper. HTTPS remains independent and recommended because endpoints,
headers, timing, sizes, message-versus-attachment use, and other network
metadata remain observable.

Protected HTTP sends the presentation as a POST body and omits the clear
`X-Mythic-Body-Format` selector. A raw request records `raw-v1` only inside the
protected wrapper. A response can omit that field when Mythic's exact response
body is not UUID-prefixed; Nuwa passes the recovered message unchanged to its
existing response-framing code. Protected Discord uses final presented text
length for the 1,900 UTF-16-unit inline cutoff and uses the neutral attachment
name `message.txt`. Neither carrier transmits a protection, key-mode, nonce,
direction, version, UUID, or route selector outside the protected
presentation.

### Optional static wire protection

Nuwa permits zero or one named protection profile. The profiles are not
arbitrary layers that an operator can reorder; the AES/HMAC profile is one
versioned, reviewed composite with a fixed construction.

| Profile | Wire bytes before the selected inner codec | Security property |
| --- | --- | --- |
| `none` | compact JSON UTF-8 bytes | No confidentiality, integrity, or peer authentication. |
| `nuwa_xor_v1` | plaintext XORed with a repeating 32-byte key | Lightweight obfuscation, not security. It has no nonce or authentication tag and is vulnerable to known-plaintext and key-reuse analysis. |
| `nuwa_hmac_sha256_v1` | `plaintext || HMAC-SHA256(key, plaintext)` | Provides integrity and shared-key authentication, but not confidentiality. |
| `nuwa_aes256_hmac_v1` | `IV || AES-256-CBC-PKCS7(key, plaintext) || HMAC-SHA256(key, IV || ciphertext)` | Provides confidentiality, integrity, and shared-key authentication. Implementations encrypt first and authenticate `IV || ciphertext`, verify the tag before decryption, and use one fresh 16-byte IV for every message. |

Protection is independent of raw versus legacy Base64 framing, the selected
inner codec, Discord wrapper framing, and the `require_https` policy.
Encodings are not substitutes for protection. None of
the current profiles carries a sequence number or nonce ledger, so protection
does not prevent replay. Discord's processed-message tracking reduces duplicate
handling within one process but is not cryptographic replay protection.

Every static protected build contains exactly one 32-byte key and exactly one
profile implementation. The static key is embedded in the generated
PowerShell and is therefore recoverable from the artifact or a compromised
process. It is also reused for that payload's messages. Static protection is
useful against passive content inspection or unauthenticated modification,
depending on the selected profile, but it does not provide forward secrecy or
survive endpoint compromise. Optional RSA staging narrows post-stage key reuse,
but it does not change these limitations for the initial embedded key.

`powershell_runtime` selects one backend at payload construction time; Nuwa
does not inspect PowerShell's language mode or ship both implementations in
one artifact. Omitted and explicit `full-language` builds use the existing
optimized .NET implementation and remain byte-for-byte identical. A
`constrained-language` static XOR, HMAC-SHA256, AES/HMAC, or staged AES/HMAC
build instead contains only the selected pure-PowerShell backend and its
necessary helpers. The plaintext renderer is unchanged for either runtime
selection. Historical keyless `aes256_hmac` selections are also treated as this
no-op compatibility case when exchange is disabled. Enabling exchange with
that value is rejected rather than silently emitting plaintext.

The constrained AES/HMAC backend obtains two independent `[guid]::NewGuid()` values,
requires lowercase canonical version-4 GUID text, decodes their 32 hexadecimal
bytes with script primitives, hashes those bytes with its pure-PowerShell
SHA-256, and transmits the first 16 digest bytes as the established CBC IV.
The GUID strings are ephemeral and never transmitted or logged. This is a
Windows-specific entropy construction; it is not FIPS validated and should not
be represented as a FIPS random-number generator. The pure-PowerShell backend
is materially slower than the Full Language .NET backend and makes no
constant-time or side-channel-resistance claim beyond the best-effort tag
comparison.

### Optional RSA-staged session keys

RSA staging is an optional keying mode for exactly one protection profile,
`nuwa_aes256_hmac_v1`. Set `encrypted_exchange_check=true` for HTTP or `T` for
Discord. `none`, XOR, HMAC-only, and the historical keyless `aes256_hmac`
compatibility shape cannot stage, and protection profiles cannot be layered.
Full Language remains the default; a constrained-language staged build selects
one dedicated pure-PowerShell RSA module instead of dynamically probing or
falling back to a Full Language provider, static key, or plaintext.

A staged execution first authenticates Mythic's standard `staging_rsa`
request and response with the payload UUID and embedded static initial key.
The agent creates an ephemeral 2,048-bit RSA key pair and 20-byte identifier,
then decrypts Mythic's fresh 32-byte session key using RSA-OAEP-SHA1. SHA-1 is
used only because it is the checked-in Mythic interoperability contract. The
CLM module implements bounded two-prime key generation, SHA-1, MGF1, OAEP
decoding, and PKCS#1 PEM serialization with PowerShell primitives and
`[bigint]`; it generates all entropy from Windows version-4 GUIDs. After
validating the echoed identifier, canonical staging UUID, ciphertext, and
exact key length, the agent replaces the UUID and key together. Check-in uses
the staging UUID and session key in the outer envelope while its inner `uuid`
remains the original payload UUID; subsequent traffic uses the callback UUID
and the same session key.

The benefit is per-execution runtime keys: two launches of the same artifact
do not reuse their post-stage session key. The static initial key is still
embedded in every staged artifact and protects the handshake, however, so
artifact disclosure can expose that initial channel. Compromise of a running
process exposes its active key. RSA-OAEP-SHA1 staging does not provide perfect
forward secrecy, does not add replay protection, and does not replace HTTPS;
HTTPS remains recommended for HTTP because endpoints, timing, sizes, and
other transport metadata remain visible.

Staging fails closed after at most three attempts. It never falls back to a
static-key check-in or plaintext. Retries are bounded but not transactionally
idempotent: a lost staging response can leave an orphan staging record, and a
lost staged check-in response can create a duplicate callback before the
agent retries. Operators should diagnose transport and authentication failures
rather than weakening validation.

Raw and legacy outer framing both support staging. A staged raw artifact still
uses raw outer framing (`ASCII UUID || wire bytes`), but its standard staging
JSON necessarily carries `pub_key` and `session_key` as internal Base64 text.
The zero-`base64|b64` source invariant therefore remains exact for plaintext
and static protected raw artifacts, not staged raw artifacts. Selecting no
exchange, whether omitted or explicitly false/`F`, keeps the corresponding
plaintext or static artifact byte-for-byte unchanged and adds no RSA module or
startup work.

### Discord channel envelopes

Discord Nuwa messages contain a Nuwa wire message shared with the translation
container, raw or historical Base64 UUID framing selected by `use_base64`, and
one fixed `transport_envelope_format`. `json-v1` is compact JSON with routing
fields; `binary-v1` is one flags byte, a 36-byte canonical route UUID, and the
inner message bytes. Neither format carries a magic marker, version, codec name,
or negotiation field. The complete envelope is converted to channel text by
the independently selected `transport_presentation`.

With the recommended raw inner codec and raw UUID framing, the wrapper's
`message` value contains `ASCII UUID || compact JSON`. The JSON serializer escapes
the inner JSON's quotes so that value remains a valid wrapper string; parsing
reverses those escapes exactly. That required JSON serialization is not another
Nuwa codec. Plain presentation preserves readable unprotected JSON. Encoded
text presentations support either format; binary is the compact choice for
arbitrary inner bytes such as protected `raw`. The fixed listener reverses
exactly its selected format, presentation, and protection and rejects
mismatches rather than probing. Presented documents are limited
to 2,097,152 UTF-8 bytes, decoded wrapper JSON to 524,288 bytes, and inline
messages to 1,900 UTF-16 code units before attachment use.

Each generated payload contains one inner codec and one fixed outer pipeline.
The agent never probes inner codecs. The translation container probes all
server-supported inner codecs independently for every inbound message, requires
exactly one valid result, and carries the selected name only through the
matching Mythic response as `nuwa_codec_profile`; it stores no agent affinity.

The shared HTTP and DiscordX profiles expose `use_base64`. HTTP retains its
`true` compatibility default, while new DiscordX instances default to `false`
for Nuwa's raw-v1 framing. Missing values remain a historical-compatibility
fallback in the builder, and existing saved instances retain their stored
choice. Nuwa's primary `windows-http-ps1` conformance row explicitly sets it to
`false`; the `windows-http-base64-ps1` row sets it to `true` to prove the
legacy path. `windows-discordx-outer-chacha20-ps1` exercises the new default
DiscordX stack. `windows-discordx-ps1` remains the readable-development row:
`json-v1` with raw framing, the raw inner codec, and plain presentation. The
release-qualification row `windows-discordx-binary-double-protected-ps1` uses
`binary-v1`, raw framing, the raw inner codec, authenticated inner and outer
protection, and Base64 outer presentation.
`windows-discordx-base64-codec-ps1` selects canonical Base64 for both the Nuwa
message codec and the complete Discord channel document; its
`windows-discordx-base64-codec-clm-ps1` counterpart exercises the dedicated
Constrained Language implementation.
The protected release representatives are `windows-http-aes-static-ps1`,
`windows-http-base64-aes-static-ps1`, and
`windows-discordx-aes-static-ps1`. They keep exchange disabled and prove the
same static AES/HMAC profile over both HTTP framings and raw Discord.
The staged representatives are `windows-http-aes-staged-ps1`,
`windows-http-base64-aes-staged-ps1`, and
`windows-discordx-aes-staged-ps1`; they retain the same codec, framing, Discord
envelope, and HTTPS-policy choices while enabling the profile-specific exchange
value.

`windows-http-clm-ps1` and `windows-http-aes-static-clm-ps1` select the
runtime-selected CLM launcher for unprotected and static AES/HMAC raw HTTP.
Protected Discord CLM is build-, shared-vector-, and bounded mock-composition
covered, but this release does not claim a long-running protected Discord
deployment qualification.

Shared profile parameters are materialized into `$script:NuwaConfig`; they are
not read from the environment at runtime. The common configuration contains
the payload UUID, profile name, callback interval and jitter, proxy settings,
kill date, outbound codec profile, inbound decoder profiles, debug flag, and
the fixed 36-character UUID length.
The profile-specific fields are:

| Profile | Embedded fields |
| --- | --- |
| `http` | `callback_host`, `callback_port`, `post_uri`, and `headers` |
| `discordx` | `discord_token`, `bot_channel`, `message_checks`, and `time_between_checks` |

The relevant source boundaries are:

```text
Payload_Type/nuwa/nuwa/mythic/agent_functions/   Mythic builder and task definitions
Payload_Type/nuwa/nuwa/agent_code/base/          shared PowerShell runtime
Payload_Type/nuwa/nuwa/agent_code/codecs/        target-side codecs
Payload_Type/nuwa/nuwa/agent_code/protection/    optional target-side protection
Payload_Type/nuwa/nuwa/agent_code/transport_envelope/ fixed outer wrapper protection/presentation
Payload_Type/nuwa/nuwa/agent_code/staging/       optional RSA staging and staged entry point
Payload_Type/nuwa/nuwa/agent_code/profiles/      target-side transports
Payload_Type/nuwa/nuwa/agent_code/commands/      target-side command handlers
Translation_Containers/nuwa_translation/          server-side wire translation
```

## Runtime lifecycle

`Start-Nuwa` records the initial provider path as Nuwa's logical working
directory, performs check-in, and enters a single-threaded task loop. A staged
entry point completes `Invoke-NuwaRsaStaging` before calling `Start-Nuwa`;
disabled and static builds retain the original entry point exactly.

Check-in sends `action=checkin` under the payload UUID with the current user,
host, domain, PID, payload UUID, architecture, and logical working directory.
The `ip` field is intentionally empty. Nuwa makes at most three check-in
attempts, waiting the configured callback interval between attempts (with a
one-second minimum for this retry path). The callback ID returned by Mythic
replaces the payload UUID for subsequent messages.

Each task-loop iteration performs the following operations:

1. Parse and evaluate the kill date. If it has passed, leave the loop.
2. Request all available tasks with `action=get_tasking` and
   `tasking_size=-1`.
3. Execute returned tasks sequentially in response order.
4. Submit one `action=post_response` message after each task.
5. Sleep for the current interval plus jitter.

Nuwa retains up to 256 completed task responses in memory, keyed by nonempty
task ID. If a task is delivered again, Nuwa resends the cached response instead
of re-executing the command and its side effects. This replay cache is reset
when the process starts.

Jitter is positive-only: for nonzero jitter, the delay is
`interval + interval * (jitter / 100) * U[0,1)`, rounded to milliseconds. It
does not vary symmetrically around the interval. `sleep` changes the in-memory
interval and jitter and reports the new profile sleep state through
`action=update_info`; `cd` similarly reports its logical working directory.

Task exceptions are caught at the dispatcher boundary. Nuwa returns the
formatted PowerShell error in `user_output`, sets `status=error`, and continues
the loop. Tasks are not executed concurrently and there is no task-level
cancellation primitive.

## Wire protocol

Nuwa uses a markerless codec representation with a raw or legacy outer format.
The default plaintext inner transformation is:

```text
Mythic message object
  -> compact JSON
  -> UTF-8 bytes
  -> raw identity codec (the bytes are unchanged)
```

If a fixed transport envelope is configured, those unchanged inner bytes are
placed in its string-valued routing wrapper and only the complete outer wrapper
is protected or presented. This outer-only encoding is JSON-compatible because
the JSON serializer escapes string syntax such as quotes and backslashes; it
does not require an additional inner encoding for valid UTF-8 message text.

The optional inner protection pipeline remains `compact JSON -> UTF-8 -> inner
protection -> selected inner codec`. Its ciphertext, tags, and XOR
output can contain arbitrary bytes. The builder rejects protected `raw` only
when `json-v1` with raw-v1 framing would require those bytes to be UTF-8;
`binary-v1` carries them directly.

Inbound handling reverses that pipeline. A protected receiver selects only the
configured profile: it does not probe protection modes and never retries the
message as plaintext after an authentication failure. HMAC tags are checked
before AES decryption. Codec probing occurs around that one protected contract,
then strict UTF-8 and top-level JSON-object validation complete the parse.

Legacy HTTP (`use_base64=true`, including the missing-value default) then sends
`base64(ASCII UUID || wire message)`. Raw HTTP (`use_base64=false`) sends
`ASCII UUID || wire message` directly and adds
`X-Mythic-Body-Format: raw-v1`. The shared HTTP profile converts that selected
raw request internally to the body Mythic core expects and removes the selector
before proxying. Release review requires no case-insensitive occurrence of
either `base64` or `b64` in a generated plaintext or static raw `.ps1` whose
selected inner and outer presentations are not Base64, and applies that
assertion to the final exported artifact, not only the source fragments.
Staged raw keeps the same raw outer body but permits only the internal Base64
operations required by the standard RSA staging schema.

Discord uses the same inner framing selector inside one saved outer format.
Historical framing contains canonical Base64 of `UUID || wire message`; raw-v1
contains those bytes directly. JSON records raw-v1 as `message_format`, while
binary records it in flag bit 1. The configured listener accepts only its saved
choice; a channel does not negotiate or probe alternate forms.

The configured `codec_profile` selects the outbound inner representation.
`raw` is an identity transform and accepts only messages that subsequently pass
strict UTF-8 and top-level JSON-object validation. Custom codecs can supply
other representations through the same extension point. The translation
container probes every server-supported codec independently per message and
accepts a candidate only after codec
decoding, strict UTF-8 decoding, valid JSON parsing, and confirmation that the
top-level JSON value is an object. Exactly one complete decoder match must
succeed. Zero matches reject malformed or unsupported data, and multiple
matches reject an ambiguous payload rather than making decoder order part of
the protocol. JSON is encoded without
ASCII escaping, so both implementations preserve UTF-8 exactly.

The 36-byte UUID prefix is the ASCII payload UUID during check-in and the ASCII
callback UUID afterward. Each generated agent uses one fixed framing function
and one fixed decoder; a route mismatch or decode failure is silently ignored,
never retried through another framing or codec.

Raw file messages add `nuwa_binary_format: "byte_array"`. Agent-facing
`chunk_data` values are integer arrays containing values from 0 through 255;
the translation container converts only the defined upload/download protocol
locations to and from Mythic's internal Base64 strings. It retains the field on
inbound messages so Mythic can reflect the representation choice and removes it
from the agent-facing response after selecting the outbound representation.

Both implementations construct a codec context containing `direction`,
`uuid`, `message_type`, `c2_profile`, `codec_profile`, and `codec_version`.
These fields support context-sensitive custom codecs. Each inbound decoder receives a
fresh context with its own codec profile. The translation container reports
parse/codec/JSON failures to Mythic as unsuccessful translation responses; it
does not manufacture a fallback message.

This markerless format is an incompatible cutover. Newly built agents and the
updated translation container must be rebuilt and installed together. Legacy
marker-prefixed payloads and older translation containers that require that
marker do not interoperate with this version.

Nuwa keeps `mythic_encrypts = False` because `nuwa_translation`, rather than
Mythic core, owns the optional transform between compact JSON and the selected
inner codec. `generate_keys` returns no key for `none` and returns one random 32-byte
symmetric key pair for a selected static profile. Historical keyless
`aes256_hmac` remains plaintext, while Mythic's keyed staging/callback
`aes256_hmac` runtime value narrowly selects Nuwa's versioned AES/HMAC bytes.
The codec layer provides encoding, not encryption; protection is separate.

## C2 transport semantics

### HTTP

The HTTP transport constructs its endpoint as
`callback_host.TrimEnd('/') + ':' + callback_port + normalized_post_uri` and
sends a POST in the selected outer format. It uses
`Invoke-WebRequest -UseBasicParsing`, copies the configured headers verbatim,
and returns the response content as a string whether PowerShell exposes it as
a string, byte array, or generic array.

`require_https=true` validates `callback_host` during the build and rejects an
HTTP or malformed URL; it does not rewrite the endpoint and emits no runtime
source. Leaving it false preserves existing HTTP and HTTPS behavior and exact
payload bytes. Application-layer wire protection and HTTPS are independent:
HTTPS protects the connection and more metadata, while Nuwa's protected bytes
can remain protected beyond a TLS endpoint. Operators should normally use
both `require_https=true` and `nuwa_aes256_hmac_v1` when the deployment supports
them.

Raw HTTP is POST-only and rejects a completed public body larger than 262,144
UTF-8 bytes before transmission. File chunk sizing accounts for JSON and codec
expansion. The shared profile has a
separate 16 MiB selected-raw ingress limit because it can serve compatible
agents with different budgets.

The default codec uses 16,384-byte raw HTTP/Discord chunks and
51,200-byte legacy HTTP/Discord chunks. More expansive encodings can require
smaller chunks to stay within transport limits.

If `proxy_host` is set, the request uses `proxy_host:proxy_port`. A raw build
rejects nonempty `proxy_user` or `proxy_pass` values. Legacy HTTP and legacy
Discord retain credentialed proxies and add a `Proxy-Authorization: Basic ...`
header. Raw Discord supports an unauthenticated proxy host and port only.
TLS, server authentication, redirects, and HTTP error behavior otherwise come
from `Invoke-WebRequest` and the host's .NET/PowerShell configuration.

### Discord

The Discord transport is a synchronous REST poller over Discord API v10; it
does not use the Discord Gateway. The saved envelope format, presentation,
protection, key mode, and `use_base64` values define one exact pipeline. Binary
envelopes preserve arbitrary inner bytes end to end. Documents of at most 1,900
characters are posted as message content. Larger documents are uploaded as a
neutral `message.txt` attachment. Discord
API JSON, inbound attachment retrieval, and manually rendered outbound
`multipart/form-data` requests all use `Invoke-WebRequest`. The attachment
metadata size is checked before retrieval and the decoded UTF-8 byte count is
checked again after retrieval; either value must not exceed 2,097,152 bytes.

After posting, the agent polls the configured channel up to `message_checks`
times, separated by `time_between_checks` seconds. Candidate responses are
filtered by direction, the current callback ID or allowed payload ID, decoded
action, and, for file transfers, task/file/chunk correlation. Direct polls
follow the posted request's Discord message ID. Because tasking can be posted
while a preceding exchange is still completing, a tasking fallback can scan
channel history; it accepts only messages addressed to the exact live callback
ID and skips already processed Discord message IDs. Tasking polls prefer a
response containing tasks and retain an empty response only as a final
fallback. Nuwa makes a best-effort attempt to delete the matched response
message.

Discord REST calls default to a 30-second timeout and disabled keep-alive.
Rate-limit (`429`) responses honor `retry_after` plus 100 ms; selected `5xx`
responses use a 1.1-second retry delay. A request is attempted at most five
times. The attachment path constructs multipart bytes with PowerShell and
`Invoke-WebRequest`; it does not use `System.Net.Http` and is included in the
qualified runtime-selected CLM transport surface.

## Command reference

All commands are compiled into the payload only when selected at build time.
They execute without elevation checks and share `$script:NuwaState`.

| Command | Arguments | Runtime semantics |
| --- | --- | --- |
| `cd` | `path` | Resolves the target from Nuwa's logical current directory, updates that state without permanently changing the runspace location, and emits `update_info`. |
| `download` | `path` | Reads a target file and sends it to Mythic in 16,384-byte raw HTTP/Discord chunks or 51,200-byte legacy HTTP/Discord chunks. It creates file metadata first, uses the returned file ID, and requires an acknowledgement for each chunk, with up to three attempts per request. |
| `exit` | none | Sets the exit flag. The dispatcher posts the command response before the task loop terminates. |
| `hostname` | none | Returns `COMPUTERNAME`, or `unknown-host` when unavailable. |
| `ls` | optional `path` | Lists hidden and normal entries with `name`, `is_file`, and `size`; output is structured JSON consumed by Mythic's file browser. |
| `shell` | `command` | Runs `Invoke-Expression` in the logical current directory, merges the error stream into output, and returns `$LASTEXITCODE` through `process_response`. |
| `sleep` | `interval`, optional `jitter` | Replaces the in-memory callback timing. Command-line use defaults omitted jitter to 30 percent. |
| `upload` | Mythic `file`, `remote_path` | Pulls a Mythic-hosted file in 16,384-byte raw HTTP/Discord chunks or 51,200-byte legacy HTTP/Discord chunks with up to three attempts per chunk. It removes an existing destination before requesting the first chunk. |
| `whoami` | none | Returns `USERDOMAIN\USERNAME`, `USERNAME`, or `unknown`, in that order. |

Plain task parameters are accepted for `shell`, `download`, `cd`, and `ls`;
other structured parameters are JSON objects. `upload` is designed for named
arguments or Mythic's upload modal rather than a positional command line.

## Constrained Language Mode support

Nuwa's local Windows PowerShell 5.1 test suite covers unprotected HTTP and
Discord payloads plus static XOR, HMAC-SHA256, and AES/HMAC protected HTTP
payloads running in runtime-selected `ConstrainedLanguage` mode for:

- Check-in, task polling, task response submission, and Discord attachment
  upload/download transport paths
- The `sleep`, `cd`, `whoami`, `hostname`, `ls`, `shell`, and `exit` commands
- The `upload` and `download` transfer commands
- The tested codecs and their UTF-8, transport framing, and
  Discord envelope helpers
- Pure-PowerShell SHA-256/HMAC, AES-256-CBC/PKCS#7, shared wire vectors,
  authenticated tamper rejection, and GUID-derived IV parsing

The following limitations apply:

- Full Language remains the default. A CLM staged build selects a
  pure-PowerShell RSA backend and never dynamically falls back to the Full
  Language backend.
- The pure-PowerShell crypto implementation is not FIPS validated and may be
  slower or expose different timing behavior than the .NET implementation.
- `shell` tasks remain subject to CLM itself. Commands or APIs blocked by the
  host's language mode remain unavailable through Nuwa.
- Runtime-selected `ConstrainedLanguage` validation does not replace
  qualification under an enforced AppLocker or Windows Defender Application
  Control policy, which can impose additional restrictions.

Runtime-selected CLM support is limited to the tested Windows PowerShell 5.1
command and transfer surface. The unprotected `windows-discordx-clm-ps1`
representative is deployment-qualified for that surface. Its live debug Gate B
and independent release Gate C passed the declared command, upload, download,
state, exit, and cleanup lifecycle. Protected HTTP CLM staging is qualified by
its own raw and legacy HTTP campaigns; protected Discord CLM staging remains
limited to build, vector, and local mock coverage. These qualifications do not
extend to enforced application-control environments.

## Security and trust boundaries

- C2 and proxy values are build-time material. A Discord token or proxy
  password is embedded as a PowerShell string in the generated artifact.
- Raw HTTP does not permit proxy credentials; use an unauthenticated proxy or
  select legacy HTTP when a credentialed proxy is required.
- The wire codec provides no confidentiality or tamper detection. Use an HTTPS
  callback URL when an unprotected HTTP transport needs connection
  confidentiality; Discord API requests use HTTPS. For application-layer
  protection, prefer `nuwa_aes256_hmac_v1`; HMAC-only does not hide content and
  XOR must not be treated as a security control.
- Static protection keys are embedded in the artifact, provide no forward
  secrecy, and do not prevent replay. An endpoint compromise exposes both
  plaintext and the active key. HTTPS remains recommended because Nuwa's wire
  layer does not hide destinations, timing, sizes, or all transport metadata.
- RSA staging limits reuse of the post-stage session key, but its authenticated
  initial exchange still depends on the embedded static key and interoperable
  RSA-OAEP-SHA1. It does not provide perfect forward secrecy. Never retain
  private RSA material, session keys, or unredacted handshake traffic in build
  output, logs, fixtures, or gate evidence.
- The CLM RSA implementation is intentionally small and pure PowerShell. It is
  slower, GUID-backed, not FIPS validated, not RSA-blinded, and not
  constant-time. It is compatible with runtime-selected CLM, not proof that a
  particular enforced WDAC or AppLocker policy permits every operation.
- `debug_logging=true` writes callback identifiers, actions, endpoints, and
  decoded response JSON to the PowerShell host in backward-compatible
  plaintext builds. In a protected build, debug logging does not log plaintext
  or protected message bodies, HMAC values, or keys. Treat all debug payload
  output as sensitive.
- Nuwa's `debug_logging` controls only agent-side output; Mythic server-side
  logging is separate. On Mythic builds without key-material redaction, keep
  the global `mythic_debug_agent_message` / `debug_agent_message` setting false
  when using protected profiles. Older server debug and staging-error paths may
  serialize request fields or key-bearing records. This release was validated
  with equivalent Mythic core redaction; apply that hardening before enabling
  server-side logging in another deployment.
- `shell` deliberately evaluates operator-supplied PowerShell. Nuwa does not
  add a sandbox beyond the token, language mode, application-control policy,
  and privileges of the hosting process.
- `upload` overwrites an existing destination. File paths are resolved relative
  to Nuwa's logical working directory unless absolute or UNC.
- Discord channel history is a shared persistence and correlation surface.
  Message deletion is best-effort and is not a retention guarantee.

## Development and validation

Run focused unit tests from the workspace root:

```shell
python3 -m pytest Mythic_Agents/Nuwa/tests/unit -q
```

Run Nuwa's generated-artifact and mock-protocol gate with:

```shell
make -C Mythic_Agents/Nuwa gate-a
```

The checked-in implementation and tests are authoritative when this document
and behavior diverge. `PUBLIC_RELEASE.md` describes the separate sanitized
public-export workflow.
