# Nuwa

Nuwa is a single-file Windows PowerShell 5.1 agent for Mythic v3.4 designed for evasion through simplicity and rapid iteration. It
supports the shared `http` and `discord` C2 profiles through the
`nuwa_translation` translation container. The generated HTTP payload provides
partial support for Windows PowerShell 5.1 Constrained Language Mode (CLM).

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
omit that implementation and every identifier, call, and comment containing
`base64` or `b64`. A staged raw build is the deliberate exception because the
standard Mythic staging JSON contains Base64 text fields even though its outer
framing remains raw. The decimal encoding is a deliberately simple
reference codec for the cross-language codec extension point, not a CLM
requirement. It is easy to inspect and validate and produces transport-safe
ASCII, but its three-digit representation expands every input byte 3x and
provides no confidentiality, integrity, authentication, or security boundary.

The builder requires exactly one C2 profile per payload. It rejects a build
with zero profiles, multiple profiles, or a profile other than `http` or
`discord`. It then emits an uncompressed UTF-8 `.ps1` by concatenating these
sections in order:

```text
generated configuration and runtime state
UTF-8 helpers
exactly one raw or legacy framing/helper set
runtime timing and response helpers
codec dispatch and every bundled codec
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
| `codec_profile` | `decimal` | `decimal` | Selects outbound encoding; inbound decoding probes every bundled codec. |
| `discord_envelope_codec` | `decimal`, `legacy-json` | `decimal` | Selects how the complete Discord wrapper is rendered; it has no effect on HTTP artifacts. |
| `debug_logging` | Boolean | `false` | Enables neutral `[Status]` host messages. Plaintext builds retain their existing diagnostics; protected builds never log message bodies or key material. |
| `require_https` | Boolean | `false` | Rejects an HTTP build unless `callback_host` has an HTTPS scheme and nonempty host. It is a non-emitting build policy; Discord already uses HTTPS. |

The shared profiles also expose `AESPSK` and `encrypted_exchange_check` as C2
parameters. Nuwa narrows `AESPSK` to `none`, `nuwa_xor_v1`,
`nuwa_hmac_sha256_v1`, and `nuwa_aes256_hmac_v1`, with `none` as its default.
Despite the shared parameter name, it selects exactly one Nuwa protection
profile rather than always selecting AES. `encrypted_exchange_check` remains
at its no-exchange value for static protection: Boolean `false` for HTTP and
`F` for Discord. An operator may instead enable RSA staging only with
`nuwa_aes256_hmac_v1`: Boolean `true` for HTTP or `T` for Discord. Staging is a
keying mode for that one profile, not another protection layer.

### Optional static wire protection

Nuwa permits zero or one named protection profile. The profiles are not
arbitrary layers that an operator can reorder; the AES/HMAC profile is one
versioned, reviewed composite with a fixed construction.

| Profile | Wire bytes before the decimal codec | Security property |
| --- | --- | --- |
| `none` | compact JSON UTF-8 bytes | No confidentiality, integrity, or peer authentication. |
| `nuwa_xor_v1` | plaintext XORed with a repeating 32-byte key | Lightweight obfuscation, not security. It has no nonce or authentication tag and is vulnerable to known-plaintext and key-reuse analysis. |
| `nuwa_hmac_sha256_v1` | `plaintext || HMAC-SHA256(key, plaintext)` | Provides integrity and shared-key authentication, but not confidentiality. |
| `nuwa_aes256_hmac_v1` | `IV || AES-256-CBC-PKCS7(key, plaintext) || HMAC-SHA256(key, IV || ciphertext)` | Provides confidentiality, integrity, and shared-key authentication. Implementations encrypt first and authenticate `IV || ciphertext`, verify the tag before decryption, and use a fresh random 16-byte IV for every message. |

Protection is independent of raw versus legacy Base64 framing, the decimal
inner codec, Discord's outer envelope codec, and the `require_https` policy.
Base64 and decimal remain encodings, not substitutes for protection. None of
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

All protected profiles require Windows PowerShell 5.1 Full Language Mode.
Only the unprotected HTTP surface retains the CLM qualification described
below. When protection is omitted, or explicitly set to `none` together with
`require_https=false`, the builder selects the unchanged plaintext renderer:
the generated payload is byte-for-byte identical to the corresponding
pre-protection artifact and contains no protection code or key. Historical
keyless `aes256_hmac` selections are also treated as this no-op compatibility
case rather than silently enabling a new protocol.

### Optional RSA-staged session keys

RSA staging is an optional keying mode for exactly one protection profile,
`nuwa_aes256_hmac_v1`. It requires Windows PowerShell 5.1 Full Language Mode.
Set `encrypted_exchange_check=true` for HTTP or `T` for Discord. `none`, XOR,
HMAC-only, and the historical keyless `aes256_hmac` compatibility shape cannot
stage, and protection profiles cannot be layered.

A staged execution first authenticates Mythic's standard `staging_rsa`
request and response with the payload UUID and embedded static initial key.
The agent creates an ephemeral 2,048-bit RSA key pair and random session
identifier, then decrypts Mythic's fresh 32-byte session key using
RSA-OAEP-SHA1. SHA-1 is used only because it is the checked-in Mythic
interoperability contract. After validating the echoed session identifier,
canonical staging UUID, ciphertext, and exact key length, the agent replaces
the UUID and key together. Check-in uses the staging UUID and session key in
the outer envelope while its inner `uuid` remains the original payload UUID;
subsequent traffic uses the callback UUID and the same session key.

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

Discord Nuwa messages have three independent layers: the inner Nuwa codec
shared with the translation container, raw or legacy UUID framing selected by
`use_base64`, and the outer channel envelope shared with the Discord C2
profile. The default outer `decimal` codec converts every compact wrapper JSON
UTF-8 byte to three digits, so both inline channel content and Nuwa wrapper
attachments contain digits only. Discord's HTTPS REST request is still JSON;
decimal is reversible encoding, not encryption.

`legacy-json` retains readable wrappers for compatibility. The profile probes
that format and every registered codec, accepts exactly one complete match,
and fails closed on zero or ambiguous matches. Encoded documents are limited
to 2,097,152 UTF-8 bytes, decoded wrapper JSON to 524,288 bytes, and inline
messages to 1,900 UTF-16 code units before attachment use.

An envelope codec is an arbitrary trusted local encode/decode function pair,
not an alphabet setting. Adding one requires matching PowerShell and C# source,
a valid lowercase name, declared worst-case expansion, Unicode golden vectors,
malformed and ambiguity tests, CLM validation, and matched Nuwa/profile
deployment. Code is materialized and reviewed at build/install time; messages
never carry source and no runtime evaluation is allowed. Retire a codec only
after rebuilding all active payloads, then remove both peers and verify old
traffic fails without readable fallback.

The shared HTTP and Discord profiles expose `use_base64`. Its default is
`true` for compatibility with existing agents. Nuwa's primary
`windows-http-ps1` conformance row explicitly sets it to `false`; the
`windows-http-base64-ps1` row sets it to `true` to prove the legacy path.
The Discord rows follow the same convention: `windows-discord-ps1` is raw with
the decimal outer envelope, `windows-discord-base64-ps1` combines legacy inner
framing with the decimal outer envelope, and
`windows-discord-json-envelope-ps1` proves readable outer-wrapper compatibility.
The protected release representatives are `windows-http-aes-static-ps1`,
`windows-http-base64-aes-static-ps1`, and
`windows-discord-aes-static-ps1`. They keep exchange disabled and prove the
same static AES/HMAC profile over both HTTP framings and raw Discord.
The staged representatives are `windows-http-aes-staged-ps1`,
`windows-http-base64-aes-staged-ps1`, and
`windows-discord-aes-staged-ps1`; they retain the same codec, framing, Discord
envelope, and HTTPS-policy choices while enabling the profile-specific exchange
value.

Shared profile parameters are materialized into `$script:NuwaConfig`; they are
not read from the environment at runtime. The common configuration contains
the payload UUID, profile name, callback interval and jitter, proxy settings,
kill date, outbound codec profile, inbound decoder profiles, debug flag, and
the fixed 36-character UUID length.
The profile-specific fields are:

| Profile | Embedded fields |
| --- | --- |
| `http` | `callback_host`, `callback_port`, `post_uri`, and `headers` |
| `discord` | `discord_token`, `bot_channel`, `message_checks`, and `time_between_checks` |

The relevant source boundaries are:

```text
Payload_Type/nuwa/nuwa/mythic/agent_functions/   Mythic builder and task definitions
Payload_Type/nuwa/nuwa/agent_code/base/          shared PowerShell runtime
Payload_Type/nuwa/nuwa/agent_code/codecs/        target-side codecs
Payload_Type/nuwa/nuwa/agent_code/protection/    optional target-side protection
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
For the current decimal profile, the common inner transformation is:

```text
Mythic message object
  -> compact JSON
  -> UTF-8 bytes
  -> the selected protection profile, if any
  -> each byte rendered as exactly three ASCII decimal digits
```

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
either `base64` or `b64` in a generated plaintext or static raw `.ps1` and
applies that assertion to the final exported artifact, not only the source fragments.
Staged raw keeps the same raw outer body but permits only the internal Base64
operations required by the standard RSA staging schema.

Discord uses the same build-time selector, but its wrapper is a UTF-8 JSON
contract rather than an HTTP header contract. Legacy Discord omits
`message_format` and carries the established UUID envelope. Raw Discord adds
`"message_format":"raw-v1"` and carries `ASCII UUID || markerless wire
message` directly in `message`. The shared profile validates that the first 36
ASCII bytes are a canonical UUID equal to `sender_id`, limits raw wrappers to
262,144 UTF-8 bytes, and forwards raw text through Mythic's raw message field.
One Discord channel can carry both forms because the selector is per wrapper.

For example, the UTF-8 bytes for `{}` are `123,125`, so their codec body is
the complete markerless wire message `123125`. The decimal codec expands the
JSON byte stream by exactly 3x before Base64 overhead.

The configured `codec_profile` selects outbound encoding. Inbound decoding
probes every statically bundled codec and accepts a candidate only after codec
decoding, strict UTF-8 decoding, valid JSON parsing, and confirmation that the
top-level JSON value is an object. Exactly one complete decoder match must
succeed. Zero matches reject malformed or unsupported data, and multiple
matches reject an ambiguous payload rather than making decoder order part of
the protocol. Decimal candidates also reject non-digit data, lengths not
divisible by three, and groups outside `000..255`. JSON is encoded without
ASCII escaping, so both implementations preserve UTF-8 exactly.

The 36-byte UUID prefix is the ASCII payload UUID during check-in and the ASCII
callback UUID afterward. A raw build accepts only the bare markerless response
produced by the translation container. A legacy build treats that bare response
and a complete Base64 UUID envelope as separate framing candidates, probes all
bundled codecs across both, and accepts exactly one framing/codec match. An
envelope with a UUID other than the expected nonempty UUID is discarded.

Raw file messages add `nuwa_binary_format: "byte_array"`. Agent-facing
`chunk_data` values are integer arrays containing values from 0 through 255;
the translation container converts only the defined upload/download protocol
locations to and from Mythic's internal Base64 strings. It retains the field on
inbound messages so Mythic can reflect the representation choice and removes it
from the agent-facing response after selecting the outbound representation.

Both implementations construct a codec context containing `direction`,
`uuid`, `message_type`, `c2_profile`, `codec_profile`, and `codec_version`. The
v1 decimal codec is context-independent, but these fields define the extension
point for a future context-sensitive codec. Each inbound decoder receives a
fresh context with its own codec profile. The translation container reports
parse/codec/JSON failures to Mythic as unsuccessful translation responses; it
does not manufacture a fallback message.

This markerless format is an incompatible cutover. Newly built agents and the
updated translation container must be rebuilt and installed together. Legacy
marker-prefixed payloads and older translation containers that require that
marker do not interoperate with this version.

Nuwa keeps `mythic_encrypts = False` because `nuwa_translation`, rather than
Mythic core, owns the optional transform between compact JSON and the decimal
codec. `generate_keys` returns no key for `none` and returns one random 32-byte
symmetric key pair for a selected static profile. Historical keyless
`aes256_hmac` remains plaintext, while Mythic's keyed staging/callback
`aes256_hmac` runtime value narrowly selects Nuwa's versioned AES/HMAC bytes.
The decimal transform itself is still encoding, not encryption, compression,
integrity protection, or authentication.

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
UTF-8 bytes before transmission. Its file chunks are 16,384 bytes to leave room
for integer-array JSON and decimal-codec expansion. The shared profile has a
separate 16 MiB selected-raw ingress limit because it can serve compatible
agents with different budgets.

If `proxy_host` is set, the request uses `proxy_host:proxy_port`. A raw build
rejects nonempty `proxy_user` or `proxy_pass` values. Legacy HTTP and legacy
Discord retain credentialed proxies and add a `Proxy-Authorization: Basic ...`
header. Raw Discord supports an unauthenticated proxy host and port only.
TLS, server authentication, redirects, and HTTP error behavior otherwise come
from `Invoke-WebRequest` and the host's .NET/PowerShell configuration.

### Discord

The Discord transport is a synchronous REST poller over Discord API v10; it
does not use the Discord Gateway. Missing or true `use_base64` sends the legacy
UUID envelope in a JSON wrapper with `message`, `sender_id`, `to_server`, `id`,
and `final` fields. False sends the raw UUID-prefixed markerless decimal text
and adds `message_format: "raw-v1"`. Discord responses remain markerless
decimal UTF-8 text; arbitrary binary response text is outside this transport
contract. Wrappers of at most 1,900 characters are posted as message content.
Larger wrappers are uploaded as a `nuwa-server` JSON attachment.

After posting, the agent polls the configured channel up to `message_checks`
times, separated by `time_between_checks` seconds. Candidate responses are
filtered by direction, client/payload ID, request timestamp, decoded action,
and, for file transfers, task/file/chunk correlation. Tasking polls prefer a
response containing tasks and retain an empty response only as a final
fallback. Processed Discord message IDs are retained in memory to avoid replay;
Nuwa also makes a best-effort attempt to delete the matched response message.

Discord REST calls default to a 30-second timeout and disabled keep-alive.
Rate-limit (`429`) responses honor `retry_after` plus 100 ms; selected `5xx`
responses use a 1.1-second retry delay. A request is attempted at most five
times. The attachment path uses temporary files and `System.Net.Http`, which is
one reason it is outside the CLM-qualified surface.

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

Nuwa's generated HTTP payload has been validated with Windows PowerShell 5.1
running in `ConstrainedLanguage` mode for:

- HTTP check-in, task polling, and task response submission
- The `sleep`, `cd`, `whoami`, `hostname`, `ls`, `shell`, and `exit` commands
- The custom decimal codec and its UTF-8 and transport framing helpers

The following limitations apply:

- `upload` and `download` are not CLM-compatible because their current
  response handling invokes methods on non-core PowerShell objects.
- The Discord transport is not CLM-qualified. Its oversized-message and
  attachment path uses non-core `System.IO` and `System.Net.Http` APIs that CLM
  blocks.
- Every protected profile is Full Language Mode only because its PowerShell
  implementation uses .NET cryptographic types that are outside Nuwa's
  qualified CLM surface. This includes XOR despite its simple wire operation;
  the protected dispatcher is qualified as one Full-Language-only surface.
- `shell` tasks remain subject to CLM itself. Commands or APIs blocked by the
  host's language mode remain unavailable through Nuwa.
- Runtime-selected `ConstrainedLanguage` validation does not replace
  qualification under an enforced AppLocker or Windows Defender Application
  Control policy, which can impose additional restrictions.

Nuwa is not fully CLM-compatible. Use the HTTP profile and the validated
command subset when CLM compatibility is required.

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
