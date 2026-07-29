# Nuwa

Nuwa is a Windows PowerShell 5.1 agent for the Mythic framework. It supports
Mythic's HTTP and Discord C2 profiles through a custom translation container.

Only use Nuwa on systems you own or are explicitly authorized to test.

## Installation

Clone this repository, then install it from the Mythic directory with an
absolute path:

```shell
./mythic-cli install folder /absolute/path/to/Nuwa -f
```

## Supported C2 profiles

- `http`
- `discord`

Discord builds use Mythic's shared `discord` C2 profile and require its normal
`discord_token` and `bot_channel` build parameters. Credentials are supplied at
build time and must never be committed to this repository.

## Commands

- `cd`
- `download`
- `exit`
- `hostname`
- `ls`
- `shell`
- `sleep`
- `upload`
- `whoami`

Public releases are curated snapshots of Nuwa's development tree. Internal
automation, test evidence, local instructions, and private Git history are not
part of this repository.
