# Telegram from z23

`z23 telegram` lets any agent or operator on a fleet host message the owner
through one Telegram bot and read the owner's replies. Four leaves live under
`ops telegram`; `z23 telegram <leaf>` is the short spelling.

| Command | Does | MCP |
|---|---|---|
| `telegram status` | checks the credentials file, asks the bot `getMe`, reports the poll lock | read |
| `telegram send` | sends text to the owner chat | needs `idempotency_key` |
| `telegram inbox` | takes new direct messages from allowlisted users | read |
| `telegram configure` | writes the credentials file from stdin | refused (owner authority) |

## Setup

The credentials live in `~/.config/z23/telegram.env`, mode 0600:

```
TELEGRAM_BOT_TOKEN=<bot id>:<secret>
TELEGRAM_CHAT_ID=<owner numeric user id>
TELEGRAM_ALLOW_FROM=<optional comma list of further user ids>
```

On a new host pipe the file in; the token never goes in arguments:

```sh
ssh other-host 'z23 telegram configure' < ~/.config/z23/telegram.env
z23 telegram status
```

`Z23_TELEGRAM_ENV` names a different credentials path. A file that is a
symlink, is not yours, or has any group or other permission bit is refused
with `TELEGRAM_CREDENTIALS_NOT_PRIVATE`; fix it with `chmod 600`.

## Send

```sh
z23 telegram send --text='build finished' --idempotency_key=build-42
echo '{"text":"42"}' | z23 telegram send --input=-
```

- Text over 4096 UTF-16 units is split on character boundaries and sent as
  several messages, up to 12000 bytes in all. The reply lists the message ids.
- `chat_id` defaults to `TELEGRAM_CHAT_ID` and must be that id or one in
  `TELEGRAM_ALLOW_FROM`.
- A repeated `idempotency_key` returns the first send's ids and sends nothing.
- Text holding the bot token, an API key shape, a mention of a private key,
  seed phrase or mnemonic, or an onion address is refused with
  `TELEGRAM_SECRET_REFUSED` before any request.
- A value that looks like a number or `true`/`false` in `--text=` is read as
  that type; send such text through `--input`.

## Receive: one poller per bot

Telegram allows exactly one `getUpdates` consumer per bot token across every
host. A second poller gets `409 Conflict`, reported as `POLLER_CONFLICT`.
Sending works from any number of hosts. Choose one host to receive and run
`telegram inbox` only there.

```sh
z23 telegram inbox --wait_s=30
```

- One `getUpdates` call from the offset saved under the z23 state root
  (`telegram/offset-<bot id>`, owner-private). The offset advances past what is
  returned, so each message is delivered once; `more: true` asks for another call.
- Only direct messages from `TELEGRAM_CHAT_ID` and `TELEGRAM_ALLOW_FROM` users
  are returned. Everything else is dropped and counted in `dropped`.
- An exclusive lock (`telegram/poll.lock`) stops two processes on one host from
  polling together (`POLL_LOCKED`).
- Message text is cut at 3000 bytes (`truncated: true`).

## Transport

The z23 binary links no TLS client and no trust store by design, so requests
run through the host `curl` with certificate verification. The bot URL, which
holds the token, goes into a config file in a fresh owner-private temporary
directory read by `curl -q -K`; it is removed when the call returns, so the
token is never in argv. Hosts without IPv6 routes fall back to IPv4 inside curl.
`Z23_TELEGRAM_API` may name a `https://` or loopback `http://127.0.0.1:` base for tests.

## Not covered

Streaming edits, photos and files, groups and inline keyboards are not
implemented. Messages are plain text.
