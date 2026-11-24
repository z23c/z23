# Regtest reply shapes: what a real Z23 node answers

These files are real replies from a real `z23` node running in `-regtest`
mode in an isolated, throwaway datadir. Every address, txid and amount in them
is a regtest value; nothing here is mainnet data and no key or passphrase is
in any file. They are the truth for what a node returns to the calls a wallet
front end makes. A mock node used by a GUI test must match these shapes.

Each file is one call in one case:

```json
{"case":"<name>","request":[<words after the binary>],"exit":0,"reply":<what the node printed>}
```

- `request` is the exact argument list after `z23 -datadir=... -rpcport=...`:
  a native command path with its `--input=<json>`, or a legacy-compatible RPC
  method with its positional parameters. A passphrase is never recorded.
- `exit` is the process exit status; `0` means the command succeeded.
- `reply` is the JSON the node printed. A reply that is not JSON (a bare txid,
  a bare decimal balance, an error line) is recorded as a JSON string.

File names are `<case>.<step>.json`, for example `shield.plan.json`,
`shield.commit.json`, `zz_text.commit_repeat.json`, `refuse.invalid_address.commit.json`.
The case names follow the transaction matrix in
`tests/harness/src/test_wallet_tx_matrix_regtest.c`:
`fund` (funding), `t2t`, `shield` (t to z), `zz_text` and `zz_bin` (z to z with a
text and a non-UTF-8 memo), `deshield` (z to t), `multi` (four recipients),
`refuse.*` (refusals), `legacy.*` (legacy-compatible methods), `max_z` and
`max_t` (exact-balance sends), `lock.*` (wallet lock).

## How they are kept honest

`make t-fast ONLY=wallet_tx_matrix_regtest` replays the matrix against a fresh
regtest node and compares every live reply with its file here: the same field
names, nested the same way, with the same value types (array shapes by their
first element), and the same exit class. A reply whose shape drifts fails the
group. Values (txids, times, amounts) are not compared; the test asserts the
balances, confirmations and memos separately, in integer zatoshi.

To re-record after an intended change to a reply, run
`ZCL_REGTEST_SHAPES_RECORD=1 make t-fast ONLY=wallet_tx_matrix_regtest` and
review the diff: a changed shape is a changed interface.

The legacy zclassicd replies for the same matrix are in
`../regtest_shapes_legacy/`.

Three files are documentation only and are not compared: `legacy.z_validateaddress`,
`legacy.z_getoperationstatus` and `legacy.z_getoperationresult` record the
refusal this node gives for a legacy method it does not have. The command
client prints it either as `error=UNKNOWN_COMMAND detail=...` text (recorded) or
as a `zcl.result.v1` envelope with `ok:false`, so the test only asserts that the
call fails and names an `UNKNOWN_` code.

## Conventions a front end must know

- Money in the native commands is a decimal string with eight places
  (`"5.00000000"`) and, where stated, `*_zat` integers. The legacy methods
  return JSON numbers or decimal text (`z_gettotalbalance`) as zclassicd does.
- A native refusal is `ok:false` with `error.code`, `error.message` and exit
  status non-zero. The legacy client prints `Error: ...` on stderr and exits
  non-zero.
- Shielded sends are plan then commit. `core.wallet.shielded.send` takes
  `from` and `to` that may each be transparent or shielded; its commit is
  keyed (`idempotency_key`) and a repeat returns `replayed:true` with the same
  txid. `core.wallet.transaction.send` (transparent only) is not deduplicated.
- The plan validates little: an invalid address, a memo to a transparent
  recipient and an amount above the balance are accepted by the plan and
  refused (or not) only at commit. A zero or malformed amount is refused at
  the plan.
- `getbalance` and `z_gettotalbalance` count confirmed funds only. A send that
  is not yet mined is visible in `core.wallet.history` as `status:"pending"`,
  `confirmations:0`, and in `listtransactions` with `confirmations:0`.
- A shielded note must have 10 confirmations (3 for a change note the wallet
  made) before it can be spent.
- A memo that is valid UTF-8 is read back in the note's `memo` field; one that
  is not is read back as `memo_hex`.
