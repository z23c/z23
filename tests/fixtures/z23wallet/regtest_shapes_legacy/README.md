# Regtest reply shapes: what legacy zclassicd answers

The same transaction matrix as `../regtest_shapes/`, run once by hand against a
legacy `zclassicd` v2.1.2-beta6 in `-regtest` mode with a throwaway datadir,
loopback-only RPC and no peers, driven through `zclassic-cli`:
`z_sendmany` then `z_getoperationstatus` polling, then `z_getoperationresult`.
All values are regtest values; no key or passphrase is in any file.

The format is the one in `../regtest_shapes/README.md`, with two differences:
`request` is the single command line as a string, and `reply` is the JSON
`zclassic-cli` printed (pretty-printed) or a JSON string for text.

Unlike the Z23 files these are a recorded run, not a test: nothing replays
them. Re-run by starting a regtest `zclassicd` with
`-nuparams=5ba81b19:1 -nuparams=76b809bb:1` (Sapling is otherwise not active on
regtest) and replaying the matrix.

What the run showed about legacy behaviour a front end depends on:

- `z_sendmany` returns an operation id; the txid comes from
  `z_getoperationstatus` / `z_getoperationresult` (`result.txid`).
- Default fee is `0.0001` (10000 zatoshi).
- Coinbase funds can only be shielded (`z_shieldcoinbase`, or `z_sendmany` to a
  single zaddr); a transparent spend of coinbase fails in the operation with
  `Could not find any non-coinbase UTXOs to spend.`
- `z_sendmany` `memo` is hex. `z_listreceivedbyaddress` returns it as 1024 hex
  characters, zero padded.
- A memo to a transparent recipient is refused at the call:
  `Memo cannot be used with a taddr.  It can only be used with a zaddr.`
- An unknown address is refused at the call; insufficient funds and a zero
  amount are decided inside the operation (zero amount succeeds as a
  fee-only transaction).
- There is no idempotency key: repeating the same `z_sendmany` sends twice.
- `encryptwallet` is disabled (`wallet encryption is disabled`), so there is no
  locked-wallet case.
