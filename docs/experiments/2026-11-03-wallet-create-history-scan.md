<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Wallet create on a datadir whose secondary indexes are dropped

Date: 2026-11-03
Compiler: cc (Ubuntu 14.2.0-4ubuntu2~24.04.1) 14.2.0
CPU: AMD Ryzen 9 7950X3D 16-Core Processor
Host: Linux 6.8.0-139-generic, 93 GiB RAM

## Question

On 2026-11-03 a phone create ran `core wallet recovery restore` with its
birthday at the local tip for 13 minutes without writing anything. At the
time, a node.db history catch-up bulk pass had dropped the secondary
indexes. Which part of the restore spends that time, and what changes when
a phrase made just now no longer reads chain history?

## Field evidence

- The app's request (`restore_request` in `apps/z23android/setup_node.c`)
  carries `shielded_only` and `birthday_at_local_tip`. A shielded-only
  rebuild never runs the transparent gap scan, so per-address history probes
  were not the cost on the phone.
- A stack of the restore process at 12:33:46Z reads `wallet_recovery_run`,
  then two unnamed Z23 frames, then `sqlite3_step`, then SQLite frames in
  which one return address repeats three times (b-tree recursion, as in the
  integrity check). `node_db_open` tail-calls the static `node_db_open_impl`,
  which reaches `db_quick_check_ok`, the Z23 function that steps
  `PRAGMA quick_check(1)` directly. The restore was in its second full
  integrity read of node.db.
- The node log shows the catch-up's first bulk-mode entry at 12:09:54Z
  failing every `DROP INDEX` ("database table is locked") and then printing
  "indexes dropped". The entry at 12:12:11Z dropped them. The indexes were
  absent when the create began at 12:20:11Z.

## Method

Fixture: a node.db made by the base binary (a restore into an empty
datadir) with its wallet rows deleted, filled with connected blocks 0..200,
18,000,000 `tx_outputs` rows, 3,600,000 `utxos` rows and 10,800,000
`tx_inputs` rows. Each txid is an 8-byte big-endian counter followed by 24
random bytes; `address_hash` is 20 random bytes, NULL in one row in ten.
The 19 secondary indexes `node_db_drop_indexes` removes were then dropped.
The file is 7,315,968,000 bytes.

Each run copies the fixture to tmpfs and runs

```sh
ZCL_ALLOW_PLAINTEXT_WALLET=1 ZCL_RECOVERY_PHRASE="<test-vector phrase>" \
  z23 core wallet recovery restore \
  --input='{"datadir":"<copy>","confirm":true<flags>}' --format=json
```

with the BIP39 test-vector phrase of `tests/harness/src/test_wallet_create.c`,
sampling `/proc/<pid>/io` every 200 ms. tmpfs keeps the host disk out of the
timing; other jobs saturated it during the measurement (IO pressure "full"
52-56 %). `rchar` counts the bytes the process read, which a phone reads
from flash. The base binary is origin/main cc12d2f828; the fix binary is
59ed41a2a9. Base and fix runs alternate.

- App request: `"shielded_only":true,"birthday_at_local_tip":true`.
- Transparent at-tip request: `"birthday_at_local_tip":true`.

## Results

| Run | Wall | Bytes read | Bytes written | `create_schema` | boot `quick_check` | History consulted |
|---|---:|---:|---:|---:|---:|---|
| base, app 1 | 79.6 s | 23,344,169,392 | 5,582,765,592 | 71.1 s | 3.9 s | false |
| fix, app 1 | 75.1 s | 23,344,169,417 | 5,582,765,589 | 66.7 s | 4.0 s | false |
| base, app 2 | 114.1 s | 23,459,070,423 | 5,697,726,140 | 99.9 s | 6.9 s | false |
| fix, app 2 | 98.1 s | 23,458,914,780 | 5,697,568,925 | 76.7 s | 4.4 s | false |
| base, transparent at tip | 85.7 s | 23,462,347,230 | 5,697,582,385 | 77.1 s | 3.9 s | true |
| fix, transparent at tip | 83.6 s | 23,458,890,207 | 5,697,486,358 | 74.2 s | 4.6 s | false |

Phases, from the run logs: the read-only `PRAGMA quick_check` that precedes
any write handle took about 4 s. The write open (`node_db_open`) then ran
`PRAGMA quick_check(1)` again, and `create_schema` rebuilt the dropped
indexes. Its slow statements were the `CREATE INDEX IF NOT EXISTS`
statements on `utxos` (SCHEMA[13..15]), `tx_outputs` (SCHEMA[52..54]) and
`tx_inputs` (SCHEMA[56..58]). `create_schema` was 78-90 % of each run's wall
time.

On a read-only handle with the indexes absent, one gap-scan probe for an
address with no history took 170 ms on `utxos` and 736 ms on `tx_outputs`.
A plan with no birthday (`"confirm":false`, transparent, base binary) on
the same fixture took 288.1 s, read 395,952,180,905 bytes, consulted the
chain for 240 floor addresses and left the file byte-identical.

## Conclusion

- The fix removes every address-history statement from a create and from a
  restore with `birthday_at_local_tip`. The transparent at-tip run read
  3,457,023 fewer bytes; on the app's path the populated-index check is gone.
  Wall time did not change beyond host noise. On a commit, `node_db_open`
  has rebuilt the address indexes before the scan runs, so the probes it
  removed were index seeks.
- On this datadir the create's cost is the write open: about 23.3 GB read
  and 5.6 GB written per run. Most of it is `create_schema` rebuilding the
  indexes the bulk pass dropped, plus two full integrity reads of the
  7.3 GB file. At the 22 MB/s the phone sustained (17 GB in 13 minutes),
  23.3 GB of reads alone takes about 18 minutes.
- The gap scan is expensive only on a plan, because a read-only handle
  cannot rebuild an index: 240 addresses cost two full table scans each,
  396 GB of reads here.

## What would remove the remaining cost

- The wallet write open on an existing node.db repeats the boot ceremony:
  the restore has already proven the file with a read-only `quick_check`
  under its writer lock, and `node_db_open` reads it again and runs
  `create_schema`. An open for an existing store at the current schema that
  runs no DDL would leave the dropped indexes to the catch-up pass that owns
  them. `node_db_open_existing_runtime` runs no DDL but prepares none of the
  cached node_db statements, and the restore's write path uses at least one:
  `db_block_find_by_height` reads `stmt_block_by_height` when a named
  birthday is verified. Every statement that path uses has to be checked
  before it can take that open.
- `create_schema` rebuilds the same indexes on every node boot during a
  bulk pass. Leaving the `node_db_drop_indexes` set to `node_db_normal_mode`
  while a pass is in progress would remove the rebuild from both opens.
- `node_db_ibd_turbo_mode` prints "indexes dropped" when every
  `DROP INDEX` failed.
