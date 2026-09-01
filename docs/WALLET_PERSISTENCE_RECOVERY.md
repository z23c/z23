# Wallet persistence recovery

The node refused to boot because it found wallet keys on disk that it could
not safely load. It stopped instead of generating a fresh keypool over them.
That refusal is the protection: an earlier version of this code took the
silent path and made spendable funds unspendable.

Nothing has been rewritten. Every key row is still where it was.

This page covers the three boot refusals that name it:

| code | what the node observed |
| --- | --- |
| `BOOT_WALLET_PERSISTENCE_OPEN_FAILED` | `wallet_keys` has rows, but the wallet persistence layer would not open. |
| `BOOT_WALLET_CANARY_FAILED` | The wallet opened, but its write-then-read self-test failed. |
| `BOOT_WALLET_KEYSTORE_COUNT_MISMATCH` | Fewer keys loaded into memory than there are rows on disk. |

## 1. Copy the data directory first

Before anything else:

```sh
cp -a ~/.zclassic-c23 ~/.zclassic-c23.rescue-copy
```

Work on the copy. The original is your evidence and your key material.

## 2. Where the keys actually live

Wallet key material is stored inside `<datadir>/node.db` (SQLite), in the
`wallet_keys`, `wallet_sapling_keys`, and `wallet_seed` tables. There is no
separate `wallet.dat` file to move.

`<datadir>/wallet_projection.db` is a derived read model, not the key store.
Copying or repairing it recovers nothing.

`z23 core storage query` and `core storage query offline` deliberately
**refuse** any statement that names those tables — they answer
`QUERY_REJECTED: query references secret wallet key material and is denied`.
Do not plan a recovery around reading them through that command; it will not
work by design.

## 3. Read the evidence line

Each of the three refusals prints an `evidence:` line with the measurements
that decided it — the SQLite error code and the `file:line` that produced it,
the canary's own error text, or the two counts that disagreed. That line names
the failing layer. Start there rather than guessing.

Common, checkable causes:

```sh
ls -l ~/.zclassic-c23/node.db ~/.zclassic-c23/node.db-wal ~/.zclassic-c23/node.db-shm
df -h  ~/.zclassic-c23
```

An open failure is usually ownership, mode, or a truncated file. A canary
failure is usually a full or read-only filesystem — the canary writes a probe
row and reads it back through the wallet's own handle, so it fails whenever
the wallet could not durably write.

`BOOT_WALLET_KEYSTORE_COUNT_MISMATCH` is different: it means the loader
dropped rows it could see. That is a z23 defect, not an environment
problem. Keep the rescue copy — it is the only reproduction.

## 4. Rotated wallet backups

The node writes periodic verified wallet backups outside the datadir, so a
damaged `node.db` is not the only copy:

```sh
ls -lt ~/wallet_backups/wallet_backup_*.sqlite | head
```

Each file is a standalone SQLite database holding the eight wallet tables as of
that run, plus a `wallet_backup_manifest` table recording, per wallet table,
whether the source had it and how many rows were written. The service verifies
every one of the eight against the source before calling a backup good; a run
that dropped `wallet_sapling_keys` fails loudly instead of reporting success.
The set includes `wallet_key_encryption`: without its passphrase-wrapped DEK,
restored WKD1 transparent keys would be authenticated ciphertext with no
recovery key.
Check what the last run saw:

```sh
z23 ops state --subsystem=wallet_backup
# last_tables_verified / wallet_table_count / last_missing_tables
```

When `WALLET_BACKUP_PASSWORD` was set, backups are encrypted (`*.sqlite.enc`).
`core wallet restore` decrypts them in place, so a separate decrypt step is only
needed when you want a readable copy:

```sh
z23 core wallet backup decrypt \
  --input='{"from":"<src.enc>","to":"<dst.sqlite>","confirm":true}'
```

(The legacy argv form `z23 --decrypt-wallet-backup <src.enc> <dst.sqlite>`
still works and reads the same environment variable.)

## 4a. Restoring one

`core wallet restore` merges a backup file's wallet tables into
`<datadir>/node.db`. **Stop the node first** — `<datadir>/zclassic23.pid` is the
single-writer lock and the command refuses with `DATADIR_LOCKED` while it is
held.

```sh
systemctl --user stop zclassic23

# Rehearsal: runs the real merge in a transaction, rolls it back, and reports
# per table what a commit would do.
z23 core wallet restore \
  --input='{"from":"'"$HOME"'/wallet_backups/wallet_backup_<ts>.sqlite",
            "datadir":"'"$HOME"'/.zclassic-c23"}'

# Commit (use the plan's commit_input, or add "confirm":true).
z23 core wallet restore --input='{"from":"...","datadir":"...","confirm":true}'

systemctl --user start zclassic23
z23 core wallet rescan             # transparent history
z23 core wallet rescan-witnesses   # REQUIRED before spending a shielded note
```

What the report means:

| field | meaning |
|---|---|
| `collision_policy` | always `keep-existing` — a row whose primary key is already in the target is never overwritten |
| `rows_inserted` | rows that landed |
| `rows_collided` | rows the target already had (its row wins) |
| `rows_rejected` | rows the target's schema refused — a real integrity signal, not noise |
| `manifest_mismatches` | the file holds fewer rows than the backup run recorded writing: it was truncated or damaged afterwards |

The restore merges into the schema-correct tables on purpose. Do **not** copy a
backup file into place as `node.db`: the backup's tables are built with
`CREATE TABLE t AS SELECT * FROM src.t`, which copies values but drops primary
keys, CHECK constraints and indexes, and installing that makes the damage
permanent.

Restoring rows does not rebuild derived state. In particular, a restored
Sapling note has no Merkle witness and **cannot be spent** until
`core wallet rescan-witnesses` has run and verified its final tree root against
the block header.

If `core wallet rescan` reports `complete: false`, this node has no block body
for some heights in the range (the usual cause is a snapshot bootstrap, which
clears `BLOCK_HAVE_DATA`). A zero result there says nothing about the wallet —
sync full history first, then rescan again.

## 5. What not to do

- Do not delete `node.db` to "start clean". That is the key store.
- Do not delete `<datadir>/zclassic23.pid` while a node is running; it is the
  single-writer lock, and two nodes on one datadir corrupt both stores.
- Do not re-run the node against the original datadir until the cause named in
  the `evidence:` line is fixed. Every refused boot is harmless; the harmful
  step is the one that writes.

## Related

- `docs/BOOT_INVARIANTS.md` — what each boot stage guarantees, including the
  `wallet_loaded` boundary these refusals sit on.
- `engine/composition/include/config/boot_error.h` — the contract these messages are
  rendered in (`code` / `phase` / `message` / `evidence` / `next[]`).
