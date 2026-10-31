# Custody model

What holds the keys, what authorizes a spend, and what an AI agent operating
this node can and cannot do with them.

This page states the boundary as the code enforces it. Where a control is a
convention rather than a mechanism, it says so — a boundary you believe in and
the code does not draw is worse than no boundary.

---

## 1. The one-sentence shape

The node process holds every spending key in RAM in cleartext while it is
unlocked; the disk copy can be wrapped under a passphrase the operator supplies;
and every typed command an agent issues is bounded by a grant the agent cannot
mint for itself — but the grant is presented in the agent's own environment,
so an agent that declines to cooperate is bounded only by the operating system,
not by this code.

---

## 2. Where private keys live

Five places. All five are inside the operator's own control domain; private
keys can be exported through authenticated loopback JSON-RPC.

| # | Location | Form | Encrypted at rest |
|---|---|---|---|
| 1 | `node.db` → `wallet_keys.privkey` (32 B secp256k1 scalar) | blob | WKD1 envelope under the wallet DEK when a passphrase is in force |
| 1a | `node.db` → `wallet_key_encryption.wrapped_dek` | blob | the random wallet DEK wrapped once in WKS1 under the passphrase |
| 2 | `node.db` → `wallet_sapling_keys.xsk` (169 B extended spending key) | blob | WKS1 envelope when a passphrase is in force |
| 3 | `node.db` → `wallet_seed.seed` (32 B HD seed) | blob | WKS1 envelope when a passphrase is in force |
| 4 | Process RAM — `wallet.keystore` and `wallet.sapling_keys` | cleartext | never; this is the working set |
| 5 | Backup files written by the wallet backup service | verbatim copies of rows 1–3 | inherits row 1–3's state; a second layer if `WALLET_BACKUP_PASSWORD` is set |

Row 4 is not a defect — a node that signs must hold the scalar. It is the
reason a core dump, a debugger attach, or `/proc/<pid>/mem` read as the node's
uid is a total compromise, and the reason confining the agent is an OS problem
(§7).

Row 5 copies `wallet_keys`, `wallet_key_encryption`, `wallet_sapling_keys`,
`wallet_seed`, and the other wallet-owned tables with `CREATE TABLE … AS
SELECT *`, so a backup taken from an encrypted wallet contains encrypted
blobs and a backup taken from a plaintext wallet contains raw keys. The two
layers use **independent passphrases**: `ZCL_WALLET_PASSPHRASE` wraps the rows,
while `WALLET_BACKUP_PASSWORD` wraps every scheduled backup file
(`wallet_backup_service.c`, ChaCha20-Poly1305 over the whole file). For an
operator who will not place the second secret in an environment,
`core wallet backup now --input=-` also accepts an invocation-scoped
`password`: it is stdin-only, is never retained in service configuration, and
is deliberately absent from the rendered `commit_input`. Setting one layer
does not set the other, and leaving scheduled-backup encryption unset logs one
warning and proceeds.

**Export paths:** `dumpprivkey` / `z_exportkey` over authenticated JSON-RPC
export directly; `core.wallet.address.export-key` is OWNER-gated and uses
plan/commit on the typed surface
(`contexts/wallet/controllers/src/wallet_native_handlers.c:390-451`). The
typed form returns a non-revealing plan without `confirm:true`, warns that
commit reveals the key, and returns the WIF in `reply.data.privkey` on commit. `rpc_dumpprivkey` logs failure context and addresses, not key bytes
(`contexts/wallet/controllers/src/wallet_controller_keys.c:11-57`).

### 2.1 The sixth place — twelve words on paper, if they exist

A wallet created from a BIP39 recovery phrase has a **sixth** copy of its keys:
the twelve words, which regenerate row 3 (the HD seed) and therefore rows 1 and
2 by derivation. It is the only copy outside the machine, and the only one that
survives the disk. Whether it exists is decided **once, at wallet creation, and
cannot be added afterwards** — the node stores the seed, never the words, so no
command can print the phrase of an existing wallet.

The decision is `boot_wallet_phrase_plan_for()`
(`engine/composition/src/boot_wallet_phrase.c`), and the input that matters is whether
stdout is a terminal:

| stdout | other condition | plan | result |
|---|---|---|---|
| a terminal | — | SHOW | words printed once, for paper. **The only way they are ever obtained.** |
| a file or pipe | `-wallet-no-phrase-backup` / `ZCL_WALLET_NO_PHRASE_BACKUP` | SKIP | wallet created, **no phrase drawn at all** |
| a file or pipe | `ZCL_WALLET_PASSPHRASE` set (→ `CREATE_ENCRYPTED`) | SKIP | same — the at-rest decision is taken as consent |
| a file or pipe | offline mint producer, or a non-canonical lane | SKIP | same; these hold nobody's money |
| a file or pipe | none of the above | REFUSE | **no wallet created**, and no half-made one |

Under the shipped service stdout is `node.log` — rotated, copied into backups,
and readable with `z23 ops logs` — so the phrase may never be printed
there. SKIP is not a downgraded SHOW: it draws no phrase, so there are no words
to leak on that path. The cost is that the wallet's only backup is the wallet
file plus its passphrase.

The two refusals differ: `wallet_at_rest_boot_decision()` returning
`WALLET_BOOT_REFUSE` continues boot in keyless **NO-SPEND mode** and syncs.
The phrase plan's REFUSE returns failure from `boot_wallet_create_new()`,
and its boot caller exits with status 1 rather than continuing sync.

Two typed commands read and use this, both `AUTH_OWNER`:

- `core wallet recovery status` — answers `recoverable_from_phrase` by
  **attempting the derivation**, not by reading a stored flag. A wallet that
  predates recovery phrases, or one created by SKIP, answers `false` and is
  directed to file backup instead. Takes a `datadir` that defaults to the live
  one and opens it **read-only** (`zcl_native_node_db_open_readonly()`).
- `core wallet recovery restore` — plan/commit rebuild from the words alone.
  `datadir` is **required with no default**, deliberately not the running
  node's; the phrase may be passed as input or kept out of argv via
  `ZCL_RECOVERY_PHRASE`. Rebuilding installs spending keys, so a rescan over
  block bodies is needed afterwards to see the notes.

`core wallet create` makes a new shielded-only wallet for the phone. It is
`AUTH_OWNER`, local, and never available to agents or MCP. Send
`{"datadir","passphrase"}` on standard input with `--input=-`; a passphrase
in argv or the environment is refused (`STDIN_REQUIRED`). The datadir must be
empty (no seed, key, note or `<datadir>/wallet` directory) and unheld by a
node. The reply carries a 24-word phrase **once**: it is not stored, logged or
journaled, and no command prints it again. Standard output holds only the
reply document; the log lines of opening the datadir go to standard error. The
command disables core dumps on entry. The seed and Sapling keys are written
under the passphrase (WKS1, WKD1) from the first write, at least 12 bytes. No
transparent address is made.

Birthday. The highest connected block the datadir holds (status 3 or more) is
the wallet's tip, stored as `wallet_birthday_height` in `node_state`, and the
hash of the block 100 below it is stored as `wallet_birthday_hash`. Rows above
a rewound tip keep their status, so the tip can be stale; that is safe because
every row existed before the wallet, and what boot checks is the floor block.
Only the first boot catch-up of a wallet that has scanned nothing uses it. It
checks the in-memory active chain: if the chain holds the floor block (which
fixes every block below it), the scan starts there. If it does not (reorganised
away, rewound below it, or no chain loaded), nothing below the floor can be
assumed. Boot then records a pending scan retry from height 0 with blocker
`WALLET_BIRTHDAY_CHAIN_CHANGED`, so the wallet claims no scanned-through height
and a tip that advances cannot stand in for blocks never read. The catch-up
reads the whole chain; above 1000 blocks it defers the way every first catch-up
does ("use rescanblockchain"). The marker stays until a rescan over the whole
marked range reads it (`core wallet rescan` or `rescanblockchain`); boot reads
it only on a chain of 1000 blocks or fewer. A chain of 100 blocks or fewer
records no birthday. A wallet that has scanned nothing and has no valid
birthday (a create whose reply was lost before any block existed, a failed
birthday write) gets the same marker, from the start it would have scanned,
whenever boot defers its first catch-up: above 1000 blocks from genesis, or a
gap of 50000 blocks or more. Every other scan
covers its whole range: transparent scans, `rescanblockchain` and the full scan
an imported key triggers never raise their start, so a coin received before the
birthday by a key imported later is found.

Boot. A seed row, a Sapling key row or a transparent key means a wallet exists:
boot mints no keypool over it and the legacy `<datadir>/wallet` import does not
run over it, whether the seed is readable or locked. If the persistence layer
will not open while any of those rows are on disk, boot refuses (STATE D). A
closed persistence layer mints nothing.

Lost reply. If the process dies or the reply never arrives after the commit,
the phrase is gone and a second create is refused (`WALLET_ALREADY_PRESENT`).
There is deliberately no discard flag: whether a wallet holds no coins cannot
be proved from its own rows, because a payment sits on the chain until a scan
finds it. The caller keeps the way back: it creates in a datadir made only for
that attempt, deletes that datadir whole if the reply did not arrive (the
wallet was never started as a node and its address never shown), and uses the
datadir only after the phrase is on screen. A datadir that was ever used is
never deleted; its wallet is restored from the written phrase with
`core wallet recovery restore` into a NEW datadir, because restoring into the
datadir that already holds the wallet is refused (`WALLET_ALREADY_PRESENT`).

Restore. `core wallet recovery restore` writes the wallet with a pending scan
retry from height 0 (blocker `WALLET_RESTORE_UNREAD`), so a restored wallet
reads `incomplete` in `getwalletinfo` and never `complete` until its range has
been read. A boot catch-up reads it on a chain of 1000 blocks or fewer; above
that boot defers, and `core wallet rescan` over the whole marked range, from the
marker to the tip with every block body read, clears the marker. A partial
rescan keeps it.

Restore inputs for the phone. Besides `phrase`, `datadir` and `confirm`,
`core wallet recovery restore` takes:

- `passphrase`: standard input only (`--input=-`); in argv it is refused
  (`STDIN_REQUIRED`). At least 12 bytes (`PASSPHRASE_TOO_SHORT`; an empty
  string fails input validation). The seed and Sapling keys are written under
  it from the first write, so no plaintext reaches disk. Without it the creation policy of
  the environment decides, as before.
- `shielded_only`: no transparent key is minted, as create does.
- `birthday`: `{"height","hash"}`: the birthday height and the hash of the block 100
  below it, as a create reply gives them (`birthday_height`, `birthday_hash`).
  It is honoured only when the datadir holds that block, connected, at that
  hash; the wallet then scans from there and carries no marker. A birthday
  whose block is not held (a wrong hash, a chain that moved) is not stored: the
  reply sets `birthday_rejected` and the wallet is marked unread from 0. A
  malformed birthday is refused (`BAD_BIRTHDAY`) before anything is written.
  The check shows the block is on the chain, not that the phrase is new: the
  caller vouches for that. A create run in an empty directory has no chain and
  returns no birthday; the caller then takes the height and hash from the live
  node's chain, 100 blocks below its tip, at the moment of creation.

Below the seed. A datadir seeded from a snapshot holds no connected block
below its seed height, the lowest block it holds. A restore with no verified birthday on such
a datadir cannot show funds received below it, and says so:
`history_below_seed_hidden` is true, `seed_floor_height` names the height, and
`history_warning` says it in words. A datadir that holds block 0, or no block
at all, reports false (a datadir with no block yet is read from 0 under the
unread marker).

The restore refuses while a node holds the datadir (`DATADIR_LOCKED`), so the
node is stopped for it, and it refuses a datadir that already holds a wallet
(`WALLET_ALREADY_PRESENT`). A node started without a passphrase or plaintext
opt-in mints no wallet, so a seeded datadir that has only run that way accepts
the restore.

`tests/harness/src/test_wallet_create.c` holds the proof.

---

## 3. What is encrypted, with what

Two authenticated envelopes are used. `contexts/wallet/modules/wallet/src/wallet_keystore.c`
provides the passphrase-facing **WKS1 envelope**:

```
magic "WKS1" | version u32be | kdf_iters u32be | reserved u32 | salt[16] | nonce[12] | tag[16] | ciphertext
```

PBKDF2-HMAC-SHA512 (200 000 iterations by default) from the passphrase, then
AES-256-GCM with a fresh 12-byte nonce and a 16-byte tag. Sapling spending
keys and the HD seed remain WKS1 rows. Transparent keys use WKS1 once to wrap
a random 32-byte wallet data-encryption key in `wallet_key_encryption`, then
`contexts/wallet/modules/wallet/src/wallet_sqlite_key_crypto.c` writes fast **WKD1** rows:

```
magic "WKD1" | version u32be | nonce[12] | tag[16] | ciphertext
```

WKD1 uses AES-256-GCM under that DEK and authenticates the row's 20-byte
public-key hash as AAD. Copying ciphertext to another wallet row therefore
fails authentication. The password KDF is paid once per unlocked database,
not once per address; explicit lock, auto-lock, passphrase changes, and
database close wipe the cached DEK.

The persistence layer applies both formats. `wallet_sqlite.c` dispatches
transparent reads to legacy WKS1 or WKD1 and still accepts a plaintext row for
backward compatibility. `wallet_sqlite_key_crypto.c` owns the wrapped DEK,
WKD1 AEAD, and migration transaction. A wallet may therefore be mixed during
an interrupted upgrade without any row being mistaken for zero or deleted.

The passphrase is resolved in one place,
`wallet_lock_effective_passphrase()` (`contexts/wallet/modules/wallet/src/wallet_lock.c`), in this
order:

1. force-locked (explicit `lock`) → NULL, wins over everything
2. runtime passphrase (explicit stdin `unlock`, or the one boot credential)
   → that value
3. otherwise → NULL

`ZCL_WALLET_PASSPHRASE` remains a first-creation/recovery policy input, but it
cannot auto-unlock a live encrypted wallet. A headless service instead receives
the user-scoped systemd credential named `wallet-passphrase`; boot reads its
private bounded file once before the first WKS1/WKD1 row and registers it in the
same cleansable runtime buffer used by explicit unlock. A missing credential
supplies no passphrase and the wallet boots locked (see below). Malformed
credentials fail boot by name, and a wrong passphrase with a configured
credential reaches the persistence abort guards.

NULL means no active runtime passphrase. Transparent writes to a wallet known
to be encrypted refuse when wrapping fails; a plaintext wallet can still write
raw keys. Undecryptable loaded rows are skipped with a counted warning
(`g_read_keys_corrupt_rows`). A plaintext wallet is always "unlocked".

**What locking does to memory.** An encrypted wallet that is locked, by
`walletlock`, by the unlock timeout, or by a refused unlock or timeout, holds
no secret in RAM. `wallet_lock_lock` cleanses the transparent private keys, the
HD master key, the Sapling seed, the Sapling master key and every Sapling
spending key (`sapling_keystore_wipe_secrets`). Transparent entries stay in the
keystore by key id and public key, marked sealed: the wallet still recognises its
own outputs, and `keystore_get_key` never returns a private key for them. It keeps each shielded entry's
incoming viewing key, full viewing key, diversifier and `pk_d`, and the address
list. A locked wallet therefore still finds incoming shielded notes and computes
their nullifiers from the full viewing key, and `z_listaddresses` still answers.
Unlock restores the seed and each spending key into the entry that already
exists, matched by incoming viewing key, so any number of lock and unlock cycles
leaves the key count and the balances unchanged. A plaintext wallet has no
passphrase to restore from, so locking leaves its Sapling keys as they were.

**A wallet may boot locked.** With encrypted rows on disk and no passphrase,
boot continues instead of aborting. Transparent rows that cannot be decrypted
stay sealed on disk and load as sealed entries (their public key is stored in the
clear), so the STATE F invariant `loaded == rows` holds, the scan key set equals
the unlocked one, and the cursor-gated wallet scan never reads a sealed boot as a
changed key set. Nothing deletes wallet records because keys are sealed, and an
output paid to a sealed key is recorded when it arrives. Sealed rows are counted
separately from corruption (`wallet_sqlite_read_keys_locked_count`). Shielded rows
load as viewing entries. Unlock after a locked boot adopts the stored seed when it
governs the keys, so new keys derive from the recovery phrase. A shielded row
that stores no full viewing key cannot scan until unlock; it is counted in
`getwalletinfo.persistence.sapling_unscannable` and logged, not dropped
silently. Boot mints nothing while sealed: no first keypool, no legacy-pool
top-up, no LevelDB import, and no seed adoption.

**A locked wallet cannot replace its seed.** While the in-memory seed is absent,
`sapling_keystore_new_address`, `_generate_seed`, `_set_seed` and `_import_xsk`
refuse, as do `z_getnewaddress`, `getnewaddress`, key-pool top-up and any
transparent key derivation. Without that refusal the keystore would see no seed,
generate a random one, and a later flush would overwrite the stored seed row.
Wallet writes also fail closed: an encrypted wallet with no passphrase refuses to
write a Sapling seed or key row in the clear, and the seed writer refuses to
store a seed that differs from one already stored. A seed read that fails is
`WALLET_SEED_UNREADABLE`, never absent, and an unlock that cannot read the seed
returns an error and leaves the wallet locked. A full flush while sealed writes only
public rows and succeeds when every sealed key and address already has its row, so
a sealed shutdown stays clean. It fails when a key was minted in memory and sealed
before it was stored; the check runs inside the write transaction under the
keystore mutexes, so a lock landing while the flush waits for the database cannot
slip past it. A key-pool refill or top-up that a lock refuses, at the mint or at the flush, removes its unstored keys, and a transactions-only flush writes only pool entries whose keys are stored, so a restart can always read the pool back. Flushes of
transactions only are never refused, so a send whose proof outlives the unlock
window still records its transaction.

**Unlock.** `walletunlock` first proves the passphrase against the sealed rows (the
wrapped data key, the seed row, the Sapling key rows, legacy wrapped rows) without
touching any live key, cached passphrase or lock state; a wrong attempt, including
one against an unlocked wallet, changes nothing. One row that opens proves the
passphrase. A damaged row is reported per key (`getwalletinfo.persistence.
sapling_damaged`), only the funds at that address are unavailable, and a send from
it says the stored key could not be decrypted. Unlock fails only when sealed rows
exist and none opens. Lock, timeout lock and unlock share one transition mutex, so
they never interleave; lock order is transition mutex, then wallet and keystore
mutexes, then the passphrase mutex.

**Exports.** While locked, `z_exportkey`, `z_exportviewingkey`, `dumpprivkey`
(and so `core.wallet.address.export-key`) and `z_importkey` refuse with the lock
error. `z_exportkey` encodes from a private copy of the entry taken under the
keystore mutex.

**A send that meets the lock.** `z_sendmany` copies the sending key entry under
the Sapling keystore mutex after the spend guard, signs only with the copy, and
cleanses it on every exit. The mutex is not held across proving. A lock that
fires first yields the lock error instead of a signature made with wiped memory.

**Persistence behavior, checked.** The `wallet_sqlite` path uses AES-256-GCM
when encryption is active and accepts legacy plaintext rows. The first-creation
policy's environment decision alone does not load a runtime passphrase.

**It is now the whole truth: `wallet_keys` has a single writer.** The former
second writer — `db_wallet_key_save` / `db_sapling_key_save` /
`db_wallet_seed_save` in `contexts/wallet/models/src/wallet_key.c`, driven by
`node_db_sync_wallet_keys` at every boot, after legacy/snapshot imports, and
from the `reindexdb` RPC — is deleted. The `wallet_sqlite` layer
(`contexts/wallet/modules/wallet/src/wallet_sqlite.c`) is the only writer of the `wallet_keys` /
`wallet_sapling_keys` / `wallet_seed` secret columns, the
`check-before-save-hooks` lint gate ratchets that the plaintext saves never
return, and the key-saved event / wallet-projection feed moved into that
writer (emitted once per new row). `reindexdb` now repairs through the
encryption-aware `wallet_sqlite_flush_r`.

**Legacy rows are migrated at boot.** After wallet load and the STATE F
keystore-count invariant, `wallet_sqlite_migrate_transparent_keys_r` rewrites
the already-decrypted transparent keys into WKD1 in one transaction. Thus a
legacy WKS1 row pays its password KDF once, during the load that was already
required, rather than again during migration. `wallet_sqlite_scrub_plaintext_r`
then upgrades any residual unloaded transparent row to WKD1 and retains WKS1
for Sapling keys and the seed. Byte content is preserved and nothing is
deleted. With no passphrase the migration and scrub are no-ops. Any SQL,
encryption, authentication, or commit failure aborts boot loudly.

One residual blind spot remains: neither `getwalletinfo.persistence` nor any
dumper counts enveloped-vs-plaintext rows, so an operator cannot ask the node
which rows are which (§8).

---

## 4. Everything that can sign or move value

| Path | Reached by | Gate |
|---|---|---|
| `sendtoaddress` / `sendmany` / `z_sendmany` JSON-RPC | loopback HTTP + `<datadir>/.cookie` Basic auth | cookie only |
| `core.wallet.transaction.send`, `core.wallet.shielded.send` | typed CLI | kernel authority + capability + **agent spend policy** |
| `vault.send`, `vault.send-shielded` | typed CLI | vault dispatch + **agent spend policy** |
| `app.market.buy`, `app.swap.initiate`, `app.swap.participate` | typed CLI | same |
| `vault.swap.redeem` / `.refund` | typed CLI | authority; **no amount to bound**, so the spend policy refuses them for a grant |
| `dumpprivkey` / `core.wallet.address.export-key` | both | RPC: authentication; typed: OWNER + plan/commit. Export hands over the key, after which no gate applies |
| `importprivkey` | JSON-RPC | RPC authentication; imports a private key |
| `core.wallet.address.import` | typed CLI | OWNER; imports a watch-only address |

### 4.1 One keyed shielded send pays once

`core.wallet.shielded.send` requires an `idempotency_key` (1 to 128 characters
of letters, digits, `.`, `_`, `:`, `-`) on the plan and on the commit. The plan
quotes the wallet fee and binds wallet scope, `from`, `to`, amount, fee, memo
and key into `plan_token`; `commit_input` carries the token and the commit
refuses without it (`PLAN_REQUIRED`) or with a different request
(`PLAN_TOKEN_MISMATCH`) before any RPC. The commit sends the planned fee to the
node; the node reads the send record first and only then compares the fee with
the wallet fee (`FEE_CHANGED`, key free).

The node records the key in `node.db` (`wallet_send_once`) before it builds
anything. The built txid is written with `synchronous=FULL` (the level found is
restored afterwards) before the wallet admits the transaction, so a relayed
transaction always has a durable row. The row is marked committed only after the
send returned. It holds two SHA3-256 values (the key hash and a request digest
bound to the key), a state, the txid and two timestamps; never the key, an
address, an amount or a memo. A repeat of a key reads the row first and never
builds or broadcasts:

| Row | Repeat returns |
|---|---|
| committed and the wallet holds the txid | the earlier txid, `replayed=true` |
| committed and the wallet lost the txid | `SEND_OUTCOME_UNKNOWN` with the txid |
| built (wallet holds the txid or not) | `SEND_OUTCOME_UNKNOWN` with the txid |
| started only (no txid was ever durable, so nothing was admitted) | the row is freed and the send runs once |
| a run of this key is executing | `SEND_IN_PROGRESS` (transient) |
| different request under the same key | `IDEMPOTENCY_KEY_REUSED` |

A built row is never answered as committed: the wallet holding a transaction
does not prove it was relayed. Rebroadcasting held, unrelayed transactions at
boot is a separate follow-up. A failed run frees its key
(`SEND_REFUSED_KEY_RELEASED`) only when the wallet never admitted the
transaction. Once admission succeeded the pool may have held the transaction
and a peer may have fetched it, so every later failure (a wallet flush that
fails, a rollback, a relay error) answers `SEND_OUTCOME_UNKNOWN` with the txid
and the row stays. A built record that cannot be written before admission
refuses the send and releases the key (`SEND_REFUSED_KEY_RELEASED`), because
nothing was sent. A record that cannot be read or created, and a full table,
are a plain error, never a release. The txid is returned in the reply only; the node
log does not carry it.

After `SEND_OUTCOME_UNKNOWN` the caller must not resend under the same key and
must not pay again under a new key yet. After a crash following pool entry the
wallet transaction list can be empty, yet the transaction can still confirm
until it expires: a shielded send expires 20 blocks after the height it was
built at. Wait until the chain is more than 20 blocks past the send, then check
the wallet transaction list and History, and only then pay again. One keyed
send can admit exactly one transaction.

The durable write is its own `BEGIN IMMEDIATE ... COMMIT` with
`synchronous=FULL` read back inside the transaction; if another writer holds a
transaction on the connection the send is refused. The `wallet_send_once` test
group counts write-ahead-log `xSync` calls through a SQLite VFS and fails when
the built row is written without one.

Limit: the record lives in `node.db` and cannot outlive it. A malformed
`node.db` is quarantined at boot and a restored one carries only its own rows,
so after a database loss or restore the node cannot recognize an earlier key.
The app never retries a payment on its own, and after a restore a payment is a
new tap on a new review. Before paying again after a database loss or restore,
the owner checks History and waits past expiry (20 blocks) for any payment that
had not confirmed. A node that predates send-once ignores the key
and returns a bare txid, which the handler reports as sent.

Retention: committed keys 90 days, keys without a known outcome 365 days; at
100000 rows a new keyed send is refused rather than an older key forgotten.
Retention uses wall-clock time: a forward clock jump ages rows early.
Unkeyed `z_sendmany` (JSON-RPC, in-process callers) is unchanged and unrecorded.

The spending paths also use two independent runtime gates:

- **`wallet_lock_spend_guard()`** — a locked wallet cannot spend even when
  verification permits (`contexts/wallet/modules/wallet/include/wallet/wallet_lock.h`).
  Shielded sends additionally require the spending key to be resident (section 3).
- **the sync-verified `WALLET_SPEND` capability** — spending is disabled until
  the node's own state is self-verified.

### 4.1 Fresh receive addresses (diversified)

`core wallet shielded receive` (node RPC `z_getreceiveaddress`) returns the next
unused ZIP-32 diversified address of the wallet's one account (the key with the
lowest child index). All such addresses share one incoming viewing key, so a
single key finds every note sent to any of them, and a payer cannot link two of
them on chain. The reply is `{"address":"zs1..."}`.

- **Recorded first, synced to disk.** The diversifier index is written to
  `wallet_sapling_diversifier` and committed before the address is returned.
  The write runs at `synchronous=FULL` whatever the connection mode (normal
  mode syncs the log only at checkpoints), so power loss after the address is
  shown cannot take the index back. When the sync fails no address is
  returned. A crash between the write and the reply burns that index; an index
  is never issued twice from one datadir.
- **Not while the node is catching up.** Bulk-sync mode runs the database
  without syncing, so a write there could be taken back by power loss. The
  command refuses with "the node is catching up; a new address is available
  when it is in sync" and consumes no index.
- **Works while locked.** The address comes from the viewing key and the
  diversifier key, both resident while locked. No seed or spending key is read
  or written, and the leaf is not on the agent surface: an agent session is
  refused as for every unlisted wallet leaf.
- **Notes.** Trial decryption with the account's incoming viewing key finds a
  note sent to any diversified address. The note keeps its own diversifier and
  `pk_d`, and the commitment, proof and nullifier of a spend use them.
- **Spending.** `z_sendmany` with the from address `account` selects from every
  spendable note of the account, across its addresses, in one transaction.
  Change returns to the account's default address: a change output is
  encrypted on chain, so a fresh address there adds no privacy.
- **A balance is per address, a spend is per account.** `z_getbalance` on an
  issued address reports only the notes received at that address, but a send
  "from" an issued address may spend any unspent note of the account, not just
  that address's. Every owned shielded from address spends account-wide today
  (`wallet_shielded_send_shielded.c:276,303`): the diversified addresses are
  one account for spending.
- **Restore.** The index record is not in the wallet backup, and a restored
  wallet has not read the chain, so it cannot know which addresses an earlier
  copy issued. A wallet with no record, new or restored, starts at a random
  index in `[2^40, 2^40 + 2^60)` drawn from the system CSPRNG and records it
  before the address is returned; no address is returned when randomness
  fails. It then counts up from there. A restored wallet therefore does not
  hand out an address the earlier copy issued, except by a chance of about
  2^-60 per issued address. Notes sent to any index are found by trial
  decryption with the one incoming viewing key, so no address list is needed,
  and a balance query reports the notes received at that address.
- **Copies roll the index back.** The index lives in `node.db`. Restoring a
  file copy of `node.db` over a running wallet, or running a cloned datadir
  beside the original, returns the index to an earlier value, and the copy
  issues addresses the other already showed. Both are unsupported for a wallet
  in use; recover from the phrase instead, which starts at a random index.

---

## 5. What the agent grant bounds

The grant is a row in `agent_sessions` (migration v36,
`engine/models/src/database_migrate_features_v30_up.c:200-224`), minted by
`vault session create` for an existing principal, and presented per invocation
as `ZCL_AGENT_SESSION=<32 hex chars>`
(`tools/command/native_command.c:3530, 4333`).

It bounds the following; spending checks also require determined custody state:

| bound | column | enforced in |
|---|---|---|
| amount per transaction, including the fee allowance | `max_per_tx_zat` | `agent_session_service_authorize`, `agent_session_authorize` |
| amount per resetting window | `max_per_window_zat` + `window_seconds` (≤ 1 year) | `agent_session_authorize` |
| destination | `recipient_allowlist` (exact CSV token, never a prefix) | same |
| lifetime | `expires_at`, `revoked` | same |
| wallet scope and identity | `wallet_scope`, `wallet_instance_id`, `wallet_genesis` | same |
| development reserve and shared lifetime allocation | `reserve_floor_zat`, `lifetime_spent_zat` (5,000,000 zatoshis across dev sessions) | service availability checks and model lifetime checks |

The model check and debit run under a process-local mutex, with a targeted
`UPDATE` of the two window columns and lifetime-spend counter
guarded by `revoked=0` — so concurrent model invocations serialize their cap checks,
and a revocation landing mid-spend is not undone by the debit rewriting the
row (`cognition/models/include/models/agent_session.h`, the
`agent_session_authorize` contract).

**Can the bounded party widen it?** Through the typed surface: no.

- `vault.session.*` is refused outright for any presented grant, matched on the
  branch prefix so a leaf added tomorrow is covered the day it is added
  (`cognition/services/src/agent_spend_policy.c:asp_is_grant_surface`) →
  `POLICY_NO_GRANT_MINT`.
- The policy classifies the **leaf**, from its registry spec, not the input's
  shape. A wallet-touching or mutating leaf it has no rule for is refused
  (`POLICY_NOT_UNDERSTOOD`) — which is what stops `export-key`, `import`,
  `backup.now` and `rescan`, none of which carries an amount.
- A leaf whose *reach* cannot be bounded is refused by name
  (`POLICY_UNBOUNDABLE`): `core.storage.query` and
  `core.storage.query.offline` run arbitrary SELECT over `node.db`, and
  `node.db` holds material whose possession authorizes a spend — another
  grant's bearer token, an HTLC preimage.
- The gate runs **after** the lane/authority/capability checks, because it is
  the only one that writes; ahead of them, anyone who could reach it could
  drain a session's window with commands that were then denied anyway
  (`engine/modules/kernel/src/command_registry_execute.c:184-188`).
- A plan-stage preview enforces the caps and debits nothing; a handler that
  reports no mutation gets the debit released.

Through the operating system: **yes** — see §7.

---

## 6. Where secrets are not allowed to appear

| surface | rule | enforced in |
|---|---|---|
| `core storage query` (SELECT-only SQL) | `wallet_keys`, `wallet_sapling_keys`, `wallet_seed`, `agent_sessions`, `zswp_contracts` denied wholesale; `privkey`, `xsk`, `seed`, `session_id`, `secret`, … denied as columns | `engine/controllers/src/dbquery_controller.c` |
| refusal `evidence` in a reply | the **redacted** grant id (first 8 chars + `…`), never the bearer token | `agent_session_redact_id`, asserted on rendered bytes |
| `vault session list` | redacted ids only; the full token crosses the service boundary exactly once, out of mint | `services/agent_session_service.h` |
| `ops state --subsystem=agent_sessions` | count only with no key; with a key it echoes back the session the caller already named | `agent_session_dump_state_json` |
| `node.log` | no path formats a private key, WIF, seed or extended spending key | `wallet_controller_keys.c` logs the address only |

The denylist rule that actually holds is the **table** list, not the column
list: `SELECT * FROM t` names no column, so a column-level rule cannot see it.
A table whose row carries any authorizing value belongs on the table list.

---

## 7. What this does not bound — stated, not implied

The grant is presented in the agent's own environment and the agent runs as the
node's uid. Therefore an agent that does not cooperate can:

- run `env -u ZCL_AGENT_SESSION z23 …` and be the unbounded local
  operator (`tools/command/native_command.c:4319-4323` — `granted_capabilities=~0`,
  `authority_ceiling=OWNER`);
- read `<datadir>/.cookie` and call `sendtoaddress` straight over JSON-RPC,
  below the kernel and below this policy entirely
  (`engine/controllers/src/rpc_client.c:349-365`);
- read any wallet secret deliberately placed in its own environment, and—when
  it shares the node uid—may reach the node's user-scoped boot credential;
- read the node's memory, where every spending key is resident.

Confining an agent is an **operating-system** job: a separate uid with no read
access to the cookie or the datadir, or a wrapper binary that injects the grant
and refuses to exec anything else. This layer is the bound a cooperating agent
runs under and the audit trail of what it moved — every reply carries an
`authority` block naming `policy: bounded|exempt`, the redacted grant, and what
was debited, so the exemption is stated rather than inferred from an absence.

---

## 8. Known gaps

1. **At-rest state is single-writer but not yet observable.** The plaintext
   second writer is deleted (§3) and the boot scrub upgrades legacy plaintext
   rows, but nothing counts enveloped-vs-plaintext rows, so an operator
   cannot ask the node to prove the scrub ran clean. Closing this needs a
   count surfaced on `getwalletinfo.persistence`.
2. **The secret denylist is hand-maintained.** A future table with a
   spend-authorizing column is readable through `core storage query` until
   someone remembers to list it. There is no mechanism tying `SECRET_TABLES`
   to the schema.
3. **JSON-RPC is outside the grant.** By design (§7), but it means the audit
   trail is complete only for the typed surface.
4. **`vault.swap.redeem` / `.refund` have no amount to bound**, so a grant
   cannot use them at all — settlement is operator-only today.
