# Custody model

What holds the keys, what authorizes a spend, and what an AI agent operating
this node can and cannot do with them.

This page states the boundary as the code enforces it. Where a control is a
convention rather than a mechanism, it says so — a boundary you believe in and
the code does not draw is worse than no boundary.

---

## 1. The one-sentence shape

The node process holds every spending key in RAM in cleartext while it is
unlocked; the disk copy is wrapped under a passphrase the operator supplies;
and every typed command an agent issues is bounded by a grant the agent cannot
mint for itself — but the grant is presented in the agent's own environment,
so an agent that declines to cooperate is bounded only by the operating system,
not by this code.

---

## 2. Where private keys live

Five places. All five are inside the operator's own trust domain; none is
network-reachable.

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

**Export paths** (deliberate, OWNER-gated, plan/commit): `dumpprivkey` /
`z_exportkey` over JSON-RPC, and `core.wallet.address.export-key` over the
typed surface (`contexts/wallet/controllers/src/wallet_native_handlers.c:310-365`). The
typed form refuses without `confirm:true`, warns in the plan body that commit
reveals the key, and returns the WIF in `reply.data.privkey`. Neither path
logs the key: `rpc_dumpprivkey` logs only the address on every failure branch
(`contexts/wallet/controllers/src/wallet_controller_keys.c:29-54`).

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

REFUSE does not stop the node. Per §2's neighbour
`wallet_at_rest_boot_decision()` the boot continues in **NO-SPEND mode** (zero
keys minted, nothing written in the clear) and syncs normally; only sending and
receiving wait. A refusal is scoped to the asset it protects, never to the boot.

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
leaves the wallet locked, a malformed credential fails boot by name, and a
wrong passphrase reaches the existing wallet persistence abort guards rather
than silently dropping keys.

NULL means "no encryption": writes go out in cleartext and enveloped rows on
disk fail to decrypt and are dropped with a counted warning
(`g_read_keys_corrupt_rows`). A plaintext wallet is always "unlocked" because
there is nothing to lock.

**The README's claim, checked.** "AES-256-GCM for new wallets; an existing
plaintext wallet still loads with a warning" is accurate for the
`wallet_sqlite` path, which is the path the wallet itself uses.

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
| `dumpprivkey` / `core.wallet.address.export-key` | both | OWNER + plan/commit; hands over the key, after which no gate applies |
| `importprivkey` / `core.wallet.address.import` | both | OWNER; installs a key the operator never saw |

Two independent runtime gates sit under all of them:

- **`wallet_lock_spend_guard()`** — a locked wallet cannot spend even when
  trust permits (`contexts/wallet/modules/wallet/include/wallet/wallet_lock.h`).
- **the sync-trust `WALLET_SPEND` capability** — spending is disabled until
  the node's own state is self-verified.

---

## 5. What the agent grant bounds

The grant is a row in `agent_sessions` (migration v36,
`engine/models/src/database_migrate_features_v30_up.c:200-224`), minted by
`vault session create` for an existing principal, and presented per invocation
as `ZCL_AGENT_SESSION=<32 hex chars>`
(`tools/command/native_command.c:2735, 3173`).

It bounds four things and nothing else:

| bound | column | enforced in |
|---|---|---|
| amount per transaction | `max_per_tx_zat` | `agent_session_authorize` |
| amount per rolling window | `max_per_window_zat` + `window_seconds` (≤ 1 year) | same |
| destination | `recipient_allowlist` (exact CSV token, never a prefix) | same |
| lifetime | `expires_at`, `revoked` | same |

The check and the window debit are **one indivisible step** under a
process-local mutex, with a targeted `UPDATE` of only the two window columns
guarded by `revoked=0` — so concurrent invocations cannot jointly blow a cap,
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
  (`engine/modules/kernel/src/command_registry.c:1740-1800`).
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
  operator (`native_command.c:3159` — `granted_capabilities=~0`,
  `authority_ceiling=OWNER`);
- read `<datadir>/.cookie` and call `sendtoaddress` straight over JSON-RPC,
  below the kernel and below this policy entirely
  (`engine/controllers/src/rpc_client.c:184`);
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
