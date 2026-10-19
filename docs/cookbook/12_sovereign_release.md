# 12_sovereign_release — your first chain-verified release in 5 minutes

What it demonstrates: the sovereign identity layer end to end, with nothing
to install and nothing to rely on but the chain you already synced. You will
verify a signed release, sign your own, and anchor an epoch — the
~40-byte transaction that commits the *entire overlay state* of the
network. Depth lives in `docs/spec/sovereign-identity-layer.md`; this page
is the fast path.

Conventions: commands are one-shot native commands
(`build/bin/z23 <command>`). Every command here either works
read-only or prints exactly what to do next.

## Step 0 — verify a release (read-only, always succeeds)

A release record is a `zid_doc`: an ed25519 signature over
`name ‖ version ‖ manifest_root`, made by the publisher's chain-anchored
master key. Verifying needs no wallet, no network, no chain — just the doc:

```bash
build/bin/z23 zcode release verify --file=<release.zid>
```

Expected output sketch:

```
name=demo-lib version=0.1.0
manifest_root=9f2c…(64 hex)
master_pubkey=d75a…(64 hex)
seq=1 expiry=1893456000 valid=true
```

Invalid docs are hard errors with named codes — `DOC_EXPIRED`,
`BAD_SIGNATURE`, `NOT_A_RELEASE_BODY`, `DOC_DECODE_FAILED` — so the
failure mode is always explicit.

That answers *"was this signed by the key it names?"* and nothing more.
*"Should I accept that key?"* is a second, separate question, and Step 4
answers it from the chain with `--anchored`.

## Step 1 — make your publisher key (one command, keep it secret)

Any 32-byte seed is a publisher identity. Generate one and lock it down:

```bash
head -c 32 /dev/urandom | xxd -p -c 64 > ~/.zcl-release-seed
chmod 600 ~/.zcl-release-seed
```

`zcode release sign` **refuses** a seed file with looser permissions —
your master key is your reputation; treat it like a wallet seed. It is
never logged, echoed, or written anywhere but your file.

## Step 2 — sign your first release

```bash
build/bin/z23 zcode release sign \
    --name=my-lib --version=0.1.0 \
    --root=<64-hex sha3 of your release tarball> \
    --seed-file=~/.zcl-release-seed
```

Expected output: the signed doc hex, your `master_pubkey` (this is your
publisher identity), and the path of the saved
`<datadir>/zcode/releases/my-lib-0.1.0.zid`.

Now anchor that key on-chain, so nobody has to take your word for it:

```bash
build/bin/z23 core identity anchor --pubkey=<your master_pubkey>
build/bin/z23 core identity resolve --pubkey=<your master_pubkey>
```

`anchor` broadcasts through the node wallet when one is loaded; with no
wallet (or no running node) it prints `op_return_hex` for you to include
in a transaction you sign yourself. Once it confirms, `resolve` answers
from the chain: anchor height, txid, status, and the ZNAM name if you
registered one. Rotating or retiring the key later is
`core identity rotate --input='{"pubkey":"<old>","new_pubkey":"<new>"}'`
and `core identity revoke --pubkey=<key>`; both prove ownership through
the spending input, so only you can move your own identity.

Anyone with the doc can now run Step 0 against *your* release. New
version? Increment `--seq` — consumers reject out-of-order docs, so a
replayed old release can't masquerade as the current one.

## Step 3 — anchor an epoch (optional, one tx, operator's choice)

The node's OP_RETURN catalog already commits every overlay record it has
ever seen (every ZNAM name, ZSLP transfer, ZANC anchor) into one rolling
digest. Anchoring it publishes that commitment on-chain:

```bash
build/bin/z23 core epoch status     # tip, catalog digest, anchored?
build/bin/z23 core epoch anchor     # with wallet: broadcasts; without:
                                           # returns op_return_hex to include
                                           # in any tx you make yourself
build/bin/z23 core epoch verify     # recompute + match against chain
```

One ~40-byte OP_RETURN commits the whole overlay state. Every honest node
computes the *same* digest, so when independent operators anchor the same
epoch, the anchors cross-check each other — agreement is public
confirmation, disagreement is a named, visible problem.

## Step 4 — prove it to someone else

Hand them one thing: the `.zid` file. Their own node answers the rest:

```bash
build/bin/z23 zcode release verify --file=<release.zid> --anchored
```

`--anchored` resolves the doc's `master_pubkey` against the identity
anchors their node folded out of the chain, and reports `anchored`,
`anchor_height`, `anchor_txid`, `anchor_name`, and `anchor_status`. Two
facts stay separate, and the output says both:

- **signature valid** — the doc really was signed by the key it names;
- **key anchored** — that key is published on-chain, by whoever spent the
  anchoring input, at a height the verifier can see for themselves.

Neither one rescues the other. A tampered doc under an anchored key is
still `BAD_SIGNATURE`. A perfect signature under a key nobody anchored is
`KEY_NOT_ANCHORED` — the verifier is told, in as many words, that they
would be accepting the key on the publisher's say-so. A key you later
retired is `KEY_REVOKED`; a key you rotated still verifies and reports its
`successor`.

Nothing is pinned out of band: no README, no GitHub account, no CA, no
keyserver, no CDN. Add the epoch anchor's txid from Step 3 if you also
want them to cross-check the whole overlay state their node derived.

## Where this goes next

`docs/spec/sovereign-identity-layer.md` — release batches folded into the
`zcode` domain MMR (one anchor covers a whole day's releases), swarm
distribution of packages, FROST t-of-n publisher committees, and the
pruning story that makes "no byte is stuck forever" true.
