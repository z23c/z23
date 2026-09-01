# Promotion receipts — evidence that outlives the machine that made it

A promotion is the one moment this project puts a specific build on the
immutable proof server. The record of that moment has to be worth something
later, to someone who was not there and does not trust the person handing them
the repository.

## What was wrong with the record we had

`tools/scripts/proof_server_pin.sh` records a promotion as a **local annotated
git tag**. That was the right instinct — it self-records at the one moment
`tools/ship.sh` provably holds the binding, right after the running daemon
confirms it reports the candidate's source id — and the wrong storage:

| property | local git tag | what that means |
|---|---|---|
| replication | never pushed (origin holds only `main`) | the record dies with the disk; a fresh clone has none |
| immutability | `git tag -d` / `git tag -f` | a record can be removed or moved leaving no trace |
| authorship | unsigned | you have to trust whoever hands you the repo |

So the evidence that the immutable proof server ran a given build was exactly as
trustworthy as one local mutable ref.

## The record we have now

`platform/deploy/promotion-receipts.jsonl` — one JSON object per line, append-only,
following the same shape conventions as `platform/deploy/release-candidates.jsonl` (see
[`RELEASE_CANDIDATE_PIN.md`](./RELEASE_CANDIDATE_PIN.md)). Four properties, each
load-bearing:

1. **Hash-chained.** Every record carries `prev_hash`, the SHA-256 of the
   previous record's exact bytes *including its signature*. Editing, deleting,
   inserting, or re-ordering any past record breaks a link that a verifier can
   name. The chain starts at a **genesis** record that asserts nothing about any
   build, minted once by the owner (see "Owner setup" below).
2. **Signed.** Every record is signed with `ssh-keygen -Y sign` under the
   namespace `zcl-promotion-receipt`. Verification reads only
   `platform/deploy/promotion-signers`, a committed OpenSSH allowed-signers file — no
   private key, no network, no cooperation from the author. Stock OpenSSH; this
   repository already runs `ssh`/`scp` for every fleet operation, so nothing new
   was added. The signing identity is never a default: writing refuses until
   `ZCL_RECEIPT_KEY` names a key whose only job is signing evidence.
3. **Replicated.** The ledger is a **tracked file**. It reaches GitHub with
   every push of `main`. That is precisely the property a tag cannot have, and
   it is why the tag is now only a convenience index.
4. **Verified and gated.** `verify` walks the whole chain and names the first
   break; the lint gate `check-promotion-receipt-chain` runs it on the in-tree
   ledger plus a hermetic tamper-detection self-test.

### Why both a chain and signatures

They catch different attacks, and neither is sufficient:

- Signatures alone: an author who holds the key can edit a past record and
  re-sign it. Every record still verifies. Only `prev_hash` on the *following*
  record catches that, and the self-test asserts exactly this case.
- A chain alone: anyone can rewrite the whole ledger consistently. Only a
  signature ties records to an identity.

## Owner setup — the one-time root-of-trust decision

**The ledger ships with zero records and `platform/deploy/promotion-signers` ships with
zero keys.** Not even genesis. That is not an oversight: the identity that signs
evidence is the owner's decision, and so is publishing which key holds that
authority. Nothing in the tooling picks one, and both write paths refuse until
one is named:

```
promotion_receipt: refuse — no signing key configured; set ZCL_RECEIPT_KEY to a key whose only purpose is signing promotion evidence
```

An earlier draft of this tool defaulted to `~/.ssh/id_ed25519` — the operator's
personal SSH *authentication* key, the one `git push` and `gh` use. That is wrong
twice over, and the second reason is the important one:

- It made the root of trust a **default rather than a decision**. The first run
  picked an identity nobody had chosen.
- It **conflates two authorities**. A push key's job is authenticating pushes.
  Make it the evidence authority and anyone who can push can mint receipts, and
  rotating it for an ordinary git-access reason silently invalidates the whole
  evidence chain. An evidence chain's root of trust should be a key whose only
  job is signing evidence.

So, once, deliberately:

```bash
# 1. A key whose ONLY job is signing promotion evidence. Not a login/push key.
ssh-keygen -t ed25519 -C 'z23 promotion receipts' \
    -f ~/.ssh/zcl-promotion-receipt

# 2. Publish its PUBLIC half as the evidence authority.
printf '%s %s\n' promotions@example.invalid \
    "$(cut -d' ' -f1-2 ~/.ssh/zcl-promotion-receipt.pub)" \
    >> platform/deploy/promotion-signers

# 3. Mint the genesis record under that key.
ZCL_RECEIPT_KEY=~/.ssh/zcl-promotion-receipt \
    tools/scripts/promotion_receipt.sh init

# 4. Commit both. Uncommitted, they exist on one disk — the exact defect
#    this page is about.
git add platform/deploy/promotion-signers platform/deploy/promotion-receipts.jsonl
git commit -m 'start the promotion receipt chain'
```

Choose the principal in step 2 to name the *role*, not a person's mailbox.
Whatever it is, it is the string every future receipt carries in `signer` and
every verifier passes to `ssh-keygen -Y verify -I`.

Until step 3 runs, `verify` reports zero records as clean-and-unrecorded and
exits 0, and `latest` says `NO PROMOTION RECORDED`. That is the truth, and the
lint gate passes on it.

## Commands

```bash
# integrity of the whole chain — no private key needed, works offline
tools/scripts/promotion_receipt.sh verify

# the newest promotion receipt, or an honest "no promotion recorded"
tools/scripts/promotion_receipt.sh latest

# tamper-detection proof (hermetic: throwaway repo + throwaway key under /tmp)
tools/scripts/promotion_receipt.sh --self-test
```

Appending is not a manual step. `tools/ship.sh`'s promotion path calls
`promotion_receipt.sh append` itself, immediately after the remote health check
confirms the running daemon reports the candidate's source id — the same moment
the pin tag is written. It needs `ZCL_RECEIPT_KEY` in the environment for that,
and says so if it is missing rather than silently reaching for a key.

**Then commit the ledger.** Until it is committed the receipt exists on one disk
only, which is the defect this whole page is about; ship's clean-tree preflight
will refuse the next run until you do.

## Record shape

Fixed key order, because the bytes a signature covers must be reproducible
without a JSON canonicaliser. The signed payload is the record with its own
`sig_b64` field removed — still a well-formed JSON object.

| field | meaning |
|---|---|
| `schema` | `zcl.promotion_receipt.v1` |
| `seq` | position in the chain, from 0 |
| `prev_hash` | SHA-256 of the previous record's bytes; 64 zeros at genesis |
| `kind` | `genesis` or `promotion` |
| `host` | the promoted-to host (empty at genesis) |
| `commit` | the source revision shipped (empty at genesis) |
| `source_id_sha256` | what the running daemon reported of itself (empty at genesis) |
| `artifact_sha256` | the exact bytes installed (empty at genesis) |
| `recorded_utc` | when the record was written |
| `recorded_by` | the branch/lane that wrote it |
| `signer` | allowed-signers principal |
| `sig_b64` | the sshsig, base64 body only (the PEM wrapper is rebuilt at verify time) |

The three identity fields are the same triple
[`RELEASE_CANDIDATE_PIN.md`](./RELEASE_CANDIDATE_PIN.md) explains: none of
`commit`, `source_id_sha256`, `artifact_sha256` is sufficient alone.

`host`, `recorded_by` and `signer` are restricted to a charset with no `"`,
`,` or backslash. That is not cosmetic: it is what lets the payload-vs-signature
split be a plain suffix strip, and it stops a crafted value from smuggling a
second `sig_b64` field into a record.

## What is deliberately NOT in the ledger

**There are no promotion receipts. Zero.** The build currently running on the
proof server cannot be identified: `agentbuild` answers
`"build_commit":"external"`, and its `source_id` is not re-derivable from a bare
commit because `tools/dev/source-identity.sh` deliberately hashes host-local,
git-ignored build inputs. There is strong circumstantial evidence — a ship
receipt under `~/.cache/zcl-ship/`, an mtime, a reflog tip — and **strong
evidence is not proof**.

A receipt invented from that evidence would be a *fabricated evidence record*,
which is strictly worse than no record: it would make every later receipt
suspect. So nothing was minted, `verify` reports an empty ledger as intact with
`0 record(s), 0 promotion(s)`, and `latest` answers:

```
promotion_receipt: NO PROMOTION RECORDED — the receipt chain verifies clean and
  carries no promotion receipt. No promotion has ever been recorded, so whatever
  any proof server is running cannot be tied to a reviewed commit. This is the
  honest state of the ledger, not an error in it.
```

That is the correct answer and it must stay reachable. It is not a failure, and
the lint gate passes on it.

## Signing identity

One identity, listed in `platform/deploy/promotion-signers` — chosen by the owner, in the
one-time ritual above, and **absent from the shipped tree**. Key management and
rotation are deliberately **not** built here. Adding a second line to that file
is a reviewed commit, which is the audit trail a rotation actually needs. A
receipt signed by a key later removed from the file stops verifying — the honest
outcome, since the whole claim of a receipt is "this identity vouched for this
promotion."

## Limits, stated plainly

- **Tail truncation.** A pure hash chain cannot detect deletion of its *newest*
  records from the file alone. Two things cover it here: the ledger is committed,
  so git history holds the older head, and the gate enforces that HEAD's bytes
  remain a byte-exact prefix of the working file.
- **The ledger says what was promoted, not that the box still runs it.** That
  is a live question; `tools/scripts/proof_server_pin.sh check` dials the host
  read-only and answers it.
- **A verifier needs the allowed-signers file to be the real one.** It arrives
  through the same reviewed git history as the code, which is the same trust
  root the rest of the repository already rests on.

## The gate

`check-promotion-receipt-chain` (`tools/lint/check_promotion_receipt_chain.sh`)
checks five things: the hermetic self-test passes; the in-tree ledger verifies
with `ZCL_RECEIPT_KEY` pointed at a nonexistent path (the offline-third-party
contract); the allowed-signers file names a key *whenever the ledger holds a
record* — zero keys plus zero records is the shipped state and is fine, but a
record nobody can verify is an assertion rather than evidence; the committed
ledger at `HEAD` is still a byte-exact prefix of the working file (append-only,
enforced against git rather than a hand-maintained baseline); and
`tools/ship.sh` still calls `promotion_receipt.sh append`.

The self-test builds a chain and tampers with it six ways — edit a record,
delete one, re-order two, corrupt a signature, **re-sign an edited record with a
valid key**, and swap in an unlisted signer — asserting the *exact* first break
message for each. Exact messages, not just a non-zero exit: a previous receipt
self-test in this repository passed while checking nothing, because three
"bad input is refused" assertions all succeeded for an unrelated reason.
