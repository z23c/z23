# Z23 Blog

Blog is the reference Rails-style Z23 application:

Every participating node serves the blog at `/blog` on its own HTTPS and
onion endpoints. There is no canonical mount and no privileged host: the
path is identical everywhere, and which node you read it from is your
choice, not the network's.

- **Model:** `BlogPost` and `BlogPublicationReceipt` use the project
  ActiveRecord lifecycle and schema migration v28. Relationships are explicit:
  a post has many receipts, each receipt belongs to one post, and sequenced
  posts belong to their signed predecessor.
- **View:** escaped HTML reports signature, name binding, chain observation,
  served-frontier proof, and local content availability separately.
- **Controller:** thin typed `create`, `import`, and `show` actions delegate to
  one publication service.
- **Service:** the Core wallet signs an immutable `blog.posts.v1` event; the
  signer must match the current on-chain ZNAM owner; the node stores the post
  locally and emits a compact anchor script.

The full article is not put on chain. Its signed `event_id` commits to the
name, slug, title, body, author key, chain genesis, sequence, timestamp, and
previous event. The optional chain commitment is:

```text
OP_RETURN <"ZBLG"> <version=1> <znam-name> <event-id:32>
```

Any relay can carry the signed event, so rejecting it at one server does not
change its identity or authenticity. A reader verifies the event before
ActiveRecord persistence and can retrieve it from another peer or onion.
ZNAM supplies the human name; the wallet key supplies authorship; the chain
anchor supplies ordering/commitment evidence; peers supply availability.

## Fast authoring, hard promotion boundary

The application layer is intentionally friendly to LLM-authored C23, HTML, and
Markdown. Trust does not come from the generator. Core applies a fixed ladder:

```text
source → validate → focused tests/simulation → artifact + manifest digest
       → capability grant → wallet signature → optional chain anchor
```

The signature and chain can prove publisher identity, exact bytes, ordering,
and later revocation. They cannot prove that generated code is correct or safe;
the compiler, ActiveRecord validations, deterministic tests, sandbox, and
capability review remain mandatory. Third-party code never receives private
keys and does not execute inside consensus.

## Current proof boundary

This slice is deliberately non-broadcast while the canonical node is wedged.
Tests prove pre-sign validation, wallet signing, deterministic fork storage,
alternate-order import, explicit ActiveRecord relationships, strict/minimal
anchor parsing, full-node projection confirmation, owned-lane reorg-to-orphan
refresh, read-only public routes, fail-closed routing, and escaped responsive
rendering in isolated databases. Production publication remains contained until:

1. the Core active-generation/local-grant broker is the sole constructor of
   the opaque signing binding;
2. a generic wallet transaction composer broadcasts the anchor;
3. P2P/onion anti-entropy carries event bodies; and
4. anchor verification gates on H*, the active-chain slot, and canonical block
   body—not merely the lossy `node.db` explorer projection.
5. a historical ZNAM owner-epoch projection binds the author key at the event
   and anchor heights instead of consulting only the mutable current owner.

Accordingly, the UI calls today’s receipt `projection-confirmed`, never final.
It labels the ZNAM import check as an observation, not historical ownership
proof. `/blog` fails closed with 503 when proof storage is unavailable; it never
falls back to unsigned legacy static content.
