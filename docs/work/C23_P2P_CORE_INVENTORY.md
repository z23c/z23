# C23 P2P Core Consolidation Inventory

Status: reviewed consolidation slice, 2026-08-12. This is a code inventory, not a
new architecture or authority plane. Consensus, wallet, node operation, and
deployment are out of scope.

## Boundaries

The reusable core is a set of small C23 mechanisms beneath the existing
domain objects. A task remains a task, a package remains a package, and a DHT
record remains a DHT record. The core may canonicalize hashing, signing,
bounded transfer, leases, and evidence mechanics; it must not create a generic
development lifecycle or another source of truth.

Layering stays:

1. pure canonical codecs and cryptographic bindings;
2. bounded stateful engines with caller-driven clocks;
3. the existing full-node adapters in `config/`, `app/`, and `core/modules/net/`.

Libraries do not acquire sockets, wallet authority, consensus state, a live
datadir, deployment authority, or command ownership.

## Mechanism map

| Concept | Canonical candidate | Existing consumers | Duplication / difference audit | Deletion path |
|---|---|---|---|---|
| Content-addressed bytes | `package_store` content.v2 chunk CAS for node-carried bytes; `vcs_object` for working-copy ZVCS objects | package/source swarm, blob facade, work contexts; ZVCS commits/manifests/evidence | Two stores are necessary today: different roots, locations, quotas, and lifecycle owners. `blob_store` is already a facade over content.v2, not a third CAS. | Do not merge stores. Remove any future raw node-byte store in favor of content.v2; keep explicit bridges such as package mappings. |
| Manifests | `package_manifest` for transferable content; `vcs_manifest` for source-tree semantics | contexts/commons/packages/blobs/work context; ZVCS tree/commit | Different commitments and path semantics are necessary. Candidate trees and action inputs bind these roots rather than redefining transfer manifests. | Keep both formats; delete ad-hoc transfer manifests if found. |
| Missing-object transfer | `package_swarm` codec + `package_swarm_node` / engine | package hosting, source checkout, `blob_store`, `zcode_work_context` | This is already the shared ANNOUNCE/WANT/DATA/CANCEL path. Work control messages are not byte transfer. | Route new bounded objects through content.v2; no second object-transfer protocol. |
| Signed evidence root | `signed_evidence` (this slice) | work/lane/score and benchmark receipts; work-swarm control; continuity, creation, patronage, science, seed, contributor, C23 corpus, and space evidence | The codecs repeated domain SHA3, Ed25519 seal, and signer-bound verification. Payload/domain differences are necessary; the crypto lifecycle was accidental. | Completed for compatible root-based objects without changing roots, signatures, or wires. Extend only when another codec has the exact root-signing contract. |
| Signed preimage records | Domain codecs over Ed25519 (`zcode_dht_record`, delegation, package attest/release, and selected C23/space records) | DHT, publication, reproduction, and discovery | Some contracts sign canonical preimages directly rather than a 32-byte root, and expected-signer rules differ. Those are wire-contract differences, not permission to duplicate common validation forever. | Keep the direct-preimage formats until an independent rule-of-two primitive can preserve their exact bytes and policy. Do not rewrite formats merely to share code. |
| Identity | ZID master identity + DHT delegated online identity; explicit signer keys on evidence | DHT records, work capability/results, receipts | Master/online separation is necessary. Work signer provisioning and DHT online signer provisioning are separate local paths and may be accidental duplication, but authority equivalence is not established. | First define an explicit signer-role/key-source interface; never silently treat transport, DHT, worker, or promotion keys as interchangeable. |
| Capability advertisement | `zcode_work_capability_v1` for remote work; DHT PROVIDER records for content reachability | work-node selection; DHT discovery | Work resources/slots and content availability are different capabilities. Both repeat expiry/signer/canonical-envelope mechanics. | Share envelope and bounded-selection utilities, not the domain payload or trust policy. |
| Capacity / slots | Signer-owned effective slots in `zcode_work_node` | requester peer selection and admission | Transport sessions must not multiply signer capacity. Build-fabric queue limits and package-store quotas measure different resources. | Keep resource-specific bounds; extract signer-keyed slot accounting only when a second live scheduler can delete its own implementation. |
| Leases / expiry | Durable compare-and-swap action lease in `build_fabric`; signed request deadline in work swarm | local executor ledger; remote request admission | Durable execution ownership versus untrusted network validity is a necessary split. Package request timeouts are transport retries, not execution leases. | Project wire expiry into the canonical action lease; do not create a generic parallel lease ledger. A signer/slot/lease helper is a next candidate only with two real consumers. |
| Deduplication | Immutable `action_id` in build-fabric; chunk/root identity in CAS | local/remote exact actions; package transfer | Action dedup and byte dedup are distinct keys over distinct facts. Session/request-id suppression is replay protection, not semantic dedup. | Centralize exact-action lookup at build-fabric and byte reuse at CAS; delete caller-local caches or alternate action keys. |
| Scheduling | Build-fabric worker queue for executable actions; package possession scheduler for bounded scrub work | async proof; storage ACK renewal | Execution ownership and incremental possession verification have different state transitions. Both need bounded budgets and fair wakeups, but neither is a generic authority. | Extract a caller-driven bounded-work cursor only after two consumers can delete their loops and keep domain state canonical. |
| Receipts / projections | Canonical signed receipt objects in VCS/CAS; build-fabric and discovery tables as rebuildable projections | proof acceptance, lanes, score, replication, reproduction | Receipt payloads are intentionally domain-specific. REQUESTED/RUNNING/READY-style rows must remain projections of task/action/receipt facts. | Share signed evidence mechanics; remove projection-only lifecycle facts that cannot be rebuilt from canonical objects. |

`vcs/package_content.h` is the common in-memory edge of the existing
content.v2 machinery. Package carriers, accepted-source carriers, proof
contexts, candidate trees, and proof outputs use it for canonical chunk
hashing plus coordinate-checked CAS admission/reconstruction. It owns no wire,
retry, scheduler, completion flag, or policy; missing-object transfer and all
retry state remain exclusively in `package_swarm`.

## First rule-of-two consolidation

`vcs/signed_evidence.h` is stateless and has three operations: derive a root
from an explicit domain byte span and canonical body, sign that 32-byte root,
and verify it while binding the embedded signer to the caller's expected
signer. It has no codec, storage, network, clock, key provisioning, or policy.

The consumers now include:

- immutable work receipts (`zcode_dev.c`);
- chained durability-lane receipts (`zcode_lane.c`);
- evidence-bound score and benchmark receipts;
- signed work-swarm capability, request, cancel, and progress objects
  (`zcode_work_swarm.c`);
- continuity, creation, patronage, funding, settlement, science, seed, and
  contributor evidence;
- C23 productivity/corpus objects and read-only space/scout roots.

Existing golden receipt roots and rejection tests are the compatibility gate.
The explicit domain length preserves the existing, format-specific decision
to include or exclude a trailing NUL. No wire version, object ID, signature,
or public domain API changed.

## Next five deletion targets

1. Reconcile worker signer provisioning with delegated online identity through
   explicit roles; delete duplicate key-file lifecycle code only if authority
   remains fail-closed.
2. Isolate signer-keyed slot accounting from transport sessions and prove a
   second scheduler can reuse it while deleting its local counter state.
3. Keep removing caller-local missing-object and retry loops where the package
   swarm already provides the same bounded transfer state. The carrier-local
   byte/chunk/store loops are consolidated; network retries remain solely in
   the swarm engine.
4. Compare build-fabric, possession, and DHT maintenance wake/budget loops for
   a small caller-driven work cursor; extract it only when two loops disappear.
5. Inventory the remaining direct-preimage records by signer policy and extract
   a primitive only if two formats can delete their local mechanics unchanged.

The success criterion for every follow-up is negative: fewer implementations,
fewer lifecycle owners, and no new authority, protocol, scheduler, or CAS.
