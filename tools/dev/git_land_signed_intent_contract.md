<!-- Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0 -->

# Git land signed-intent acceptance contract (RED)

Run `devbuild --wait tools/dev/git_land_signed_intent_acceptance.sh
build/bin/z23-dev` from a checkout. The script uses only a disposable local
bare remote and an SSH-signed fixture commit. It does not publish a repository
candidate. A failing run retains its fixture path and JSON replies for review.

The first black-box case currently passes: after a test-only PASS proof
observation, `dev.land` refuses a candidate for which no signed publication
intent and attachment exist. The fixture checks the remote ref, pre-push hook
marker, refusal code, and retained queue row. It requires
`PUBLICATION_INTENT_REQUIRED`, unchanged `origin/main`, and no hook invocation.
A signed Git commit is **not** a publication intent. The acceptance is RED at
the next transition: `dev.land` has no registered `attach` action or input
schema for the signed objects, so a proven row cannot lawfully advance.
Once that route exists, the same script sends nonexistent all-zero CAS roots
and requires `PUBLICATION_INTENT_INVALID` with no hook or remote mutation.

## Proposed command contract

Extend the existing `dev.land` command and queue row. Do not add a scheduler
or sidecar ledger. A new `attach` action takes `seq`, `publication_root`,
`attachment_root`, `bundle_path`, `publisher_signer`,
`target_identity_root`, `target_ref`, `authority_root`, `accepted_root`,
`task_root`, `policy_root`, `action_id`, `workspace`, and `datadir`. Roots and
signer are 64 lowercase hex digits; `target_ref` is `refs/heads/main` for
this lander. `workspace` and `datadir` are receiver-scoped local fixture or
operator paths, never a request to mutate a canonical node. The receiver
must resolve an actual local target grant independently of these caller
fields and verify that its root equals the signed `authority_root`; a caller
cannot self-assert a grant. For Gitlinks, the receiver supplies pinned
dependency locators and expected closure root. A caller-provided locator
never becomes public authority. The action is accepted only for one already PROVEN, frozen
`row.local@row.base` pair. Its CAS objects must have been stored with the
existing accepted-work service and pass its exact action, task, candidate,
proof-set and policy qualification. `attach` is idempotent only for identical
roots and bytes; changing any coordinate requires a successor row.

The existing `vcs_zcode_publication_v1` binds `candidate_root`,
`proof_set_root`, `target_identity_root`, `authority_root`, `target_ref`,
`expected_base`, and `head_commit`, signed by `author_pubkey`. The existing
`vcs_zcode_publication_attachment_v1` binds the intent root, complete Git
bundle SHA-256, expected base and head, signed by the same publisher. For
Gitlinks, `zcl_dev_git_publication_check_with_dependencies` additionally
requires the receiver's exact superproject closure and one pinned locator
per link. The old source check remains strict.

The queue row must durably retain `publication_root`, `attachment_root`,
`bundle_sha256`, `publisher_signer`, `target_identity_root`, `target_ref`,
`authority_root`, `accepted_root`, `task_root`, `policy_root`, `action_id`,
`expected_base`, `head_commit`, and the immutable bundle locator before any
push. Its existing `local`, `base`, `tree`, and `proof_intent` must agree with
those fields and the exact PASS receipt. A row cannot enter `push` merely
because the proof stub or real proof says PASS. CAS write barriers and the
queue file plus parent-directory flush are both part of the pre-push
checkpoint. A failed flush refuses dispatch.

## Black-box cases to add to the same fixture runner

Each case uses a fresh local bare remote, a signed candidate, isolated
`XDG_STATE_HOME`, and an observed hook/receive-pack invocation count. The
runner must inspect the command JSON, persisted row after a new process
starts, remote ref, and signed CAS roots. No case may infer LANDED solely from
client push output or a local tracking ref.

| Case | Injected state | Required observation |
| --- | --- | --- |
| Missing intent | PASS proof, no `attach` | `PUBLICATION_INTENT_REQUIRED`; no pre-push hook; remote remains base; row reclaimable. |
| Missing or tampered attachment | Intent exists; attachment absent, wrong signer, changed bundle byte, wrong root or wrong pair | `PUBLICATION_ATTACHMENT_INVALID`; no hook or remote mutation; exact original objects retained. |
| Bound coordinates | Valid intent/attachment, then alter candidate, expected base, head, target identity/ref, proof-set root or bundle SHA-256 one at a time | Every altered field refuses before push; matching fields load from CAS after process restart. |
| Competing integrator | Advance bare `main` from base to a sibling after attach, before step | `EXPECTED_BASE_MISMATCH`; no push/rebase of the frozen intent; original row and receipts retained for immutable successor. |
| Crash before push | Kill the step after the durable intent and `push` phase checkpoint, before Git invocation | Restart reloads the same signed objects and exact pair; one push attempt at most; no new signature or implicit rebase. |
| Push succeeded, result lost | Kill publisher after remote ref transaction but before acknowledgement/queue outcome | Restart first fetches remote; receive-pack marker stays at one invocation; it seals a remote receipt or retains UNKNOWN, never replays push blindly. |
| Independent remote receipt | Push acknowledges, but fresh fetch is unavailable or fetched source/ancestry differs | Row remains `UNKNOWN`/inflight; no LANDED outcome. A later independent fetch that verifies exact target, intended head ancestry, pinned source and dependency closure may persist the signed receipt, then mark LANDED. |
| Receipt recovery | Crash after signed receipt CAS store but before outcome append | Restart reloads and verifies the exact receipt and intent; appends one terminal outcome without another push or losing predecessor evidence. |

## Smallest owner patch sketch

1. Add `attach` keys to the existing `dev.land` schema and row codec.
   During `attach`, call the existing accepted-work qualification and
   `zcl_dev_git_publication_check[_with_dependencies]`; resolve the local
   receiver target grant and compare its root to the signed authority root;
   compare intent and attachment coordinates to `row.local`, `row.base`, receiver target, actual
   bundle bytes and exact proof receipt. Persist the bound roots in the
   existing queue with file and parent flush. Never sign for the caller.
2. At `dl_step_push`, reload those roots and fail closed if missing or stale.
   Freshly observe `origin/main == expected_base`, check base-to-head
   ancestry, then persist `phase=push` plus exact intent roots before the
   existing force-with-lease push. A changed base makes a new immutable
   successor necessary; do not rebase this intent.
3. On any ambiguous push result or restart, call the existing independent
   Git remote observer. Seal/store the existing versioned remote receipt only
   after fetched ref, source/dependency closure and ancestry agree under
   receiver policy. `dl_already_landed` cannot be the terminal authority for
   this path: require the persisted verified receipt before writing LANDED.
4. Extend the existing `test_dev_land` rig (the owner controls that file)
   with the remaining cases above. Keep the separate black-box witness as
   the command-bound check. No unsigned or hook-skipping path qualifies a
   real candidate.

Until this contract is green, `9e4407cc8c0582a6272523329d97fca946041dbb`
on `96e63147ae9047f8eb8e843ca06f251715e3dd0e` remains PROVEN only.
If main advances, preserve that proof and cut a new immutable successor;
never alter the frozen candidate or replay an old receipt.
