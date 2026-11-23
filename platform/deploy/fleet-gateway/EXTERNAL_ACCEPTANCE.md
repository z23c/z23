<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# External acceptance: one real hosted-client round-trip

This is the finish-line procedure. It runs once, after the owner deploy in
[README.md](./README.md), against the QUALIFIED SHA only. It proves the
claims no loopback harness can: the endpoint is reachable from the hosted
client's own network, OAuth works for that real client, and a real
receiver's acknowledgement and result come back through the same
connection. The client invokes the tools itself; a curl transcript or a
relayed message is not acceptance.

## Preconditions (STOP gates; any mismatch refuses before the journey)

| # | Gate | How |
|---|---|---|
| S1 | Qualified SHA exists | Harness printed `verdict: PASS sha=<S> …` for this exact `<S>` |
| S2 | Source published | `git fetch origin main`; `<S>` is reachable from `origin/main` |
| S3 | Exact images | `sha256sum` of the deployed gateway, front and node equal the PASS report; `/proc/<pid>/exe` of each unit resolves to those bytes |
| S4 | Dependency pin | `git ls-tree <S> vendor/tor` equals the pin in the PASS report |
| S5 | Units serving | `systemctl --user is-active` is `active` for both units |
| S6 | Reachable from outside | Off-box, a real (non `-k`) TLS client fetches both discovery documents and gets `401` + `WWW-Authenticate` from a credential-less tools/call |
| S7 | Grant scope | The sign-in requests exactly `brief send evidence`, never more. The gateway vocabulary is closed (`brief send evidence terminate deliver wiki-write`; unknown names are refused). `wiki-write` is granted only when the client explicitly lists it in the requested scope; the sign-in page then adds a notice that wiki writes publish PUBLIC knowledge signed by this node, and accepting it does not widen any other grant |

## The journey (one connection, the client invoking)

1. **Connect.** Add the custom connector `<base>/steer` (README,
   "Connecting a Claude custom connector"). The first protected call shows
   **Connect**; the owner approves once on the approval page.
2. **Status.** The client calls `steer_brief`; the reply is the node's live
   brief (`isError:false`).
3. **Send.** The client calls `steer_send` with one item addressed to the
   receiving worker, carrying a fresh idempotency key recorded for this run.
   Save the returned item sequence. Call `steer_brief` with `cursor_token` set to
   the exact `cursor_token` string from step 2 (legacy clients may continue to
   use `since`, but do not supply both). Look in `changes` for the
   outbound row with the same sequence, recipient and work ref. If absent,
   follow the returned token while `changes_truncated` is true. An unavailable
   mail source leaves the check inconclusive. A healthy, exhausted page without
   the row or a client-side rejection of the string fails the check. An integer
   cursor can skip independently numbered inbox rows.
4. **Receive.** The receiving worker claims the item and records its
   acknowledgement and result under the same `ref`.
5. **Read back.** The client calls `steer_brief` / `steer_evidence` for
   that `ref`: the lifecycle reads `delivered`, then `acknowledged`, then
   the completed result, and the evidence equals the worker's recorded
   result bytes.
6. **Revoke.** The owner revokes the connection's grant
   (`fleet steer grant` action `revoke`); the client's next call returns
   `STEER_GRANT_REVOKED`.

## Restart, duplicate and lost-ACK safety (same journey)

- **Restart:** between steps 3 and 5, restart the gateway unit. Step 5 must
  return identical evidence (same image hash, new PID).
- **Duplicate:** resend step 3 with the same key and identical payload: the
  reply reports `duplicate:true` and appends nothing; a changed payload
  under the same key is refused `IDEMPOTENCY_CONFLICT`.
- **Lost ACK:** read before the worker acknowledges: the state is
  `delivered`, never skipped ahead, never an error.

## Proof separation

- source published: S2
- build and exact images qualified: harness PASS plus S3
- endpoint reachable: S6 plus step 1
- OAuth works for the real client: step 1 (the throwaway-cert harness legs
  prove the seam only)
- real round-trip: steps 2–5 invoked by the client
- deployment authorized: the owner ran the README deploy; agents never do
