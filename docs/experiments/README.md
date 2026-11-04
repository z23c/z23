<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Experiment records

Dated records of measured experiments: the question, the method, the
environment and the result. A record is evidence for a change; it is kept
when the change lands and is not edited afterwards except to correct a
factual error.

Commands: `discover.wiki`, `discover.read`

- Name a new record `YYYY-MM-DD-short-slug.md`, dated in UTC.
- State the compiler version, CPU model and date of every measurement, the
  exact commands that produced it, and the raw numbers next to any summary.
- List the records with summaries: `z23 wiki experiments`; page through them
  with the `next` entry each reply carries.

## Index

| Date (UTC) | Record | Result |
|---|---|---|
| 2026-08-26 | [Cooperative API-cache shutdown](./2026-08-26-api-cache-cooperative-shutdown.md) | See the record. |
| 2026-08-26 | [Package verifier object reuse](./2026-08-26-package-verifier-object-reuse.md) | The first command populated the shared production object epoch and linked the verifier in 193.62 seconds wall time. |
| 2026-08-29 | [Connected-peer block manifest refresh — 2026-08-29](./2026-08-29-block-manifest-refresh.md) | See the record. |
| 2026-08-29 | [Signed mesh capability frames and durable transfer cancellation](./2026-08-29-mesh-capability-cancel.md) | Tests prove private-object cancellation survives restart and a re-signed offer with the same transfer identity; grant revocation survives database reopen. |
| 2026-08-29 | [Onion discovery and projection catch-up contention](./2026-08-29-onion-discovery-catchup-contention.md) | See the record. |
| 2026-08-29 | [Private-object grant and encryption order](./2026-08-29-private-object-grant-encryption-order.md) | The key context is unchanged when the later grant identifier and ciphertext root are attached, and altering either field is refused by exact expectation matching. |
| 2026-08-29 | [Sub-second holdings read baseline](./2026-08-29-subsecond-holdings.md) | One hundred warm build/bin/z23 vault list process invocations against the running local node completed with 87.229 ms median, 97.128 ms p99, 98.030 ms maximum, and 87.179 ms mean wall latency. |
| 2026-08-29 | [Sync discovery liveness acceptance](./2026-08-29-sync-discovery-liveness.md) | Bundle discovery now admits a peer only to the download rotation for the exact artifact commitment that peer advertised. |
| 2026-08-29 | [Windows VCS checkout cross-compilation](./2026-08-29-windows-vcs-checkout.md) | All five MinGW C2x checks passed. |
| 2026-08-31 | [Story-ranked product-loop retrieval](./2026-08-31-story-retrieval-product-loop.md) | It improves measured first-page recall over the historical literal behavior while slightly reducing projected five-file context. |
| 2026-09-03 | [Muse vs GLM as executors on one lint-gate task (2026-09-03)](./2026-09-03-muse-vs-glm-lint-gate.md) | Both gates are correct, both pass every check in this comparison (self-test, run_lint.sh, doc-accuracy, lint-fast, and all three mutation tests), and both are wired into lint-fast/Makefile/DEFENSIVE_CODING.md identically. |
| 2026-09-03 | [Proof warm-start: cold-vs-warm measurement (2026-09-03)](./2026-09-03-proof-warm-start.md) | See the record. |
| 2026-09-03 | [Initial block sync throughput: profile and two optimisations](./2026-09-03-sync-throughput.md) | See the record. |
| 2026-09-25 | [Shadow proof-obligation selection](./2026-09-25-shadow-obligation-selector.md) | See the record. |
| 2026-09-27 | [Exact output boundary before touch](./2026-09-27-ledger-blue-exact-output-stop.md) | The earlier review controller rejected a second completed output in one upload chunk, but accepted bytes after the first completed output if they did not complete another output. |
| 2026-09-27 | [Ledger Blue local SHA-256 and read-only approval](./2026-09-27-ledger-blue-local-sha-and-readonly-approval.md) | The C23 wallet reviewer uses Z23's self-contained zsha256 package for transaction replay, wire comparison, CLI preflight, and UTXO script hashes. |
| 2026-09-27 | [Bounded transparent output review controller](./2026-09-27-ledger-blue-output-review.md) | The read-only controller retains one P2PKH or P2SH output at a time during pass three. |
| 2026-09-27 | [Read-only transparent payment APDU boundary](./2026-09-27-ledger-blue-payment-apdu.md) | The C23 Wallet command candidate uses CLA A5, zero P1/P2, and an exact single-byte payload length. |
| 2026-09-27 | [Transparent output screen preview](./2026-09-27-ledger-blue-payment-screen.md) | See the record. |
| 2026-09-27 | [Transaction-driven transparent payment simulator](./2026-09-27-ledger-blue-payment-simulator.md) | The C23 host simulator runs the same bounded review controller used by the unit test. |
| 2026-09-27 | [One-context ZIP-243 replay bound to transaction bytes](./2026-09-27-ledger-blue-replay-zip243.md) | See the record. |
| 2026-09-27 | [Ledger Blue transparent signing boundary](./2026-09-27-ledger-blue-signing-boundary.md) | Two portable C23 modules now compile for both host and ARM. |
| 2026-09-27 | [Ledger Blue fixed-path signing callback](./2026-09-27-ledger-blue-signing-callback.md) | The callback selects only m/44'/147'/0'/0/0 or m/44'/147'/0'/1/0 after PIN validation. |
| 2026-09-27 | [Ledger Blue signing footprint](./2026-09-27-ledger-blue-signing-footprint.md) | The ordinary image has 33,792 bytes of .text, 5,472 bytes of .bss, and zero .data. |
| 2026-09-27 | [Ledger Blue signing route candidate](./2026-09-27-ledger-blue-signing-route.md) | See the record. |
| 2026-09-27 | [Streaming transparent ZIP-243 digest and Blue memory limit](./2026-09-27-ledger-blue-streaming-zip243.md) | See the record. |
| 2026-09-27 | [Bounded C23 intake for transparent ZCL transactions](./2026-09-27-ledger-blue-tx-stream.md) | See the record. |
| 2026-09-27 | [Ledger Blue Wallet 0.3.6 Cortex-M3 startup test](./2026-09-27-ledger-blue-wallet-036-m3-startup.md) | See the record. |
| 2026-09-27 | [Ledger Blue Wallet 0.3.6 stack-path audit](./2026-09-27-ledger-blue-wallet-036-stack-audit.md) | See the record. |
| 2026-09-27 | [Ledger Blue Wallet 0.3.6 startup shell](./2026-09-27-ledger-blue-wallet-036-startup.md) | See the record. |
| 2026-09-27 | [Ledger Blue Wallet 0.3.7 SDK stack canary](./2026-09-27-ledger-blue-wallet-037-canary.md) | See the record. |
| 2026-09-27 | [Ledger Blue Wallet Cortex-M0 EXIT packet test](./2026-09-27-ledger-blue-wallet-m0-touch.md) | See the record. |
| 2026-09-27 | [Ledger Blue read-only payment review failure](./2026-09-27-ledger-blue-wallet-review-failure.md) | See the record. |
| 2026-09-27 | [Linked Blue Wallet read-only review candidate](./2026-09-27-ledger-blue-wallet-review-link.md) | See the record. |
| 2026-09-28 | [Ledger Blue account revocation after PIN loss](./2026-09-28-ledger-blue-account-revocation.md) | See the record. |
| 2026-09-28 | [Ledger Blue host assembly callback mutation](./2026-09-28-ledger-blue-assembly-callback-snapshot.md) | See the record. |
| 2026-09-28 | [Ledger Blue signing and broadcast copy](./2026-09-28-ledger-blue-broadcast-copy.md) | The final payment page and both later screens now say HOST MAY BROADCAST. |
| 2026-09-28 | [Ledger Blue exception reply erasure](./2026-09-28-ledger-blue-exception-reply-erasure.md) | See the record. |
| 2026-09-28 | [Ledger Blue final signing chain warning](./2026-09-28-ledger-blue-final-chain-warning.md) | See the record. |
| 2026-09-28 | [Ledger Blue host abort workspace erasure](./2026-09-28-ledger-blue-host-abort-workspace.md) | Wallet 0.3.34 calls the controller erasure path after the APDU validates and acknowledges the host abort. |
| 2026-09-28 | [Ledger Blue host signing storage boundary](./2026-09-28-ledger-blue-host-signing-storage.md) | See the record. |
| 2026-09-28 | [Ledger Blue address APDU after PIN loss](./2026-09-28-ledger-blue-locked-apdu.md) | See the record. |
| 2026-09-28 | [Ledger Blue lock screen after PIN loss](./2026-09-28-ledger-blue-lock-screen.md) | See the record. |
| 2026-09-28 | [Ledger Blue NO SIGN erasure](./2026-09-28-ledger-blue-no-sign-erasure.md) | Wallet 0.3.28 calls the existing volatile erasure path as soon as the NO SIGN callback succeeds. |
| 2026-09-28 | [Ledger Blue payment ownership wording](./2026-09-28-ledger-blue-ownership-wording.md) | See the record. |
| 2026-09-28 | [Ledger Blue payment APDU storage boundary](./2026-09-28-ledger-blue-payment-apdu-storage.md) | See the record. |
| 2026-09-28 | [Ledger Blue payment reply cleanup](./2026-09-28-ledger-blue-payment-reply-cleanup.md) | See the record. |
| 2026-09-28 | [Ledger Blue PIN loss during signing](./2026-09-28-ledger-blue-pin-loss-signing.md) | See the record. |
| 2026-09-28 | [Ledger Blue totals after transparent approval](./2026-09-28-ledger-blue-post-approval-totals.md) | See the record. |
| 2026-09-28 | [Ledger Blue private-key initialization result](./2026-09-28-ledger-blue-private-key-init-result.md) | See the record. |
| 2026-09-28 | [Ledger Blue reported APDU receive length](./2026-09-28-ledger-blue-receive-length-bound.md) | Wallet 0.3.30 checks the reported receive count before inspecting the instruction or passing the request to either handler. |
| 2026-09-28 | [Ledger Blue repeated touch at final signing page](./2026-09-28-ledger-blue-repeat-tap-signing.md) | The final page now places SIGN ZCL at x=20..154 and NO SIGN at x=165..299. |
| 2026-09-28 | [Ledger Blue review exchange failure](./2026-09-28-ledger-blue-review-exchange-failure.md) | See the record. |
| 2026-09-28 | [Ledger Blue PIN loss during payment review](./2026-09-28-ledger-blue-runtime-pin-loss.md) | See the record. |
| 2026-09-28 | [Ledger Blue shielded APDU reply erasure](./2026-09-28-ledger-blue-shielded-reply-erasure.md) | See the record. |
| 2026-09-28 | [Ledger Blue shielded upload isolation](./2026-09-28-ledger-blue-shielded-upload-isolation.md) | See the record. |
| 2026-09-28 | [Ledger Blue review USB reset](./2026-09-28-ledger-blue-shielded-usb-reset.md) | See the record. |
| 2026-09-28 | [Ledger Blue short APDU reply erasure](./2026-09-28-ledger-blue-short-reply-erasure.md) | The corrected loop erases the unused buffer after a successful command and the entire buffer after a rejected command, before appending status bytes. |
| 2026-09-28 | [Ledger Blue signing buffer isolation](./2026-09-28-ledger-blue-sign-buffer-isolation.md) | See the record. |
| 2026-09-28 | [Ledger Blue host signing expectation snapshot](./2026-09-28-ledger-blue-sign-expectation-snapshot.md) | The new test, compiled against the prior signer from commit cdf7d0f32, failed at the first repaired path case: the prior signer returned success and accepted that signature. |
| 2026-09-28 | [Ledger Blue Sapling SpendAuth storage boundary](./2026-09-28-ledger-blue-spend-auth-storage.md) | See the record. |
| 2026-09-28 | [Ledger Blue receive-account startup after PIN loss](./2026-09-28-ledger-blue-startup-pin-loss.md) | See the record. |
| 2026-09-28 | [Blue signing interruption and pending-reply erasure](./2026-09-28-ledger-blue-usb-sign-interruption.md) | See the record. |
| 2026-09-29 | [Ledger Blue APDU tail erasure](./2026-09-29-ledger-blue-apdu-tail-erasure.md) | See the record. |
| 2026-09-29 | [Ledger Blue final approval binding](./2026-09-29-ledger-blue-final-approval-binding.md) | See the record. |
| 2026-09-29 | [Ledger Blue shielded review full-wire commitment](./2026-09-29-ledger-blue-full-wire-commitment.md) | See the record. |
| 2026-09-29 | [Laptop payment facts beside the Ledger Blue](./2026-09-29-ledger-blue-laptop-payment-facts.md) | See the record. |
| 2026-09-29 | [Ledger Blue output screen binding](./2026-09-29-ledger-blue-output-screen-binding.md) | See the record. |
| 2026-09-29 | [Ledger Blue payment interruption inside device callbacks](./2026-09-29-ledger-blue-payment-inflight-interrupt.md) | See the record. |
| 2026-09-29 | [Ledger Blue payment touch binding](./2026-09-29-ledger-blue-payment-touch-binding.md) | See the record. |
| 2026-09-29 | [Shielded Review USB generation and stale reply](./2026-09-29-ledger-blue-review-usb-generation.md) | See the record. |
| 2026-09-29 | [Shielded replay branch on Ledger Blue](./2026-09-29-ledger-blue-shielded-branch-screen.md) | Release and sanitized Debug tests passed 60/60. |
| 2026-09-29 | [Shielded Review device-loop redraw and reconnect](./2026-09-29-ledger-blue-shielded-device-loop.md) | Version 0.5.8 redraws at review begin, completion of each upload pass, advance, finish, abort, and command rejection. |
| 2026-09-29 | [Ledger Blue signer storage alias boundary](./2026-09-29-ledger-blue-signer-storage-alias.md) | See the record. |
| 2026-09-29 | [Ledger Blue approval-timeout APDU erasure](./2026-09-29-ledger-blue-timeout-apdu-erasure.md) | See the record. |
| 2026-09-29 | [Commons journey across three physical hosts (2026-09-29)](./COMMONS_MULTIHOST_2026-09-29.md) | See the record. |
| 2026-10-08 | [Passive accounting and fleet dispatch qualification](./2026-10-08-agent-fleet-accounting.md) | See the record. |
| 2026-10-11 | [Guest held-port raw helper](./2026-10-11-guest-port-raw-helper.md) | See the record. |
| 2026-10-11 | [Guest loopback SSH with hybrid post-quantum key exchange](./2026-10-11-guest-pq-ssh-loopback.md) | See the record. |
| 2026-10-13 | [MCP workhorse qualification](./2026-10-13-mcp-workhorse.md) | See the record. |
| 2026-10-15 | [Four-host shell and transfer observation — 2026-10-15](./FLEET_SHELL_ROUTES_2026-10-15.md) | See the record. |
| undated | [C23 download performance laboratory](./C3_DOWNLOAD_PERF_LAB.md) | See the record. |
| undated | [Historical C23 speed-contract baseline](./C3_SPEED_BASELINE.md) | See the record. |
| undated | [Fleet ledger column integrity](./FLEET_LEDGER_COLUMNS.md) | See the record. |
| undated | [Fleet terminal contract inventory](./FLEET_TERMINAL_CONTRACT.md) | See the record. |
| undated | [Soak runner path arguments](./SOAK_RUNNER_PATH_ARGUMENTS.md) | See the record. |

Attachments referenced by the records above:

