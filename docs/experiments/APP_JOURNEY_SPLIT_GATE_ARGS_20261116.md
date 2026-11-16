<!-- Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 -->
# Split-role app journey arguments

`make app-journey-live` accepts `APP_JOURNEY_LIVE_ARGS` and passes it to the
existing journey program. An empty value preserves the combined two-node
journey. A caller can supply the existing split-role options when running the
make target through a remote gate. The program still validates those options
and requires fresh work directories and finite execution budgets.
<!-- claim: symbol-present APP_JOURNEY_LIVE_ARGS Makefile # journey make target passes caller arguments -->

For a sender, an admitted caller can use:

```sh
make app-journey-live APP_JOURNEY_LIVE_ARGS='--sender --work=/absolute/fresh-path --seconds=300'
```

A receiver also supplies `--receiver`, `--work`, `--seconds`, `--peer` and
`--expected`, with optional `--serve`; use its verified peer and expected-file
values. The make variable is a shell argument list supplied by the trusted
caller. Sender and receiver evidence must be reconciled separately; an
accepted make invocation alone does not prove a live exchange.

Make dry runs passed for the empty default and sender and receiver argument
lists. They show the command line only; they do not execute the parser.
The existing parser and supervised-role selftest passed on source
`9111274f25b69b6b01a7477f72270917e85ba515` under the remote gate. Its
negative-fixture diagnostics are expected. The gate returned zero and its
transferred evidence manifest verified. Full candidate proof and two-host
app-sharing acceptance: NOT RUN.

A fresh remote clone exposed an ordering gap in parallel
`lint-fast-preflight`: its direct gate dispatcher reached vendor provenance
without depending on Tor provenance preparation; the full Tor archive was
absent when the gate ran. The parallel target
now depends on `tor-provenance-ready`, matching the existing full and landing
lint paths. The vendor provenance gate remains required. Serial mode already
reaches that prerequisite through the gate target. A pre-submission fresh-clone preflight on source
`b443277a61ffb19d911abae3ca6408a1246de757` passed 60 selected gates, including vendor
provenance, and the 153-gate differential precheck. During early preparation,
the full Tor archive was absent. The result establishes
this run, not the identity of any other archive creator.
<!-- claim: symbol-present tor-provenance-ready Makefile # Tor preparation precedes lint provenance dispatch -->
