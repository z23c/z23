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
Focused selftest, full candidate proof and two-host app-sharing acceptance:
NOT RUN.
