<!-- Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 -->

# Receive address during node startup

A successful committed offline restore returns its first shielded address. The setup model retains a checksum-validated address in memory and exposes it only after confirmation and the durable setup marker. Receive can show it while the latest-address request runs. A process restart has no retained address and uses the existing node request.

On the 2026-11-06 candidate, Android host setup, wallet and host checks passed. An isolated encrypted wallet restore, close, reopen and unlock test verified that the reported first shielded address belongs to the reopened wallet. Phone setup and Receive timing for this change remain unmeasured.

Reproduce the focused checks from the repository root on an admitted maintainer host:

```sh
DEVBUILD_CLASS=normal devbuild --wait make -C apps/z23android test-setup test-wallet test-host
DEVBUILD_CLASS=normal devbuild --wait make t-fast ONLY=wallet_create
```

The host checks and encrypted restore test above used the draft based on commit `41f38fa29e860c7c4d7273ec662a48f97899c622`; the held-request assertion is verified separately at the final candidate.
