<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Exact work attachment after verified context admission

Date: 2026-09-24T20:50:14-04:00 (2026-09-25T00:50:14+00:00).
Base: `e0e3338b46abe9487056f8e7a4fa8a7996cd16fa`.
Host: AMD Ryzen 7 PRO 8840U. Compiler: GCC 16.1.1 20260430, C23.

The work node already admits a second signed request for the same exact
action binding as `ATTACHED`. The worker previously fetched the context root
and restored its source closure for every attached requester. The action's
build-fabric plan/submit was idempotent, but that redundant preparation still
occupied the supervised lane.

The worker now marks a slot ready only after the first context was loaded,
its task/candidate/action/input/policy/toolchain roots were checked, its source
closure was restored, and build-fabric admission succeeded. An attached
request with the same signed binding and a live lease then bypasses context
fetch and restore. The node continues to send each requester its own signed
admission, progress, and exact result binding. Expired, cancelled, finished,
and mismatched requests cannot use the ready slot. A new action or an attached
request arriving before the first admission still follows the full path.
The frame adapter also requires an accepted inbound track and the exact
signed request before fetching context; refused and altered repeat frames
cannot start a redundant download.

The `remote_attach` performance event records one duplicate execution and one
context restore avoided per drained attached request, the number of verified
context bytes reused, and admission time. Reused bytes are **not** labeled
network bytes saved: the content store may already hold the same root, so a
second fetch could have transferred zero bytes even before this change.

## Exact local verification

```bash
make CC=gcc -j8 t-fast ONLY=zcode_dev_objects
make CC=gcc -j8 t-fast ONLY=zcode_package_dev
make CC=gcc -j8 lint-fast
make CC=gcc -j8 z23-dev
git diff --check
```

| Gate | Result | Captured log SHA-256 |
| --- | --- | --- |
| `zcode_dev_objects` | 1/1 registered group passed, 50.1 s wall after a full GCC epoch build; ready false before admission, true for exact attached requester, false at lease expiry and after result | `9cfd60fe92c64cea716b402109af23115a4cbaf66ebc85455a7b6c34d7a48339` |
| `zcode_package_dev` | 1/1 registered group passed, 22.3 s wall | `42dfc45e76484a2b4b89b95dc8d865a302df76e7e48783aa93b790133d3e80af` |
| `lint-fast` | 32/32 gates passed; existing frame-handler complexity pin remains 32 | `032fdd0eabe9c302d4433fcb27529120371b017b81fa7dfcfa9fb485e4ca0cec` |

The source SHA-256 values for the work node, its interface, network adapter,
and focused test are respectively
`f45f0755266aa9f3ab27d96a107e1a0cd3a6c1382af241a32050d58191a20928`,
`d8869a208f05bd4e672067b01d246429c869f6576b73642fb72608fc61639e34`,
`7fadcd5d0630f13aaefdb6c114113cf033afa22ce35f29d1bd44cb7796cff799`,
and `25391c6c03f06587908a0b1aa28ab2142b57d7c4c6b036ea7460c674ebb5c2a8`.
The generated capability inventory SHA-256 is
`0ad0ef15aefff07b696f0290fd08c614247a3b97665dd0b1c2c29debf0bb619f`.

After `origin/main` advanced to `3945fbcee217b62b7e2d0775601c5b81926510a7`,
the combined tree regenerated the capability inventory and passed its
generated-file check. The merged inventory SHA-256 is
`94ebd0b7b43ff61a9ae3bb7e359b03d21c84cffaab2724bebf0ae30b59bd9c05`.
The affected `zcode_package_dev` group passed again in 23.8 s (log SHA-256
`09a44104cfbdddc3ebd9a01ad61a5b887c0cfc374cfc797d776f97b24783b3d6`),
and `lint-fast` passed 32/32 gates (log SHA-256
`f69c9ab452ee6d9987096c4dc82599d6fa2f440c213f3d81ffbda09b3dcf2f50`).

This run proves the bounded in-process fast path and focused lifecycle
behavior. It does not measure network bytes saved, six-worker queue latency,
partition recovery, or cross-candidate input-key reuse. Those require a
live authenticated fleet run with the same component input closure and
different requester actions. Remote GREEN remains evidence subject to each
receiver's policy, not acceptance or deployment authority.
