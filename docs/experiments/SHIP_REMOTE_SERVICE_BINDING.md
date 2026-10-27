<!-- Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 -->

# Remote shipping service binding

## Scope

A canonical node can retain the legacy `zclassic23.service` name while the
remote shipping transaction addresses `z23-node.service`. The compatibility
change selects one explicit remote service through `ZCL_SHIP_NODE_UNIT`.
The default remains `z23-node.service`. Local deployment is unchanged.

The isolated fixture executes the transaction embedded in `tools/ship.sh`
against a stand-in service manager and real temporary processes. It checks
legacy selection, reload and restart rollback, unchanged default behavior,
refusal of missing or ambiguous service bindings, and the pre-transfer
binding barrier. It does not activate or qualify a live node.

## Evidence

The source baseline was `d901abd198d31bd673caf4e7470130840750e93e`.
The registered gate ran through native admission:

```sh
DEVBUILD_CLASS=light devbuild --wait make -j2 check-ship-remote-transaction
```

The candidate passed with exit status 0. Its log SHA-256 was
`58a97eabacf56997c8c7e07e0bc7a77ef5ae3dc5eef9a8087287fc7003270f27`.

A single-line mutation replaced the remote activation program's assignment
`node_unit="${18:-z23-node.service}"` with
`node_unit="z23-node.service"`, ignoring the explicit legacy selection.
The fixture and documentation were unchanged. The same registered gate
failed with exit status 2 in the isolated transaction check; the preceding
shipping self-tests passed. The mutation log SHA-256 was
`71b4115deec557ae770d0849492e54f32f0ba7bb64da749ee68eb4defbab6f64`.
The fixture did not trace its internal failure line. A rejected read of the
forced service during the legacy transaction is inferred from the program
and fixture, rather than claimed as a traced observation.

After the mutation, the shipping source was restored and its Git blob
verified as `dbb5e8df3ed6befed845f1daeb831356b9c18718`. The fixture blob
remained `41c2f1350de86b75b5eb04fea08dce1660e7dd0e`, and the developer
manual blob remained `6a658e6a14a6f1448d03325b90dd6b46046ab4de`.

These results establish the isolated gate's sensitivity to the selected
service binding. They make no performance claim and do not establish live
activation, production health, or full candidate qualification.
