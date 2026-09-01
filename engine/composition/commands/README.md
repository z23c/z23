# Command registry definitions

This directory is the authored source for the native LLM command ontology in
[`docs/NATIVE_COMMAND_INTERFACE.md`](../../../docs/NATIVE_COMMAND_INTERFACE.md).

Checkpoint status (2026-07-11):

- `root.def`, `core.def`, `apps.def`, and `ops.def` are declared here AND
  wired into the binary: `engine/composition/src/command_catalog.c` `#include`s all
  four, expands them into one immutable `g_catalog_commands[]` table via the
  `ZCL_COMMAND_*` X-macros, and binds native handler pointers for this
  build. `zcl_command_catalog()` (declared in `config/command_catalog.h`) is
  called from `tools/command/native_command.c`, which `engine/entry/main.c` reaches
  through `zcl_native_command_main()` for any method
  `zcl_native_command_is_root()` recognizes — this is a live dispatch path,
  not a declaration-only exercise.
- `dev.def` is bound in `command_catalog.c` via the `ZCL_COMMAND_DEV_READ` /
  `ZCL_COMMAND_DEV_COMMAND` macros: one declarative leaf maps to a real
  handler in the dev build (`tools/command/native_dev_command.c`, guarded by
  `ZCL_DEV_BUILD`) and to an honest `ZCL_COMMAND_COMPAT` stub with a
  `compat_target` in the release build. The old checkout-local devloop
  dispatcher path in `engine/entry/main.c` is deleted;
  `tools/lint/check_release_no_dev_symbols.sh` proves with `nm` that the
  release binary links none of the dev executors.
- The transport-neutral registry engine compiles in `engine/modules/kernel`
  (`engine/modules/kernel/src/command_registry.c`).

No `lib/` source may include App, controller, service, or development
handler headers. Keep metadata separate from handler
bindings so release discovery can describe the `dev` branch while the release
binary contains no development executor pointers or loader path.

Before marking any leaf `ready`, the catalog validator must prove it has a
handler, input schema, output schema, typed safety policy, allowed lanes, and a
golden dispatch test. A `planned` leaf must have no handler and must fail closed
with a `zcl.result.v1` blocker. Compatibility leaves may name the old command,
but cannot silently fall through to arbitrary RPC.
