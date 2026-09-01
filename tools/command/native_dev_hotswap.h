/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Native Tier-1 hot-swap command glue. The resident activation path is kept
 * separate from the CLI probe so release builds link only a contained stub.
 *
 * dev.hotswap.probe and dev.hotswap.apply are hard-contained until a
 * disposable probe worker, pre-load ELF admission, immutable artifacts, and
 * the complete source/proof/rollback transaction exist. This file declares
 * the resident typed-refusal RPC registration; CLI handlers are declared in
 * command/native_command.h under ZCL_DEV_BUILD. */

#ifndef ZCL_TOOLS_NATIVE_DEV_HOTSWAP_H
#define ZCL_TOOLS_NATIVE_DEV_HOTSWAP_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

struct rpc_table;
struct hotswap_publish_hooks;
struct zcl_hotswap_service_report;

/* Register the resident-node RPC method `dev_hotswap_native` on `table`.
 * DEV-ONLY, and a successful no-op on a release build or a non-dev-lane
 * datadir (returns true without registering).
 * Called once at boot from engine/composition/src/boot_services.c. Returns false only if a
 * required registration could not be completed. */
bool register_dev_native_hotswap_rpc(struct rpc_table *table,
                                     const char *datadir, int rpc_port);

#if defined(ZCL_DEV_BUILD) || defined(ZCL_TESTING)
/* Fill `out` with THE canonical publish hooks for the command registry in this
 * process: the all-or-nothing batch commit, the probe-before-publish dispatch
 * (public spec lookup + input validation + declared-output-schema check), and
 * optionally the retired-snapshot quiesce poll that gates dlclose.
 *
 * `with_quiesce` is false for a one-shot CLI (nothing to reclaim; the process
 * exits) and true in the resident node. Shared by the resident RPC, the CLI
 * `dev hotswap probe`, the ZCL_HOTSWAP_PRELOAD path in native_command.c, and
 * the parallel test harness's module mode, so exactly one implementation of
 * "how a candidate is validated and published" exists. These hooks perform no
 * dynamic loading; a release build (neither macro) links none of them. */
void zcl_native_hotswap_publish_hooks(struct hotswap_publish_hooks *out,
                                      bool with_quiesce);

/* Release the thread-local buffer registry_probe_cb retains for the activation
 * receipt. The dev RPC path clears it as part of rendering the receipt; a
 * caller that does not render one (the test harness) calls this instead. */
void zcl_native_hotswap_probe_rendered_clear(void);

#endif /* ZCL_DEV_BUILD || ZCL_TESTING */

/* Verify one pure service module entirely inside the caller. This never
 * activates a generation and never reaches RPC/network/storage. It exists so
 * the warm watcher can fork a disposable HOT_SHADOW child over resident
 * frozen contracts and fixtures. Non-dev builds return false without loading
 * code, preserving the release/test containment boundary. */
bool zcl_native_hotswap_service_probe_local(
    const char *so_path, struct zcl_hotswap_service_report *report);

#ifdef __cplusplus
}
#endif

#endif /* ZCL_TOOLS_NATIVE_DEV_HOTSWAP_H */
