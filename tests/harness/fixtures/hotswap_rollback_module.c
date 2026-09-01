/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Hot-swap ROLLBACK fixture module (NOT compiled into any binary; it lives
 * under tests/harness/fixtures/, which the build globs never pick up). The Makefile
 * rule `$(HOTSWAP_ROLLBACK_FIXTURE_SOS)` compiles this ONE file twice — once
 * with ZCL_ROLLBACK_FIXTURE_MARK="a" and once with "b" — into two real,
 * byte-distinct module .so images under build/hotswap.
 *
 * WHY A REAL MODULE AND NOT A FABRICATED STRUCT. hotswap_rollback() re-enters
 * the whole admission gauntlet over a SEALED IMAGE: ELF shape probe, artifact
 * hash, map, symbol resolution, the sealed-core consensus pin, admit,
 * probe-before-publish, and the one all-or-nothing registry batch. None of that
 * can be driven by a module struct fabricated inside a test translation unit —
 * a shelved image is BYTES, and bytes are the only thing that gauntlet eats
 * (see hotswap/hotswap_shelf.h). So proving a rollback SUCCEEDS requires two
 * genuine artifacts whose handlers are distinguishable at dispatch.
 *
 * The two images differ only in the marker string they render, so a dispatch
 * of core.status says exactly which image the live registry snapshot is
 * running. That is the observation tests/harness/src/test_hotswap_rollback.c uses to
 * decide whether a rollback really put the previous module back.
 *
 * IDENTITY. The module stamps itself with the swappable allowlist row supplied
 * by the build (-DZCL_HOTSWAP_MODULE_SOURCE_TU), and declares the two leaves
 * that row owns. core.status is the probe leaf engine/composition/hotswap_eligible.def
 * declares for it, so the admission gauntlet finds the probe it requires. The
 * sealed-core ROOT, TREE and SECTION declaration come from the emitter macro:
 * with no per-module narrowing header in scope this file declares the
 * resident's ENTIRE sealed section set, which is the maximally conservative
 * statement a module can make.
 *
 * REACH. The only resident entry point this module imports is
 * json_push_kv_str — the JSON return path every command leaf writes through,
 * declared in config/hotswap_module_imports.def. It touches no node state.
 */

#include "hotswap/hotswap_module.h"

#include "json/json.h"
#include "kernel/command_registry.h"

#include <stddef.h>

/* Which of the two images this is. The build supplies it; the default exists
 * so a hand compile is still well-formed and still obviously unmarked. */
#ifndef ZCL_ROLLBACK_FIXTURE_MARK
#define ZCL_ROLLBACK_FIXTURE_MARK "unmarked"
#endif

static void rollback_fixture_render(struct zcl_command_reply *reply)
{
    if (!reply)
        return;
    (void)json_push_kv_str(&reply->data, "image", ZCL_ROLLBACK_FIXTURE_MARK);
}

/* One distinct function per leaf: the loader publishes them independently and
 * the test compares the live effective handler against what it saw before. */
static void rollback_fixture_status(const struct zcl_command_request *request,
                                    struct zcl_command_reply *reply)
{
    (void)request;
    rollback_fixture_render(reply);
}

static void rollback_fixture_diagnose(const struct zcl_command_request *request,
                                      struct zcl_command_reply *reply)
{
    (void)request;
    rollback_fixture_render(reply);
}

/* Structural health hook. There is no state to check here; the module's whole
 * body is two pure renderers. */
static bool rollback_fixture_selftest(char *err, size_t cap)
{
    if (err && cap)
        err[0] = '\0';
    return true;
}

static const struct zcl_hotswap_leaf k_rollback_fixture_leaves[] = {
    { "core.status", rollback_fixture_status },
    { "core.sync.diagnose", rollback_fixture_diagnose },
};

ZCL_HOTSWAP_MODULE_LEAVES(k_rollback_fixture_leaves, rollback_fixture_selftest)
