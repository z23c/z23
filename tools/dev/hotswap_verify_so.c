/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * hotswap_verify_so — CLI front end for hotswap_verify_module_so(): dlopen a
 * built hot-swap module .so and run the REAL admission gauntlet against the
 * REAL, compiler-emitted `zcl_hotswap_module`.
 *
 * WHY THIS EXISTS. Before this tool, every hot-swap test in the tree
 * (test_hotswap_module.c, test_hotswap_module_v2.c) drove
 * hotswap_module_admit() with a struct FABRICATED in the test's own
 * translation unit. That proves the gauntlet's logic and nothing about any
 * real artifact: a row in config/hotswap_swappable.def whose TU never emits
 * the `zcl_hotswap_module` symbol at all, or whose leaf body lives in a TU
 * outside its island, passed every gate in the repo and would have failed the
 * first time a human tried it. (That was the exact state of
 * app/controllers/src/diagnostics_native_handlers.c.) An entry in an allowlist
 * that has never been loaded is a claim, not an admission.
 *
 * All dlopen/dlsym/dlclose lives in lib/hotswap behind #ifdef ZCL_DEV_BUILD —
 * the invariant tools/lint/check_hotswap_dev_only.sh enforces, so a release
 * build links zero dynamic-loading code. This file deliberately contains none.
 *
 * WHAT IT PROVES / DOES NOT PROVE: see hotswap_verify_module_so() in
 * hotswap/hotswap_module.h. Driver: tools/dev/hotswap-verify.sh.
 */

#include "hotswap/hotswap_artifact_digest.h"
#include "hotswap/hotswap_module.h"

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* `--sha3 <file>` — print ONLY `artifact_sha3 : <64 hex>` for a file, with no
 * dlopen and no admission claim whatsoever.
 *
 * WHY THIS MODE EXISTS. The shipped artifact links -Wl,-z,now, so this small
 * process cannot dlopen it at all (it never defines the resident kernel
 * symbols the module imports); the verification lane therefore admits a
 * -z lazy RE-LINK of the same object, whose bytes are NOT the shipped bytes.
 * A packaging receipt must record the digest of the file that will actually
 * ship, so that digest has to be readable without loading anything. This mode
 * is exactly that: open, hash the descriptor, print. It is the in-tree
 * FIPS-202 implementation (lib/sha3) reached through the fd-pinned primitive,
 * so no host `sha3sum`/`openssl` needs to exist for a module to be packaged.
 *
 * It proves integrity of bytes, never that they are safe to load — see
 * hotswap/hotswap_artifact_digest.h. */
static int sha3_only(const char *path)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        fprintf(stderr, "hotswap-verify: cannot open %s\n", path);
        return 1;
    }
    char hex[65];
    bool ok = hotswap_artifact_sha3_fd(fd, hex);
    (void)close(fd);
    if (!ok) {
        fprintf(stderr, "hotswap-verify: SHA3-256 of %s failed\n", path);
        return 1;
    }
    printf("artifact_sha3 : %s\n", hex);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc == 3 && strcmp(argv[1], "--sha3") == 0)
        return sha3_only(argv[2]);

    if (argc < 2 || argc > 3) {
        fprintf(stderr,
                "usage: hotswap_verify_so <module.so> [expected_source_tu]\n"
                "       hotswap_verify_so --sha3 <file>\n");
        return 2;
    }

    struct hotswap_activate_report report;
    bool ok = hotswap_verify_module_so(argv[1],
                                       (argc == 3) ? argv[2] : NULL, &report);

    printf("module      : %s\n", argv[1]);
    printf("artifact_sha3 : %s\n",
           report.artifact_sha3_256[0] ? report.artifact_sha3_256 : "(unread)");
    printf("source_tu   : %s\n", report.source_tu);
    printf("leaf_count  : %u (ceiling %u)\n", report.leaf_count,
           ZCL_HOTSWAP_MODULE_MAX_LEAVES);
    if (report.leaves[0]) {
        /* report.leaves is a comma-joined list; print one per line. */
        const char *p = report.leaves;
        unsigned i = 0;
        while (*p) {
            const char *comma = strchr(p, ',');
            int len = comma ? (int)(comma - p) : (int)strlen(p);
            printf("  leaf[%2u]  : %.*s\n", i++, len, p);
            if (!comma)
                break;
            p = comma + 1;
        }
    }
    printf("probe_leaf  : %s\n",
           report.probe_leaf[0] ? report.probe_leaf : "(none declared)");

    if (!ok) {
        fprintf(stderr, "hotswap-verify: FAIL stage=%s: %s\n", report.stage,
                report.error);
        if (strcmp(report.stage, "symbol") == 0)
            fprintf(stderr,
                    "  The TU has no `#ifdef ZCL_HOTSWAP_MODULE_GEN` block, or\n"
                    "  its ZCL_HOTSWAP_MODULE_LEAVES()/ZCL_HOTSWAP_MODULE()\n"
                    "  emitter sits outside it. A swappable allowlist row\n"
                    "  without that block can never be activated.\n");
        if (strcmp(report.stage, "dlopen") == 0)
            fprintf(stderr,
                    "  If this is an 'undefined symbol: zcl_native_*_body'\n"
                    "  error, the leaf's BODY lives in a TU outside this\n"
                    "  module's island. Re-pointing that leaf would dispatch\n"
                    "  into resident code and the swap would silently do\n"
                    "  nothing for it. Add the body's TU to that owner's row\n"
                    "  in config/hotswap_islands.def.\n");
        return 1;
    }

    printf("VERDICT     : ADMITTED (seal + shape + dlopen + symbol + consensus "
           "+ abi + fields + capacity + allowlist + duplicate + probe "
           "+ self_test)\n");
    return 0;
}
