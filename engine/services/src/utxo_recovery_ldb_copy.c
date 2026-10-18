/* Point-in-time copy of a live zclassicd chainstate LevelDB.
 *
 * A plain cp of a LevelDB under active write tears — MANIFEST, SSTs
 * and the .log are copied at different instants, and leveldb_open on
 * the copy "succeeds" with holes: an imported UTXO set can silently lack a
 * coin created below the anchor, whose first spend wedges the reducer
 * with prevout_unresolved. The copy here is provably point-in-time: signature the
 * source dir before and after the copy and retry until nothing
 * changed mid-copy. zclassicd flushes its chainstate at block cadence
 * (~minutes), so a clean window is the common case.
 */

#include "utxo_recovery_internal.h"
#if !defined(_WIN32)
#include "util/log_macros.h"
#include "util/file_tree_ops.h"

#include <dirent.h>
#include <errno.h>
#endif
#include <stdint.h>
#if !defined(_WIN32)
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

/* FNV-1a signature over (name, size, mtime_ns) of every entry in a
 * LevelDB directory. Two equal signatures taken around a copy prove no
 * file changed while the copy ran — i.e. the copy is a point-in-time
 * image. A partial census is never a signature: every path and stat must be
 * representable, and the directory stream must reach a clean EOF. */
#if !defined(_WIN32)
static bool chainstate_dir_signature(const char *path, uint64_t *out)
{
    if (!out)
        return false;
    DIR *d = opendir(path);
    if (!d)
        return false;
    uint64_t sig = 14695981039346656037ULL;
    bool ok = true;
    for (;;) {
        errno = 0;
        struct dirent *e = readdir(d);
        if (!e) {
            ok = errno == 0;
            break;
        }
        if (e->d_name[0] == '.')
            continue;
        char fp[1400];
        int n = snprintf(fp, sizeof(fp), "%s/%s", path, e->d_name);
        if (n <= 0 || (size_t)n >= sizeof(fp)) {
            ok = false;
            break;
        }
        struct stat st;
        if (stat(fp, &st) != 0) {
            ok = false;
            break;
        }
        const char *c = e->d_name;
        while (*c) { sig ^= (uint8_t)*c++; sig *= 1099511628211ULL; }
        uint64_t fields[3] = { (uint64_t)st.st_size,
                               (uint64_t)st.st_mtim.tv_sec,
                               (uint64_t)st.st_mtim.tv_nsec };
        const uint8_t *b = (const uint8_t *)fields;
        for (size_t i = 0; i < sizeof(fields); i++) {
            sig ^= b[i];
            sig *= 1099511628211ULL;
        }
    }
    if (closedir(d) != 0)
        ok = false;
    if (ok)
        *out = sig;
    return ok;
}

#ifdef ZCL_TESTING
struct zcl_result utxo_recovery_chainstate_signature_for_test(
    const char *path, uint64_t *out)
{
    if (!chainstate_dir_signature(path, out))
        return ZCL_ERR(-3, "chainstate census incomplete");
    return ZCL_OK;
}
#endif
#endif

#if !defined(_WIN32)
static const char *chainstate_copy_attempt(const char *cs_path,
                                           const char *import_path,
                                           int attempt, int max_attempts,
                                           bool *complete)
{
    uint64_t before = 0, after = 0, dest = 0;
    *complete = false;
    if (!chainstate_dir_signature(cs_path, &before))
        return "source census incomplete";

    (void)zcl_tree_remove(import_path);
    struct zcl_result cp = zcl_tree_copy(cs_path, import_path,
                                         ZCL_COPY_PRESERVE_TIMES, NULL, NULL);
    if (!cp.ok)
        LOG_WARN("utxo_recovery",
                 "chainstate copy attempt %d/%d reported: %s",
                 attempt, max_attempts, cp.message);
    if (!chainstate_dir_signature(cs_path, &after))
        return "source census incomplete";
    if (!chainstate_dir_signature(import_path, &dest))
        return "destination census incomplete";
    if (before != after)
        return "source changed during copy";
    if (dest != after)
        return "destination incomplete (cp raced/failed)";
    *complete = true;
    return NULL;
}
#endif

struct zcl_result utxo_recovery_copy_chainstate_stable(const char *cs_path,
                                                       const char *import_path)
{
    if (!cs_path || !import_path)
        return ZCL_ERR(-3, "copy_chainstate_stable: NULL path");

#if defined(_WIN32)
    return ZCL_ERR(
        -3,
        "copy_chainstate_stable: Windows recovery copy is disabled until "
        "directory-handle-relative, reparse-safe stable copying qualifies");
#else
    const int max_copy_attempts = 6;
    for (int attempt = 1; attempt <= max_copy_attempts; attempt++) {
        /* `rm -rf import_path && cp -a cs_path import_path`, via the single
         * fd-based tree walker (no shell). ZCL_COPY_PRESERVE_TIMES is
         * LOAD-BEARING: correctness is proven structurally, not by the copy's
         * return code — (1) the source did not change during the copy
         * (point-in-time, which no copy return can attest), and (2) the
         * destination is a COMPLETE image of it. chainstate_dir_signature
         * folds (name,size,mtime_ns) over every entry, so dest_sig == source
         * sig only when the copy preserved mtime_ns exactly (what PRESERVE_TIMES
         * guarantees, matching the old `cp -a`); a torn/failed copy (vanished
         * SST, disk-full) does not match. The copy's own error return is still
         * logged as a hint, but the signature comparison below is the gate. */
        bool complete = false;
        const char *why = chainstate_copy_attempt(
            cs_path, import_path, attempt, max_copy_attempts, &complete);
        if (complete)
            return ZCL_OK;   /* point-in-time source + complete destination */

        printf("chainstate copy not yet point-in-time (attempt %d/%d: %s) — "
               "retrying...\n", attempt, max_copy_attempts,
               why ? why : "unknown refusal");
        fflush(stdout);
        if (attempt < max_copy_attempts)
            sleep(2);
    }
    return ZCL_ERR(-3,
        "copy_chainstate_stable: could not capture a complete point-in-time "
        "copy of %s across %d attempts — refusing a torn import (retry when "
        "the source is idle)", cs_path, max_copy_attempts);
#endif
}
