/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * codeindex_merkle contract: the SHA3-256 Merkle tree over the indexed source
 * tree, and the code.merkle leaf that projects it.
 *
 * Coverage:
 *   1. determinism      — two cold builds of one fixture agree on the root, and
 *                         a byte-identical COPY at a different absolute path
 *                         agrees too (no absolute path may enter a preimage).
 *   2. sensitivity      — flip one byte in one file: that file's leaf changes,
 *                         the root changes, and every untouched leaf is
 *                         byte-identical. Counted, not asserted in prose.
 *   3. locality         — the change under core/modules/net moves core/modules/net's subtree root
 *                         and the tree root, and leaves core/modules/crypto's subtree
 *                         root byte-identical.
 *   4. incrementality   — after touching ONE file, a warm refresh re-reads one
 *                         file (not all of them), hashes only the nodes on that
 *                         file's path to the root, and lands on exactly the root
 *                         a cold build produces.
 *   5. cache is a cache — deleting the snapshot changes no answer; a truncated
 *                         snapshot is discarded, not repaired; a bare `touch`
 *                         re-reads the file but moves no digest.
 *   6. command surface  — code.merkle emits the fields it claims THROUGH the
 *                         serializer (json_write), for the tree, a directory, a
 *                         file, and an absent path, inside its list budget.
 *
 * All scratch work happens under ./test-tmp/ (project no-/tmp convention).
 */

#include "test/test_core.h"

#include "codeindex/codeindex_merkle.h"
#include "command/native_command.h"
#include "kernel/command_registry.h"
#include "json/json.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define CM_FIX  "test-tmp/code_merkle_fix"
#define CM_COPY "test-tmp/code_merkle_copy"

static bool cm_write(const char *dir, const char *rel, const char *content)
{
    char full[4096];
    snprintf(full, sizeof(full), "%s/%s", dir, rel);
    for (char *p = full + 1; *p; p++) {
        if (*p == '/') { *p = '\0'; mkdir(full, 0755); *p = '/'; }
    }
    FILE *f = fopen(full, "wb");
    if (!f) return false;
    if (content && content[0]) fwrite(content, 1, strlen(content), f);
    bool ok = fclose(f) == 0;
    return ok;
}

static bool cm_flip_last_byte(const char *path)
{
    FILE *f = fopen(path, "r+b");
    if (!f || fseek(f, -1, SEEK_END) != 0) {
        if (f) fclose(f);
        return false;
    }
    int byte = fgetc(f);
    if (byte == EOF || fseek(f, -1, SEEK_CUR) != 0 ||
        fputc(byte ^ 0x01, f) == EOF) {
        fclose(f);
        return false;
    }
    return fclose(f) == 0;
}

/* Two library modules so locality is observable, each with a src/ and an
 * include/ arm so the directory tree has real depth. */
static bool cm_fixture(const char *dir)
{
    bool ok = true;
    ok = ok && cm_write(dir, "core/modules/net/include/net/cm_a.h",
                        "#ifndef CM_A_H\n#define CM_A_H\nint cm_a(void);\n#endif\n");
    ok = ok && cm_write(dir, "core/modules/net/src/cm_a.c",
                        "/* cm_a — merkle fixture. */\n#include \"net/cm_a.h\"\n"
                        "int cm_a(void)\n{\n    return 1;\n}\n");
    ok = ok && cm_write(dir, "core/modules/net/src/cm_b.c",
                        "/* cm_b — merkle fixture. */\nint cm_b(void)\n{\n"
                        "    return 2;\n}\n");
    ok = ok && cm_write(dir, "core/modules/crypto/src/cm_c.c",
                        "/* cm_c — merkle fixture. */\nint cm_c(void)\n{\n"
                        "    return 3;\n}\n");
    ok = ok && cm_write(dir, "core/cm_core.c",
                        "/* cm_core — merkle fixture. */\nint cm_core(void)\n{\n"
                        "    return 4;\n}\n");
    return ok;
}

static void cm_reset(void)
{
    system("rm -rf " CM_FIX " " CM_COPY);
}

static bool cm_subtree_hex(struct ci_merkle *m, const char *dir, char out[65])
{
    struct ci_merkle_node n;
    bool found = false;
    if (!ci_merkle_node(m, dir, &n, &found) || !found) return false;
    ci_merkle_hex(&n.digest, out);
    return true;
}

static bool cm_leaf_hex(struct ci_merkle *m, const char *path, char out[65])
{
    struct ci_merkle_leaf l;
    bool found = false;
    if (!ci_merkle_leaf(m, path, &l, &found) || !found) return false;
    ci_merkle_hex(&l.digest, out);
    return true;
}

/* ── 1: determinism, including across a different absolute path ── */
static int test_cm_determinism(void)
{
    int failures = 0;
    TEST("code_merkle: two cold builds and a relocated copy agree on the root") {
        cm_reset();
        ASSERT(cm_fixture(CM_FIX));
        ASSERT(cm_fixture(CM_COPY));

        struct ci_merkle_cost c1, c2, c3;
        struct ci_merkle *a = ci_merkle_build_cold(CM_FIX, &c1);
        struct ci_merkle *b = ci_merkle_build_cold(CM_FIX, &c2);
        struct ci_merkle *cp = ci_merkle_build_cold(CM_COPY, &c3);
        ASSERT(a && b && cp);

        struct ci_merkle_node ra, rb, rc;
        ASSERT(ci_merkle_root(a, &ra));
        ASSERT(ci_merkle_root(b, &rb));
        ASSERT(ci_merkle_root(cp, &rc));
        ASSERT(memcmp(ra.digest.bytes, rb.digest.bytes, 32) == 0);
        /* the copy lives at a different absolute path — same root or the
         * preimage is contaminated with an absolute path. */
        ASSERT(memcmp(ra.digest.bytes, rc.digest.bytes, 32) == 0);

        /* the fixture's shape, so a silent enumeration change is visible. */
        ASSERT(ra.file_count == 5);
        ASSERT(ra.total_bytes > 0);
        ASSERT(c1.files_read == 5 && c1.files_total == 5);
        ASSERT(c1.bytes_total == ra.total_bytes);
        ASSERT(c1.bytes_read == c1.bytes_total);
        ASSERT(c1.nodes_hashed == c1.nodes_total);
        ASSERT(!c1.snapshot_used && !c1.snapshot_saved);

        ci_merkle_free(a); ci_merkle_free(b); ci_merkle_free(cp);
        cm_reset();
        PASS();
    } _test_next:;
    return failures;
}

/* ── 2 + 3: one changed byte moves exactly one leaf, its ancestors, and the
 * root — and nothing else ── */
static int test_cm_sensitivity_and_locality(void)
{
    int failures = 0;
    TEST("code_merkle: one changed byte moves one leaf + its ancestors + the "
         "root, and leaves every other leaf and core/modules/crypto byte-identical") {
        cm_reset();
        ASSERT(cm_fixture(CM_FIX));

        struct ci_merkle *before = ci_merkle_build_cold(CM_FIX, NULL);
        ASSERT(before);
        char root_before[65], net_before[65], crypto_before[65];
        char a_before[65], b_before[65], c_before[65], core_before[65];
        struct ci_merkle_node rb;
        ASSERT(ci_merkle_root(before, &rb));
        ci_merkle_hex(&rb.digest, root_before);
        ASSERT(cm_subtree_hex(before, "core/modules/net", net_before));
        ASSERT(cm_subtree_hex(before, "core/modules/crypto", crypto_before));
        ASSERT(cm_leaf_hex(before, "core/modules/net/src/cm_a.c", a_before));
        ASSERT(cm_leaf_hex(before, "core/modules/net/src/cm_b.c", b_before));
        ASSERT(cm_leaf_hex(before, "core/modules/crypto/src/cm_c.c", c_before));
        ASSERT(cm_leaf_hex(before, "core/cm_core.c", core_before));
        ci_merkle_free(before);

        /* exactly one byte differs: `return 1` becomes `return 9`. */
        ASSERT(cm_write(CM_FIX, "core/modules/net/src/cm_a.c",
                        "/* cm_a — merkle fixture. */\n#include \"net/cm_a.h\"\n"
                        "int cm_a(void)\n{\n    return 9;\n}\n"));

        struct ci_merkle *after = ci_merkle_build_cold(CM_FIX, NULL);
        ASSERT(after);
        char root_after[65], net_after[65], crypto_after[65];
        char a_after[65], b_after[65], c_after[65], core_after[65];
        struct ci_merkle_node ra;
        ASSERT(ci_merkle_root(after, &ra));
        ci_merkle_hex(&ra.digest, root_after);
        ASSERT(cm_subtree_hex(after, "core/modules/net", net_after));
        ASSERT(cm_subtree_hex(after, "core/modules/crypto", crypto_after));
        ASSERT(cm_leaf_hex(after, "core/modules/net/src/cm_a.c", a_after));
        ASSERT(cm_leaf_hex(after, "core/modules/net/src/cm_b.c", b_after));
        ASSERT(cm_leaf_hex(after, "core/modules/crypto/src/cm_c.c", c_after));
        ASSERT(cm_leaf_hex(after, "core/cm_core.c", core_after));

        /* The resident edit seam hashes only the known changed path and lands
         * on the exact canonical leaf; it does not refresh or enumerate. */
        struct ci_merkle_leaf changed_leaf;
        bool changed_found = false;
        ASSERT(ci_merkle_hash_changed_leaf(
            CM_FIX, "core/modules/net/src/cm_a.c", &changed_leaf, &changed_found));
        ASSERT(changed_found);
        char changed_hex[65];
        ci_merkle_hex(&changed_leaf.digest, changed_hex);
        ASSERT(strcmp(changed_hex, a_after) == 0);

        /* changed: the edited leaf, its two ancestors, the root. */
        ASSERT(strcmp(a_before, a_after) != 0);
        ASSERT(strcmp(net_before, net_after) != 0);
        ASSERT(strcmp(root_before, root_after) != 0);
        /* unchanged: every other leaf, and the sibling module's subtree. */
        int unchanged = 0;
        if (strcmp(b_before, b_after) == 0) unchanged++;
        if (strcmp(c_before, c_after) == 0) unchanged++;
        if (strcmp(core_before, core_after) == 0) unchanged++;
        ASSERT(unchanged == 3);
        ASSERT(strcmp(crypto_before, crypto_after) == 0);

        ci_merkle_free(after);
        cm_reset();
        PASS();
    } _test_next:;
    return failures;
}

/* ── 4: incrementality — the headline claim, in counters ── */
static int test_cm_incremental(void)
{
    int failures = 0;
    TEST("code_merkle: after editing one file a warm refresh re-reads 1 of 5 "
         "files, hashes only that file's ancestor nodes, and matches cold") {
        cm_reset();
        ASSERT(cm_fixture(CM_FIX));

        struct ci_merkle_cost cold;
        struct ci_merkle *first = ci_merkle_refresh(CM_FIX, &cold);
        ASSERT(first);
        ASSERT(!cold.snapshot_used);        /* nothing to reuse yet */
        ASSERT(cold.files_read == 5);
        ASSERT(cold.snapshot_saved);        /* the cache got published */
        uint32_t nodes_total = cold.nodes_total;
        /* "", core, core/modules, core/modules/crypto, core/modules/crypto/src, core/modules/net,
         * core/modules/net/include, core/modules/net/include/net, core/modules/net/src */
        ASSERT(nodes_total == 9);
        ci_merkle_free(first);

        /* a refresh over an untouched tree reads no file bytes at all. */
        struct ci_merkle_cost idle;
        struct ci_merkle *same = ci_merkle_refresh(CM_FIX, &idle);
        ASSERT(same);
        ASSERT(idle.snapshot_used);
        ASSERT(idle.files_read == 0);
        ASSERT(idle.bytes_read == 0);
        ASSERT(idle.bytes_total == cold.bytes_total);
        ASSERT(idle.leaves_reused == 5);
        ASSERT(idle.nodes_hashed == 0);
        ASSERT(idle.nodes_reused == nodes_total);
        ASSERT(!idle.snapshot_saved);       /* nothing moved, nothing rewritten */
        ci_merkle_free(same);

        /* now edit one file. */
        ASSERT(cm_write(CM_FIX, "core/modules/net/src/cm_b.c",
                        "/* cm_b — merkle fixture, edited. */\n"
                        "int cm_b(void)\n{\n    return 22;\n}\n"));

        struct ci_merkle_cost warm;
        struct ci_merkle *inc = ci_merkle_refresh(CM_FIX, &warm);
        ASSERT(inc);
        ASSERT(warm.snapshot_used);
        ASSERT(warm.files_read == 1);       /* ONE file re-read, not five */
        ASSERT(warm.bytes_total > 0);
        ASSERT(warm.bytes_read < warm.bytes_total);
        ASSERT(warm.leaves_reused == 4);
        /* exactly the edited file's path to the root: core/modules/net/src,
         * core/modules/net, core/modules, core, "" — 5 of 9. */
        ASSERT(warm.nodes_hashed == 5);
        ASSERT(warm.nodes_hashed < nodes_total);
        ASSERT(warm.nodes_reused == nodes_total - warm.nodes_hashed);

        /* and the incremental root is EXACTLY the cold root — a cheaper path
         * to the same identity, not a different one. */
        struct ci_merkle_node inc_root;
        ASSERT(ci_merkle_root(inc, &inc_root));
        struct ci_merkle *reference = ci_merkle_build_cold(CM_FIX, NULL);
        ASSERT(reference);
        struct ci_merkle_node ref_root;
        ASSERT(ci_merkle_root(reference, &ref_root));
        ASSERT(memcmp(inc_root.digest.bytes, ref_root.digest.bytes, 32) == 0);

        ci_merkle_free(inc);
        ci_merkle_free(reference);
        cm_reset();
        PASS();
    } _test_next:;
    return failures;
}

/* ── 5: the store is a cache, provably ── */
static int test_cm_cache_is_derived(void)
{
    int failures = 0;
    TEST("code_merkle: a seal mismatch, deletion, or truncation discards the "
         "snapshot, and a bare touch re-reads without moving a digest") {
        cm_reset();
        ASSERT(cm_fixture(CM_FIX));

        struct ci_merkle *warm = ci_merkle_refresh(CM_FIX, NULL);
        ASSERT(warm);
        struct ci_merkle_node r1;
        ASSERT(ci_merkle_root(warm, &r1));
        ci_merkle_free(warm);

        /* A syntactically valid image with one changed byte must not be
         * trusted. The old unsealed format accepted a flip in the final
         * cached node metadata and reused every source digest. */
        ASSERT(cm_flip_last_byte(
            CM_FIX "/.codeindex/source_tree.merkle"));
        struct ci_merkle_cost unsealed;
        struct ci_merkle *after_seal_mismatch =
            ci_merkle_refresh(CM_FIX, &unsealed);
        ASSERT(after_seal_mismatch);
        ASSERT(!unsealed.snapshot_used);
        ASSERT(unsealed.files_read == 5);
        struct ci_merkle_node sealed_root;
        ASSERT(ci_merkle_root(after_seal_mismatch, &sealed_root));
        ASSERT(memcmp(r1.digest.bytes, sealed_root.digest.bytes, 32) == 0);
        ci_merkle_free(after_seal_mismatch);

        /* touch: mtime moves, content does not. The leaf is re-read (the cache
         * key moved) but nothing is dirty, so no node is rehashed. */
        system("touch " CM_FIX "/core/cm_core.c");
        struct ci_merkle_cost touched;
        struct ci_merkle *t = ci_merkle_refresh(CM_FIX, &touched);
        ASSERT(t);
        ASSERT(touched.files_read == 1);
        ASSERT(touched.nodes_hashed == 0);
        struct ci_merkle_node r2;
        ASSERT(ci_merkle_root(t, &r2));
        ASSERT(memcmp(r1.digest.bytes, r2.digest.bytes, 32) == 0);
        ci_merkle_free(t);

        /* delete the snapshot: always safe, costs only a full pass. */
        ASSERT(ci_merkle_forget(CM_FIX));
        ASSERT(ci_merkle_forget(CM_FIX));  /* idempotent: absent == success */
        struct ci_merkle_cost cold;
        struct ci_merkle *fresh = ci_merkle_refresh(CM_FIX, &cold);
        ASSERT(fresh);
        ASSERT(!cold.snapshot_used);
        ASSERT(cold.files_read == 5);
        struct ci_merkle_node r3;
        ASSERT(ci_merkle_root(fresh, &r3));
        ASSERT(memcmp(r1.digest.bytes, r3.digest.bytes, 32) == 0);
        ci_merkle_free(fresh);

        /* corrupt the snapshot: it is discarded, not repaired, and the answer
         * is unchanged. */
        system("printf 'junk' > " CM_FIX "/.codeindex/source_tree.merkle");
        struct ci_merkle_cost bad;
        struct ci_merkle *after_bad = ci_merkle_refresh(CM_FIX, &bad);
        ASSERT(after_bad);
        ASSERT(!bad.snapshot_used);
        ASSERT(bad.files_read == 5);
        struct ci_merkle_node r4;
        ASSERT(ci_merkle_root(after_bad, &r4));
        ASSERT(memcmp(r1.digest.bytes, r4.digest.bytes, 32) == 0);
        ci_merkle_free(after_bad);

        cm_reset();
        PASS();
    } _test_next:;
    return failures;
}

static int test_cm_inventory_reconciliation(void)
{
    int failures = 0;
    TEST("code_merkle: added and removed source paths are reported as inventory "
         "changes while unchanged file bytes remain reusable") {
        cm_reset();
        ASSERT(cm_fixture(CM_FIX));
        struct ci_merkle *initial = ci_merkle_refresh(CM_FIX, NULL);
        ASSERT(initial);
        ci_merkle_free(initial);

        ASSERT(cm_write(CM_FIX, "core/modules/net/src/cm_added.c",
                        "int cm_added(void)\n{\n    return 5;\n}\n"));
        struct ci_merkle_cost added = {0};
        struct ci_merkle *with_added = ci_merkle_refresh(CM_FIX, &added);
        ASSERT(with_added);
        ASSERT(added.snapshot_used);
        ASSERT(added.inventory_changed);
        ASSERT(added.files_total == 6 && added.files_read == 1);
        ASSERT(added.leaves_reused == 5);
        ci_merkle_free(with_added);

        ASSERT(remove(CM_FIX "/core/modules/net/src/cm_added.c") == 0);
        struct ci_merkle_leaf removed_leaf;
        bool removed_found = true;
        ASSERT(ci_merkle_hash_changed_leaf(
            CM_FIX, "core/modules/net/src/cm_added.c", &removed_leaf,
            &removed_found));
        ASSERT(!removed_found);
        struct ci_merkle_cost removed = {0};
        struct ci_merkle *without_added =
            ci_merkle_refresh_reconciled(CM_FIX, &removed);
        ASSERT(without_added);
        ASSERT(!removed.snapshot_used);
        ASSERT(removed.inventory_changed);
        ASSERT(removed.full_rescan);
        ASSERT(removed.files_total == 5 && removed.files_read == 5);
        ASSERT(removed.leaves_reused == 0);
        ci_merkle_free(without_added);

        cm_reset();
        PASS();
    } _test_next:;
    return failures;
}

/* ── 6: the command surface, read back through the serializer ── */
static void cm_call(const char *path, struct zcl_command_reply *reply)
{
    struct zcl_command_context ctx = { .source_root = CM_FIX };
    struct json_value input;
    json_init(&input); json_set_object(&input);
    if (path) (void)json_push_kv_str(&input, "path", path);
    struct zcl_command_request request = {
        .input = &input, .context = &ctx,
        .view = "normal", .invoked_name = "code.provenance.merkle",
    };
    zcl_command_reply_init(reply, "zcl.code_merkle.v1");
    zcl_native_handle_code_merkle(&request, reply);
    json_free(&input);
}

/* Serialize the reply and hand back the exact bytes a caller receives. Every
 * field assertion below runs against THIS text, not against the in-memory
 * struct: a value the writer drops must fail here. */
static size_t cm_render(struct zcl_command_reply *reply, char *buf, size_t cap)
{
    size_t n = json_write(&reply->data, buf, cap);
    return (n == 0 || n >= cap) ? 0 : n;
}

static int test_cm_command(void)
{
    int failures = 0;
    TEST("code.merkle: tree / directory / file / absent answers survive the "
         "serializer and fit the list budget") {
        cm_reset();
        ASSERT(cm_fixture(CM_FIX));

        /* (a) the whole tree */
        struct zcl_command_reply reply;
        cm_call(NULL, &reply);
        ASSERT(reply.status != ZCL_COMMAND_STATUS_FAILED);
        char buf[ZCL_COMMAND_LIST_BUDGET + 4096];
        size_t n = cm_render(&reply, buf, sizeof(buf));
        ASSERT(n > 0 && n <= ZCL_COMMAND_LIST_BUDGET);

        /* the digest, taken from the struct, must appear in the TEXT twice:
         * once as `digest` and once as `tree_root`. */
        struct ci_merkle *ref = ci_merkle_build_cold(CM_FIX, NULL);
        ASSERT(ref);
        struct ci_merkle_node ref_root;
        ASSERT(ci_merkle_root(ref, &ref_root));
        char root_hex[65];
        ci_merkle_hex(&ref_root.digest, root_hex);
        char want[128];
        snprintf(want, sizeof(want), "\"digest\":\"%s\"", root_hex);
        ASSERT(strstr(buf, want) != NULL);
        snprintf(want, sizeof(want), "\"tree_root\":\"%s\"", root_hex);
        ASSERT(strstr(buf, want) != NULL);
        ASSERT(strstr(buf, "\"kind\":\"tree\"") != NULL);
        ASSERT(strstr(buf, "\"found\":true") != NULL);
        ASSERT(strstr(buf, "\"file_count\":5") != NULL);
        ASSERT(strstr(buf, "\"tree_files\":5") != NULL);
        /* the fixture's top level is exactly core/. */
        ASSERT(strstr(buf, "\"children_total\":1") != NULL);
        ASSERT(strstr(buf, "\"children_truncated\":false") != NULL);
        ASSERT(strstr(buf, "\"path\":\"core\"") != NULL);
        /* the cost report is present and honest about the fixture's size */
        ASSERT(strstr(buf, "\"files_total\":5") != NULL);
        ASSERT(strstr(buf, "\"nodes_hashed\":") != NULL);
        ASSERT(strstr(buf, "\"nodes_reused\":") != NULL);
        ASSERT(strstr(buf, "\"snapshot_used\":") != NULL);
        ASSERT(strstr(buf, "\"summary\":\"") != NULL);
        zcl_command_reply_free(&reply);

        /* (b) one directory subtree: its own digest, plus the tree root */
        char net_hex[65];
        ASSERT(cm_subtree_hex(ref, "core/modules/net", net_hex));
        ASSERT(strcmp(net_hex, root_hex) != 0);
        cm_call("core/modules/net", &reply);
        ASSERT(reply.status != ZCL_COMMAND_STATUS_FAILED);
        n = cm_render(&reply, buf, sizeof(buf));
        ASSERT(n > 0 && n <= ZCL_COMMAND_LIST_BUDGET);
        ASSERT(strstr(buf, "\"kind\":\"dir\"") != NULL);
        ASSERT(strstr(buf, "\"path\":\"core/modules/net\"") != NULL);
        snprintf(want, sizeof(want), "\"digest\":\"%s\"", net_hex);
        ASSERT(strstr(buf, want) != NULL);
        snprintf(want, sizeof(want), "\"tree_root\":\"%s\"", root_hex);
        ASSERT(strstr(buf, want) != NULL);
        ASSERT(strstr(buf, "\"file_count\":3") != NULL);
        ASSERT(strstr(buf, "\"path\":\"core/modules/net/include\"") != NULL);
        ASSERT(strstr(buf, "\"path\":\"core/modules/net/src\"") != NULL);
        zcl_command_reply_free(&reply);

        /* (c) one file leaf */
        char leaf_hex[65];
        ASSERT(cm_leaf_hex(ref, "core/modules/net/src/cm_b.c", leaf_hex));
        cm_call("core/modules/net/src/cm_b.c", &reply);
        ASSERT(reply.status != ZCL_COMMAND_STATUS_FAILED);
        n = cm_render(&reply, buf, sizeof(buf));
        ASSERT(n > 0 && n <= ZCL_COMMAND_LIST_BUDGET);
        ASSERT(strstr(buf, "\"kind\":\"file\"") != NULL);
        snprintf(want, sizeof(want), "\"digest\":\"%s\"", leaf_hex);
        ASSERT(strstr(buf, want) != NULL);
        ASSERT(strstr(buf, "\"size_bytes\":") != NULL);
        ASSERT(strstr(buf, "\"children\"") == NULL);
        zcl_command_reply_free(&reply);

        /* (d) a path outside the indexed set: explicit, not an error */
        cm_call("core/modules/net/src/not_here.c", &reply);
        ASSERT(reply.status != ZCL_COMMAND_STATUS_FAILED);
        n = cm_render(&reply, buf, sizeof(buf));
        ASSERT(n > 0 && n <= ZCL_COMMAND_LIST_BUDGET);
        ASSERT(strstr(buf, "\"kind\":\"absent\"") != NULL);
        ASSERT(strstr(buf, "\"found\":false") != NULL);
        ASSERT(strstr(buf, "\"digest\":\"\"") != NULL);
        snprintf(want, sizeof(want), "\"tree_root\":\"%s\"", root_hex);
        ASSERT(strstr(buf, want) != NULL);
        zcl_command_reply_free(&reply);

        ci_merkle_free(ref);
        cm_reset();
        PASS();
    } _test_next:;
    return failures;
}

int test_code_merkle(void)
{
    int failures = 0;
    failures += test_cm_determinism();
    failures += test_cm_sensitivity_and_locality();
    failures += test_cm_incremental();
    failures += test_cm_cache_is_derived();
    failures += test_cm_inventory_reconciliation();
    failures += test_cm_command();
    return failures;
}
