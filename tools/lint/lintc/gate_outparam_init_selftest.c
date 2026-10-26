/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: --selftest for check-outparam-init-before-return
 * (gate_outparam_init.c). Feeds planted C text through the same lexer and
 * analyzers the gate runs and asserts each verdict: a clean function and a
 * compact-block-shaped violation, a finding BEHIND an unbalanced file in the
 * same batch, declaration syntax above a null guard, a literal array bound, a
 * `//` inside a one-line block comment, publisher derivation from the store
 * rather than the name, publish-then-free without an unpublish, and — the
 * property the awk pipeline lacked — an unreadable input is a non-zero exit,
 * never a clean pass.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <stdio.h>
#include <string.h>
#include "lintc.h"
#include "gate_outparam_init_priv.h"

static const char k_st_case[] =
    "#include <string.h>\n\n"
    "/* CLEAN: out is initialized before the first thing that can fail. */\n"
    "bool clean_reconstruct(const struct wire *w, struct block *out_block)\n{\n"
    "    block_init(out_block);\n"
    "    size_t total = w->a + w->b;\n"
    "    if (total == 0 || total > 100)\n"
    "        LOG_FAIL(\"t\", \"bad count %zu\", total);\n"
    "    out_block->n = total;\n"
    "    return true;\n}\n\n"
    "/* VIOLATING: LOG_FAIL expands to `return false` and sits above block_init. */\n"
    "bool dirty_reconstruct(const struct wire *w, struct block *out_block)\n{\n"
    "    size_t total = w->a + w->b;\n"
    "    if (total == 0 || total > 100)\n"
    "        LOG_FAIL(\"t\", \"bad count %zu\", total);\n"
    "    block_init(out_block);\n"
    "    out_block->n = total;\n"
    "    return true;\n}\n";

static const char k_st_imb[] =
    "bool imb_ensure(struct wire *w)\n{\n"
    "#if defined(_WIN32)\n    if (w->a) {\n#else\n    if (w->b) {\n#endif\n"
    "        return false;\n    }\n    return true;\n}\n";

static const char k_st_late[] =
    "bool late_reconstruct(const struct wire *w, struct block *out_block)\n{\n"
    "    size_t total = w->a + w->b;\n"
    "    if (total == 0 || total > 100)\n"
    "        LOG_FAIL(\"t\", \"bad count %zu\", total);\n"
    "    block_init(out_block);\n    return true;\n}\n\n"
    "bool decl_guard_only(const struct wire *w, struct block *out_block)\n{\n"
    "    const struct wire *catalog;\n    char text[WIRE_TEXT_MAX];\n"
    "    if (!w || !out_block)\n        return false;\n"
    "    block_init(out_block);\n    catalog = w;\n    text[0] = 0;\n"
    "    return catalog != NULL;\n}\n\n"
    "bool bound_guard_only(const struct wire *w, struct block *out_block)\n{\n"
    "    uint8_t pad[32];\n    if (!w || !out_block)\n        return false;\n"
    "    block_init(out_block);\n    memset(pad, 0, sizeof(pad));\n    return true;\n}\n\n"
    "static int slash_inside_block_comment(void)\n{\n"
    "    int n = 1; /* end of the // run */\n    return n;\n}\n\n"
    "bool after_comment(const struct wire *w, struct block *out_block)\n{\n"
    "    size_t total = w->a + w->b;\n    if (total > 7)\n"
    "        LOG_FAIL(\"t\", \"bad %zu\", total);\n"
    "    block_init(out_block);\n    return true;\n}\n";

static const char k_st_sink[] =
    "static struct groth16_vk *sapling_spend_vk = NULL;\n"
    "void sapling_set_spend_vk(struct groth16_vk *vk) { sapling_spend_vk = vk; }\n"
    "void set_by_value(struct groth16_vk *vk) { vk->n = 0; }\n";

static const char k_st_loader[] =
    "static struct groth16_vk spend_vk;\n\n"
    "bool dirty_init(const char *dir)\n{\n"
    "    sapling_set_spend_vk(&spend_vk);\n"
    "    if (!read_sprout(dir)) {\n        free(spend_vk.ic);\n        return false;\n    }\n"
    "    return true;\n}\n\n"
    "bool clean_init(const char *dir)\n{\n"
    "    sapling_set_spend_vk(&spend_vk);\n"
    "    if (!read_sprout(dir)) {\n        sapling_set_spend_vk(NULL);\n"
    "        free(spend_vk.ic);\n        return false;\n    }\n"
    "    return true;\n}\n";

static int op_st_check(int ok, const char *what)
{
    if (!ok)
        fprintf(stderr, "check_outparam_init_before_return selftest: FAIL — %s\n", what);
    return !ok;
}

static int op_st_has_key(const struct op_scan *s, const char *key)
{
    for (int i = 0; i < s->nfind; i++)
        if (strcmp(s->find[i].key, key) == 0)
            return 1;
    return 0;
}

/* Leg 1 over the planted files; returns the number of failed assertions. */
static int op_st_leg1(void)
{
    struct op_hset frees;
    struct op_scan s;
    struct op_fn f;
    int bad = 0, d = 0;
    if (op_hset_init(&frees, 16))
        return 1;
    memset(&s, 0, sizeof s);
    s.frees = &frees;
    bad += op_hset_add(&frees, "block_free") != 0;
    op_fn_init(&f, OP_MODE_SCAN, op_scan_emit, &s, NULL);
    bad += op_feed_text(&f, "case.c", k_st_case, &d) != 0;
    bad += op_st_check(op_st_has_key(&s, "dirty_reconstruct|out_block|block"),
                       "the violating case was not detected");
    bad += op_st_check(!op_st_has_key(&s, "clean_reconstruct|out_block|block"),
                       "the clean case was reported as a violation");
    bad += op_st_check(s.nfuncs == 2 && s.nparams == 2,
                       "parser did not see 2 functions and 2 out-params");
    bad += op_feed_text(&f, "imb.c", k_st_imb, &d) != 0;
    bad += op_st_check(d == 1, "the brace imbalance was not reported");
    bad += op_feed_text(&f, "late.c", k_st_late, &d) != 0;
    bad += op_st_check(d == 0, "late.c did not end balanced");
    bad += op_st_check(op_st_has_key(&s, "late_reconstruct|out_block|block"),
                       "a finding behind an unbalanced file was swallowed");
    bad += op_st_check(!op_st_has_key(&s, "decl_guard_only|out_block|block"),
                       "a pointer declarator above a null guard read as DATA");
    bad += op_st_check(op_st_has_key(&s, "bound_guard_only|out_block|block"),
                       "a literal array bound stopped reading as DATA");
    bad += op_st_check(op_st_has_key(&s, "after_comment|out_block|block"),
                       "a '//' inside a one-line block comment swallowed a brace");
    op_fn_free(&f);
    op_scan_free(&s);
    op_hset_free(&frees);
    return bad;
}

/* Leg 2: publisher derivation, then publish-then-free. */
static int op_st_leg2(void)
{
    struct op_hset pubs, objs;
    struct op_pub p;
    struct op_fn f;
    int bad = 0, d = 0;
    if (op_hset_init(&pubs, 16))
        return 1;
    if (op_hset_init(&objs, 16)) {
        op_hset_free(&pubs);
        return 1;
    }
    memset(&p, 0, sizeof p);
    p.found = &pubs;
    op_fn_init(&f, OP_MODE_PUB, op_pubfind_emit, &p, &objs);
    bad += op_feed_text(&f, "sink.c", k_st_sink, &d) != 0;
    bad += op_st_check(op_hset_has(&pubs, "sapling_set_spend_vk"),
                       "the publisher was not derived from the store");
    bad += op_st_check(!op_hset_has(&pubs, "set_by_value"),
                       "a set_* that only writes through the pointer read as a publisher");
    op_fn_free(&f);
    p.known = &pubs;
    op_fn_init(&f, OP_MODE_FREE, op_pubfree_emit, &p, NULL);
    bad += op_feed_text(&f, "loader.c", k_st_loader, &d) != 0;
    bad += op_st_check(p.nhit == 1 && strcmp(p.hit[0].fn, "dirty_init") == 0,
                       "publish-then-free without unpublish was not detected (or the "
                       "unpublish-first case was reported)");
    op_fn_free(&f);
    op_pub_free(&p);
    op_hset_free(&pubs);
    op_hset_free(&objs);
    return bad;
}

/* Fail closed: a file that cannot be read is an error, not an empty scan. */
static int op_st_unreadable(void)
{
    struct op_scan s;
    struct op_fn f;
    int bad = 0, d = 0;
    memset(&s, 0, sizeof s);
    op_fn_init(&f, OP_MODE_SCAN, op_scan_emit, &s, NULL);
    fputs("(expected diagnostics follow: two unreadable inputs)\n", stderr);
    bad += op_st_check(op_fn_file(&f, "/nonexistent-outparam-init-selftest/x.c", &d) != 0,
                       "a missing file read as a clean scan");
    bad += op_st_check(op_fn_file(&f, ".", &d) != 0,
                       "a directory read as a clean scan");
    op_fn_free(&f);
    op_scan_free(&s);
    return bad;
}

int check_outparam_init_before_return_selftest(void)
{
    int bad = op_st_leg1() + op_st_leg2() + op_st_unreadable();
    if (bad) {
        fputs("check_outparam_init_before_return --selftest: FAIL\n", stderr);
        return 1;
    }
    fputs("check_outparam_init_before_return --selftest: PASS\n", stdout);
    return 0;
}
