/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: --selftest for check-raw-sqlite (gate_raw_sqlite.c). The shell
 * script had no self-test mode, so this exercises the three scanners on
 * fixtures under $HOME/.local/state/zclassic23/scratch (never a bare /tmp
 * path): clean files pass, raw step calls trip, per-line raw-sql-ok tags
 * and quoted occurrences pass, multi-line node.db DML trips, a PRAGMA
 * passes, a controller destructive model call trips, direct wallet-table
 * DML in a service trips, and a clean service file passes. Fixture text
 * is written with the exec token split across adjacent C literals so this
 * file itself never matches the gate's own scans of tools/.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <stdio.h>
#include <string.h>
#include "lintc.h"
#include "lintc_text.h"
#include "gate_raw_sqlite_priv.h"

static struct crs_viol g_st_v;
static struct bln_set g_st_none;

static int crs_st_check(const char *name, int got, int want)
{
    if (got != want) {
        fprintf(stderr, "check_raw_sqlite selftest: %s: want %d "
                "violations, got %d\n", name, want, got);
        return 1;
    }
    printf("  selftest ok: %s (%d)\n", name, got);
    return 0;
}

static int crs_st_write(const char *root, const char *rel, const char *text)
{
    char path[1024];
    if (ovf(snprintf(path, sizeof path, "%s/%s", root, rel), sizeof path))
        return 2;
    return csr_write(path, text);
}

enum { CRS_K_RAW, CRS_K_EXEC, CRS_K_CTX };

/* Run one scanner (kind) over one planted file and compare the number of
 * violation rows it reports with the expected count. */
static int crs_st_case(int kind, const char *root, const char *name,
                       const char *rel, const char *text, int want)
{
    char path[1024];
    int total = 0, rc;
    struct crs_raw_ctx rawc = { &g_st_v, &g_st_none, &total };
    if (crs_st_write(root, rel, text) != 0)
        return 2;
    if (ovf(snprintf(path, sizeof path, "%s/%s", root, rel), sizeof path))
        return 2;
    memset(&g_st_v, 0, sizeof g_st_v);
    if (kind == CRS_K_RAW)
        rc = crs_raw_file(path, &rawc);
    else if (kind == CRS_K_EXEC)
        rc = crs_exec_file(path, &g_st_v);
    else
        rc = crs_ctx_file(path, &g_st_v);
    return rc != 0 ? 2 : crs_st_check(name, g_st_v.n, want);
}

/* Allowlist path: the same planted violation passes when its file is in
 * the allowlist set (and is counted), and fails when it is not. */
static int crs_st_allow_case(const char *root)
{
    const char *rel = "tools/allow_me.c";
    char path[1024];
    if (crs_st_write(root, rel, "int f(void *s)\n{\n    sqlite3_step(s);\n"
                     "    return 0;\n}\n") != 0)
        return 2;
    if (ovf(snprintf(path, sizeof path, "%s/%s", root, rel), sizeof path))
        return 2;
    static struct bln_set allow;
    memset(&allow, 0, sizeof allow);
    if (bln_add(&allow, path) != 0)
        return 2;
    int bad = 0;
    for (int listed = 0; listed < 2; listed++) {
        memset(&g_st_v, 0, sizeof g_st_v);
        int total = 0;
        struct crs_raw_ctx c = { &g_st_v, listed ? &allow : &g_st_none,
                                 &total };
        if (crs_raw_file(path, &c) != 0)
            return 2;
        bad |= crs_st_check(listed ? "allowlisted file passes"
                                   : "unlisted file trips",
                            g_st_v.n, listed ? 0 : 1) != 0;
        bad |= listed && total != 1;
    }
    return bad;
}

int check_raw_sqlite_selftest(void)
{
    if (crs_raw_init() != 0 || crs_exec_init() != 0)
        return 2;
    char root[1024];
    if (lct_scratch_dir(root, sizeof root, "raw-sqlite") != 0)
        return 2;
    int bad = 0;
    bad |= crs_st_case(CRS_K_RAW, root, "clean file passes", "tools/a.c",
                           "int f(void)\n{\n    return 0;\n}\n", 0) != 0;
    bad |= crs_st_case(CRS_K_RAW, root, "raw step call trips", "tools/b.c",
                           "int f(void *s)\n{\n    sqlite3_step(s);\n"
                           "    return 0;\n}\n", 1) != 0;
    bad |= crs_st_case(CRS_K_RAW, root, "raw-sql-ok tag passes", "tools/c.c",
                           "int f(void *s)\n{\n    sqlite3_step(s); "
                           "// raw-sql-ok:tag-x\n    return 0;\n}\n",
                           0) != 0;
    bad |= crs_st_case(CRS_K_RAW, root, "quoted occurrence passes", "tools/d.c",
                           "int f(void)\n{\n    log(\"at sqlite3_step(x) "
                           "failed\");\n    return 0;\n}\n", 0) != 0;
    bad |= crs_st_case(CRS_K_EXEC, root, "multi-line node.db DML trips", "tools/e.c",
                            "int f(void *ndb)\n{\n    return "
                            "sqlite3_" "exec(ndb->db,\n        "
                            "\"DELETE FROM wallet_utxos\");\n}\n", 1) != 0;
    bad |= crs_st_case(CRS_K_EXEC, root, "PRAGMA passes", "tools/f.c",
                            "int f(void *ndb)\n{\n    return "
                            "sqlite3_" "exec(ndb->db, \"PRAGMA "
                            "journal_mode=WAL\");\n}\n", 0) != 0;
    bad |= crs_st_case(CRS_K_CTX, root, "controller destructive call trips",
                           "contexts/wallet/controllers/ctl.c",
                           "int s(void *ndb)\n{\n    return "
                           "db_wallet_utxo_delete_all(ndb);\n}\n", 1) != 0;
    bad |= crs_st_case(CRS_K_CTX, root, "service wallet-table DML trips",
                           "contexts/wallet/services/svc.c",
                           "int s(void *h)\n{\n    return db_exec(h, "
                           "\"DELETE FROM wallet_utxos\");\n}\n", 1) != 0;
    bad |= crs_st_case(CRS_K_CTX, root, "clean service passes",
                           "contexts/wallet/services/svc2.c",
                           "int s(void)\n{\n    return 0;\n}\n", 0) != 0;
    bad |= crs_st_case(CRS_K_RAW, root, "quote earlier on the line still trips",
                           "tools/g.c",
                           "int f(void *s)\n{\n    log(\"x\"); sqlite3_step(s);"
                           "\n    return 0;\n}\n", 1) != 0;
    bad |= crs_st_case(CRS_K_RAW, root, "wrapper token after the call still trips",
                           "tools/h.c",
                           "int f(void *s)\n{\n    sqlite3_step(s); "
                           "/* AR_STEP_DONE */\n    return 0;\n}\n", 1) != 0;
    bad |= crs_st_case(CRS_K_RAW, root, "wrapped call passes", "tools/i.c",
                           "int f(void *s)\n{\n    return AR_STEP_ROW("
                           "sqlite3_step(s));\n}\n", 0) != 0;
    bad |= crs_st_case(CRS_K_EXEC, root, "second exec call on the line is judged",
                            "tools/j.c",
                            "int f(void *ndb)\n{\n    return sqlite3_" "exec("
                            "ndb->db, \"PRAGMA x\", 0, 0, 0) + sqlite3_"
                            "exec(ndb->db, \"DELETE FROM t\", 0, 0, 0);\n}\n",
                            1) != 0;
    bad |= crs_st_allow_case(root) != 0;
    bad |= crs_st_case(CRS_K_RAW, root, "char-literal quote does not hide a call",
                       "tools/k.c",
                       "int f(void *s)\n{\n    c = '\"'; sqlite3_step(s);\n"
                       "    return 0;\n}\n", 1) != 0;
    bad |= crs_st_case(CRS_K_RAW, root, "quote in an earlier comment does not hide a call",
                       "tools/l.c",
                       "int f(void *s)\n{\n    /* \" */ sqlite3_step(s);\n"
                       "    return 0;\n}\n", 1) != 0;
    bad |= crs_st_case(CRS_K_RAW, root, "wrapped call does not hide a second call",
                       "tools/m.c",
                       "int f(void *a, void *b)\n{\n    AR_STEP_ROW("
                       "sqlite3_step(a)); sqlite3_step(b);\n    return 0;\n}\n",
                       1) != 0;
    bad |= crs_st_case(CRS_K_RAW, root, "unrelated drop token does not hide a call",
                       "tools/n.c",
                       "int f(void *s)\n{\n    p = safe_alloc(n); "
                       "sqlite3_step(s);\n    return 0;\n}\n", 1) != 0;
    rap_rm_rf(root);
    return st_ok(bad, "check_raw_sqlite selftest: OK\n");
}
