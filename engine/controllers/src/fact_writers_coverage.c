/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The writer census's coverage half, running the OTHER direction: for every
 * FACT_STORE row's declared api_headers, find keyed-write declarations that no
 * FACT_WRITE_API row claims. A canonical registry that no manifest row claims
 * must fail — that is the second structural clamp on the manifest (the first is
 * the link: a row naming a nonexistent function does not build).
 *
 * It also refuses to report a clean answer off a hollow scan: a declared
 * api_header that cannot be read is a moved write surface, and that returns an
 * error rather than a comfortable zero.
 */

#define _GNU_SOURCE
#include "fact_writers_priv.h"

#include "base/log_macros.h"

#include <stdio.h>
#include <string.h>

/* ── coverage: declared write entry points no manifest row claims ───────── */

static bool fw_is_mutating_name(const char *fn)
{
    static const char *const reads[] = {
        "_get", "get_", "check", "_have", "_first", "_probe", "_enabled",
        "_find", "_count", "_dump", "_is_", "is_", "_read", "_at_", "_rows",
        "_value", "_matches", "_json",
    };
    for (size_t i = 0; i < sizeof(reads) / sizeof(reads[0]); i++)
        if (strstr(fn, reads[i])) return false;
    static const char *const writes[] = {
        "_set", "set_", "_put", "_write", "_delete", "_clear", "_mark",
        "_force", "_clamp", "_raise", "_note", "_remove", "_reset",
        "_upsert", "_advance", "_stamp",
    };
    for (size_t i = 0; i < sizeof(writes) / sizeof(writes[0]); i++)
        if (strstr(fn, writes[i])) return true;
    return false;
}

/* Scan one declared header for `bool <ident>(… const char *<key_column> …)`
 * declarations whose name mutates, and report the unclaimed ones. */
static int fw_scan_header(const char *root, const struct fw_store_row *sr,
                          const char *header, char (*out)[FACT_KEY_MAX],
                          int cap, int found)
{
    struct fw_file f;
    if (!fw_file_load(root, header, &f)) return found;
    char keyparam[64];
    snprintf(keyparam, sizeof(keyparam), "const char *%s", sr->key_column);
    for (size_t ln = 1; ln <= f.nlines; ln++) {
        char line[1024];
        fw_file_line(&f, ln, line, sizeof(line));
        const char *p = line;
        if (strncmp(p, "bool ", 5) != 0) continue;   /* file-scope decl only */
        p += 5;
        while (*p == ' ') p++;
        char fn[FW_MACRO_NAME_MAX];
        size_t k = 0;
        while (fw_ident_char(*p) && k + 1 < sizeof(fn)) fn[k++] = *p++;
        fn[k] = '\0';
        if (k == 0 || *p != '(') continue;
        /* join to the terminating ';' so a multi-line prototype is one string */
        char decl[2048];
        size_t o = 0;
        decl[0] = '\0';
        for (size_t i = 0; i < 8 && ln + i <= f.nlines; i++) {
            char cur[1024];
            fw_file_line(&f, ln + i, cur, sizeof(cur));
            for (const char *q = cur; *q && o + 2 < sizeof(decl); q++)
                decl[o++] = *q;
            if (o + 1 < sizeof(decl)) decl[o++] = ' ';
            decl[o] = '\0';
            if (strchr(cur, ';')) break;
        }
        if (!strstr(decl, keyparam)) continue;
        if (!fw_is_mutating_name(fn)) continue;
        if (fw_api_claimed(sr->store, fn)) continue;
        if (found < cap)
            snprintf(out[found], FACT_KEY_MAX, "%s %s", sr->store, fn);
        found++;
    }
    fw_file_free(&f);
    return found;
}

int fact_writers_unclaimed_apis(const char *root, char (*out)[FACT_KEY_MAX],
                                int cap)
{
    if (!root || !out || cap <= 0) LOG_ERR(FW_DOMAIN, "bad arg to unclaimed");
    int found = 0;
    int headers_read = 0;
    size_t nstores = 0;
    const struct fw_store_row *stores = fw_store_rows(&nstores);
    for (size_t s = 0; s < nstores; s++) {
        const char *h = stores[s].api_headers;
        while (h && *h) {
            char one[FACT_PATH_MAX];
            const char *colon = strchr(h, ':');
            size_t n = colon ? (size_t)(colon - h) : strlen(h);
            if (n >= sizeof(one)) LOG_ERR(FW_DOMAIN, "header path too long");
            memcpy(one, h, n);
            one[n] = '\0';
            struct fw_file probe;
            if (!fw_file_load(root, one, &probe))
                LOG_ERR(FW_DOMAIN,
                        "declared api_header missing: %s (store %s) — the write "
                        "surface moved; update the manifest row deliberately "
                        "instead of letting the coverage scan go hollow",
                        one, stores[s].store);
            fw_file_free(&probe);
            headers_read++;
            found = fw_scan_header(root, &stores[s], one, out, cap, found);
            h = colon ? colon + 1 : NULL;
        }
    }
    if (headers_read == 0)
        LOG_ERR(FW_DOMAIN, "no api_headers scanned (refusing to report clean)");
    return found;
}
