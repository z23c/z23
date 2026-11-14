/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Bounded warm session of the semantic sensor: one process serves a batch of emits, reparsing each TU, with cold extraction as the oracle.
 *
 *   z23-clang-manifest session [--verify-cold] [--no-warm] [--max-tus N]
 *
 * stdin carries one request per line: the arguments `emit` takes, separated
 * by TAB (an optional leading "emit" field is ignored). A line ends at LF;
 * trailing CRs are dropped. An empty line ends the session and nothing after
 * it is read; so does end of input, after serving a last line that has no
 * LF. A line longer than CM_SESSION_LINE_MAX bytes, holding a NUL byte, or
 * not valid UTF-8 is refused whole, never truncated. Each request writes its
 * manifest to its --out, exactly as `emit` would, and prints one JSON line on
 * stdout, whose strings are ASCII (JSON escapes carry everything else). No
 * daemon, socket or service: the warm state lives only as long as this
 * process.
 *
 * Truth rules (docs/work/SEMANTIC_MANIFEST.md, "Warm session"):
 *   - Every extraction is fresh: no cursor, location or file handle survives
 *     an emit; only the CXTranslationUnit (and its preamble) does.
 *   - A TU is recreated (disposed, parsed again) when its argv, root or the
 *     producer digest changed, when any non-main file its last accepted
 *     manifest read changed bytes, when an include slot that manifest saw
 *     absent now exists, when it made a lookup that cannot be re-checked, or
 *     on every emit whose argv holds a response file or a modules flag.
 *   - A reparse's own manifest passes the same binding checks (file SHA3s,
 *     no unbound lookup, the TU's baseline shadow candidates) before it is
 *     used, or the reparse is retried once as a fresh parse.
 *   - The first emit after a TU is created or recreated is always verified:
 *     a cold parse in this process must produce the byte-identical manifest.
 *     --verify-cold verifies every emit.
 *   - On a mismatch the cold bytes are written, never the warm ones, and
 *     warm reuse is disabled for that TU while it holds its table slot. An
 *     evicted TU that is requested again starts over as a new one, whose
 *     first emit is verified again.
 *   - Any warm failure, post-check failure or unqualified case writes the
 *     cold bytes.
 *   - The reply's "trust" says which case wrote the bytes: "verified" or
 *     "cold" (cold bytes), or "qualified" (warm bytes no cold parse checked
 *     this emit, advisory only). The manifest bytes carry no such label. */
#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif

#include "clang_manifest.h"

#include "base/safe_alloc.h"
#include "sha3/sha3.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* The longest request line: 256 full-length paths (a root, a source, an out
 * and the rest for flags; the widest dev compile argv has about 150 -I dirs,
 * most far shorter than PATH_MAX). 1 MiB where PATH_MAX is 4096. The reader
 * holds one buffer of this size and never grows it. */
#define CM_SESSION_LINE_MAX (256u * PATH_MAX)
/* The TU table. A table smaller than the caller's working set evicts every TU
 * before its next request, and each request then pays a warm parse plus the
 * cold verification of a first emit: about twice a cold emit (measured in
 * docs/work/SEMANTIC_MANIFEST.md). A hotswap TU costs about 4 MiB resident
 * with its preamble in memory, so the default covers a module-sized batch. */
#define CM_SESSION_TUS_DEFAULT 64
#define CM_WARM_OPTIONS                                                        \
    (CXTranslationUnit_DetailedPreprocessingRecord |                          \
     CXTranslationUnit_PrecompiledPreamble |                                  \
     CXTranslationUnit_CreatePreambleOnFirstParse)

/* One warm TU. Nothing here refers into a previous extraction. */
struct cm_warm_tu {
    char *source;
    char root[PATH_MAX];
    char **argv;
    int argc;
    CXIndex index;
    CXTranslationUnit tu;
    uint8_t producer[32];
    bool producer_named;
    uint8_t *accepted; /* the manifest last written for this TU */
    size_t accepted_len;
    uint8_t *main_bytes; /* the main file bytes handed to this parse */
    size_t main_len;
    uint8_t main_sha3[32];
    /* The shadow candidates (cm_warm_shadows) taken right after the parse that
     * built the preamble, before its cold check. */
    char *shadows;
    size_t shadows_len;
    bool verified;  /* a cold-equal emit since the TU was (re)created */
    bool disabled;  /* a mismatch: cold while this slot lives */
    double parse_ms; /* the front end's share of the last warm emit */
    uint64_t last_use;
};

struct cm_session_stats {
    unsigned requests, refused, warm_written, cold_written;
    unsigned verified_equal, mismatches, evicted, created, reparsed, recreated;
};

struct cm_session {
    struct cm_cc_snapshot cc_snapshot;
    struct cm_warm_tu *tus;
    size_t ntus, cap, max_tus;
    bool verify_cold, no_warm, inject_mismatch;
    char cwd[PATH_MAX];
    uint64_t clock;
    struct cm_session_stats s;
};

/* What one request did, for its JSON line. */
struct cm_outcome {
    const char *tu;      /* none, created, recreated, reparsed */
    const char *written; /* warm or cold */
    const char *verify;  /* equal, mismatch, skipped */
    char reason[512];
    char sections[256];
    double warm_ms, warm_parse_ms, cold_ms, bind_ms;
    const uint8_t *m; /* the bytes written */
    size_t n;
    uint8_t *owned;   /* m, when no TU holds it */
};

static double cm_now_ms(void)
{
    struct timespec ts;
    (void)clock_gettime(CLOCK_MONOTONIC, &ts); // platform-ok: standalone sensor timing, links no platform clock
    return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1e6;
}

/* ---- JSON out ------------------------------------------------------------------ */

/* The length of a UTF-8 lead byte's sequence and its payload bits, else 0. */
static size_t cm_utf8_lead(unsigned char b, uint32_t *cp, uint32_t *min)
{
    if ((b & 0xe0) == 0xc0) {
        *cp = b & 0x1f;
        *min = 0x80;
        return 2;
    }
    if ((b & 0xf0) == 0xe0) {
        *cp = b & 0x0f;
        *min = 0x800;
        return 3;
    }
    if ((b & 0xf8) == 0xf0) {
        *cp = b & 0x07;
        *min = 0x10000;
        return 4;
    }
    return 0;
}

/* The length of the well-formed UTF-8 sequence at s (n bytes left) and its
 * code point, else 0: no stray continuation, overlong form, surrogate, or
 * code point past U+10FFFF. */
static size_t cm_utf8_at(const unsigned char *s, size_t n, uint32_t *cp)
{
    uint32_t min = 0;
    size_t len;
    if (s[0] < 0x80) {
        *cp = s[0];
        return 1;
    }
    len = cm_utf8_lead(s[0], cp, &min);
    if (len == 0 || n < len)
        return 0;
    for (size_t k = 1; k < len; k++) {
        if ((s[k] & 0xc0) != 0x80)
            return 0;
        *cp = (*cp << 6) | (s[k] & 0x3f);
    }
    if (*cp < min || *cp > 0x10ffff || (*cp >= 0xd800 && *cp <= 0xdfff))
        return 0;
    return len;
}

static bool cm_utf8_valid(const char *s, size_t n)
{
    const unsigned char *p = (const unsigned char *)s;
    uint32_t cp;
    for (size_t i = 0, len; i < n; i += len) {
        len = cm_utf8_at(p + i, n - i, &cp);
        if (len == 0)
            return false;
    }
    return true;
}

/* One code point as a JSON escape: \uXXXX, or a surrogate pair past the BMP. */
static void cm_json_escape(uint32_t cp)
{
    if (cp < 0x10000) {
        printf("\\u%04x", (unsigned)cp);
        return;
    }
    cp -= 0x10000;
    printf("\\u%04x\\u%04x", (unsigned)(0xd800 + (cp >> 10)),
           (unsigned)(0xdc00 + (cp & 0x3ff)));
}

/* A JSON string of ASCII bytes only: quote, backslash, controls and DEL are
 * escaped, and so is every code point past ASCII, so a decoder gets the
 * source's exact UTF-8 back. A request is refused unless it is UTF-8; a
 * byte of a diagnostic that is not (a path the tree spells so, a reason cut
 * mid-sequence) becomes U+FFFD. */
static void cm_json_str(const char *key, const char *s)
{
    const unsigned char *p = (const unsigned char *)s;
    size_t n = strlen(s);
    printf("\"%s\":\"", key);
    for (size_t i = 0, len; i < n; i += len) {
        uint32_t cp = 0xfffd;
        len = cm_utf8_at(p + i, n - i, &cp);
        if (len == 0) {
            len = 1;
            cp = 0xfffd;
        }
        if (cp == '"' || cp == '\\')
            printf("\\%c", (int)cp);
        else if (cp < 0x20 || cp >= 0x7f)
            cm_json_escape(cp);
        else
            putchar((int)cp);
    }
    putchar('"');
}

static void cm_reply_refused(unsigned seq, const char *source, const char *why)
{
    printf("{\"seq\":%u,\"ok\":false,", seq);
    cm_json_str("source", source != NULL ? source : "");
    putchar(',');
    cm_json_str("why", why);
    printf("}\n");
    (void)fflush(stdout);
}

/* How far the written bytes can be trusted, for the reply only (the manifest
 * bytes carry no label): "qualified" warm bytes no cold parse checked this
 * emit; "verified" cold bytes a warm parse of this emit equalled; "cold"
 * cold bytes alone. */
static const char *cm_trust(const struct cm_outcome *r)
{
    if (strcmp(r->written, "warm") == 0)
        return "qualified";
    return strcmp(r->verify, "equal") == 0 ? "verified" : "cold";
}

static void cm_reply_ok(unsigned seq, const struct cm_opts *o,
                        const struct cm_outcome *r, const uint8_t *m,
                        size_t n)
{
    uint8_t root[32];
    char hex[65] = "", why[128];
    if (vcs_semantic_root_v1(m, n, root, why, sizeof(why)))
        cm_hex(root, hex);
    printf("{\"seq\":%u,\"ok\":true,", seq);
    cm_json_str("source", o->source);
    putchar(',');
    cm_json_str("out", o->out);
    printf(",\"root\":\"%s\",\"bytes\":%zu,", hex, n);
    cm_json_str("tu", r->tu);
    putchar(',');
    cm_json_str("written", r->written);
    putchar(',');
    cm_json_str("verify", r->verify);
    putchar(',');
    cm_json_str("trust", cm_trust(r));
    putchar(',');
    cm_json_str("reason", r->reason);
    putchar(',');
    cm_json_str("sections", r->sections);
    printf(",\"warm_ms\":%.3f,\"warm_parse_ms\":%.3f,\"cold_ms\":%.3f,"
           "\"bind_ms\":%.3f}\n",
           r->warm_ms, r->warm_parse_ms, r->cold_ms, r->bind_ms);
    (void)fflush(stdout);
}

static void cm_reply_summary(const struct cm_session *ss)
{
    const struct cm_session_stats *s = &ss->s;
    printf("{\"session\":\"end\",\"requests\":%u,\"refused\":%u,"
           "\"warm_written\":%u,\"cold_written\":%u,\"verified_equal\":%u,"
           "\"mismatches\":%u,\"evicted\":%u,\"created\":%u,\"reparsed\":%u,"
           "\"recreated\":%u}\n",
           s->requests, s->refused, s->warm_written, s->cold_written,
           s->verified_equal, s->mismatches, s->evicted, s->created, s->reparsed,
           s->recreated);
    (void)fflush(stdout);
}

/* ---- the TU table -------------------------------------------------------------- */

static void cm_tu_drop_parse(struct cm_warm_tu *w)
{
    if (w->tu != NULL)
        clang_disposeTranslationUnit(w->tu);
    if (w->index != NULL)
        clang_disposeIndex(w->index);
    w->tu = NULL;
    w->index = NULL;
    w->verified = false;
}

static void cm_tu_free_argv(struct cm_warm_tu *w)
{
    for (int k = 0; k < w->argc; k++)
        free(w->argv[k]);
    free(w->argv);
    w->argv = NULL;
    w->argc = 0;
}

static void cm_tu_free(struct cm_warm_tu *w)
{
    cm_tu_drop_parse(w);
    cm_tu_free_argv(w);
    free(w->source);
    free(w->accepted);
    free(w->shadows);
    free(w->main_bytes);
    memset(w, 0, sizeof(*w));
}

static bool cm_tu_set_argv(struct cm_warm_tu *w, char **argv, int argc)
{
    cm_tu_free_argv(w);
    w->argv = zcl_calloc((size_t)argc + 1, sizeof(char *),
                         "clang_manifest.session_argv");
    if (w->argv == NULL)
        return false;
    for (int k = 0; k < argc; k++) {
        w->argv[k] = cm_strdup(argv[k]);
        if (w->argv[k] == NULL)
            return false;
        w->argc = k + 1;
    }
    return true;
}

static bool cm_tu_same_argv(const struct cm_warm_tu *w, char **argv, int argc)
{
    if (w->argc != argc)
        return false;
    for (int k = 0; k < argc; k++) {
        if (strcmp(w->argv[k], argv[k]) != 0)
            return false;
    }
    return true;
}

static struct cm_warm_tu *cm_tu_find(struct cm_session *ss, const char *root,
                                     const char *source)
{
    for (size_t k = 0; k < ss->ntus; k++) {
        if (strcmp(ss->tus[k].root, root) == 0 &&
            strcmp(ss->tus[k].source, source) == 0)
            return &ss->tus[k];
    }
    return NULL;
}

/* A new slot; the least recently used TU is disposed when the table is full. */
static struct cm_warm_tu *cm_tu_add(struct cm_session *ss, const char *root,
                                    const char *source)
{
    struct cm_warm_tu *w;
    if (ss->ntus == ss->max_tus) {
        size_t lru = 0;
        for (size_t k = 1; k < ss->ntus; k++) {
            if (ss->tus[k].last_use < ss->tus[lru].last_use)
                lru = k;
        }
        cm_tu_free(&ss->tus[lru]);
        ss->s.evicted++;
        ss->tus[lru] = ss->tus[--ss->ntus];
    }
    if (!cm_grow((void **)&ss->tus, &ss->cap, ss->ntus, sizeof(*ss->tus)))
        return NULL;
    w = &ss->tus[ss->ntus];
    memset(w, 0, sizeof(*w));
    w->source = cm_strdup(source);
    if (w->source == NULL)
        return NULL;
    (void)snprintf(w->root, sizeof(w->root), "%s", root);
    ss->ntus++;
    return w;
}

/* ---- the warm front end ------------------------------------------------------- */

static CXIndex cm_warm_index(void)
{
#if CINDEX_VERSION_MINOR >= 64 && !defined(__APPLE__)
    /* Preambles in memory: no temporary PCH file outlives a killed session. */
    CXIndexOptions opts;
    CXIndex idx;
    memset(&opts, 0, sizeof(opts));
    opts.Size = sizeof(opts);
    opts.StorePreamblesInMemory = 1;
    idx = clang_createIndexWithOptions(&opts);
    if (idx != NULL)
        return idx;
#endif
    return clang_createIndex(0, 0);
}

/* The main file is handed to the front end as an unsaved buffer holding the
 * exact bytes this emit read and hashed; headers come from the preamble,
 * which the binding checks have already tied to their exact bytes. */
static bool cm_warm_parse(struct cm_state *st, const struct cm_opts *o,
                          const struct cm_args *args, void *ctx)
{
    struct cm_warm_tu *w = ctx;
    struct CXUnsavedFile main = {.Filename = o->source,
                                 .Contents = (const char *)w->main_bytes,
                                 .Length = w->main_len};
    double t0 = cm_now_ms();
    if (w->tu != NULL) {
        int rc = clang_reparseTranslationUnit(w->tu, 1, &main,
                                              clang_defaultReparseOptions(w->tu));
        if (rc != 0) {
            cm_tu_drop_parse(w);
            return cm_fail(&st->core, "libclang reparse failed (code %d)", rc);
        }
    } else {
        enum CXErrorCode rc;
        w->index = w->index != NULL ? w->index : cm_warm_index();
        if (w->index == NULL)
            return cm_fail(&st->core, "cannot create index");
        rc = clang_parseTranslationUnit2(w->index, o->source, args->parse,
                                         (int)args->nparse, &main, 1,
                                         CM_WARM_OPTIONS, &w->tu);
        if (rc != CXError_Success || w->tu == NULL) {
            w->tu = NULL;
            return cm_fail(&st->core, "libclang parse failed (code %d)",
                           (int)rc);
        }
    }
    st->index = w->index;
    st->tu = w->tu;
    w->parse_ms = cm_now_ms() - t0;
    return true;
}

/* ---- deciding how one emit may use its TU ------------------------------------ */

/* Does the tree still hold the shadow candidates w's preamble was built
 * against, for the files manifest m read? m is the accepted manifest before
 * a reparse, and the reparse's own manifest after it. */
static bool cm_tu_shadows_same(const struct cm_warm_tu *w, const uint8_t *m,
                               size_t n, char *why, size_t why_len)
{
    char *now = NULL;
    size_t now_len = 0;
    bool same;
    if (w->shadows == NULL) {
        (void)snprintf(why, why_len, "no-shadow-baseline");
        return false;
    }
    if (!cm_warm_shadows(w->root, m, n, &now, &now_len)) {
        (void)snprintf(why, why_len, "shadow-candidates-unreadable");
        return false;
    }
    same = cm_warm_shadows_same(w->shadows, w->shadows_len, now, now_len, why,
                                why_len);
    free(now);
    return same;
}

/* The baseline of a fresh parse: its shadow candidates, taken before the cold
 * check, so a header that appears between the parse and this listing makes
 * the cold oracle differ instead of hiding in the baseline. */
static bool cm_tu_baseline(struct cm_warm_tu *w, const uint8_t *m, size_t n,
                           char *why, size_t why_len)
{
    free(w->shadows);
    w->shadows = NULL;
    w->shadows_len = 0;
    if (cm_warm_shadows(w->root, m, n, &w->shadows, &w->shadows_len))
        return true;
    (void)snprintf(why, why_len, "shadow-candidates-unreadable");
    return false;
}

/* An argv whose meaning lies outside every file a manifest hashes: a
 * response file (@file) or a config file, whose contents nothing binds, or
 * modules, where an implicit module map can pull in headers the file set
 * never names. Checked on every emit, not only when argv changed. */
static bool cm_argv_untrackable(char *const *argv, int argc)
{
    static const char *const prefixes[] = {
        "-fmodule", "-fimplicit-module-maps", "-fbuiltin-module-map",
        "-fcxx-modules", "--config",
    };
    for (int k = 0; k < argc; k++) {
        if (argv[k][0] == '@')
            return true;
        for (size_t p = 0; p < sizeof(prefixes) / sizeof(prefixes[0]); p++) {
            if (strncmp(argv[k], prefixes[p], strlen(prefixes[p])) == 0)
                return true;
        }
    }
    return false;
}

/* Why the TU must be (re)created, or NULL when a reparse may be tried. */
static const char *cm_tu_stale(struct cm_warm_tu *w, const struct cm_opts *o,
                               const uint8_t producer[32], bool named,
                               char *why, size_t why_len)
{
    if (w->tu == NULL)
        return w->accepted == NULL ? "first-parse" : "no-live-tu";
    if (cm_argv_untrackable(o->argv, o->argc))
        return "argv-untrackable";
    if (!cm_tu_same_argv(w, o->argv, o->argc))
        return "argv-changed";
    if (!named || !w->producer_named)
        return "producer-unnamed";
    if (memcmp(producer, w->producer, 32) != 0)
        return "producer-changed";
    if (w->accepted == NULL)
        return "nothing-accepted";
    if (!cm_warm_bound(w->root, w->accepted, w->accepted_len, why, why_len))
        return why;
    if (!cm_tu_shadows_same(w, w->accepted, w->accepted_len, why, why_len))
        return why;
    return NULL;
}

static bool cm_read_main(struct cm_warm_tu *w, const char *source)
{
    free(w->main_bytes);
    w->main_bytes = NULL;
    if (!cm_read_file(source, &w->main_bytes, &w->main_len))
        return false;
    zcl_sha3_256(w->main_bytes, w->main_len, w->main_sha3);
    return true;
}

/* Prepare w for this emit: recreate it when stale. False: warm is off. */
static bool cm_tu_prepare(struct cm_session *ss, struct cm_warm_tu *w,
                          const struct cm_opts *o, struct cm_outcome *r)
{
    uint8_t producer[32];
    char why[400] = "";
    const char *stale;
    bool named = cm_producer_digest(CM_TYPE_GRAMMAR, producer);
    double t0 = cm_now_ms();
    stale = cm_tu_stale(w, o, producer, named, why, sizeof(why));
    r->bind_ms = cm_now_ms() - t0;
    if (stale != NULL) {
        bool fresh = w->tu == NULL && w->accepted == NULL;
        cm_tu_drop_parse(w);
        r->tu = fresh ? "created" : "recreated";
        (void)snprintf(r->reason, sizeof(r->reason), "%s", stale);
        if (fresh)
            ss->s.created++;
        else
            ss->s.recreated++;
        if (!cm_tu_set_argv(w, o->argv, o->argc))
            return false;
        memcpy(w->producer, producer, 32);
        w->producer_named = named;
    } else {
        r->tu = "reparsed";
        ss->s.reparsed++;
    }
    return cm_read_main(w, o->source);
}

/* ---- one request ---------------------------------------------------------------- */

/* The post-checks of a reparse's manifest m. Against the accepted manifest:
 * every non-main file both read has the same digest, IDENTITY is equal, and
 * every lookup the accepted one also made is byte-identical. Then m itself
 * is bound as the next pre-check would bind it, because no cold parse checks
 * a reparse: every file it read still has the digest it records, it made no
 * lookup without a negative claim, and its shadow candidates are the TU's
 * baseline. That catches what moved after the pre-checks and what only this
 * reparse read. A fresh parse is checked by the cold oracle instead. */
static bool cm_reparse_post(const struct cm_warm_tu *w, const uint8_t *m,
                            size_t n, char *why, size_t why_len)
{
    if (w->accepted != NULL &&
        (!cm_warm_files_agree(w->accepted, w->accepted_len, m, n, why,
                              why_len) ||
         !cm_warm_lookups_agree(w->accepted, w->accepted_len, m, n, why,
                                why_len)))
        return false;
    return cm_warm_bound(w->root, m, n, why, why_len) &&
           cm_tu_shadows_same(w, m, n, why, why_len);
}

/* The warm manifest, checked against what this emit handed the front end and
 * what the last accepted manifest read; NULL (with reason) when unusable. */
static uint8_t *cm_warm_emit(struct cm_warm_tu *w, const struct cm_opts *o,
                             bool reparse, size_t *len, struct cm_outcome *r)
{
    struct cm_front front = {.parse = cm_warm_parse, .ctx = w};
    uint8_t *m = NULL, main_digest[32];
    char why[400] = "";
    double t0 = cm_now_ms();
    bool ok = cm_emit_bytes(o, &front, &m, len, why, sizeof(why));
    r->warm_ms = cm_now_ms() - t0;
    r->warm_parse_ms = w->parse_ms;
    if (ok && (!cm_warm_main_digest(m, *len, main_digest) ||
               memcmp(main_digest, w->main_sha3, 32) != 0)) {
        (void)snprintf(why, sizeof(why), "main file bytes differ");
        ok = false;
    }
    if (ok && !reparse)
        ok = cm_tu_baseline(w, m, *len, why, sizeof(why));
    if (ok && reparse)
        ok = cm_reparse_post(w, m, *len, why, sizeof(why));
    if (ok)
        return m;
    (void)snprintf(r->reason, sizeof(r->reason), "warm-unusable: %s", why);
    cm_tu_drop_parse(w);
    free(m);
    return NULL;
}

static void cm_name_sections(const uint8_t *a, size_t an, const uint8_t *b,
                             size_t bn, char *out, size_t cap)
{
    struct vcs_semantic_diff_v1 d;
    size_t w = 0;
    out[0] = '\0';
    if (!vcs_semantic_manifest_v1_diff(a, an, b, bn, &d, NULL, NULL)) {
        (void)snprintf(out, cap, "undecodable");
        return;
    }
    for (int t = 1; t < VCS_SEMANTIC_SECTION_V1_COUNT && w < cap; t++) {
        if (d.changed_sections & (1u << t))
            w += (size_t)snprintf(out + w, cap - w, "%s%s", w ? " " : "",
                                  vcs_semantic_section_v1_name(
                                      (enum vcs_semantic_section_v1)t));
    }
}

/* Compare warm with the cold oracle; on a mismatch disable warm reuse. */
static void cm_verify(struct cm_session *ss, struct cm_warm_tu *w,
                      const struct cm_opts *o, const uint8_t *warm,
                      size_t warm_len, const uint8_t *cold, size_t cold_len,
                      struct cm_outcome *r)
{
    if (warm_len == cold_len && memcmp(warm, cold, cold_len) == 0) {
        r->verify = "equal";
        w->verified = true;
        ss->s.verified_equal++;
        return;
    }
    r->verify = "mismatch";
    ss->s.mismatches++;
    w->disabled = true;
    cm_tu_drop_parse(w);
    cm_name_sections(cold, cold_len, warm, warm_len, r->sections,
                     sizeof(r->sections));
    fprintf(stderr,
            "clang-manifest: session: warm manifest of %s differs from the "
            "cold oracle (sections: %s); cold bytes written, warm reuse "
            "disabled for this TU\n",
            o->source, r->sections);
}

static bool cm_accept(struct cm_warm_tu *w, const struct cm_opts *o,
                      uint8_t *m, size_t n, struct cm_outcome *r, char *why,
                      size_t why_len)
{
    if (!cm_write_file(o->out, m, n)) {
        (void)snprintf(why, why_len, "cannot write %s", o->out);
        free(m);
        return false;
    }
    free(w->accepted);
    w->accepted = m;
    w->accepted_len = n;
    r->m = m;
    r->n = n;
    return true;
}

/* The fault flag: corrupt the warm bytes so the oracle must catch them. */
static void cm_inject(const struct cm_session *ss, uint8_t *warm, size_t n)
{
    if (ss->inject_mismatch && warm != NULL && n > 0)
        warm[n - 1] ^= 0x5a;
}

static bool cm_session_cold(const struct cm_opts *o, uint8_t **m, size_t *n,
                            struct cm_outcome *r, char *why, size_t why_len)
{
    double t0 = cm_now_ms();
    bool ok = cm_emit_bytes(o, &cm_cold_front, m, n, why, why_len);
    r->cold_ms = cm_now_ms() - t0;
    return ok;
}

/* The warm manifest of this emit, or NULL. A reparse whose result fails a
 * post-check (a probe moved, the main bytes or a preamble file differ) is
 * retried once as a fresh parse, which then needs the oracle again. */
static uint8_t *cm_warm_try(struct cm_session *ss, struct cm_warm_tu *w,
                            const struct cm_opts *o, struct cm_outcome *r,
                            size_t *len)
{
    uint8_t *warm;
    if (!cm_tu_prepare(ss, w, o, r)) {
        (void)snprintf(r->reason, sizeof(r->reason), "warm-unavailable");
        cm_tu_drop_parse(w);
        return NULL;
    }
    warm = cm_warm_emit(w, o, strcmp(r->tu, "reparsed") == 0, len, r);
    if (warm == NULL && strcmp(r->tu, "reparsed") == 0) {
        r->tu = "recreated";
        ss->s.reparsed--;
        ss->s.recreated++;
        warm = cm_warm_emit(w, o, false, len, r);
    }
    cm_inject(ss, warm, *len);
    return warm;
}

static bool cm_warm_path(struct cm_session *ss, struct cm_warm_tu *w,
                         const struct cm_opts *o, struct cm_outcome *r,
                         char *why, size_t why_len)
{
    uint8_t *cold = NULL;
    size_t warm_len = 0, cold_len = 0;
    uint8_t *warm = cm_warm_try(ss, w, o, r, &warm_len);
    if (warm != NULL && !ss->verify_cold && w->verified) {
        ss->s.warm_written++;
        r->written = "warm";
        return cm_accept(w, o, warm, warm_len, r, why, why_len);
    }
    struct cm_opts oracle = *o;
    oracle.cc_snapshot = NULL; /* the cold verifier must independently hash */
    if (!cm_session_cold(&oracle, &cold, &cold_len, r, why, why_len)) {
        free(warm);
        return false;
    }
    if (warm != NULL)
        cm_verify(ss, w, o, warm, warm_len, cold, cold_len, r);
    free(warm);
    ss->s.cold_written++;
    return cm_accept(w, o, cold, cold_len, r, why, why_len);
}

static bool cm_session_emit(struct cm_session *ss, const struct cm_opts *o,
                            struct cm_outcome *r, char *why, size_t why_len)
{
    struct cm_warm_tu *w;
    uint8_t *cold = NULL;
    size_t cold_len = 0;
    w = cm_tu_find(ss, o->root, o->source);
    if (w == NULL && !ss->no_warm)
        w = cm_tu_add(ss, o->root, o->source);
    if (w != NULL && !w->disabled) {
        w->last_use = ++ss->clock;
        return cm_warm_path(ss, w, o, r, why, why_len);
    }
    (void)snprintf(r->reason, sizeof(r->reason), "%s",
                   ss->no_warm ? "no-warm" : "warm-disabled");
    if (!cm_session_cold(o, &cold, &cold_len, r, why, why_len))
        return false;
    ss->s.cold_written++;
    r->owned = cold;
    r->m = cold;
    r->n = cold_len;
    if (!cm_write_file(o->out, cold, cold_len)) {
        (void)snprintf(why, why_len, "cannot write %s", o->out);
        return false;
    }
    return true;
}

/* ---- the request loop ----------------------------------------------------------- */

/* Split a line into TAB-separated fields, in place. */
static char **cm_split(char *line, int *n)
{
    size_t count = 1;
    char **f;
    for (const char *p = line; *p != '\0'; p++)
        count += *p == '\t';
    f = zcl_calloc(count + 1, sizeof(char *), "clang_manifest.session_fields");
    if (f == NULL)
        return NULL;
    *n = 0;
    for (char *p = line;;) {
        char *tab = strchr(p, '\t');
        f[(*n)++] = p;
        if (tab == NULL)
            break;
        *tab = '\0';
        p = tab + 1;
    }
    return f;
}

/* Resolve --root against the session's start directory and enter it. */
static bool cm_enter_root(const struct cm_session *ss, struct cm_opts *o,
                          char abs[PATH_MAX])
{
    if (chdir(ss->cwd) != 0 || realpath(o->root, abs) == NULL ||
        chdir(abs) != 0)
        return false;
    o->root = abs;
    return true;
}

static void cm_session_line(struct cm_session *ss, char *line)
{
    struct cm_outcome r = {.tu = "none", .written = "cold",
                           .verify = "skipped"};
    struct cm_opts o = {.cc_snapshot = &ss->cc_snapshot};
    char abs[PATH_MAX], why[512] = "";
    int n = 0;
    char **f = cm_split(line, &n);
    unsigned seq = ++ss->s.requests;
    int first = f != NULL && n > 0 && strcmp(f[0], "emit") == 0 ? 1 : 0;
    if (f == NULL || !cm_parse_opts(n, f, first, &o)) {
        ss->s.refused++;
        cm_reply_refused(seq, NULL, "malformed request: expected the emit "
                                    "arguments separated by TAB");
    } else if (!cm_enter_root(ss, &o, abs)) {
        ss->s.refused++;
        cm_reply_refused(seq, o.source, "cannot enter root");
    } else if (!cm_session_emit(ss, &o, &r, why, sizeof(why))) {
        ss->s.refused++;
        fprintf(stderr, "clang-manifest: refused: %s\n", why);
        cm_reply_refused(seq, o.source, why);
    } else {
        cm_reply_ok(seq, &o, &r, r.m, r.n);
    }
    free(r.owned);
    free(f);
}

/* --max-tus: digits only, 1 to 256; no sign, space or trailing byte. */
static bool cm_parse_tus(const char *s, size_t *out)
{
    char *end = NULL;
    unsigned long v;
    if (s[0] < '0' || s[0] > '9')
        return false;
    errno = 0;
    v = strtoul(s, &end, 10);
    if (errno != 0 || end == NULL || *end != '\0' || v == 0 || v > 256)
        return false;
    *out = (size_t)v;
    return true;
}

static bool cm_session_opts(struct cm_session *ss, int argc, char **argv)
{
    ss->max_tus = CM_SESSION_TUS_DEFAULT;
    for (int k = 2; k < argc; k++) {
        if (strcmp(argv[k], "--verify-cold") == 0)
            ss->verify_cold = true;
        else if (strcmp(argv[k], "--no-warm") == 0)
            ss->no_warm = true;
        else if (strcmp(argv[k], "--max-tus") != 0 || k + 1 >= argc ||
                 !cm_parse_tus(argv[++k], &ss->max_tus))
            return false;
    }
    return true;
}

/* What reading one request line found. */
enum cm_line_state {
    CM_LINE_OK,
    CM_LINE_END,  /* an empty line, or end of input with nothing read */
    CM_LINE_LONG, /* past CM_SESSION_LINE_MAX: read to its end, dropped */
    CM_LINE_NUL,  /* a NUL byte before the line's end */
    CM_LINE_ERROR, /* input failed; no partial request may be served */
};

/* One line of stdin into buf (CM_SESSION_LINE_MAX + 1 bytes), without its LF
 * or trailing CRs. The buffer never grows; an overlong line is consumed to
 * its LF so the next request starts clean. */
static enum cm_line_state cm_read_line(char *buf, size_t *len)
{
    size_t n = 0;
    bool nul = false, over = false;
    int ch;
    while ((ch = getc(stdin)) != EOF && ch != '\n') {
        nul = nul || ch == '\0';
        if (n < CM_SESSION_LINE_MAX)
            buf[n++] = (char)ch;
        else
            over = true;
    }
    while (!over && n > 0 && buf[n - 1] == '\r')
        n--;
    buf[n] = '\0';
    *len = n;
    if (ferror(stdin)) {
        buf[0] = '\0';
        *len = 0;
        return CM_LINE_ERROR;
    }
    if (over)
        return CM_LINE_LONG;
    if (nul)
        return CM_LINE_NUL;
    return n == 0 ? CM_LINE_END : CM_LINE_OK;
}

static void cm_session_refuse(struct cm_session *ss, const char *why)
{
    ss->s.refused++;
    cm_reply_refused(++ss->s.requests, NULL, why);
}

/* Serve stdin until an empty line or its end. */
static void cm_session_loop(struct cm_session *ss, char *buf)
{
    size_t len = 0;
    for (;;) {
        enum cm_line_state st = cm_read_line(buf, &len);
        if (st == CM_LINE_END)
            return;
        if (st == CM_LINE_ERROR) {
            fprintf(stderr, "clang-manifest: session: cannot read session input\n");
            cm_session_refuse(ss, "cannot read session input");
            return;
        }
        if (st == CM_LINE_LONG)
            cm_session_refuse(ss, "request line too long");
        else if (st == CM_LINE_NUL)
            cm_session_refuse(ss, "request line has a NUL byte");
        else if (!cm_utf8_valid(buf, len))
            cm_session_refuse(ss, "request line is not UTF-8");
        else
            cm_session_line(ss, buf);
    }
}

int cm_session_main(int argc, char **argv)
{
    struct cm_session ss = {0};
    const char *inject = getenv("ZCL_CLANG_MANIFEST_INJECT_WARM_MISMATCH");
    char *buf;
    if (!cm_session_opts(&ss, argc, argv)) {
        fprintf(stderr, "usage: z23-clang-manifest session [--verify-cold] "
                        "[--no-warm] [--max-tus 1..256]\n");
        return 2;
    }
    if (getcwd(ss.cwd, sizeof(ss.cwd)) == NULL) {
        fprintf(stderr, "clang-manifest: session: no current directory\n");
        return 2;
    }
    buf = zcl_malloc(CM_SESSION_LINE_MAX + 1, "clang_manifest.session_line");
    if (buf == NULL) {
        fprintf(stderr, "clang-manifest: session: no memory for a request\n");
        return 2;
    }
    ss.inject_mismatch = inject != NULL && strcmp(inject, "1") == 0;
    cm_session_loop(&ss, buf);
    free(buf);
    for (size_t k = 0; k < ss.ntus; k++)
        cm_tu_free(&ss.tus[k]);
    free(ss.tus);
    for (size_t k = 0; k < 2; ++k) free(ss.cc_snapshot.entries[k].bytes);
    cm_reply_summary(&ss);
    return ss.s.refused == 0 ? 0 : 3;
}
