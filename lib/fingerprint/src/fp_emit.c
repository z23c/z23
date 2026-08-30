/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * fp_emit — generate the call harness.
 *
 * There is no hand-written harness for any function. For each candidate this
 * writes one C probe that declares the locals its signature needs, fills them
 * from the shape-seeded corpus, makes the call, and absorbs every observable
 * result into the accumulator.
 *
 * Two decisions in here are what keep the generated code sound rather than
 * merely compiling:
 *
 *  - ONE TRANSLATION UNIT PER INCLUDED FILE. A single generated file
 *    including two hundred of this tree's headers would hit macro and type
 *    collisions that have nothing to do with any candidate, and one such
 *    collision would take every probe down with it. Grouping by the included
 *    file keeps each TU's project include set at exactly one file, so a TU
 *    that fails to compile costs only the functions that file declares — and
 *    that failure is recorded as an exclusion rather than papered over.
 *
 *    That included file is a HEADER for an externally linkable function and
 *    the DEFINING .c ITSELF for a file-local one, which is the only way a
 *    `static` can be called at all. A source-included TU is the riskier of
 *    the two by construction — it inherits the unit's file-scope objects,
 *    its other statics and its whole include set — and two things keep it
 *    honest. The unit is included FIRST, so its own feature macros still
 *    take effect. And every generated identifier is spelled `fp__…`: a probe
 *    body that used `iter` or `h` would be silently rewritten by any tree
 *    unit that happens to `#define` those, and the probe would still
 *    compile.
 *
 *  - EVERY PARAMETER SLOT HAS ITS OWN GENERATOR, seeded from the shape and
 *    the slot index. If one generator produced all of a call's inputs, a
 *    parameter whose size differs between two functions (a struct, a buffer)
 *    would shift every later parameter's value, and two implementations of
 *    the same behavior would stop matching for a reason that has nothing to
 *    do with their behavior.
 *
 * A buffer's bound length is passed as FP_BUF_BYTES against a buffer of
 * FP_BUF_BYTES ELEMENTS. That is deliberate and it is the one place the
 * harness must not be clever: `f(const T *p, size_t n)` may mean n bytes or
 * n elements, the signature does not say which, and this choice is in bounds
 * under both readings.
 */

#include "fp_priv.h"

#include <stdio.h>
#include <string.h>

#define FP_SEED_STRIDE 0xA24BAED4963EE407ull

size_t fp_emit_group_of(const struct fp_candidate *cands, size_t n_cands,
                        size_t index)
{
    size_t g = 0;
    size_t i;
    for (i = 1; i <= index && i < n_cands; i++)
        if (strcmp(cands[i].include, cands[i - 1].include) != 0)
            g++;
    return g;
}

/* Index of an earlier parameter slot with the identical kind and identical
 * written type, or -1. Two such slots are what an equality, comparison or
 * "does A supersede B" function is made of, and independent random fills
 * make every one of them answer "not equal" on every input — which is how
 * twenty unrelated comparators end up sharing a fingerprint. */
static int fp_twin_slot(const struct fp_candidate *c, int i)
{
    int j;
    for (j = 0; j < i; j++) {
        if (c->param[j].kind != c->param[i].kind)
            continue;
        if (strcmp(c->param[j].type_text, c->param[i].type_text) != 0)
            continue;
        if (strcmp(c->param[j].elem_text, c->param[i].elem_text) != 0)
            continue;
        return j;
    }
    return -1;
}

/* Force a quarter of the corpus to pass a slot's twin verbatim and another
 * quarter to pass it with exactly one bit flipped, so a comparator sees the
 * equal case, the almost-equal case and the unrelated case. */
static void fp_emit_twin(FILE *out, const struct fp_candidate *c, int i,
                         bool addr_of)
{
    int j = fp_twin_slot(c, i);
    const char *amp = addr_of ? "&" : "";
    if (j < 0)
        return;
    fprintf(out, "    if ((fp__iter & 3u) == 1u) memcpy(%sfp__a%d, %sfp__a%d,"
                 " sizeof fp__a%d);\n", amp, i, amp, j, i);
    fprintf(out, "    else if ((fp__iter & 3u) == 2u) { memcpy(%sfp__a%d,"
                 " %sfp__a%d, sizeof fp__a%d); ((unsigned char *)%sfp__a%d)"
                 "[fp__iter %% sizeof fp__a%d] ^= 1u; }\n",
            amp, i, amp, j, i, amp, i, i);
}

static void fp_emit_local(FILE *out, const struct fp_candidate *c, int i,
                          uint64_t seed)
{
    const struct fp_param *p = &c->param[i];
    switch (p->kind) {
    case FP_K_SCALAR:
        fprintf(out, "    %s fp__a%d;\n", p->type_text, i);
        fprintf(out, "    { struct fp_rng fp__r; fp_rng_seed(&fp__r, %lluull,"
                     " fp__iter, fp__salt); fp__a%d = (%s)fp_rng_scalar(&fp__r,"
                     " (unsigned)sizeof fp__a%d, fp__iter, %du); }\n",
                (unsigned long long)seed, i, p->type_text, i, (unsigned)i);
        {
            int j = fp_twin_slot(c, i);
            if (j >= 0) {
                fprintf(out, "    if ((fp__iter & 3u) == 1u) fp__a%d = fp__a%d;\n",
                        i, j);
                fprintf(out, "    else if ((fp__iter & 3u) == 2u) fp__a%d ="
                             " (%s)(fp__a%d ^ 1);\n", i, p->type_text, j);
            }
        }
        break;
    case FP_K_CSTR_IN:
        fprintf(out, "    char fp__a%d[FP_STR_BYTES];\n", i);
        fprintf(out, "    { struct fp_rng fp__r; fp_rng_seed(&fp__r, %lluull,"
                     " fp__iter, fp__salt); fp_rng_cstr(&fp__r, fp__a%d,"
                     " sizeof fp__a%d, fp__iter); }\n",
                (unsigned long long)seed, i, i);
        if (fp_twin_slot(c, i) >= 0)
            fprintf(out, "    if ((fp__iter & 3u) == 1u) memcpy(fp__a%d,"
                         " fp__a%d, sizeof fp__a%d);\n",
                    i, fp_twin_slot(c, i), i);
        break;
    case FP_K_BUF_IN:
        fprintf(out, "    %s fp__a%d[FP_BUF_BYTES];\n", p->type_text, i);
        fprintf(out, "    { struct fp_rng fp__r; fp_rng_seed(&fp__r, %lluull,"
                     " fp__iter, fp__salt); fp_rng_textbytes(&fp__r, fp__a%d,"
                     " sizeof fp__a%d, fp__iter); }\n",
                (unsigned long long)seed, i, i);
        fp_emit_twin(out, c, i, false);
        break;
    case FP_K_ARR_IN:
        fprintf(out, "    %s fp__a%d[%s];\n", p->type_text, i, p->elem_text);
        fprintf(out, "    { struct fp_rng fp__r; fp_rng_seed(&fp__r, %lluull,"
                     " fp__iter, fp__salt); fp_rng_bytes(&fp__r, fp__a%d,"
                     " sizeof fp__a%d); }\n",
                (unsigned long long)seed, i, i);
        fp_emit_twin(out, c, i, false);
        break;
    case FP_K_OBJ_IN:
        fprintf(out, "    %s fp__a%d;\n", p->type_text, i);
        fprintf(out, "    { struct fp_rng fp__r; fp_rng_seed(&fp__r, %lluull,"
                     " fp__iter, fp__salt); fp_rng_objbytes(&fp__r, &fp__a%d,"
                     " sizeof fp__a%d, fp__iter); }\n",
                (unsigned long long)seed, i, i);
        fp_emit_twin(out, c, i, true);
        break;
    case FP_K_OUT_SCALAR:
    case FP_K_OUT_OBJ:
        fprintf(out, "    %s fp__a%d;\n", p->type_text, i);
        fprintf(out, "    memset(&fp__a%d, (int)fp__fill, sizeof fp__a%d);\n",
                i, i);
        break;
    case FP_K_OUT_ARR:
        if (p->elem_text[0] == '\0')
            fprintf(out, "    %s fp__a%d[FP_BUF_BYTES];\n", p->type_text, i);
        else
            fprintf(out, "    %s fp__a%d[%s];\n", p->type_text, i,
                    p->elem_text);
        fprintf(out, "    memset(fp__a%d, (int)fp__fill, sizeof fp__a%d);\n",
                i, i);
        break;
    case FP_K_LEN:
    case FP_K_VOID:
    case FP_K_CSTR_OUT:
    default:
        break;
    }
}

static void fp_emit_arg(FILE *out, const struct fp_candidate *c, int i)
{
    const struct fp_param *p = &c->param[i];
    if (i > 0)
        fprintf(out, ", ");
    switch (p->kind) {
    case FP_K_SCALAR:      fprintf(out, "fp__a%d", i); break;
    case FP_K_CSTR_IN:     fprintf(out, "fp__a%d", i); break;
    case FP_K_BUF_IN:      fprintf(out, "fp__a%d", i); break;
    case FP_K_ARR_IN:      fprintf(out, "fp__a%d", i); break;
    case FP_K_OBJ_IN:      fprintf(out, "&fp__a%d", i); break;
    case FP_K_OUT_SCALAR:  fprintf(out, "&fp__a%d", i); break;
    case FP_K_OUT_OBJ:     fprintf(out, "&fp__a%d", i); break;
    case FP_K_OUT_ARR:     fprintf(out, "fp__a%d", i); break;
    case FP_K_LEN:         fprintf(out, "FP_BUF_BYTES"); break;
    default:               fprintf(out, "0"); break;
    }
}

static void fp_emit_probe(FILE *out, const struct fp_candidate *c, size_t idx)
{
    int i;

    /* A marker on its own line. The map from source line back to probe is
     * built by re-reading the finished file for these, which is the only way
     * that stays correct no matter how many lines a probe body turns out to
     * need — and the map has to be exact, because it is what decides which
     * probe a compiler error belongs to. */
    fprintf(out, "/*FPPROBE %zu*/\n", idx);
    fprintf(out, "static void fp_p_%zu(struct fp_acc *fp__h, uint32_t fp__iter,"
                 " unsigned fp__fill, uint64_t fp__salt)\n{\n", idx);
    fprintf(out, "    (void)fp__h; (void)fp__iter; (void)fp__fill;"
                 " (void)fp__salt;\n");
    for (i = 0; i < c->n_params; i++)
        fp_emit_local(out, c, i, c->shape ^ ((uint64_t)i * FP_SEED_STRIDE));

    /* Absorb the WIDTH of every by-reference object before the call. The
     * scan-time shape cannot carry a struct's size — it deliberately does
     * not name the type, so that two identical structs under two names still
     * match — and without the size every `bool eq(const T *, const T *)` in
     * the tree collapses onto one fingerprint no matter what T is. The
     * width is part of the interface, so it belongs in the hash. */
    for (i = 0; i < c->n_params; i++) {
        const struct fp_param *p = &c->param[i];
        if (p->kind == FP_K_OBJ_IN || p->kind == FP_K_OUT_OBJ ||
            p->kind == FP_K_OUT_ARR || p->kind == FP_K_ARR_IN)
            fprintf(out, "    fp_acc_u64(fp__h, %uu, (uint64_t)sizeof"
                         " fp__a%d);\n", (unsigned)(128 + i), i);
    }

    fprintf(out, "    ");
    if (c->ret.kind == FP_K_SCALAR)
        fprintf(out, "%s fp__rv = ", c->ret.type_text);
    else if (c->ret.kind == FP_K_CSTR_OUT)
        fprintf(out, "const char *fp__rv = ");
    fprintf(out, "%s(", c->name);
    for (i = 0; i < c->n_params; i++)
        fp_emit_arg(out, c, i);
    fprintf(out, ");\n");

    if (c->ret.kind == FP_K_SCALAR)
        fprintf(out, "    fp_acc_u64(fp__h, 0u, (uint64_t)fp__rv);\n");
    else if (c->ret.kind == FP_K_CSTR_OUT)
        fprintf(out, "    fp_acc_cstr(fp__h, 0u, fp__rv);\n");

    for (i = 0; i < c->n_params; i++) {
        const struct fp_param *p = &c->param[i];
        if (p->kind == FP_K_OUT_SCALAR || p->kind == FP_K_OUT_OBJ)
            fprintf(out, "    fp_acc_mem(fp__h, %uu, &fp__a%d,"
                         " sizeof fp__a%d);\n", (unsigned)(i + 1), i, i);
        else if (p->kind == FP_K_OUT_ARR)
            fprintf(out, "    fp_acc_mem(fp__h, %uu, fp__a%d,"
                         " sizeof fp__a%d);\n", (unsigned)(i + 1), i, i);
    }
    fprintf(out, "}\n\n");
}

static bool fp_write_reg_header(const char *work_dir, size_t ngroups)
{
    char path[FP_MAX_PATH * 2];
    FILE *out;
    size_t g;

    snprintf(path, sizeof path, "%s/fp_reg.h", work_dir);
    out = fopen(path, "w");
    if (out == NULL)
        return false;
    fprintf(out, "/* GENERATED by lib/fingerprint. Do not edit. */\n");
    fprintf(out, "#ifndef FP_REG_H\n#define FP_REG_H\n");
    fprintf(out, "#include \"fingerprint/fp_runtime.h\"\n");
    fprintf(out, "#include <stdint.h>\n#include <stddef.h>\n");
    fprintf(out, "typedef void (*fp_probe_fn)(struct fp_acc *, uint32_t,"
                 " unsigned, uint64_t);\n");
    fprintf(out, "void fp_register(unsigned idx, const char *id,"
                 " uint64_t shape, fp_probe_fn fn);\n");
    fprintf(out, "#define FP_GROUP_COUNT %zuu\n", ngroups);
    for (g = 0; g < ngroups; g++)
        fprintf(out, "void fp_group_%zu_register(void);\n", g);
    fprintf(out, "#endif\n");
    return fclose(out) == 0;
}

/* Re-read a finished probe TU and write `<probe> <line>` rows for every
 * marker it contains, so a compiler diagnostic on line N can be attributed
 * to the last probe whose marker precedes it. */
static bool fp_write_map(const char *work_dir, size_t group)
{
    char cpath[FP_MAX_PATH * 2];
    char mpath[FP_MAX_PATH * 2];
    FILE *in;
    FILE *map;
    char line[512];
    int lineno = 0;

    snprintf(cpath, sizeof cpath, "%s/fp_probes_%zu.c", work_dir, group);
    snprintf(mpath, sizeof mpath, "%s/fp_probes_%zu.map", work_dir, group);
    in = fopen(cpath, "r");
    if (in == NULL)
        return false;
    map = fopen(mpath, "w");
    if (map == NULL) { fclose(in); return false; }
    while (fgets(line, sizeof line, in) != NULL) {
        unsigned long idx;
        lineno++;
        if (sscanf(line, "/*FPPROBE %lu*/", &idx) == 1)
            fprintf(map, "%lu %d\n", idx, lineno);
    }
    fclose(in);
    return fclose(map) == 0;
}

static bool fp_write_main(const char *work_dir, size_t n_cands, size_t ngroups)
{
    char path[FP_MAX_PATH * 2];
    FILE *out;

    snprintf(path, sizeof path, "%s/fp_main.c", work_dir);
    out = fopen(path, "w");
    if (out == NULL)
        return false;
    fprintf(out,
"/* GENERATED by lib/fingerprint. Do not edit.\n"
" *\n"
" * Each probe runs in its own FORKED CHILD under an alarm. A probe that\n"
" * segfaults on a pattern-filled input, corrupts memory through a wild\n"
" * pointer, or never returns therefore costs exactly one result line and\n"
" * cannot reach any other probe's fingerprint. Isolation is not a nicety\n"
" * here: without it a single bad candidate silently poisons the run. */\n"
"#include \"fp_reg.h\"\n"
"#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n"
"#include <unistd.h>\n#include <signal.h>\n#include <sys/wait.h>\n\n"
"#define FP_MAX_PROBES %zuu\n"
"#define FP_MAX_JOBS 256u\n\n"
"struct fp_slot { const char *id; uint64_t shape; fp_probe_fn fn; };\n"
"struct fp_kid { pid_t pid; int fd; unsigned idx; };\n"
"static struct fp_slot g_slot[FP_MAX_PROBES];\n"
"/* Empty means \"every probe\". --only=<file> narrows the run to the listed\n"
" * probe indices, which is what makes the confirmation corpus affordable:\n"
" * it is 32x the size of the first one, and it is only ever CONSULTED for\n"
" * candidates that landed in a match group. Running it over everything else\n"
" * computes hashes nothing reads. */\n"
"static unsigned char g_only[FP_MAX_PROBES];\n"
"static int g_only_set;\n\n", n_cands ? n_cands : 1u);
    fprintf(out,
"void fp_register(unsigned idx, const char *id, uint64_t shape, fp_probe_fn fn)\n"
"{\n"
"    if (idx >= FP_MAX_PROBES) return;\n"
"    g_slot[idx].id = id; g_slot[idx].shape = shape; g_slot[idx].fn = fn;\n"
"}\n\n"
"struct fp_result { uint64_t h1, h2; uint32_t distinct; };\n\n"
"static void fp_run_one(const struct fp_slot *s, unsigned fill, uint64_t salt,\n"
"                       uint32_t iters, struct fp_result *r)\n"
"{\n"
"    struct fp_acc acc;\n"
"    uint64_t seen[128];\n"
"    uint32_t nseen = 0;\n"
"    uint32_t k;\n"
"    fp_acc_init(&acc, s->shape);\n"
"    for (k = 0; k < iters; k++) {\n"
"        uint32_t j;\n"
"        /* Reset to a value that does NOT depend on the iteration, so\n"
"         * acc.cur ends the iteration as a digest of what the function\n"
"         * OUTPUT and nothing else. Folding k in here would make every\n"
"         * iteration trivially distinct and the distinct count would\n"
"         * measure the corpus rather than the function. */\n"
"        acc.cur = 0x9E3779B97F4A7C15ull;\n"
"        s->fn(&acc, k, fill, salt);\n"
"        for (j = 0; j < nseen; j++) if (seen[j] == acc.cur) break;\n"
"        if (j == nseen && nseen < 128u) seen[nseen++] = acc.cur;\n"
"    }\n"
"    r->h1 = acc.h1; r->h2 = acc.h2; r->distinct = nseen;\n"
"}\n\n"
"/* Results go to --out=<file>, NEVER to stdout. A probe TU is compiled\n"
" * against a whole tree unit, so anything that unit's file-scope\n"
" * initialisers or a wrongly-accepted callee prints lands on this process's\n"
" * stdout and stderr. Sharing a stream with the result rows would let one\n"
" * such line be parsed as a result and silently overwrite an unrelated\n"
" * probe's verdict: a log line beginning with a year parses as one. The\n"
" * streams are separated so that noise stays legible AS noise. */\n"
"int main(int argc, char **argv)\n"
"{\n"
"    unsigned fill = 0u;\n"
"    uint64_t salt = 0ull;\n"
"    uint32_t iters = FP_ITERATIONS;\n"
"    unsigned timeout = 5u;\n"
"    unsigned jobs = 1u;\n"
"    unsigned i;\n"
"    FILE *res_out = stdout;\n"
"    for (i = 1; i < (unsigned)argc; i++) {\n"
"        if (strncmp(argv[i], \"--fill=\", 7) == 0)\n"
"            fill = (unsigned)strtoul(argv[i] + 7, NULL, 0);\n"
"        else if (strncmp(argv[i], \"--salt=\", 7) == 0)\n"
"            salt = strtoull(argv[i] + 7, NULL, 0);\n"
"        else if (strncmp(argv[i], \"--iters=\", 8) == 0)\n"
"            iters = (uint32_t)strtoul(argv[i] + 8, NULL, 0);\n"
"        else if (strncmp(argv[i], \"--timeout=\", 10) == 0)\n"
"            timeout = (unsigned)strtoul(argv[i] + 10, NULL, 0);\n"
"        else if (strncmp(argv[i], \"--jobs=\", 7) == 0)\n"
"            jobs = (unsigned)strtoul(argv[i] + 7, NULL, 0);\n"
"        else if (strncmp(argv[i], \"--only=\", 7) == 0) {\n"
"            FILE *sel = fopen(argv[i] + 7, \"r\");\n"
"            unsigned long w;\n"
"            if (sel == NULL) return 2;\n"
"            g_only_set = 1;\n"
"            while (fscanf(sel, \"%%lu\", &w) == 1)\n"
"                if (w < FP_MAX_PROBES) g_only[w] = 1u;\n"
"            fclose(sel);\n"
"        }\n"
"        else if (strncmp(argv[i], \"--out=\", 6) == 0) {\n"
"            res_out = fopen(argv[i] + 6, \"w\");\n"
"            if (res_out == NULL) return 2;\n"
"        }\n"
"    }\n"
"    if (jobs < 1u) jobs = 1u;\n"
"    if (jobs > FP_MAX_JOBS) jobs = FP_MAX_JOBS;\n");
    {
        size_t g;
        for (g = 0; g < ngroups; g++)
            fprintf(out, "    fp_group_%zu_register();\n", g);
    }
    fprintf(out,
"    /* Probes run JOBS at a time. One at a time is not a safety property —\n"
"     * the isolation comes from each probe having its own process, not from\n"
"     * there being one of them — and it costs an hour per configuration on\n"
"     * a tree this size, times five configurations plus the confirmation\n"
"     * corpus. A batch is forked, then reaped in order. Nothing is shared\n"
"     * between children, each result is 24 bytes and so is written to its\n"
"     * own pipe in one unblockable go, and a child that crashes or is\n"
"     * alarmed out is still exactly one lost result. */\n"
"    for (i = 0; i < FP_MAX_PROBES; ) {\n"
"        struct fp_kid kid[FP_MAX_JOBS];\n"
"        unsigned n = 0;\n"
"        unsigned k;\n"
"        while (i < FP_MAX_PROBES && n < jobs) {\n"
"            int fds[2];\n"
"            pid_t pid;\n"
"            if (g_slot[i].fn == NULL || (g_only_set && !g_only[i])) {\n"
"                fprintf(res_out, \"%%u SKIP\\n\", i); i++; continue;\n"
"            }\n"
"            if (pipe(fds) != 0) {\n"
"                fprintf(res_out, \"%%u ERR\\n\", i); i++; continue;\n"
"            }\n"
"            /* Empty the result buffer BEFORE forking. A child inherits the\n"
"             * buffer's contents, and any path that flushed it there would\n"
"             * duplicate every row written so far. */\n"
"            fflush(res_out);\n"
"            pid = fork();\n"
"            if (pid < 0) {\n"
"                close(fds[0]); close(fds[1]);\n"
"                fprintf(res_out, \"%%u ERR\\n\", i); i++; continue;\n"
"            }\n"
"            if (pid == 0) {\n"
"                struct fp_result res;\n"
"                close(fds[0]);\n"
"                alarm(timeout);\n"
"                memset(&res, 0, sizeof res);\n"
"                fp_run_one(&g_slot[i], fill, salt, iters, &res);\n"
"                if (write(fds[1], &res, sizeof res) != (ssize_t)sizeof res)\n"
"                    _exit(3);\n"
"                _exit(0);\n"
"            }\n"
"            close(fds[1]);\n"
"            kid[n].pid = pid; kid[n].fd = fds[0]; kid[n].idx = i;\n"
"            n++; i++;\n"
"        }\n");
    fprintf(out,
"        for (k = 0; k < n; k++) {\n"
"            struct fp_result res;\n"
"            int status = 0;\n"
"            ssize_t got;\n"
"            memset(&res, 0, sizeof res);\n"
"            got = read(kid[k].fd, &res, sizeof res);\n"
"            close(kid[k].fd);\n"
"            while (waitpid(kid[k].pid, &status, 0) < 0) { }\n"
"            if (got != (ssize_t)sizeof res || !WIFEXITED(status) ||\n"
"                WEXITSTATUS(status) != 0) {\n"
"                fprintf(res_out, \"%%u %%s %%s\\n\", kid[k].idx,\n"
"                       (WIFSIGNALED(status) && WTERMSIG(status) == SIGALRM)\n"
"                           ? \"TIMEOUT\" : \"CRASH\", g_slot[kid[k].idx].id);\n"
"                continue;\n"
"            }\n"
"            fprintf(res_out, \"%%u OK %%016llx%%016llx %%u %%s\\n\","
" kid[k].idx,\n"
"                   (unsigned long long)res.h1, (unsigned long long)res.h2,\n"
"                   res.distinct, g_slot[kid[k].idx].id);\n"
"        }\n"
"    }\n"
"    if (res_out != stdout && fclose(res_out) != 0)\n"
"        return 2;\n"
"    return 0;\n"
"}\n");
    return fclose(out) == 0;
}

bool fp_emit_harness(const struct fp_candidate *cands, size_t n_cands,
                     const char *work_dir, const unsigned char *disabled,
                     size_t *groups_out)
{
    size_t i = 0;
    size_t g = 0;

    while (i < n_cands) {
        size_t start = i;
        char path[FP_MAX_PATH * 2];
        FILE *out;
        size_t k;

        while (i < n_cands && strcmp(cands[i].include, cands[start].include) == 0)
            i++;

        snprintf(path, sizeof path, "%s/fp_probes_%zu.c", work_dir, g);
        out = fopen(path, "w");
        if (out == NULL)
            return false;
        {
            /* A group with nothing left in it must still compile and still
             * define its registration function, or the driver will not link
             * at all. Dropping the project header is what makes an
             * emptied-out group harmless: the header is often the very thing
             * that could not be compiled (a package outside this build's
             * include path), so keeping it would fail forever. */
            bool alive = false;
            bool via_source = cands[start].via_source;
            for (k = start; k < i; k++)
                if (disabled == NULL || !disabled[k]) { alive = true; break; }
            fprintf(out, "/* GENERATED by lib/fingerprint. Do not edit. */\n");
            /* A source-included unit goes FIRST, ahead of even <stdint.h>.
             * A translation unit is allowed to define its own feature macros
             * (_GNU_SOURCE, _POSIX_C_SOURCE) before its first include, and
             * putting anything in front of it would silently compile it
             * against a different libc surface than the tree builds it with.
             * The probe scaffolding is happy to come second; the unit is
             * not. */
            if (alive && via_source)
                fprintf(out, "#include \"%s\"\n", cands[start].include);
            fprintf(out, "#include <stdint.h>\n#include <stddef.h>\n"
                         "#include <stdbool.h>\n#include <string.h>\n"
                         "#include <limits.h>\n");
            if (alive && !via_source)
                fprintf(out, "#include \"%s\"\n", cands[start].include);
            else if (!alive)
                fprintf(out, "/* group empty: %s */\n", cands[start].include);
            fprintf(out, "#include \"fp_reg.h\"\n\n");
        }
        for (k = start; k < i; k++) {
            if (disabled != NULL && disabled[k])
                continue;
            fp_emit_probe(out, &cands[k], k);
        }
        fprintf(out, "void fp_group_%zu_register(void)\n{\n", g);
        for (k = start; k < i; k++) {
            if (disabled != NULL && disabled[k])
                continue;
            fprintf(out, "    fp_register(%zuu, \"%s|%s:%d|%s\", %lluull,"
                         " fp_p_%zu);\n",
                    k, cands[k].name, cands[k].def_path, cands[k].def_line,
                    cands[k].shape_text, (unsigned long long)cands[k].shape, k);
        }
        fprintf(out, "}\n");
        if (fclose(out) != 0)
            return false;
        if (!fp_write_map(work_dir, g))
            return false;
        g++;
    }
    if (!fp_write_reg_header(work_dir, g))
        return false;
    if (!fp_write_main(work_dir, n_cands, g))
        return false;
    if (groups_out != NULL)
        *groups_out = g;
    return true;
}
