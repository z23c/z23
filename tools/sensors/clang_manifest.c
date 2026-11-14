/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Optional libclang semantic sensor: emit, root and diff canonical semantic manifests of one C23 TU.
 *
 * This is an EXTERNAL, optional tool. It links libclang and is built only by
 * `make clang-manifest` when libclang is present; it is never linked into
 * z23, z23-dev or core. Z23 consumes only the manifest bytes it writes,
 * through contexts/commons/modules/vcs/src/semantic_manifest.c, which has no
 * compiler dependency. Format: docs/work/SEMANTIC_MANIFEST.md. It is the
 * only facts producer; it hands every observation to the compiler-API-free
 * core, clang_manifest_core.h.
 *
 *   z23-clang-manifest emit --root DIR --source FILE --out FILE [--cc CC]
 *                           [--toolchain-id HEX] [--facts] [--tree HEX]
 *                           [--max-records N] [--max-section-bytes N]
 *                           -- ARGV...
 *   z23-clang-manifest session [--verify-cold] [--no-warm] [--max-tus N]
 *   z23-clang-manifest object-cc --root DIR --cc CC [--toolchain-id HEX]
 *   z23-clang-manifest root FILE
 *   z23-clang-manifest dump FILE
 *   z23-clang-manifest diff OLD NEW
 *
 * --cc names the compiler that builds the TU's object (a path, or a name
 * looked up on PATH, resolved through a compile-cache masquerade) and
 * --toolchain-id the build's toolchain identity (Make's BUILD_COMPILER_ID).
 * IDENTITY records the compiler by realpath, content hash and loaded shared
 * objects, and the toolchain identity, so a compiler change is identity
 * drift; without both IDENTITY says "object-cc unknown". ARGV is the
 * object's own compile argv after the compiler word. `object-cc` prints
 * the text IDENTITY would record, for a build rule to re-sense on change.
 */
/* realpath() is declared only under _DEFAULT_SOURCE on glibc without the
 * fortify inline; set it before the first header pulls in <features.h>. */
#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif

#include "clang_manifest.h"

#include "base/safe_alloc.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* Appended to the caller's argv for the parse only (never to the identity):
 * -v makes the front end print its exact include search list; the two
 * warning flags keep gcc-only warning options and -Werror from turning a
 * semantic parse into a refusal (real errors still refuse); and
 * --no-default-config keeps a clang config file beside the library or in
 * a user config dir from adding flags the argv never names. */
static const char *const k_cm_suffix[] = {"-v", "-Wno-unknown-warning-option",
                                          "-Wno-error", "--no-default-config"};
#define CM_SUFFIX_N (sizeof(k_cm_suffix) / sizeof(k_cm_suffix[0]))
#if defined(CM_HOST_RESOURCE_DIR)
static const char k_cm_resource_arg[] = "-resource-dir=" CM_HOST_RESOURCE_DIR;
#endif

char *cm_take_string(CXString s)
{
    const char *cs = clang_getCString(s);
    char *out = cm_strdup(cs != NULL ? cs : "");
    clang_disposeString(s);
    return out;
}

/* ---- argv --------------------------------------------------------------------- */

/* A plain declaration reports CXLanguage_C under C++ and Objective-C too, so
 * the argv check is the language guard (the lexing probe, cm_measure_lang,
 * checks it again from the front end's side). Driver aliases of -x and
 * -std, the Objective-C switches and a driver mode (clang++ parses .c as
 * C++) are refused with the escapes rather than modeled. So is every
 * pass-through the lookup scan cannot read a -D, -std or
 * -fms-compatibility inside: the whole -X family but -Xlinker, in any
 * spelling (-Xclang, -Xclang=, -Xpreprocessor, -Xarch_host, -Xcompiler and
 * -Xparser each reach the front end; the others are refused with them
 * rather than sorted), -Wp, and front-end plugins. */
static bool cm_indirect_mode_arg(const char *a)
{
    static const char *const exact[] = {"-ObjC", "-ObjC++"};
    static const char *const prefix[] = {
        "@", "-X", "--X", "-Wp,", "--Wp,", "-cc1", "--config", "-config",
        "--language", "--std", "--driver-mode", "-fplugin", "-fpass-plugin",
        "-load"};
    for (size_t k = 0; k < sizeof(exact) / sizeof(exact[0]); k++)
        if (strcmp(a, exact[k]) == 0)
            return true;
    for (size_t k = 0; k < sizeof(prefix) / sizeof(prefix[0]); k++)
        if (strncmp(a, prefix[k], strlen(prefix[k])) == 0)
            return true;
    return false;
}

/* Why one argv word refuses the TU, or NULL. */
static const char *cm_refused_flag(const char *a)
{
    if (cm_indirect_mode_arg(a))
        return "indirect compiler options";
    if (strncmp(a, "-fms-compatibility", 18) == 0)
        return "MSVC compatibility";
    if (strcmp(a, "-std") == 0)
        return "-std has no joined value";
    return NULL;
}

/* -Xlinker is the one pass-through let through: clang hands its value to
 * the linker alone (never the front end), so the value is skipped here
 * as clang skips it, and no word of it is read as a flag. */
static bool cm_scan_language_flags(struct cm_core *c,
                                   const char *const *argv, size_t argc,
                                   const char **mode, const char **standard)
{
    for (size_t k = 0; k < argc; k++) {
        const char *a = argv[k], *why;
        if (strcmp(a, "-Xlinker") == 0) {
            k++;
            continue;
        }
        why = cm_refused_flag(a);
        if (why != NULL)
            return cm_fail(c, "unsupported translation-unit language: %s", why);
        if (strcmp(a, "-ansi") == 0)
            *standard = "c89";
        else if (strncmp(a, "-std=", 5) == 0)
            *standard = a + 5;
        if (strcmp(a, "-x") == 0) {
            if (++k == argc)
                return cm_fail(c, "unsupported translation-unit language: -x has no value");
            *mode = argv[k];
        } else if (strncmp(a, "-x", 2) == 0 && a[2] != '\0') {
            *mode = a + 2;
        }
    }
    return true;
}

/* The AST walk describes C. Infer the mode from the exact argv that libclang
 * will receive. A response file, driver config, or cc1 escape could change
 * that argv unseen, so none can produce a manifest. The last -x selects the
 * mode of the separately supplied source; -x none restores its suffix. */
static bool cm_c_language_mode(struct cm_core *c, const char *source,
                               const char *const *argv, size_t argc)
{
    const char *mode = NULL, *standard = "default";
    const char *suffix = strrchr(source, '.');
    if (getenv("CCC_OVERRIDE_OPTIONS") != NULL ||
        getenv("CLANG_CONFIG_FILE") != NULL)
        return cm_fail(c, "unsupported translation-unit language: indirect compiler options");
    if (!cm_scan_language_flags(c, argv, argc, &mode, &standard))
        return false;
    if (mode != NULL && strcmp(mode, "c") != 0 && strcmp(mode, "none") != 0)
        return cm_fail(c, "unsupported translation-unit language: -x %s", mode);
    if ((mode == NULL || strcmp(mode, "none") == 0) &&
        (suffix == NULL || strcmp(suffix, ".c") != 0))
        return cm_fail(c, "unsupported translation-unit language: %s", source);
#if defined(__APPLE__)
    int n = snprintf(c->producer_grammar, sizeof(c->producer_grammar),
                     "%s|c|std=%s", CM_TYPE_GRAMMAR, standard);
    if (n < 0 || n > 64 || (size_t)n >= sizeof(c->producer_grammar))
        return cm_fail(c, "unsupported translation-unit language: standard mode too long");
    c->type_grammar = c->producer_grammar;
#endif
    return true;
}

#if defined(CM_HOST_RESOURCE_DIR)
static bool cm_has_resource_arg(const char *const *argv, size_t argc)
{
    for (size_t k = 0; k < argc; k++)
        if (strcmp(argv[k], "-resource-dir") == 0 ||
            strncmp(argv[k], "-resource-dir=", 14) == 0)
            return true;
    return false;
}
#endif

static bool cm_filter_args(struct cm_state *st, char **argv, int argc,
                           const char *source, struct cm_args *out)
{
    struct cm_core *c = &st->core;
    out->parse = zcl_calloc((size_t)argc + CM_SUFFIX_N + 2, sizeof(char *),
                            "clang_manifest.parse_args");
    out->identity = zcl_calloc((size_t)argc + 1, sizeof(char *),
                               "clang_manifest.identity_args");
    if (out->parse == NULL || out->identity == NULL)
        return cm_fail(c, "out of memory");
    for (int k = 0; k < argc; k++) {
        int drop = cm_output_arg(argv[k]);
        if (drop == 2) {
            k++;
            continue;
        }
        if (drop == 1 || strcmp(argv[k], source) == 0)
            continue;
        out->parse[out->nparse++] = argv[k];
        if (!cm_norm_arg(c, argv[k], &out->identity[out->nidentity++]))
            return false;
    }
    if (!cm_c_language_mode(c, source, out->parse, out->nparse))
        return false;
    for (size_t k = 0; k < CM_SUFFIX_N; k++)
        out->parse[out->nparse++] = k_cm_suffix[k];
#if defined(CM_HOST_RESOURCE_DIR)
    if (!cm_has_resource_arg(out->parse, out->nparse))
        out->parse[out->nparse++] = k_cm_resource_arg;
#endif
    return true;
}

/* ---- parse with the front end's -v report captured ------------------------- */

/* Run the front end's parse with its stderr captured into *report. */
static bool cm_parse(struct cm_state *st, const struct cm_opts *o,
                     const struct cm_front *front, const struct cm_args *args,
                     const char *capture_path, char **report)
{
    int saved = dup(2);
    int fd = open(capture_path, O_CREAT | O_TRUNC | O_RDWR, 0600);
    bool parsed;
    size_t len = 0;
    if (saved < 0 || fd < 0 || dup2(fd, 2) < 0) {
        if (saved >= 0)
            (void)close(saved);
        if (fd >= 0)
            (void)close(fd);
        return cm_fail(&st->core, "cannot capture the front end report: %s",
                       strerror(errno));
    }
    parsed = front->parse(st, o, args, front->ctx);
    (void)fflush(stderr);
    (void)dup2(saved, 2);
    (void)close(saved);
    (void)close(fd);
    if (!cm_read_file(capture_path, (uint8_t **)report, &len))
        *report = NULL;
    (void)unlink(capture_path);
    if (!parsed)
        return false;
    return *report != NULL || cm_fail(&st->core, "front end report unreadable");
}

/* The cold front end: a fresh index and a plain parse, disposed with the
 * emit. Every manifest the tree accepts is, or is byte-identical to, this. */
static bool cm_cold_parse(struct cm_state *st, const struct cm_opts *o,
                          const struct cm_args *args, void *ctx)
{
    enum CXErrorCode rc;
    (void)ctx;
    st->index = clang_createIndex(0, 0);
    if (st->index == NULL)
        return cm_fail(&st->core, "cannot create index");
    rc = clang_parseTranslationUnit2(
        st->index, o->source, args->parse, (int)args->nparse, NULL, 0,
        CXTranslationUnit_DetailedPreprocessingRecord, &st->tu);
    if (rc != CXError_Success || st->tu == NULL)
        return cm_fail(&st->core, "libclang parse failed (code %d)", (int)rc);
    return true;
}

const struct cm_front cm_cold_front = {.parse = cm_cold_parse,
                                       .owns_tu = true};

static bool cm_check_diagnostics(struct cm_state *st)
{
    unsigned n = clang_getNumDiagnostics(st->tu), errors = 0;
    for (unsigned k = 0; k < n; k++) {
        CXDiagnostic d = clang_getDiagnostic(st->tu, k);
        if (clang_getDiagnosticSeverity(d) >= CXDiagnostic_Error) {
            CXString s = clang_formatDiagnostic(
                d, clang_defaultDiagnosticDisplayOptions());
            if (errors < 8)
                fprintf(stderr, "clang-manifest: %s\n", clang_getCString(s));
            clang_disposeString(s);
            errors++;
        }
        clang_disposeDiagnostic(d);
    }
    if (errors > 0)
        return cm_fail(&st->core,
                       "%u front end error(s); no manifest for a TU that does not parse",
                       errors);
    return true;
}

/* ---- files --------------------------------------------------------------------- */

static bool cm_file_real(struct cm_state *st, CXFile f, char out[PATH_MAX])
{
    char *real = cm_take_string(clang_File_tryGetRealPathName(f));
    if (real != NULL && real[0] == '/') {
        if (realpath(real, out) == NULL)
            (void)snprintf(out, PATH_MAX, "%s", real);
        free(real);
        return true;
    }
    free(real);
    {
        char *name = cm_take_string(clang_getFileName(f));
        bool ok = name != NULL && cm_absolute(&st->core, name, out);
        free(name);
        return ok || cm_fail(&st->core, "cannot resolve an included file name");
    }
}

static void cm_inclusion(CXFile f, CXSourceLocation *stack, unsigned depth,
                         CXClientData data)
{
    struct cm_state *st = data;
    char real[PATH_MAX];
    char *opened;
    const char *contents;
    size_t size = 0;
    (void)depth;
    (void)stack;
    if (st->core.failed)
        return;
    for (size_t k = 0; k < st->core.nfiles; k++) {
        if (clang_File_isEqual((CXFile)st->core.files[k].key, f))
            return;
    }
    if (!cm_file_real(st, f, real))
        return;
    opened = cm_take_string(clang_getFileName(f));
    contents = clang_getFileContents(st->tu, f, &size);
    if (opened == NULL) {
        (void)cm_fail(&st->core, "out of memory");
        return;
    }
    (void)cm_file_add(&st->core, f, real, opened,
                      clang_File_isEqual(f, st->main_file) != 0, contents,
                      size);
    free(opened);
}

/* A file reached by an inclusion directive that clang_getInclusions did not
 * report. With a precompiled preamble, libclang 20 skips a file included
 * after the preamble (hotswap_loader.c's mid-file <dlfcn.h> is one), so the
 * table is closed over every file's own directives. Without a preamble
 * every such file was already reported and this adds nothing. */
static enum CXVisitorResult cm_include_visit(void *ctx, CXCursor c,
                                             CXSourceRange range)
{
    struct cm_state *st = ctx;
    CXFile inc = clang_getIncludedFile(c);
    (void)range;
    if (inc != NULL && cm_file_of(st, inc) == NULL)
        cm_inclusion(inc, NULL, 1, st);
    return st->core.failed ? CXVisit_Break : CXVisit_Continue;
}

static bool cm_include_closure(struct cm_state *st)
{
    CXCursorAndRangeVisitor v = {.context = st, .visit = cm_include_visit};
    for (size_t k = 0; k < st->core.nfiles && !st->core.failed; k++)
        (void)clang_findIncludesInFile(st->tu, (CXFile)st->core.files[k].key,
                                       v);
    return !st->core.failed;
}

const struct cm_file *cm_file_of(struct cm_state *st, CXFile f)
{
    const struct cm_file *hit = cm_file_by_key(&st->core, f);
    if (hit != NULL || f == NULL)
        return hit;
    for (size_t k = 0; k < st->core.nfiles; k++) {
        if (clang_File_isEqual((CXFile)st->core.files[k].key, f)) {
            st->core.file_hint = k;
            return &st->core.files[k];
        }
    }
    return NULL;
}

const struct cm_file *cm_cursor_file(struct cm_state *st, CXCursor c,
                                     unsigned *line, unsigned *offset)
{
    CXFile f = NULL;
    unsigned l = 0, col = 0, off = 0;
    clang_getExpansionLocation(clang_getCursorLocation(c), &f, &l, &col, &off);
    if (line != NULL)
        *line = l;
    if (offset != NULL)
        *offset = off;
    return cm_file_of(st, f);
}

/* ---- the front end's own printed search list (-v) --------------------------- */

static const char k_cm_framework[] = " (framework directory)";

static bool cm_line_is(const char *line, size_t len, const char *lit)
{
    return strlen(lit) == len && memcmp(line, lit, len) == 0;
}

static bool cm_search_line(struct cm_core *c, const char *line, size_t len,
                           int *mode)
{
    static const char ign[] = "ignoring nonexistent directory \"";
    if (len >= sizeof(ign) - 1 && memcmp(line, ign, sizeof(ign) - 1) == 0) {
        const char *s = line + sizeof(ign) - 1;
        const char *q = memchr(s, '"', len - (size_t)(s - line));
        return q == NULL || cm_push_dir(c, &c->ignored, s, (size_t)(q - s));
    }
    if (cm_line_is(line, len, "#include \"...\" search starts here:"))
        *mode = 1;
    else if (cm_line_is(line, len, "#include <...> search starts here:"))
        *mode = 2;
    else if (cm_line_is(line, len, "End of search list."))
        *mode = 0;
    else if (*mode != 0 && len > 1 && line[0] == ' ') {
        size_t fl = sizeof(k_cm_framework) - 1;
        if (len > fl && memcmp(line + len - fl, k_cm_framework, fl) == 0)
            len -= fl;
        return cm_push_dir(c, *mode == 1 ? &c->quote : &c->angled, line + 1,
                           len - 1);
    }
    return true;
}

/* The last search-list block of the report. A cold parse prints one. A warm
 * parse that also built a preamble prints one per front-end instance, each
 * the whole list as that instance derived it; the last is the parse whose
 * AST is extracted. With a single block this is the whole text. */
static const char *cm_last_search_block(const char *text)
{
    static const char end[] = "End of search list.";
    const char *last = NULL, *prev = NULL;
    for (const char *p = strstr(text, end); p != NULL;
         p = strstr(p + sizeof(end) - 1, end)) {
        prev = last;
        last = p;
    }
    return prev != NULL ? prev + sizeof(end) - 1 : text;
}

static bool cm_parse_search_list(struct cm_core *c, const char *report)
{
    int mode = 0;
    bool saw_end = false;
    const char *text = cm_last_search_block(report);
    for (const char *p = text; *p != '\0';) {
        const char *nl = strchr(p, '\n');
        size_t len = nl != NULL ? (size_t)(nl - p) : strlen(p);
        if (len > 0 && p[len - 1] == '\r')
            len--;
        saw_end = saw_end || cm_line_is(p, len, "End of search list.");
        if (!cm_search_line(c, p, len, &mode))
            return false;
        p = nl != NULL ? nl + 1 : p + len;
    }
    if (!saw_end || c->angled.n == 0)
        return cm_fail(c, "front end printed no include search list");
    cm_find_resource_dir(c);
    return true;
}

/* ---- emit ------------------------------------------------------------------------- */

static bool cm_emit_identity_libclang(struct cm_state *st, const char *main_path,
                                      const struct cm_args *args)
{
    CXTargetInfo ti = clang_getTranslationUnitTargetInfo(st->tu);
    char *version = cm_take_string(clang_getClangVersion());
    char *triple = cm_take_string(clang_TargetInfo_getTriple(ti));
    struct cm_identity id = {.compiler = version, .triple = triple,
                             .main_path = main_path, .argv = args->identity,
                             .argc = args->nidentity};
    bool ok;
    clang_TargetInfo_dispose(ti);
    ok = version != NULL && triple != NULL && cm_emit_identity(&st->core, &id);
    free(version);
    free(triple);
    return ok;
}

/* An MSVC target turns MSVC compatibility on, which turns trigraphs off;
 * the lookup scan splices ??/ by the C rules, so such a TU is refused. */
static bool cm_refuse_msvc_target(struct cm_state *st)
{
    CXTargetInfo ti = clang_getTranslationUnitTargetInfo(st->tu);
    char *triple = cm_take_string(clang_TargetInfo_getTriple(ti));
    bool msvc = triple == NULL || strstr(triple, "msvc") != NULL;
    clang_TargetInfo_dispose(ti);
    free(triple);
    if (msvc)
        return cm_fail(&st->core, "unsupported translation-unit language: MSVC target");
    return true;
}

/* ---- the TU's lexing rules, as the front end applies them ------------------- */

/* A probe parsed under the TU's own argv: each array's size says one rule
 * the front end applies, measured by how it lexes or types the text, never
 * by a macro (-D, -U or an -include file can make any macro lie):
 * sizeof("??=") is 2 when trigraphs are replaced (the token walk and the
 * scan's splice both need that; comments and literals are clang's own
 * lexing, clang_manifest_tokens.c); sizeof('a') is 1 in C++ (a char), and more
 * in C (an int); in Objective-C "id" is a builtin type, so the typedef
 * fails and the probe with it. The #undef lines drop any macro the argv or
 * an -include file gave the probe's own words. Reading these rules from
 * argv instead would trust a model of every option's arity: "-I -std=c17"
 * or "-Xlinker -std=c17" names no -std at all. */
#define CM_LANG_PROBE "clang-manifest-lang-probe.c"
static const char k_cm_lang_probe[] =
    "#undef cm_lang_trigraphs\n"
    "#undef cm_lang_foreign\n#undef extern\n"
    "#undef const\n#undef char\n#undef sizeof\n#undef typedef\n"
    "#undef int\n#undef id\n"
    "extern const char cm_lang_trigraphs[sizeof(\"?\?=\")];\n"
    "extern const char cm_lang_foreign[sizeof('a')];\n"
    "typedef int id;\n";

struct cm_lang_seen {
    long long trigraphs, foreign;
};

static enum CXChildVisitResult cm_lang_visit(CXCursor cur, CXCursor parent,
                                             CXClientData data)
{
    struct cm_lang_seen *s = data;
    CXString n;
    const char *name;
    long long size;
    (void)parent;
    if (clang_getCursorKind(cur) != CXCursor_VarDecl)
        return CXChildVisit_Continue;
    n = clang_getCursorSpelling(cur);
    name = clang_getCString(n);
    size = clang_getArraySize(clang_getCursorType(cur));
    if (name != NULL && strcmp(name, "cm_lang_trigraphs") == 0)
        s->trigraphs = size;
    else if (name != NULL && strcmp(name, "cm_lang_foreign") == 0)
        s->foreign = size;
    clang_disposeString(n);
    return CXChildVisit_Continue;
}

static unsigned cm_error_count(CXTranslationUnit tu)
{
    unsigned n = clang_getNumDiagnostics(tu), errors = 0;
    for (unsigned k = 0; k < n; k++) {
        CXDiagnostic d = clang_getDiagnostic(tu, k);
        errors += clang_getDiagnosticSeverity(d) >= CXDiagnostic_Error;
        clang_disposeDiagnostic(d);
    }
    return errors;
}

/* Parse the probe with the TU's argv (without the -v suffix, and with -w so
 * no warning option can turn it into an error, and no default config
 * file adds to it) and read its sizes. */
static bool cm_measure_lang(struct cm_state *st, const struct cm_args *args,
                            struct cm_lang *lang)
{
    struct cm_core *c = &st->core;
    struct CXUnsavedFile f = {.Filename = CM_LANG_PROBE,
                              .Contents = k_cm_lang_probe,
                              .Length = sizeof(k_cm_lang_probe) - 1};
    struct cm_lang_seen seen = {0};
    size_t n = args->nparse >= CM_SUFFIX_N ? args->nparse - CM_SUFFIX_N : 0;
    const char **argv = zcl_calloc(n + 3, sizeof(char *), "clang_manifest.lang");
    CXTranslationUnit tu = NULL;
    enum CXErrorCode rc;
    unsigned errors = 1;
    if (argv == NULL)
        return cm_fail(c, "out of memory");
    memcpy(argv, args->parse, n * sizeof(char *));
    argv[n] = "--no-default-config";
    argv[n + 1] = "-w";
    rc = clang_parseTranslationUnit2(st->index, CM_LANG_PROBE, argv,
                                     (int)n + 2, &f, 1, CXTranslationUnit_None,
                                     &tu);
    free(argv);
    if (rc == CXError_Success && tu != NULL) {
        errors = cm_error_count(tu);
        clang_visitChildren(clang_getTranslationUnitCursor(tu), cm_lang_visit,
                            &seen);
        clang_disposeTranslationUnit(tu);
    }
    if (errors != 0 || seen.foreign <= 1 ||
        (seen.trigraphs != 2 && seen.trigraphs != 4))
        return cm_fail(c, "unsupported translation-unit language: the front end's lexing probe failed");
    lang->trigraphs = seen.trigraphs == 2;
    return true;
}

/* The TU's lexing rule, its AST walk, clang's lexing of every file it
 * read, then the conditional-lookup scan over those tokens. */
static bool cm_walk_and_scan(struct cm_state *st, const struct cm_args *args)
{
    struct cm_lang lang = {0};
    return cm_measure_lang(st, args, &lang) && cm_walk(st) &&
           cm_tokenize_files(st, lang.trigraphs) &&
           cm_scan_has_include(&st->core, args->parse, args->nparse, lang);
}

static bool cm_extract(struct cm_state *st, const struct cm_opts *o,
                       const char *main_path, const struct cm_args *args,
                       const char *report)
{
    struct cm_core *c = &st->core;
#if CM_TYPE_PRETTY_PRINTED
    st->policy = clang_getCursorPrintingPolicy(
        clang_getTranslationUnitCursor(st->tu));
    clang_PrintingPolicy_setProperty(st->policy,
                                     CXPrintingPolicy_AnonymousTagLocations, 0);
#endif
    if (!cm_refuse_msvc_target(st) || !cm_check_diagnostics(st))
        return false;
    st->main_file = clang_getFile(st->tu, o->source);
    if (st->main_file == NULL)
        return cm_fail(c, "the front end has no main file %s", o->source);
    clang_getInclusions(st->tu, cm_inclusion, st);
    if (!c->failed)
        (void)cm_include_closure(st);
    if (c->failed || !cm_parse_search_list(c, report))
        return false;
    if (o->facts && !cm_facts_begin(c, o->tree))
        return false;
    return cm_walk_and_scan(st, args) && cm_emit_files(c) &&
           cm_emit_deferred(c) &&
           cm_emit_identity_libclang(st, main_path, args) &&
           cm_emit_facts(c, o->max_records, o->max_section_bytes);
}

static bool cm_emit_parse(struct cm_state *st, const struct cm_opts *o,
                          const struct cm_front *front, const char *main_path,
                          struct cm_args *args, const char *capture,
                          char **report)
{
    st->core.type_grammar = CM_TYPE_GRAMMAR;
    if (!cm_filter_args(st, o->argv, o->argc, o->source, args))
        return false;
#if defined(__APPLE__)
    uint8_t producer_after[32];
    if (o->facts &&
        !cm_producer_digest(st->core.type_grammar,
                            st->core.producer_before))
        return cm_fail(&st->core, "darwin producer image identity unavailable");
    st->core.producer_before_valid = o->facts;
#endif
    if (!cm_parse(st, o, front, args, capture, report) ||
        !cm_extract(st, o, main_path, args, *report))
        return false;
#if defined(__APPLE__)
    if (o->facts &&
        (!cm_producer_digest(st->core.type_grammar, producer_after) ||
         memcmp(st->core.producer_before, producer_after,
                sizeof(producer_after)) != 0))
        return cm_fail(&st->core, "darwin producer image changed during parse");
#endif
    return true;
}

/* Resolve --cc and check --toolchain-id into c, before cm_core_init enters
 * the root: a relative --cc names a file under the caller's directory, as
 * the compile would run it. False (reported) refuses; a compiler that
 * resolves only to a compile-cache wrapper is left unknown. */
static bool cm_bind_object_cc(struct cm_core *c, const char *cc,
                              const char *toolchain_id, char cc_real[PATH_MAX],
                              char *why, size_t why_len)
{
    enum cm_cc_resolution r = cc != NULL ? cm_resolve_cc(cc, cc_real)
                                         : CM_CC_WRAPPED;
    if (cc != NULL && r == CM_CC_NONE) {
        (void)snprintf(why, why_len, "object compiler %s is not an "
                       "executable file (as given, or on PATH)", cc);
        return false;
    }
    if (toolchain_id != NULL && !cm_toolchain_id_ok(toolchain_id)) {
        (void)snprintf(why, why_len, "--toolchain-id %s is not a nonzero "
                       "64-digit lowercase hex identity", toolchain_id);
        return false;
    }
    c->object_cc = r == CM_CC_FOUND ? cc_real : NULL;
    c->toolchain_id = toolchain_id;
    return true;
}

/* object-cc --root DIR --cc CC [--toolchain-id HEX]: IDENTITY's object
 * compiler text, one line on stdout. */
static int cm_cmd_object_cc(int argc, char **argv)
{
    const char *root = NULL, *cc = NULL, *toolchain_id = NULL;
    struct cm_core core = {0};
    char cc_real[PATH_MAX], *text = NULL, why[512];
    for (int k = 2; k + 1 < argc; k += 2) {
        if (strcmp(argv[k], "--root") == 0)
            root = argv[k + 1];
        else if (strcmp(argv[k], "--cc") == 0)
            cc = argv[k + 1];
        else if (strcmp(argv[k], "--toolchain-id") == 0)
            toolchain_id = argv[k + 1];
        else
            return 2;
    }
    if (root == NULL || cc == NULL || argc % 2 != 0)
        return 2;
    if (!cm_bind_object_cc(&core, cc, toolchain_id, cc_real, why, sizeof(why))) {
        fprintf(stderr, "clang-manifest: refused: %s\n", why);
        return 3;
    }
    bool ok = cm_core_init(&core, root) && (text = cm_object_cc_text(&core)) != NULL &&
              printf("%s\n", text) > 0 && fflush(stdout) == 0;
    if (!ok)
        fprintf(stderr, "clang-manifest: refused: %s\n", core.why);
    free(text);
    cm_core_free(&core);
    return ok ? 0 : 3;
}

/* Release everything one emit allocated. A front end that does not own the
 * TU keeps it (and its index) for the next emit; nothing else survives. */
static void cm_state_free(struct cm_state *st, const struct cm_front *front,
                          struct cm_args *args)
{
#if CM_TYPE_PRETTY_PRINTED
    if (st->policy != NULL)
        clang_PrintingPolicy_dispose(st->policy);
#endif
    for (size_t k = 0; k < st->ntagnames; k++)
        free(st->tagnames[k].name);
    free(st->tagnames);
    if (front->owns_tu && st->tu != NULL)
        clang_disposeTranslationUnit(st->tu);
    if (front->owns_tu && st->index != NULL)
        clang_disposeIndex(st->index);
    for (size_t k = 0; k < args->nidentity; k++)
        free(args->identity[k]);
    free(args->identity);
    free(args->parse);
    cm_core_free(&st->core);
    free(st);
}

bool cm_emit_bytes(const struct cm_opts *o, const struct cm_front *front,
                   uint8_t **bytes, size_t *len, char *why, size_t why_len)
{
    struct cm_state *st = zcl_calloc(1, sizeof(*st), "clang_manifest.state");
    struct cm_args args = {0};
    char *main_path = NULL, *report = NULL, capture[PATH_MAX + 16];
    char cc_real[PATH_MAX];
    bool ok;
    *bytes = NULL;
    *len = 0;
    if (st == NULL) {
        (void)snprintf(why, why_len, "out of memory");
        return false;
    }
    (void)snprintf(capture, sizeof(capture), "%s.clang-v", o->out);
    if (!cm_bind_object_cc(&st->core, o->cc, o->toolchain_id, cc_real, why,
                           why_len)) {
        free(st);
        return false;
    }
    ok = cm_core_init(&st->core, o->root) &&
         cm_norm_path(&st->core, o->source, &main_path);
    st->core.cc_snapshot = o->cc_snapshot;
    if (ok && (main_path[0] == '@' || strcmp(main_path, ".") == 0))
        ok = cm_fail(&st->core, "source %s is not inside the root", o->source);
    ok = ok &&
         cm_emit_parse(st, o, front, main_path, &args, capture, &report) &&
         cm_finish_bytes(&st->core, bytes, len);
    if (!ok)
        (void)snprintf(why, why_len, "%s", st->core.why);
    free(main_path);
    free(report);
    cm_state_free(st, front, &args);
    return ok;
}

static int cm_emit(const struct cm_opts *o)
{
    uint8_t *bytes = NULL, root[32];
    size_t len = 0;
    char why[512] = "", hex[65];
    bool ok = cm_emit_bytes(o, &cm_cold_front, &bytes, &len, why, sizeof(why));
    if (ok && !cm_write_file(o->out, bytes, len)) {
        (void)snprintf(why, sizeof(why), "cannot write %s", o->out);
        ok = false;
    }
    ok = ok && vcs_semantic_root_v1(bytes, len, root, why, sizeof(why));
    if (ok) {
        cm_hex(root, hex);
        printf("root %s bytes %zu\n", hex, len);
    } else {
        fprintf(stderr, "clang-manifest: refused: %s\n", why);
    }
    free(bytes);
    return ok ? 0 : 3;
}

/* ---- root / diff (no parse; the same reader Z23 uses) ----------------------------- */

static int cm_cmd_root(const char *path)
{
    uint8_t *b = NULL, d[32];
    size_t n = 0;
    /* A failed read can retain b; only validation may replace this reason. */
    char why[256] = "unreadable", hex[65];
    if (!cm_read_file(path, &b, &n) || !vcs_semantic_root_v1(b, n, d, why, sizeof(why))) {
        fprintf(stderr, "clang-manifest: %s: not a valid manifest: %s\n", path, why);
        free(b);
        return 2;
    }
    cm_hex(d, hex);
    printf("root %s\n", hex);
    if (vcs_semantic_hint_root_v1(b, n, d, why, sizeof(why))) {
        cm_hex(d, hex);
        printf("hint %s (candidate-match hint only)\n", hex);
    }
    for (int t = 1; t < VCS_SEMANTIC_SECTION_V1_COUNT; t++) {
        uint32_t count = 0;
        if (!vcs_semantic_section_root_v1(b, n, (enum vcs_semantic_section_v1)t, d) ||
            !vcs_semantic_section_count_v1(b, n, (enum vcs_semantic_section_v1)t,
                                           &count))
            continue;
        cm_hex(d, hex);
        printf("section %s records %u root %s\n",
               vcs_semantic_section_v1_name((enum vcs_semantic_section_v1)t),
               count, hex);
    }
    free(b);
    return 0;
}

static int cm_cmd_dump(const char *path)
{
    uint8_t *b = NULL;
    size_t n = 0;
    bool ok = cm_read_file(path, &b, &n) && vcs_semantic_manifest_v1_dump(b, n, stdout);
    free(b);
    if (!ok)
        fprintf(stderr, "clang-manifest: %s: not a valid manifest\n", path);
    return ok ? 0 : 2;
}

static void cm_print_fn(void *ctx, enum vcs_semantic_fn_change_v1 change,
                        const char *path, size_t path_len, const char *name,
                        size_t name_len)
{
    (void)ctx;
    printf("function %c %.*s %.*s\n", (char)change, (int)path_len, path,
           (int)name_len, name);
}

static bool cm_diff_read(const char *path, uint8_t **bytes, size_t *len)
{
    uint8_t root[32];
    char why[256] = "invalid manifest";
    if (!cm_read_file(path, bytes, len)) {
        fprintf(stderr, "clang-manifest: diff: %s: unreadable; "
                        "check that the file exists and is readable\n", path);
        return false;
    }
    if (!vcs_semantic_root_v1(*bytes, *len, root, why, sizeof(why))) {
        fprintf(stderr, "clang-manifest: diff: %s: invalid manifest: %s; "
                        "regenerate this manifest with emit\n", path, why);
        return false;
    }
    return true;
}

static int cm_cmd_diff(const char *a_path, const char *b_path)
{
    uint8_t *a = NULL, *b = NULL;
    size_t an = 0, bn = 0;
    struct vcs_semantic_diff_v1 d;
    bool ok = cm_diff_read(a_path, &a, &an) && cm_diff_read(b_path, &b, &bn) &&
              vcs_semantic_manifest_v1_diff(a, an, b, bn, &d, cm_print_fn, NULL);
    if (!ok) {
        fprintf(stderr, "clang-manifest: diff needs two valid manifests\n");
        free(a);
        free(b);
        return 2;
    }
    printf("changed");
    for (int t = 1; t < VCS_SEMANTIC_SECTION_V1_COUNT; t++) {
        if (d.changed_sections & (1u << t))
            printf(" %s", vcs_semantic_section_v1_name((enum vcs_semantic_section_v1)t));
    }
    printf("%s\nexact %s hint %s\nfunctions added %u removed %u changed %u same %u\n",
           d.changed_sections ? "" : " none", d.exact_equal ? "equal" : "differs",
           d.hint_equal ? "equal" : "differs", d.functions_added,
           d.functions_removed, d.functions_changed, d.functions_same);
    free(a);
    free(b);
    return d.changed_sections ? 1 : 0;
}

static int cm_usage(void)
{
    fprintf(stderr,
            "usage: z23-clang-manifest emit --root DIR --source FILE --out FILE [--cc CC]\n"
            "           [--toolchain-id HEX] [--facts] [--tree HEX]\n"
            "           [--max-records N] [--max-section-bytes N] -- ARGV...\n"
            "       z23-clang-manifest session [--verify-cold] [--no-warm]\n"
            "           [--max-tus N]\n"
            "           (one TAB-separated emit request per stdin line)\n"
            "       (--cc: the object's compiler, --toolchain-id: the build's\n"
            "        BUILD_COMPILER_ID; both recorded in IDENTITY)\n"
            "       z23-clang-manifest object-cc --root DIR --cc CC [--toolchain-id HEX]\n"
            "       z23-clang-manifest root FILE\n"
            "       z23-clang-manifest dump FILE\n"
            "       z23-clang-manifest diff OLD NEW\n");
    return 2;
}

static bool cm_section_limit(const char *v, uint64_t *out)
{
    uint64_t n = 0;
    if (*v == '\0')
        return false;
    for (; *v != '\0'; v++) {
        if (*v < '0' || *v > '9')
            return false;
        unsigned digit = (unsigned)(*v - '0');
        if (n > (UINT64_MAX - digit) / 10)
            return false;
        n = n * 10 + digit;
    }
    *out = n;
    return true;
}

static bool cm_max_records(const char *v, uint32_t *out)
{
    char *end;
    errno = 0;
    unsigned long long n = strtoull(v, &end, 10);
    if (v[0] < '0' || v[0] > '9' || *end != '\0' || errno != 0 ||
        n > UINT32_MAX) {
        fprintf(stderr, "clang-manifest: invalid --max-records: %s\n", v);
        return false;
    }
    *out = (uint32_t)n;
    return true;
}

static bool cm_opt_value(struct cm_opts *o, const char *key, const char *v)
{
    if (strcmp(key, "--root") == 0)
        o->root = v;
    else if (strcmp(key, "--source") == 0)
        o->source = v;
    else if (strcmp(key, "--out") == 0)
        o->out = v;
    else if (strcmp(key, "--tree") == 0)
        o->tree = v;
    else if (strcmp(key, "--cc") == 0)
        o->cc = v;
    else if (strcmp(key, "--toolchain-id") == 0)
        o->toolchain_id = v;
    else if (strcmp(key, "--max-records") == 0)
        return cm_max_records(v, &o->max_records);
    else if (strcmp(key, "--max-section-bytes") == 0)
        return cm_section_limit(v, &o->max_section_bytes);
    else
        return false;
    return true;
}

bool cm_parse_opts(int argc, char **argv, int first, struct cm_opts *o)
{
    int k = first;
    while (k < argc && strcmp(argv[k], "--") != 0) {
        if (strcmp(argv[k], "--facts") == 0) {
            o->facts = true;
            k++;
            continue;
        }
        if (k + 1 >= argc || !cm_opt_value(o, argv[k], argv[k + 1]))
            return false;
        k += 2;
    }
    if (k >= argc || strcmp(argv[k], "--") != 0)
        return false;
    o->argv = argv + k + 1;
    o->argc = argc - k - 1;
    o->facts = o->facts || o->tree != NULL || o->max_records != 0 ||
               o->max_section_bytes != 0;
    return o->root != NULL && o->source != NULL && o->out != NULL;
}

int main(int argc, char **argv)
{
    struct cm_opts o = {0};
    if (argc >= 2 && strcmp(argv[1], "object-cc") == 0)
        return cm_cmd_object_cc(argc, argv);
    if (argc >= 3 && strcmp(argv[1], "root") == 0)
        return cm_cmd_root(argv[2]);
    if (argc >= 3 && strcmp(argv[1], "dump") == 0)
        return cm_cmd_dump(argv[2]);
    if (argc >= 4 && strcmp(argv[1], "diff") == 0)
        return cm_cmd_diff(argv[2], argv[3]);
    if (argc >= 2 && strcmp(argv[1], "session") == 0)
        return cm_session_main(argc, argv);
    if (argc >= 2 && strcmp(argv[1], "emit") == 0 && cm_parse_opts(argc, argv, 2, &o))
        return cm_emit(&o);
    return cm_usage();
}
