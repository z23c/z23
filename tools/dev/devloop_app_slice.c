/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The conventional App resource slice, declared once.
 *
 * `z23 dev app plan <app> <resource>` previews this slice and
 * `z23 dev app scaffold <app> <resource>` materialises it. Both call
 * zcl_devloop_app_slice_build() — the plan is not a second, drifting
 * description of what the scaffold writes, it IS what the scaffold writes.
 *
 * The generated files are plain committed C a human reads and gdb steps, not
 * metaprogramming (FRAMEWORK.md Law 3: declare the spec, generate the code).
 * They are shaped to pass the framework lint gates the hour they are written:
 * the model carries validates_* coverage and its shape header, the service
 * returns struct zcl_result and logs every refusal, and the test group is
 * registered in the canonical catalog so it actually runs.
 *
 * Read-only: this file computes bytes into a caller-owned slice and touches
 * no disk. tools/dev/devloop_app_scaffold.c owns every write.
 */

#include "devloop.h"

#include "base/safe_alloc.h"
#include "framework/app_definition.h"
#include "platform/directory_compat.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── bounded body appender ─────────────────────────────────────────────── */
struct slice_body {
    struct zcl_devloop_app_slice_file *file;
    bool ok;
};

static void slice_body_addf(struct slice_body *b, const char *fmt, ...)
{
    if (!b->ok)
        return;
    size_t room = sizeof(b->file->body) - b->file->body_len;
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(b->file->body + b->file->body_len, room, fmt, ap);
    va_end(ap);
    if (n < 0 || (size_t)n >= room) {
        b->ok = false;
        return;
    }
    b->file->body_len += (size_t)n;
}

/* Start one slice entry. Returns NULL once the table is full so every caller
 * degrades to "slice did not build" rather than silently dropping a file. */
static struct zcl_devloop_app_slice_file *slice_open(
    struct zcl_devloop_app_slice *s, enum zcl_devloop_app_slice_kind kind,
    const char *fmt, ...)
{
    if (s->file_count >= ZCL_DEVLOOP_APP_SLICE_MAX_FILES)
        return NULL;
    struct zcl_devloop_app_slice_file *f = &s->files[s->file_count];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(f->path, sizeof(f->path), fmt, ap);
    va_end(ap);
    if (n <= 0 || (size_t)n >= sizeof(f->path))
        return NULL;
    f->kind = kind;
    f->body_len = 0;
    f->body[0] = 0;
    s->file_count++;
    return f;
}

/* SCREAMING_SNAKE form of a lowercase snake_case resource name, for the
 * generated include guards and bound constants. */
static bool slice_upper(const char *in, char *out, size_t out_sz)
{
    size_t n = strnlen(in, out_sz);
    if (n == 0 || n >= out_sz)
        return false;
    for (size_t i = 0; i < n; i++) {
        char c = in[i];
        out[i] = (c >= 'a' && c <= 'z') ? (char)(c - 'a' + 'A') : c;
    }
    out[n] = 0;
    return true;
}

/* ── the templates ─────────────────────────────────────────────────────── */

static const char LIC[] =
    "/* Copyright 2026 Rhett Creighton - Apache License 2.0";

static void emit_model_header(struct slice_body *b, const char *app,
                              const char *res, const char *RES)
{
    slice_body_addf(b,
        "%s\n"
        " *\n"
        " * %s — the ActiveRecord record for the \"%s\" resource of the \"%s\"\n"
        " * App. Written by `z23 dev app scaffold %s %s`; from here it is\n"
        " * ordinary committed source you own, review, and edit.\n"
        " *\n"
        " * The record is a dense POD row (Law 5: fat models, lean structs) and\n"
        " * db_%s_validate() is the App's authority boundary for it: a record\n"
        " * that does not validate never reaches storage, and every writer goes\n"
        " * through that one function. Pure and deterministic — no clock, no\n"
        " * randomness, no IO. Replace the placeholder columns with the real\n"
        " * ones and the validation rules follow them.\n"
        " */\n"
        "\n"
        "#ifndef ZCL_MODELS_%s_H\n"
        "#define ZCL_MODELS_%s_H\n"
        "\n"
        "#include \"models/activerecord.h\"\n"
        "\n"
        "#include <stdbool.h>\n"
        "#include <stdint.h>\n"
        "\n"
        "enum {\n"
        "    ZCL_%s_ID_MAX = 64,\n"
        "    ZCL_%s_AUTHOR_MAX = 64,\n"
        "    ZCL_%s_BODY_MAX = 512\n"
        "};\n"
        "\n"
        "struct db_%s {\n"
        "    char id[ZCL_%s_ID_MAX + 1];\n"
        "    char author[ZCL_%s_AUTHOR_MAX + 1];\n"
        "    char body[ZCL_%s_BODY_MAX + 1];\n"
        "    int64_t created_at;\n"
        "};\n"
        "\n"
        "/* Lazily-initialised before/after-save callback registry for this\n"
        " * model. Never NULL; shared by every writer of the resource. */\n"
        "struct ar_callbacks *db_%s_callbacks(void);\n"
        "\n"
        "/* Populate errors with every validation failure for r: presence of id,\n"
        " * author and body, a non-negative created_at, and printable text\n"
        " * inside each column's bound. Returns true iff r is valid. A NULL r\n"
        " * is invalid, never a crash. */\n"
        "bool db_%s_validate(const struct db_%s *r, struct ar_errors *errors);\n"
        "\n"
        "#endif\n",
        LIC, res, res, app, app, res, res, RES, RES, RES, RES, RES,
        res, RES, RES, RES, res, res, res);
}

static void emit_model_source(struct slice_body *b, const char *app,
                              const char *res, const char *RES)
{
    slice_body_addf(b,
        "%s\n"
        " *\n"
        " * ActiveRecord model: %s (App \"%s\").\n"
        " *\n"
        " * The only reader/writer of its resource row (Law 2: one way in, one\n"
        " * way out). Validation lives here and nowhere else, so the rule a\n"
        " * reviewer reads is the rule a writer runs. Written by\n"
        " * `z23 dev app scaffold %s %s`.\n"
        " */\n"
        "\n"
        "#include \"models/%s.h\"\n"
        "\n"
        "#include <string.h>\n"
        "\n"
        "/* Generates db_%s_callbacks() — the per-model hook registry. */\n"
        "DEFINE_MODEL_CALLBACKS(%s)\n"
        "\n"
        "/* True when s is a NUL-terminated printable string of at most max\n"
        " * bytes. Control bytes are rejected: a resource column is read back\n"
        " * into logs, JSON, and web output. */\n"
        "static bool %s_text_ok(const char *s, size_t max)\n"
        "{\n"
        "    size_t n = strnlen(s, max + 1u);\n"
        "    if (n > max)\n"
        "        return false;\n"
        "    for (size_t i = 0; i < n; i++) {\n"
        "        unsigned char c = (unsigned char)s[i];\n"
        "        if (c < 0x20u || c == 0x7fu)\n"
        "            return false;\n"
        "    }\n"
        "    return true;\n"
        "}\n"
        "\n"
        "bool db_%s_validate(const struct db_%s *r, struct ar_errors *errors)\n"
        "{\n"
        "    ar_errors_clear(errors);\n"
        "    if (!r) {\n"
        "        ar_errors_add(errors, \"record\", \"can't be blank\");\n"
        "        return false;\n"
        "    }\n"
        "    validates_presence_of(errors, r, id);\n"
        "    validates_presence_of(errors, r, author);\n"
        "    validates_presence_of(errors, r, body);\n"
        "    validates_non_negative(errors, r, created_at);\n"
        "    if (!%s_text_ok(r->id, ZCL_%s_ID_MAX))\n"
        "        ar_errors_add(errors, \"id\", \"must be printable\");\n"
        "    if (!%s_text_ok(r->author, ZCL_%s_AUTHOR_MAX))\n"
        "        ar_errors_add(errors, \"author\", \"must be printable\");\n"
        "    if (!%s_text_ok(r->body, ZCL_%s_BODY_MAX))\n"
        "        ar_errors_add(errors, \"body\", \"must be printable\");\n"
        "    return !ar_errors_any(errors);\n"
        "}\n",
        LIC, res, app, app, res, res, res, res, res, res, res,
        res, RES, res, RES, res, RES);
}

static void emit_service_header(struct slice_body *b, const char *app,
                                const char *res, const char *RES)
{
    slice_body_addf(b,
        "%s\n"
        " *\n"
        " * %s service (App \"%s\") — the ONE admission path for the resource.\n"
        " * A controller, a web route, or a P2P topic handler calls this and\n"
        " * nothing else; the business rule stays here, out of the glue.\n"
        " * Written by `z23 dev app scaffold %s %s`.\n"
        " */\n"
        "\n"
        "#ifndef ZCL_SERVICES_%s_SERVICE_H\n"
        "#define ZCL_SERVICES_%s_SERVICE_H\n"
        "\n"
        "#include \"base/result.h\"\n"
        "#include \"models/%s.h\"\n"
        "\n"
        "/* Admit one %s submitted to the App. Returns ZCL_OK when the record\n"
        " * satisfies db_%s_validate(); otherwise a non-ok result whose message\n"
        " * names the first failing column. Never partially applies. */\n"
        "struct zcl_result %s_service_admit(const struct db_%s *record);\n"
        "\n"
        "#endif\n",
        LIC, res, app, app, res, RES, RES, res, res, res, res, res);
}

static void emit_service_source(struct slice_body *b, const char *app,
                                const char *res)
{
    slice_body_addf(b,
        "%s\n"
        " *\n"
        " * %s service (App \"%s\") — see services/%s_service.h.\n"
        " *\n"
        " * Written by `z23 dev app scaffold %s %s`. It delegates the whole\n"
        " * decision to the model's validation so the App has exactly one\n"
        " * definition of a well-formed %s.\n"
        " */\n"
        "\n"
        "// supervisor-ok:stateless-admission — %s_service_admit() is a pure,\n"
        "// synchronous decision with no thread, timer, or socket to keep\n"
        "// alive, so it has no liveness contract to register.\n"
        "\n"
        "#include \"services/%s_service.h\"\n"
        "\n"
        "#include \"util/log_macros.h\"\n"
        "\n"
        "struct zcl_result %s_service_admit(const struct db_%s *record)\n"
        "{\n"
        "    struct ar_errors errors;\n"
        "    if (!db_%s_validate(record, &errors)) {\n"
        "        LOG_WARN(\"%s\", \"[%s] admission REFUSED: %%s\",\n"
        "                 ar_errors_full(&errors));\n"
        "        return ZCL_ERR(-1, \"%s refused: %%s\", ar_errors_full(&errors));\n"
        "    }\n"
        "    return ZCL_OK;\n"
        "}\n",
        LIC, res, app, res, app, res, res, res, res, res, res, res,
        res, res, res);
}

static void emit_slice_test(struct slice_body *b, const char *app,
                            const char *res, const char *group)
{
    slice_body_addf(b,
        "%s\n"
        " *\n"
        " * Proves the generated \"%s\" resource slice of the \"%s\" App is a\n"
        " * real boundary and not decoration: a well-formed record is admitted,\n"
        " * a blank one is refused by name, a control byte in a column is\n"
        " * refused, and the service's verdict agrees with the model's.\n"
        " * Written by `z23 dev app scaffold %s %s`; extend it as the resource\n"
        " * grows real columns.\n"
        " */\n"
        "\n"
        "#include \"test/test_core.h\"\n"
        "\n"
        "#include \"services/%s_service.h\"\n"
        "\n"
        "static void %s_fill(struct db_%s *r)\n"
        "{\n"
        "    memset(r, 0, sizeof(*r));\n"
        "    snprintf(r->id, sizeof(r->id), \"%%s\", \"%s-0001\");\n"
        "    snprintf(r->author, sizeof(r->author), \"%%s\", \"scaffold\");\n"
        "    snprintf(r->body, sizeof(r->body), \"%%s\", \"a first %s\");\n"
        "    r->created_at = 1700000000;\n"
        "}\n"
        "\n"
        "int test_%s(void)\n"
        "{\n"
        "    int failures = 0;\n"
        "\n"
        "    printf(\"%s/%s: a well-formed record validates and is admitted... \");\n"
        "    {\n"
        "        struct db_%s rec;\n"
        "        struct ar_errors e;\n"
        "        %s_fill(&rec);\n"
        "        ar_errors_clear(&e);\n"
        "        bool ok = db_%s_validate(&rec, &e) && !ar_errors_any(&e);\n"
        "        struct zcl_result r = %s_service_admit(&rec);\n"
        "        ok = ok && r.ok;\n"
        "        if (ok) printf(\"OK\\n\");\n"
        "        else { printf(\"FAIL\\n\"); failures++; }\n"
        "    }\n"
        "\n"
        "    printf(\"%s/%s: a blank record is refused, naming the column... \");\n"
        "    {\n"
        "        struct db_%s rec;\n"
        "        struct ar_errors e;\n"
        "        memset(&rec, 0, sizeof(rec));\n"
        "        ar_errors_clear(&e);\n"
        "        bool ok = !db_%s_validate(&rec, &e) &&\n"
        "                  strstr(ar_errors_full(&e), \"id\") != NULL;\n"
        "        struct zcl_result r = %s_service_admit(&rec);\n"
        "        ok = ok && !r.ok;\n"
        "        if (ok) printf(\"OK\\n\");\n"
        "        else { printf(\"FAIL\\n\"); failures++; }\n"
        "    }\n"
        "\n"
        "    printf(\"%s/%s: a control byte in a column is refused... \");\n"
        "    {\n"
        "        struct db_%s rec;\n"
        "        struct ar_errors e;\n"
        "        %s_fill(&rec);\n"
        "        rec.body[0] = '\\t';\n"
        "        ar_errors_clear(&e);\n"
        "        bool ok = !db_%s_validate(&rec, &e) &&\n"
        "                  strstr(ar_errors_full(&e), \"printable\") != NULL;\n"
        "        if (ok) printf(\"OK\\n\");\n"
        "        else { printf(\"FAIL\\n\"); failures++; }\n"
        "    }\n"
        "\n"
        "    printf(\"%s/%s: a NULL record is refused, not a crash... \");\n"
        "    {\n"
        "        struct zcl_result r = %s_service_admit(NULL);\n"
        "        if (!r.ok) printf(\"OK\\n\");\n"
        "        else { printf(\"FAIL\\n\"); failures++; }\n"
        "    }\n"
        "\n"
        "    return failures;\n"
        "}\n",
        LIC, res, app, app, res, res, group, res, res, res, group,
        app, res, res, group, res, res,
        app, res, res, res, res,
        app, res, res, group, res,
        app, res, res);
}

/* ── slice assembly ────────────────────────────────────────────────────── */

static bool slice_emit_files(struct zcl_devloop_app_slice *s, const char *RES)
{
    const char *app = s->app_id;
    const char *res = s->resource;
    struct slice_body b;
    struct zcl_devloop_app_slice_file *f;

    struct {
        enum zcl_devloop_app_slice_kind kind;
        const char *pattern;
        void (*emit)(struct slice_body *, const char *, const char *,
                     const char *);
    } const created[] = {
        { ZCL_DEVLOOP_APP_SLICE_CREATE,
          "engine/models/include/models/%s.h", emit_model_header },
        { ZCL_DEVLOOP_APP_SLICE_CREATE,
          "engine/models/src/%s.c", emit_model_source },
        { ZCL_DEVLOOP_APP_SLICE_CREATE,
          "engine/services/include/services/%s_service.h",
          emit_service_header },
    };
    for (size_t i = 0; i < sizeof(created) / sizeof(created[0]); i++) {
        f = slice_open(s, created[i].kind, created[i].pattern, res);
        if (!f)
            return false;
        b = (struct slice_body){ .file = f, .ok = true };
        created[i].emit(&b, app, res, RES);
        if (!b.ok)
            return false;
    }

    f = slice_open(s, ZCL_DEVLOOP_APP_SLICE_CREATE,
                   "engine/services/src/%s_service.c", res);
    if (!f)
        return false;
    b = (struct slice_body){ .file = f, .ok = true };
    emit_service_source(&b, app, res);
    if (!b.ok)
        return false;

    f = slice_open(s, ZCL_DEVLOOP_APP_SLICE_CREATE,
                   "tests/harness/src/test_%s.c", s->group);
    if (!f)
        return false;
    b = (struct slice_body){ .file = f, .ok = true };
    emit_slice_test(&b, app, res, s->group);
    if (!b.ok)
        return false;

    f = slice_open(s, ZCL_DEVLOOP_APP_SLICE_ROW,
                   "tools/dev/test_group_catalog.def");
    if (!f)
        return false;
    b = (struct slice_body){ .file = f, .ok = true };
    slice_body_addf(&b, "ZCL_TEST_GROUP(%s)\n", s->group);
    return b.ok;
}

static bool slice_copy(char *out, size_t out_sz, const char *src)
{
    size_t n = strnlen(src, out_sz);
    if (n == 0 || n >= out_sz)
        return false;
    memcpy(out, src, n);
    out[n] = 0;
    return true;
}

struct zcl_devloop_app_slice *zcl_devloop_app_slice_build(
    const char *repo_root, const char *app_id, const char *resource)
{
    char root[ZCL_DEVLOOP_PATH_MAX];
    if (!zcl_app_definition_id_valid_v1(app_id) ||
        !zcl_devloop_app_resource_valid(resource) ||
        !platform_directory_canonical_real(repo_root, root, sizeof(root)))
        return NULL;
    struct zcl_app_definition_v1 definition;
    if (!zcl_app_definition_load_v1(root, app_id, &definition).ok)
        return NULL;

    struct zcl_devloop_app_slice *s = zcl_calloc(
        1, sizeof(*s), "dev.app resource slice");
    if (!s)
        return NULL;
    char upper[ZCL_DEVLOOP_APP_SLICE_NAME_MAX];
    int n = snprintf(s->group, sizeof(s->group), "%s_%s_slice",
                     definition.app_id, resource);
    if (!slice_copy(s->root, sizeof(s->root), root) ||
        !slice_copy(s->app_id, sizeof(s->app_id), definition.app_id) ||
        !slice_copy(s->resource, sizeof(s->resource), resource) ||
        n <= 0 || (size_t)n >= sizeof(s->group) ||
        !slice_upper(s->resource, upper, sizeof(upper)) ||
        !slice_emit_files(s, upper)) {
        zcl_devloop_app_slice_free(s);
        return NULL;
    }
    return s;
}

void zcl_devloop_app_slice_free(struct zcl_devloop_app_slice *slice)
{
    free(slice);
}
