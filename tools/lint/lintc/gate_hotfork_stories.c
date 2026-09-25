/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: gate — every HOT_FORK capsule unity still compiles
 * (check-hotfork-stories). The reflex path compiles, per owner in
 * engine/composition/hotfork_capsules.def, a generated unity: the owner TU
 * set bracketed by its story adapter in tools/dev/hotfork_stories/. Nothing
 * in the ordinary build compiles those units, so an owner API change used
 * to turn a story COMPILE_RED on the next edit and silently remove that
 * owner's hot-load feedback. This gate renders every unity with the SAME
 * renderer the resident builder uses (tools/dev/hotfork_unity.h) and
 * compiles it -fsyntax-only with the frozen resident action plan
 * (build/hotswap-fast/flags.env: CC and DEV_CFLAGS, -Werror included), in
 * parallel (ZCL_CC_JOBS workers, default 8).
 *
 * It also refuses a story set that drifted from the manifest: a row whose
 * derived story file is missing, a story file no row claims, or two rows
 * sharing one adapter. The selftest compiles a fixture owner with a good
 * story (must pass), a story that calls the owner with the wrong pointer
 * type and one that only -Werror rejects (both must fail), and an orphan.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <dirent.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include "lintc.h"
#include "../../dev/hotfork_unity.h"

struct hfs_row {
    const char *owner_id;
    const char *source_tu;
    const char *sibling_tus;
    const char *adapter_id;
    const char *surface;
};

#define HOTFORK_CAPSULE(owner_id_, feedback_class_, source_tu_, sibling_tus_, \
                        story_id_, fixture_id_, adapter_id_, max_time_ms_,    \
                        forbidden_effect_mask_, surface_)                     \
    { owner_id_, source_tu_, sibling_tus_, adapter_id_, surface_ },
static const struct hfs_row k_hfs_rows[] = {
#include "../../../engine/composition/hotfork_capsules.def"
};
#undef HOTFORK_CAPSULE

enum {
    HFS_PLAN_MAX = 64 * 1024,
    HFS_CMD_MAX = 80 * 1024,
    HFS_LOG_MAX = 64 * 1024,
    HFS_JOBS_MAX = 32,
    HFS_ROWS_MAX = 128,
    HFS_LOG_LINES = 12,
};

struct hfs_plan {
    char cc[4096];
    char cflags[HFS_PLAN_MAX];
};

struct hfs_set {
    const char *root;           /* absolute, trailing '/' */
    const char *work;           /* absolute scratch dir for unity files */
    const struct hfs_row *rows;
    size_t count;
};

static struct hfs_plan g_hfs_plan;
static char g_hfs_cmd[HFS_CMD_MAX];
static char g_hfs_log[HFS_LOG_MAX];

static int hfs_line_value(const char *line, const char *key, char *out,
                          size_t cap)
{
    size_t kl = strlen(key);
    if (strncmp(line, key, kl) != 0)
        return 0;
    size_t n = strcspn(line + kl, "\r\n");
    if (n >= cap)
        return die("z23-lint: action plan value overflow: %s\n", key);
    memcpy(out, line + kl, n);
    out[n] = '\0';
    return 0;
}

static int hfs_plan_fresh(const char *plan_path)
{
    struct stat plan_st, make_st;
    if (stat(plan_path, &plan_st) != 0 || !S_ISREG(plan_st.st_mode)) {
        fprintf(stderr, "check-hotfork-stories: FAIL — %s is absent; run "
                "`make build/hotswap-fast/flags.env` (lint-fast builds it)\n",
                plan_path);
        return 2;
    }
    if (stat("Makefile", &make_st) == 0 &&
        make_st.st_mtime > plan_st.st_mtime) {
        fprintf(stderr, "check-hotfork-stories: FAIL — %s is older than the "
                "Makefile; rebuild it with `make build/hotswap-fast/flags.env`\n",
                plan_path);
        return 2;
    }
    return 0;
}

/* Loads CC and DEV_CFLAGS from the frozen resident action plan: the exact
 * compiler and flags the HOT_FORK builder compiles capsules with. */
static int hfs_plan_load(const char *plan_path, struct hfs_plan *plan)
{
    int rc = hfs_plan_fresh(plan_path);
    if (rc)
        return rc;
    FILE *f = fopen(plan_path, "r");
    if (!f)
        return die("z23-lint: cannot open %s\n", plan_path);
    char *line = NULL;
    size_t cap = 0;
    plan->cc[0] = plan->cflags[0] = '\0';
    while (rc == 0 && getline(&line, &cap, f) >= 0) {
        rc = hfs_line_value(line, "CC=", plan->cc, sizeof plan->cc);
        if (rc == 0)
            rc = hfs_line_value(line, "DEV_CFLAGS=", plan->cflags,
                                sizeof plan->cflags);
    }
    rc = fin(f, line, plan_path, rc);
    if (rc == 0 && (!plan->cc[0] || !plan->cflags[0])) {
        fprintf(stderr, "check-hotfork-stories: FAIL — %s has no CC or "
                "DEV_CFLAGS line\n", plan_path);
        rc = 2;
    }
    return rc;
}

static int hfs_story_claimed(const struct hfs_set *set, const char *name)
{
    char rel[ZCL_HOTFORK_UNITY_TU_MAX];
    size_t dir_len = sizeof(ZCL_HOTFORK_STORY_DIR) - 1;
    for (size_t i = 0; i < set->count; i++)
        if (zcl_hotfork_story_path(set->rows[i].adapter_id, rel, sizeof rel)
            && strcmp(rel + dir_len, name) == 0)
            return 1;
    return 0;
}

/* Every file in the story directory must be claimed by a manifest row. */
static int hfs_orphans(const struct hfs_set *set, int *red)
{
    char dir[4096];
    if (ovf(snprintf(dir, sizeof dir, "%s%s", set->root,
                     ZCL_HOTFORK_STORY_DIR), sizeof dir))
        return 2;
    DIR *d = opendir(dir);
    if (!d)
        return die("z23-lint: cannot open story directory %s\n", dir);
    const struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (e->d_name[0] == '.' || hfs_story_claimed(set, e->d_name))
            continue;
        fprintf(stderr, "check-hotfork-stories: FAIL — %s%s is claimed by no "
                "HOTFORK_CAPSULE row; delete it or name it as an adapter_id\n",
                ZCL_HOTFORK_STORY_DIR, e->d_name);
        (*red)++;
    }
    closedir(d);
    return 0;
}

/* Each row derives a story path that exists, and no two rows share one. */
static int hfs_row_shape(const struct hfs_set *set, size_t i, int *red)
{
    char rel[ZCL_HOTFORK_UNITY_TU_MAX], path[4096];
    const struct hfs_row *row = &set->rows[i];
    struct stat st;
    if (!zcl_hotfork_story_path(row->adapter_id, rel, sizeof rel)) {
        fprintf(stderr, "check-hotfork-stories: FAIL — %s: adapter_id '%s' "
                "does not derive a story path\n", row->owner_id,
                row->adapter_id);
        (*red)++;
        return 0;
    }
    for (size_t j = 0; j < i; j++)
        if (strcmp(set->rows[j].adapter_id, row->adapter_id) == 0) {
            fprintf(stderr, "check-hotfork-stories: FAIL — %s and %s share "
                    "adapter %s\n", set->rows[j].owner_id, row->owner_id,
                    row->adapter_id);
            (*red)++;
        }
    if (ovf(snprintf(path, sizeof path, "%s%s", set->root, rel), sizeof path))
        return 2;
    if (stat(path, &st) != 0 || !S_ISREG(st.st_mode)) {
        fprintf(stderr, "check-hotfork-stories: FAIL — %s: story adapter %s "
                "is missing\n", row->owner_id, rel);
        (*red)++;
    }
    return 0;
}

/* Renders row `i`'s unity to <work>/<i>.c and returns its compile command
 * in g_hfs_cmd, or leaves g_hfs_cmd empty when the unity does not render. */
static int hfs_prepare(const struct hfs_set *set, size_t i)
{
    char unity[ZCL_HOTFORK_UNITY_MAX], path[4096], qpath[8192];
    const struct hfs_row *row = &set->rows[i];
    g_hfs_cmd[0] = '\0';
    int n = zcl_hotfork_unity_render(set->root, row->source_tu,
                                     row->sibling_tus, row->adapter_id,
                                     row->surface, unity, sizeof unity);
    if (n <= 0)
        return 0;
    if (ovf(snprintf(path, sizeof path, "%s/%zu.c", set->work, i),
            sizeof path) || csr_write(path, unity) ||
        sh_single_quote(path, qpath, sizeof qpath))
        return 2;
    if (ovf(snprintf(g_hfs_cmd, sizeof g_hfs_cmd,
                     "%s %s -fPIC -fvisibility=hidden -fsyntax-only %s 2>&1",
                     g_hfs_plan.cc, g_hfs_plan.cflags, qpath),
            sizeof g_hfs_cmd))
        return 2;
    return 0;
}

static void hfs_print_log(const char *log)
{
    int lines = 0;
    for (const char *p = log; *p && lines < HFS_LOG_LINES; lines++) {
        size_t n = strcspn(p, "\n");
        fprintf(stderr, "    %.*s\n", (int)n, p);
        p += n + (p[n] == '\n');
    }
}

static int hfs_drain(FILE *pipe, const struct hfs_row *row, int *red)
{
    size_t used = 0;
    if (pipe) {
        size_t got;
        while ((got = fread(g_hfs_log + used, 1, sizeof g_hfs_log - 1 - used,
                            pipe)) > 0)
            used += got;
    }
    g_hfs_log[used] = '\0';
    int st = pipe ? pclose(pipe) : -1;
    if (st == 0)
        return 0;
    fprintf(stderr, "check-hotfork-stories: FAIL — %s (%s) unity is "
            "COMPILE_RED%s\n", row->owner_id, row->adapter_id,
            pipe ? "; first compiler lines:" : ": unity did not render");
    hfs_print_log(g_hfs_log);
    (*red)++;
    return 0;
}

static int hfs_jobs(void)
{
    int jobs = atoi(env_or("ZCL_CC_JOBS", "8"));
    return jobs < 1 ? 1 : jobs > HFS_JOBS_MAX ? HFS_JOBS_MAX : jobs;
}

/* Compiles every unity through a bounded FIFO window of popen() workers. */
static int hfs_compile_all(const struct hfs_set *set, int *red)
{
    FILE *slot[HFS_JOBS_MAX] = {0};
    size_t jobs = (size_t)hfs_jobs();
    int rc = 0;
    for (size_t i = 0; rc == 0 && i < set->count + jobs; i++) {
        if (i >= jobs)
            rc = hfs_drain(slot[i % jobs], &set->rows[i - jobs], red);
        if (rc == 0 && i < set->count) {
            rc = hfs_prepare(set, i);
            slot[i % jobs] = g_hfs_cmd[0] ? popen(g_hfs_cmd, "r") : NULL;
        }
    }
    return rc;
}

static int hfs_check(const struct hfs_set *set, int *red)
{
    *red = 0;
    if (set->count == 0 || set->count > HFS_ROWS_MAX)
        return die("z23-lint: HOT_FORK manifest row count out of range%s\n",
                   "");
    int rc = hfs_orphans(set, red);
    for (size_t i = 0; rc == 0 && i < set->count; i++)
        rc = hfs_row_shape(set, i, red);
    return rc ? rc : hfs_compile_all(set, red);
}

/* Creates build/<stem>.XXXXXX under the repo root; `out` gets its path. */
static int hfs_workdir(const char *root, const char *stem, char *out,
                       size_t cap)
{
    char build[4096];
    if (ovf(snprintf(build, sizeof build, "%sbuild", root), sizeof build) ||
        csr_mkdirs(build) ||
        ovf(snprintf(out, cap, "%s/%s.XXXXXX", build, stem), cap))
        return 2;
    return mkdtemp(out) ? 0 : die("z23-lint: mkdtemp failed under %s\n",
                                  build);
}

static int hfs_root(char *root, size_t cap)
{
    if (cic_repo_root(root, cap))
        return 2;
    if (chdir(root) != 0)
        return die("z23-lint: cannot scan %s\n", root);
    size_t n = strlen(root);
    if (n + 2 > cap)
        return 2;
    root[n] = '/';
    root[n + 1] = '\0';
    return hfs_plan_load("build/hotswap-fast/flags.env", &g_hfs_plan);
}

static int64_t hfs_now_ms(void)
{
    struct timespec ts;
    (void)clock_gettime(CLOCK_MONOTONIC, &ts); // platform-ok: z23-lint links no platform library; elapsed time for the report line only
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

int check_hotfork_stories_run(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    char root[4096], work[4096];
    int64_t started = hfs_now_ms();
    int rc = hfs_root(root, sizeof root);
    if (rc == 0)
        rc = hfs_workdir(root, "hotfork-stories", work, sizeof work);
    if (rc)
        return rc;
    struct hfs_set set = { root, work, k_hfs_rows,
                           sizeof k_hfs_rows / sizeof k_hfs_rows[0] };
    int red = 0;
    rc = hfs_check(&set, &red);
    int cl = rap_rm_rf(work);
    if (rc || cl)
        return rc ? rc : cl;
    if (red) {
        fprintf(stderr, "check-hotfork-stories: FAIL — %d problem(s) across "
                "%zu capsule(s). Repair the story in %s to the owner's "
                "current API; never delete a story to go green.\n", red,
                set.count, ZCL_HOTFORK_STORY_DIR);
        return 1;
    }
    printf("check-hotfork-stories: OK — %zu/%zu capsule unities compile with "
           "the frozen dev flags (%d jobs, %lld ms)\n", set.count, set.count,
           hfs_jobs(), (long long)(hfs_now_ms() - started));
    return 0;
}

/* ── selftest ─────────────────────────────────────────────────────────── */

static const char k_hfs_owner[] =
    "#include <stdint.h>\n"
    "static int hf_selftest_add(const int *a, int b) { return *a + b; }\n";

static const char k_hfs_story_head[] =
    "#if !defined(ZCL_HOTFORK_STORY_PHASE)\n#error phase\n"
    "#elif ZCL_HOTFORK_STORY_PHASE == 1\n#define _GNU_SOURCE\n"
    "#include <stdio.h>\n#include <string.h>\n"
    "#include \"hotswap/hotfork_capsule.h\"\n"
    "#elif ZCL_HOTFORK_STORY_PHASE == 2\n"
    "__attribute__((visibility(\"hidden\"))) bool\n"
    "zcl_hotfork_candidate_story_v1(struct zcl_hotfork_observation_v1 *out)\n"
    "{\n    if (!out) {\n        return false;\n    }\n"
    "    memset(out, 0, sizeof(*out));\n";

static const char k_hfs_story_tail[] =
    "    snprintf(out->exercised_surface, sizeof(out->exercised_surface),\n"
    "             ZCL_HOTFORK_EXERCISED_SURFACE);\n"
    "    return out->checks_passed == 1;\n}\n#endif\n";

struct hfs_case {
    const char *adapter_id;
    const char *body;       /* NULL: no story file (missing story case) */
    int want_red;
    const char *want_log;   /* the compiler must say this when red */
};

/* The good case, the real rot shape (owner signature changed under the
 * story), an error only -Werror produces, and a missing story file. Each
 * red case must be red for ITS reason, not for an unrelated fixture bug. */
static const struct hfs_case k_hfs_cases[] = {
    { "selftest-good.v1",
      "    int one = 1;\n    out->checks_run = 1;\n"
      "    out->checks_passed = hf_selftest_add(&one, 2) == 3;\n", 0, NULL },
    { "selftest-stale-signature.v1",
      "    out->checks_run = 1;\n"
      "    out->checks_passed = hf_selftest_add(1, 2) == 3;\n", 1,
      "-Wint-conversion" },
    { "selftest-werror-only.v1",
      "    int one = 1, unused = 0;\n    out->checks_run = 1;\n"
      "    out->checks_passed = hf_selftest_add(&one, 2) == 3;\n", 1,
      "unused-variable" },
    { "selftest-missing.v1", NULL, 1, "hotfork_stories/selftest_missing_v1.inc" },
};

/* Builds fixture root <fixture>case-<name>/ holding owner.c, the story
 * directory, and (when `body` is set) the story file for `adapter_id`.
 * `dir` receives the root with its trailing '/'. */
static int hfs_selftest_root(const char *fixture, const char *name,
                             const char *adapter_id, const char *body,
                             char *dir, size_t cap)
{
    char rel[ZCL_HOTFORK_UNITY_TU_MAX], path[4096], text[4096];
    if (ovf(snprintf(dir, cap, "%scase-%s/", fixture, name), cap) ||
        ovf(snprintf(path, sizeof path, "%s%s", dir, ZCL_HOTFORK_STORY_DIR),
            sizeof path) || csr_mkdirs(path) ||
        ovf(snprintf(path, sizeof path, "%sowner.c", dir), sizeof path) ||
        csr_write(path, k_hfs_owner))
        return 2;
    if (!body)
        return 0;
    if (!zcl_hotfork_story_path(adapter_id, rel, sizeof rel) ||
        ovf(snprintf(path, sizeof path, "%s%s", dir, rel), sizeof path) ||
        ovf(snprintf(text, sizeof text, "%s%s%s", k_hfs_story_head, body,
                     k_hfs_story_tail), sizeof text))
        return 2;
    return csr_write(path, text);
}

static int hfs_selftest_expect(const char *dir, const char *work,
                               const char *label, const char *adapter_id,
                               const struct hfs_case *want, int *failed)
{
    struct hfs_row row = { label, "owner.c", "", adapter_id,
                           "hf_selftest_add" };
    struct hfs_set set = { dir, work, &row, 1 };
    int red = 0;
    int rc = hfs_check(&set, &red);
    if (rc)
        return rc;
    const char *verdict = want->want_red ? "RED" : "GREEN";
    if ((red != 0) != (want->want_red != 0)) {
        fprintf(stderr, "SELFTEST FAIL: %s expected %s, got %d problem(s)\n",
                label, verdict, red);
        *failed = 1;
        return 0;
    }
    if (want->want_log && !strstr(g_hfs_log, want->want_log)) {
        fprintf(stderr, "SELFTEST FAIL: %s was RED without the expected "
                "compiler reason '%s'\n", label, want->want_log);
        *failed = 1;
        return 0;
    }
    printf("  selftest ok: %s -> %s\n", label, verdict);
    (void)fflush(stdout);
    return 0;
}

static int hfs_selftest_case(const char *fixture, const char *work, size_t i,
                             int *failed)
{
    const struct hfs_case *c = &k_hfs_cases[i];
    char dir[4096], name[32];
    if (ovf(snprintf(name, sizeof name, "%zu", i), sizeof name) ||
        hfs_selftest_root(fixture, name, c->adapter_id, c->body, dir,
                          sizeof dir))
        return 2;
    return hfs_selftest_expect(dir, work, c->adapter_id, c->adapter_id, c,
                               failed);
}

/* A story file no manifest row claims fails even beside a good story. */
static int hfs_selftest_orphan(const char *fixture, const char *work,
                               int *failed)
{
    char dir[4096], path[4096];
    const struct hfs_case *good = &k_hfs_cases[0];
    if (hfs_selftest_root(fixture, "orphan", good->adapter_id, good->body,
                          dir, sizeof dir) ||
        ovf(snprintf(path, sizeof path, "%s%sorphan_v1.inc", dir,
                     ZCL_HOTFORK_STORY_DIR), sizeof path) ||
        csr_write(path, "/* claimed by no row */\n"))
        return 2;
    const struct hfs_case orphan = { good->adapter_id, good->body, 1, NULL };
    return hfs_selftest_expect(dir, work, "selftest-orphan-story",
                               good->adapter_id, &orphan, failed);
}

static int hfs_selftest_body(const char *fixture, const char *work)
{
    int failed = 0, rc = 0;
    size_t count = sizeof k_hfs_cases / sizeof k_hfs_cases[0];
    for (size_t i = 0; rc == 0 && i < count; i++)
        rc = hfs_selftest_case(fixture, work, i, &failed);
    if (rc == 0)
        rc = hfs_selftest_orphan(fixture, work, &failed);
    if (rc)
        return rc;
    if (failed)
        return 1;
    puts("check-hotfork-stories selftest: OK");
    return 0;
}

int check_hotfork_stories_selftest(void)
{
    char root[4096], fixture[4096], work[4096];
    int rc = hfs_root(root, sizeof root);
    if (rc == 0)
        rc = hfs_workdir(root, "hotfork-stories-selftest", fixture,
                         sizeof fixture - 1);
    if (rc)
        return rc;
    strcat(fixture, "/");
    if (ovf(snprintf(work, sizeof work, "%swork", fixture), sizeof work) ||
        csr_mkdirs(work))
        rc = 2;
    if (rc == 0 && (puts("══ check-hotfork-stories selftest ══") < 0 ||
                    fflush(stdout) != 0))
        rc = die("z23-lint: write failed\n", "");
    if (rc == 0)
        rc = hfs_selftest_body(fixture, work);
    int cl = rap_rm_rf(fixture);
    return rc ? rc : cl;
}
