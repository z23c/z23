/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * z23-sem-replay: measure, on real commits, what the semantic facts plan
 * saves in compiles and test groups, and check it against the objects make
 * actually rebuilt. See docs/work/SEMANTIC_MANIFEST.md, "Replay on real
 * history", and docs/dev/DEVELOPING.md.
 *
 * This is a reporting tool only. Nothing in `make ff`, `t-fast`,
 * `t-fast-exact`, the land path or the proof path reads its output, spawns
 * it, or is gated on its exit code; its only registered caller is its own
 * self-test (group sem_replay). It exits nonzero on a code false negative
 * (too narrow: an object make rebuilt that the facts plan left out) so a
 * human running it notices; that exit never reaches any other gate. It
 * also reports, per commit and in the headline total, every false-wide TU
 * (too wide: one a plan selected whose object bytes did not move against
 * the parent's build) for both the facts plan and the plain plan; an
 * over-selection is never fatal to the run.
 *
 *   z23-sem-replay run    --repo R --state S --sensor X --planner Y
 *                         --commits FILE [--jobs N] [--devbuild PATH]
 *                         [--max-steps N]
 *   z23-sem-replay step   ... --index I --commit C
 *   z23-sem-replay repro  --repo R --state S [--label L] [--jobs N]
 *   z23-sem-replay catalog --repo R --state S [--jobs N]
 *   z23-sem-replay report --state S
 *
 * run replays each commit of FILE (one full SHA per line, oldest first) in
 * its own step, through `devbuild --wait` when --devbuild names it, so the
 * host scheduler admits each commit's builds and parses separately. A
 * finished step leaves run/<NN>_<commit>/result.tsv and is skipped when the
 * run resumes. A left-out object whose code changed stops the run (exit 3;
 * debug-only misses are counted, not stopped on). R is a dedicated
 * worktree the replay checks out; it must hold no other work.
 *
 * catalog compiles every TU of R cold with make's argv, records its compile
 * CPU in S/catalog_cost.tsv (the report prices uncosted TUs with it), and
 * fails when any cold object differs from the incremental one. */
#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE /* realpath */
#endif

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "sem_replay.h"
#include "sem_replay_build.h"
#include "sem_replay_step.h"

static int usage(void)
{
    fprintf(stderr,
            "usage: z23-sem-replay run|step|repro|catalog|report --repo DIR --state DIR\n"
            "       [--sensor BIN] [--planner BIN] [--commits FILE] [--jobs N]\n"
            "       [--devbuild BIN] [--index N] [--commit SHA] [--label NAME]\n"
            "       [--max-steps N]\n");
    return 2;
}

struct opts {
    struct sr_cfg cfg;
    char commits[SR_PATH];
    char label[64];
    int max_steps; /* 0: every remaining step */
};

static bool abs_path(const char *in, char out[SR_PATH])
{
    char buf[PATH_MAX];
    if (realpath(in, buf) == NULL) {
        fprintf(stderr, "sem-replay: %s: %s\n", in, strerror(errno));
        return false;
    }
    snprintf(out, SR_PATH, "%s", buf);
    return true;
}

/* The absolute path of this binary, which run re-executes per step: argv0
 * itself when it holds a slash, else its first match on PATH, as execvp
 * found it (an empty PATH entry is the working directory). */
static bool self_path(const char *argv0, char out[SR_PATH])
{
    const char *path = getenv("PATH");
    char cand[SR_PATH];
    if (strchr(argv0, '/') != NULL || path == NULL)
        return abs_path(argv0, out);
    for (const char *p = path; *p != '\0';) {
        size_t n = strcspn(p, ":");
        snprintf(cand, sizeof(cand), "%.*s/%s", (int)(n ? n : 1), n ? p : ".", argv0);
        if (access(cand, X_OK) == 0)
            return abs_path(cand, out);
        p += n + (p[n] == ':');
    }
    return abs_path(argv0, out);
}

static bool opt_value(struct opts *o, const char *key, const char *v)
{
    struct sr_cfg *c = &o->cfg;
    if (strcmp(key, "--repo") == 0)
        return abs_path(v, c->repo);
    if (strcmp(key, "--state") == 0)
        return sr_mkdirs(v) && abs_path(v, c->state);
    if (strcmp(key, "--sensor") == 0)
        return abs_path(v, c->sensor);
    if (strcmp(key, "--planner") == 0)
        return abs_path(v, c->planner);
    if (strcmp(key, "--devbuild") == 0)
        return abs_path(v, c->devbuild);
    if (strcmp(key, "--commits") == 0)
        return abs_path(v, o->commits);
    if (strcmp(key, "--jobs") == 0)
        return (c->jobs = atoi(v)) > 0 && c->jobs <= 8;
    if (strcmp(key, "--index") == 0)
        return (c->index = atoi(v)) >= 0;
    if (strcmp(key, "--commit") == 0)
        return snprintf(c->commit, sizeof(c->commit), "%s", v) > 0;
    if (strcmp(key, "--max-steps") == 0)
        return (o->max_steps = atoi(v)) > 0;
    if (strcmp(key, "--label") == 0)
        return snprintf(o->label, sizeof(o->label), "%s", v) > 0;
    fprintf(stderr, "sem-replay: unknown option %s\n", key);
    return false;
}

static bool parse_opts(int argc, char **argv, struct opts *o)
{
    memset(o, 0, sizeof(*o));
    o->cfg.jobs = 8;
    snprintf(o->label, sizeof(o->label), "check");
    if (!self_path(argv[0], o->cfg.self))
        return false;
    for (int i = 2; i + 1 < argc; i += 2)
        if (!opt_value(o, argv[i], argv[i + 1]))
            return false;
    return argc % 2 == 0 && o->cfg.state[0] != '\0';
}

static bool step_done(const struct sr_cfg *c, int index, const char *commit)
{
    char path[SR_PATH];
    snprintf(path, sizeof(path), "%s/run/%03d_%.10s/result.tsv", c->state, index, commit);
    return sr_exists(path);
}

static int spawn_step(const struct sr_cfg *c, int index, const char *commit)
{
    char idx[16], jobs[16], log[SR_PATH];
    snprintf(idx, sizeof(idx), "%d", index);
    snprintf(jobs, sizeof(jobs), "%d", c->jobs);
    snprintf(log, sizeof(log), "%s/run.log", c->state);
    char *tail[] = {(char *)c->self, "step", "--repo", (char *)c->repo, "--state",
                    (char *)c->state, "--sensor", (char *)c->sensor, "--planner",
                    (char *)c->planner, "--jobs", jobs, "--index", idx, "--commit",
                    (char *)commit, NULL};
    char *with[20] = {(char *)c->devbuild, "--wait"};
    size_t k = 2;
    for (size_t i = 0; tail[i]; i++)
        with[k++] = tail[i];
    with[k] = NULL;
    return sr_run(c->devbuild[0] ? with : tail, c->repo, log, NULL, NULL);
}

static int run_all(const struct opts *o)
{
    char *text = NULL;
    size_t len = 0;
    if (!sr_read_file(o->commits, &text, &len)) {
        fprintf(stderr, "sem-replay: cannot read %s\n", o->commits);
        return 2;
    }
    int rc = 0, index = 0, ran = 0;
    if (memchr(text, '\0', len) != NULL) {
        fprintf(stderr, "sem-replay: malformed commit list %s (embedded NUL)\n", o->commits);
        rc = 2;
        goto done;
    }
    for (char *line = strtok(text, "\n"); line && rc == 0 && (o->max_steps == 0 || ran < o->max_steps);
         line = strtok(NULL, "\n")) {
        index++;
        line[strcspn(line, " \t\r")] = '\0';
        if (line[0] == '\0' || line[0] == '#' || step_done(&o->cfg, index, line))
            continue;
        fprintf(stderr, "sem-replay: step %d %s\n", index, line);
        rc = spawn_step(&o->cfg, index, line);
        ran++;
    }
done:
    free(text);
    if (rc == SR_STEP_FALSE_NEGATIVE)
        fprintf(stderr, "sem-replay: stopped at a code false negative (see MISSES.tsv)\n");
    return rc;
}

/* argv: print the compile argv make gives one TU (--commit names the TU). */
static int print_argv(const struct sr_cfg *c)
{
    char epoch[SR_PATH];
    struct sr_strv tus = {0};
    struct sr_argv_map m = {0};
    bool ok = sr_epoch_dir(c->repo, epoch) && sr_strv_push(&tus, c->commit) &&
              sr_make_argv(c->repo, epoch, &tus, NULL, &m);
    const struct sr_strv *flags = ok ? sr_argv_find(&m, c->commit) : NULL;
    for (size_t i = 0; flags && i < flags->n; i++)
        printf("%s\n", flags->v[i]);
    sr_argv_free(&m);
    sr_strv_free(&tus);
    return flags ? 0 : 1;
}

static bool need_tools(const struct sr_cfg *c)
{
    bool ok = c->repo[0] && c->sensor[0] && c->planner[0];
    if (!ok)
        fprintf(stderr, "sem-replay: --repo, --sensor and --planner are required\n");
    return ok;
}

/* The commands that need only the repo and state; -1 when cmd is none. */
static int run_offline(const char *cmd, struct opts *o)
{
    if (strcmp(cmd, "report") == 0)
        return sr_report(&o->cfg);
    if (strcmp(cmd, "argv") == 0)
        return o->cfg.repo[0] && o->cfg.commit[0] ? print_argv(&o->cfg) : usage();
    if (strcmp(cmd, "catalog") == 0)
        return o->cfg.repo[0] ? sr_catalog(&o->cfg) : usage();
    if (strcmp(cmd, "repro") == 0)
        return o->cfg.repo[0] ? sr_repro(&o->cfg, o->label) : usage();
    return -1;
}

int main(int argc, char **argv)
{
    struct opts o;
    if (argc < 2 || !parse_opts(argc, argv, &o))
        return usage();
    const char *cmd = argv[1];
    int rc = run_offline(cmd, &o);
    if (rc >= 0)
        return rc;
    if (!need_tools(&o.cfg))
        return usage();
    if (strcmp(cmd, "run") == 0)
        return o.commits[0] ? run_all(&o) : usage();
    if (strcmp(cmd, "step") == 0)
        return o.cfg.commit[0] ? sr_step(&o.cfg) : usage();
    return usage();
}
