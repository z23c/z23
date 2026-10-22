/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Acceptance bar for ops.host.gc (tools/command/native_ops_host_gc.c over
 * the engine in tools/command/host_gc_sweep.c): the janitor never deletes work.
 *
 * Three real `git worktree add` generations in a throwaway repository under
 * test-tmp, each in one state the engine must respect:
 *
 *   gen-inuse    a live child process whose cwd is inside it   -> KEPT in_use
 *   gen-locked   `git worktree lock`                           -> KEPT locked
 *   gen-orphan   neither, and back-dated past the age floor    -> REAPED
 *
 * Both keeps are younger than the floor, so the class labels are asserted,
 * not just totals. A dry run changes nothing; an apply reclaims only the
 * orphan; every leaf in the engine's protected-tree table (including the two
 * live datadir names, reached only through the table) is refused by name
 * under a throwaway fixture home; a directory holding blk*.dat is refused by
 * contents.
 *
 * It also never abandons space: `git worktree remove` unregisters a worktree
 * even if the directory survives, so one generation git leaves behind must
 * be finished off (reclaimed, refusals empty), and one whose parent is
 * read-only must appear in refusals[] by name.
 */

#include "test/test_core.h"

#include "command/host_gc_sweep.h"
#include "command/native_command.h"
#include "util/spawn.h"
#include "platform/os_proc.h"

#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <sys/wait.h>
#include <unistd.h>

enum { HGT_PATH = 512, HGT_OUT = 8192 };

/* git through the same bounded capture seam the engine uses: no shell
 * string anywhere in this fixture either. */
static bool hgt_git(const char *dir, const char *const *args)
{
    const char *argv[24];
    size_t n = 0;
    char out[HGT_OUT];
    argv[n++] = "git";
    if (dir && dir[0]) {
        argv[n++] = "-C";
        argv[n++] = dir;
    }
    for (size_t i = 0; args[i]; i++) {
        if (n + 1 >= sizeof(argv) / sizeof(argv[0]))
            return false;
        argv[n++] = args[i];
    }
    argv[n] = NULL;
    return zcl_spawn_capture(argv, out, sizeof(out), 60000) == 0;
}

static bool hgt_exists(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0;
}

static bool hgt_write(const char *path, const char *text)
{
    FILE *f = fopen(path, "wb");
    if (!f)
        return false;
    if (fputs(text, f) == EOF) {
        (void)fclose(f);
        return false;
    }
    return fclose(f) == 0;
}

/* A repository with exactly one commit. Identity and signing are pinned on
 * the command line so a global gitconfig cannot decide whether the fixture
 * builds. The committed .gitignore lets a generation carry build output and
 * a vendored dependency and still be git-clean. */
static bool hgt_make_repo(const char *repo)
{
    static const char *const init[] = { "init", "-q", "-b", "main", NULL };
    static const char *const add[] = { "add", "-A", NULL };
    static const char *const commit[] = {
        "-c", "user.name=z23-test", "-c", "user.email=z23@example.invalid",
        "-c", "commit.gpgsign=false", "commit", "-q", "--allow-empty",
        "-m", "fixture", NULL };
    static const char *const origin[] = { "update-ref",
                                          "refs/remotes/origin/main", "HEAD",
                                          NULL };
    char seed[HGT_PATH];
    char ignore[HGT_PATH];
    if (mkdir(repo, 0700) != 0 || !hgt_git(repo, init))
        return false;
    (void)snprintf(seed, sizeof(seed), "%s/seed.txt", repo);
    (void)snprintf(ignore, sizeof(ignore), "%s/.gitignore", repo);
    if (!hgt_write(seed, "fixture\n") ||
        !hgt_write(ignore, "out/\nvendor/\nbuild/\n"))
        return false;
    return hgt_git(repo, add) && hgt_git(repo, commit) &&
           hgt_git(repo, origin);
}

static bool hgt_add_gen(const char *repo, const char *pool, const char *name,
                        char *out, size_t cap)
{
    const char *args[8];
    if ((size_t)snprintf(out, cap, "%s/%s", pool, name) >= cap)
        return false;
    args[0] = "worktree";
    args[1] = "add";
    args[2] = "--detach";
    args[3] = "-q";
    args[4] = out;
    args[5] = "HEAD";
    args[6] = NULL;
    return hgt_git(repo, args);
}

/* Back-date a directory past the age floor. The engine reads mtime, so
 * moving mtime is the whole fixture. */
static bool hgt_backdate(const char *path, int hours)
{
    struct timespec ts[2];
    struct stat st;
    if (stat(path, &st) != 0)
        return false;
    ts[0].tv_sec = st.st_atime;
    ts[0].tv_nsec = 0;
    ts[1].tv_sec = st.st_mtime - (time_t)hours * 3600;
    ts[1].tv_nsec = 0;
    return utimensat(AT_FDCWD, path, ts, 0) == 0;
}

/* A live process sitting in `dir`. It never returns into harness code: the
 * child chdirs and parks until the parent kills it by its exact pid. */
static bool hgt_child_ready(int fd)
{
    char byte = 0;
    ssize_t n;
    do { n = read(fd, &byte, 1); } while (n < 0 && errno == EINTR);
    close(fd);
    return n == 1 && byte == 'R';
}

static pid_t hgt_occupy_mode(const char *dir, bool fd_only)
{
    int ready[2];
    if (pipe(ready) != 0) return -1;
    pid_t pid = fork();
    if (pid == 0) {
        close(ready[0]);
        if (fd_only) {
            char file[HGT_PATH];
            (void)snprintf(file, sizeof(file), "%s/out/held", dir);
            if (chdir("/") != 0 || open(file, O_RDONLY) < 0) _exit(2);
        } else if (chdir(dir) != 0) _exit(2);
        if (write(ready[1], "R", 1) != 1) _exit(3);
        close(ready[1]);
        for (;;) pause();
    }
    close(ready[1]);
    bool ready_child = hgt_child_ready(ready[0]);
    if (pid > 0 && ready_child) return pid;
    if (pid > 0) { kill(pid, SIGKILL); waitpid(pid, NULL, 0); }
    return -1;
}

static pid_t hgt_occupy(const char *dir)
{
    return hgt_occupy_mode(dir, false);
}

/* A generation shaped like a finished dev proof: a build-complete marker
 * naming a build identity and the time the build finished. `ident` stands
 * in for all four identity digests at once; only equality matters. */
static bool hgt_add_donor(const char *repo, const char *pool, const char *name,
                          const char *ident, int completed, char *out,
                          size_t cap)
{
    char build[HGT_PATH + 16], marker[HGT_PATH + 64], body[1024];
    if (!hgt_add_gen(repo, pool, name, out, cap))
        return false;
    (void)snprintf(build, sizeof(build), "%s/build", out);
    (void)snprintf(marker, sizeof(marker), "%s/.proof-build-complete", build);
    (void)snprintf(body, sizeof(body),
                   "zcl.proof_build_complete.v1\nroot=%s\nlocal=%s\n"
                   "base=base\ncompleted=%d\ncompiler=%s\nflags=%s\n"
                   "environment=%s\nbuild_graph=%s\n",
                   repo, name, completed, ident, ident, ident, ident);
    return mkdir(build, 0700) == 0 && hgt_write(marker, body) &&
           hgt_backdate(out, 48);
}

static const struct host_gc_class *hgt_class(const struct host_gc_report *r,
                                             const char *name)
{
    for (size_t i = 0; i < r->nclasses; i++)
        if (strcmp(r->classes[i].name, name) == 0)
            return &r->classes[i];
    return NULL;
}

static const char *hgt_refusal(const struct host_gc_report *r,
                               const char *path)
{
    for (size_t i = 0; i < r->nrefusals; i++)
        if (strcmp(r->refusals[i].path, path) == 0)
            return r->refusals[i].reason;
    return NULL;
}

static void hgt_seed_request(struct host_gc_request *req, const char *pool)
{
    const char *home = getenv("HOME");
    memset(req, 0, sizeof(*req));
    req->floor_hours = HOST_GC_DEFAULT_FLOOR_HOURS;
    (void)snprintf(req->home, sizeof(req->home), "%s", home ? home : "/");
    (void)snprintf(req->pools[0].name, sizeof(req->pools[0].name), "z23p");
    (void)snprintf(req->pools[0].path, sizeof(req->pools[0].path), "%s", pool);
    req->npools = 1;
    /* Inventory completeness is deterministic here; actual native cwd/fd
     * protection is qualified separately with acknowledged child processes. */
    (void)snprintf(req->proc_root, sizeof(req->proc_root), "%s/.hgt-proc", pool);
    (void)mkdir(req->proc_root, 0700);
    char occupied[HGT_PATH], procdir[HGT_PATH], fddir[HGT_PATH], cwd[HGT_PATH];
    (void)snprintf(occupied, sizeof(occupied), "%s/gen-inuse", pool);
    if (hgt_exists(occupied)) {
        (void)snprintf(procdir, sizeof(procdir), "%s/1", req->proc_root);
        (void)mkdir(procdir, 0700);
        (void)snprintf(fddir, sizeof(fddir), "%s/fd", procdir);
        (void)mkdir(fddir, 0700);
        (void)snprintf(cwd, sizeof(cwd), "%s/cwd", procdir);
        (void)unlink(cwd);
        if (symlink(occupied, cwd) != 0)
            fprintf(stderr, "hgt_seed_request: symlink %s -> %s: %s\n", cwd, occupied,
                    strerror(errno));
    }

}

/* Exercise the advertised command boundary; every request is an explicit dry run. */
static bool hgt_handle_roots(const struct json_value *roots,
                             struct zcl_command_reply *reply)
{
    struct json_value input;
    json_init(&input);
    json_set_object(&input);
    zcl_command_reply_init(reply, "zcl.host_gc.v1");
    bool ok = json_push_kv_bool(&input, "apply", false) &&
              json_push_kv(&input, "roots", roots);
    if (ok) {
        struct zcl_command_request request = { .input = &input };
        zcl_native_handle_ops_host_gc(&request, reply);
    }
    json_free(&input);
    return ok;
}

static bool hgt_root_report_matches(const struct zcl_command_reply *reply,
                                    const char *pool, const char *expected)
{
    const struct json_value *classes = json_get(&reply->data, "classes");
    const struct json_value *row = json_at(classes, 0);
    const struct json_value *apply = json_get(&reply->data, "apply");
    const struct json_value *reclaimed =
        json_get(json_get(&reply->data, "totals"), "bytes_reclaimed");
    return reply->status == ZCL_COMMAND_STATUS_PASSED &&
        reply->exit_code == ZCL_COMMAND_EXIT_OK &&
        classes && classes->type == JSON_ARR && json_size(classes) == 1 &&
        !strcmp(json_get_str(json_get(row, "path")), pool) &&
        !strcmp(json_get_str(json_get(row, "class")), expected) &&
        apply && apply->type == JSON_BOOL && !json_get_bool(apply) &&
        reclaimed && reclaimed->type == JSON_INT && json_get_int(reclaimed) == 0;
}

static bool hgt_valid_root(const char *pool, unsigned form)
{
    struct json_value roots, element;
    json_init(&roots); json_set_array(&roots);
    json_init(&element);
    bool built = true;
    if (form == 0) {
        json_set_str(&element, pool);
    } else {
        json_set_object(&element);
        built = json_push_kv_str(&element, "path", pool);
        if (form == 1 || form == 3)
            built = built && json_push_kv_str(&element, "class",
                                             form == 1 ? "selected-pool" : "");
    }
    built = built && json_push_back(&roots, &element);
    struct zcl_command_reply reply;
    bool called = hgt_handle_roots(&roots, &reply);
    const char *expected = form == 1 ? "selected-pool" : "pool";
    bool ok = built && called && hgt_root_report_matches(&reply, pool, expected);
    zcl_command_reply_free(&reply);
    json_free(&roots); json_free(&element);
    return ok;
}

static bool hgt_invalid_roots(const char *text)
{
    struct json_value roots;
    json_init(&roots);
    if (!json_read(&roots, text, strlen(text))) {
        json_free(&roots);
        return false;
    }
    struct zcl_command_reply reply;
    bool called = hgt_handle_roots(&roots, &reply);
    bool ok = called && reply.status == ZCL_COMMAND_STATUS_FAILED &&
        reply.exit_code == ZCL_COMMAND_EXIT_INVALID &&
        !strcmp(reply.error.code, "host_gc.roots_invalid") &&
        !reply.error.mutated;
    zcl_command_reply_free(&reply);
    json_free(&roots);
    return ok;
}

#if defined(__APPLE__)
static void hgt_count_path(const char *path, void *opaque)
{
    (void)path;
    (*(unsigned *)opaque)++;
}

static int hgt_vnode_error_tests(const char *pool, const char *orphan)
{
    int failures = 0;
    int fd = -1;
    TEST("host gc: live vnode ENOENT is incomplete and cannot authorize apply") {
        char path[HGT_PATH];
        (void)snprintf(path, sizeof(path), "%s/out/held", orphan);
        fd = open(path, O_RDONLY);
        ASSERT(fd >= 0);
        uint64_t pid = os_proc_current_pid();
        unsigned observations = 0;
        /* A complete own-process baseline makes this targeted refusal
         * independent of ambient permission failures on other processes. */
        ASSERT(os_proc_test_visit_pid_paths(pid, hgt_count_path, &observations));
        ASSERT(observations > 0);
        os_proc_test_path_vnode_error(pid, fd, ENOENT);
        bool complete = os_proc_test_visit_pid_paths(pid, hgt_count_path, &observations);
        ASSERT(os_proc_test_path_vnode_error_seen());
        ASSERT(!complete && fcntl(fd, F_GETFD) >= 0);
        struct host_gc_request req;
        struct host_gc_report report;
        hgt_seed_request(&req, pool);
        req.proc_root[0] = '\0';
        req.apply = true;
        os_proc_test_path_vnode_error(pid, fd, ENOENT);
        ASSERT(host_gc_run(&req, &report));
        ASSERT(os_proc_test_path_vnode_error_seen());
        const struct host_gc_class *cls = hgt_class(&report, "z23p");
        ASSERT(cls != NULL && cls->bytes_reclaimed == 0);
        const char *reason = hgt_refusal(&report, orphan);
        ASSERT(reason != NULL && strcmp(reason, "process_inventory_incomplete") == 0);
        ASSERT(hgt_exists(orphan));
        PASS();
    }
_test_next:
    os_proc_test_path_vnode_error(0, -1, 0);
    if (fd >= 0) close(fd);
    return failures;
}

static bool hgt_native_truncation_refused(void)
{
    unsigned observations = 0;
    os_proc_test_path_capacity(1);
    bool complete = os_proc_visit_paths(hgt_count_path, &observations);
    os_proc_test_path_capacity(0);
    return !complete;
}
#endif

static int hgt_inventory_tests(const char *pool, const char *inuse,
                                const char *locked, const char *orphan)
{
    int failures = 0;
    pid_t fd_child = -1;
    TEST("host gc: native cwd/fd observations and incomplete inventory retain work") {
        struct host_gc_request req;
        struct host_gc_report report;
        hgt_seed_request(&req, pool);
        req.proc_root[0] = '\0';
        ASSERT(host_gc_run(&req, &report));
        const struct host_gc_class *cls = hgt_class(&report, "z23p");
        ASSERT(cls != NULL && cls->in_use == 1);
        ASSERT(hgt_exists(inuse));
        char out[HGT_PATH], held[HGT_PATH];
        (void)snprintf(out, sizeof(out), "%s/out", orphan);
        (void)snprintf(held, sizeof(held), "%s/held", out);
        ASSERT(mkdir(out, 0700) == 0);
        ASSERT(hgt_write(held, "held\n"));
        ASSERT(hgt_backdate(orphan, 48));
        fd_child = hgt_occupy_mode(orphan, true);
        ASSERT(fd_child > 0);
        req.apply = true;
        ASSERT(host_gc_run(&req, &report));
        cls = hgt_class(&report, "z23p");
        ASSERT(cls != NULL && cls->in_use == 2);
        ASSERT(cls->bytes_reclaimed == 0);
        ASSERT(hgt_exists(inuse) && hgt_exists(orphan) && hgt_exists(locked));
        ASSERT(kill(fd_child, SIGKILL) == 0);
        ASSERT(waitpid(fd_child, NULL, 0) == fd_child);
        fd_child = -1;
        req.apply = false;
        ASSERT(host_gc_run(&req, &report));
        cls = hgt_class(&report, "z23p");
        ASSERT(cls != NULL && cls->in_use == 1);
        hgt_seed_request(&req, pool);
        char synthetic[HGT_PATH];
        (void)snprintf(synthetic, sizeof(synthetic), "%s/1/cwd", req.proc_root);
        ASSERT(unlink(synthetic) == 0);
        char sibling[HGT_PATH];
        (void)snprintf(sibling, sizeof(sibling), "%s-other", inuse);
        ASSERT(symlink(sibling, synthetic) == 0);
        ASSERT(host_gc_run(&req, &report));
        cls = hgt_class(&report, "z23p");
        ASSERT(cls != NULL && cls->in_use == 0);
        /* Missing explicit inventory is deterministic even for privileged
         * test runners; no chmod-based permission assumption. */
        (void)snprintf(req.proc_root, sizeof(req.proc_root), "%s/no-inventory", pool);
        req.apply = true;
        ASSERT(host_gc_run(&req, &report));
        cls = hgt_class(&report, "z23p");
        ASSERT(cls != NULL && cls->need_review == 1 && cls->bytes_reclaimed == 0);
        const char *reason = hgt_refusal(&report, orphan);
        ASSERT(reason != NULL && strcmp(reason, "process_inventory_incomplete") == 0);
        ASSERT(hgt_exists(orphan));
#if defined(__APPLE__)
        ASSERT(hgt_native_truncation_refused());
#endif
        PASS();
    }
_test_next:
    if (fd_child > 0) { kill(fd_child, SIGKILL); waitpid(fd_child, NULL, 0); }
    return failures;
}

static int hgt_handler_tests(const char *pool, const char *inuse,
                              const char *locked, const char *orphan)
{
    int failures = 0;

    TEST("host gc: command accepts typed roots and preserves dry-run class/path") {
        for (unsigned form = 0; form < 4; form++)
            ASSERT(hgt_valid_root(pool, form));
        ASSERT(hgt_exists(inuse) && hgt_exists(locked) && hgt_exists(orphan));
        PASS();
    }

    TEST("host gc: command refuses malformed roots, fields and pool counts") {
        static const char *const invalid[] = {
            "[]", "null", "false", "1", "\"/unused\"",
            "{\"path\":\"/unused\"}",
            "[null]", "[false]", "[1]", "[[]]",
            "[\"\"]", "[\"relative\"]", "[{}]",
            "[{\"path\":null}]", "[{\"path\":false}]",
            "[{\"path\":1}]", "[{\"path\":[]}]",
            "[{\"path\":{}}]", "[{\"path\":\"\"}]",
            "[{\"path\":\"relative\"}]",
            "[{\"path\":\"/unused\",\"class\":null}]",
            "[{\"path\":\"/unused\",\"class\":false}]",
            "[{\"path\":\"/unused\",\"class\":1}]",
            "[{\"path\":\"/unused\",\"class\":[]}]",
            "[{\"path\":\"/unused\",\"class\":{}}]",
            ("[\"/unused\",\"/unused\",\"/unused\",\"/unused\","
             "\"/unused\",\"/unused\",\"/unused\",\"/unused\",\"/unused\"]"),
        };
        for (size_t i = 0; i < sizeof(invalid)/sizeof(invalid[0]); i++) {
            bool refused = hgt_invalid_roots(invalid[i]);
            if (!refused)
                fprintf(stderr, "host gc malformed roots case %zu: %s\n", i, invalid[i]);
            ASSERT(refused);
        }
        ASSERT(hgt_exists(inuse) && hgt_exists(locked) && hgt_exists(orphan));
        PASS();
    }

_test_next:;
    return failures;
}

/* ---------------------------------------------- clean-only removal rules
 *
 * One repository whose only commit is origin/main and six registered
 * generations, all back-dated:
 *
 *   reach   clean, HEAD is origin/main            -> removed
 *   uniq    clean, HEAD in no other ref           -> pinned under wt, removed
 *   dmod    tracked file modified                 -> kept, listed
 *   duntr   untracked file                        -> kept, listed
 *   dnest   untracked nested repository           -> kept, listed
 *   unit    clean and reachable, named by %h unit -> kept in_use
 */

enum { HGT_OLD_HOURS = 300 };

static bool hgt_out(const char *dir, const char *const *args, char *out,
                    size_t cap)
{
    const char *argv[24];
    size_t n = 0;
    argv[n++] = "git";
    argv[n++] = "-C";
    argv[n++] = dir;
    for (size_t i = 0; args[i] && n + 1 < sizeof(argv) / sizeof(argv[0]); i++)
        argv[n++] = args[i];
    argv[n] = NULL;
    out[0] = '\0';
    return zcl_spawn_capture(argv, out, cap, 60000) == 0;
}

static void hgt_chomp(char *s)
{
    size_t n = strlen(s);
    while (n > 0 && (s[n - 1] == '\n' || s[n - 1] == '\r'))
        s[--n] = '\0';
}

static int hgt_count_refs(const char *repo, const char *prefix)
{
    const char *args[] = { "for-each-ref", "--format=%(refname)", prefix,
                           NULL };
    char out[HGT_OUT];
    int n = 0;
    if (!hgt_out(repo, args, out, sizeof(out)))
        return -1;
    for (const char *p = out; *p; p++)
        n += *p == '\n';
    return n;
}

struct hgt_arch {
    char root[HGT_PATH], repo[HGT_PATH], pool[HGT_PATH], units[HGT_PATH];
    char reach[HGT_PATH], uniq[HGT_PATH], dmod[HGT_PATH], duntr[HGT_PATH];
    char dnest[HGT_PATH], unit[HGT_PATH], fail[HGT_PATH];
};

/* Back-date a worktree directory and the index and HEAD of its gitdir. */
static bool hgt_age(const struct hgt_arch *a, const char *name,
                    const char *wt)
{
    static const char *const files[] = { "index", "HEAD" };
    char path[HGT_PATH + 64];
    if (!hgt_backdate(wt, HGT_OLD_HOURS))
        return false;
    for (size_t i = 0; i < 2; i++) {
        (void)snprintf(path, sizeof(path), "%s/.git/worktrees/%s/%s", a->repo,
                       name, files[i]);
        if (!hgt_backdate(path, HGT_OLD_HOURS))
            return false;
    }
    return true;
}

/* A clean generation whose HEAD is one commit no other ref holds. */
static bool hgt_unique_gen(const struct hgt_arch *a, const char *name,
                           char *path, size_t cap)
{
    const char *commit[] = {
        "-c", "user.name=z23-test", "-c", "user.email=z23@example.invalid",
        "-c", "commit.gpgsign=false", "commit", "-q", "--allow-empty",
        "-m", name, NULL };
    return hgt_add_gen(a->repo, a->pool, name, path, cap) &&
           hgt_git(path, commit) && hgt_age(a, name, path);
}

static bool hgt_arch_dirty(const struct hgt_arch *a)
{
    char file[HGT_PATH + 32], inner[HGT_PATH + 32];
    static const char *const init[] = { "init", "-q", NULL };
    (void)snprintf(file, sizeof(file), "%s/seed.txt", a->dmod);
    if (!hgt_write(file, "changed\n"))
        return false;
    (void)snprintf(file, sizeof(file), "%s/new.txt", a->duntr);
    if (!hgt_write(file, "untracked\n"))
        return false;
    (void)snprintf(inner, sizeof(inner), "%s/inner", a->dnest);
    return mkdir(inner, 0700) == 0 && hgt_git(inner, init);
}

static bool hgt_arch_gens(struct hgt_arch *a)
{
    return hgt_add_gen(a->repo, a->pool, "reach", a->reach, HGT_PATH) &&
           hgt_add_gen(a->repo, a->pool, "dmod", a->dmod, HGT_PATH) &&
           hgt_add_gen(a->repo, a->pool, "duntr", a->duntr, HGT_PATH) &&
           hgt_add_gen(a->repo, a->pool, "dnest", a->dnest, HGT_PATH) &&
           hgt_add_gen(a->repo, a->pool, "unit", a->unit, HGT_PATH) &&
           hgt_unique_gen(a, "uniq", a->uniq, HGT_PATH);
}

static bool hgt_arch_build(struct hgt_arch *a, const char *tmp)
{
    char unit[HGT_PATH + 32];
    (void)snprintf(a->root, sizeof(a->root), "%s/archive", tmp);
    (void)snprintf(a->repo, sizeof(a->repo), "%s/repo", a->root);
    (void)snprintf(a->pool, sizeof(a->pool), "%s/pool", a->root);
    (void)snprintf(a->units, sizeof(a->units), "%s/units", a->root);
    (void)snprintf(unit, sizeof(unit), "%s/job.service", a->units);
    if (mkdir(a->root, 0700) != 0 || mkdir(a->pool, 0700) != 0 ||
        mkdir(a->units, 0700) != 0 || !hgt_make_repo(a->repo) ||
        !hgt_write(unit, "WorkingDirectory=%h/pool/unit\n"))
        return false;
    return hgt_arch_gens(a) && hgt_arch_dirty(a) &&
           hgt_age(a, "reach", a->reach) &&
           hgt_age(a, "dmod", a->dmod) && hgt_age(a, "duntr", a->duntr) &&
           hgt_age(a, "dnest", a->dnest) && hgt_age(a, "unit", a->unit);
}

static void hgt_arch_request(const struct hgt_arch *a,
                             struct host_gc_request *req, bool apply)
{
    hgt_seed_request(req, a->pool);
    (void)snprintf(req->home, sizeof(req->home), "%s", a->root);
    (void)snprintf(req->unit_dir, sizeof(req->unit_dir), "%s", a->units);
    req->age_days = HOST_GC_DEFAULT_AGE_DAYS;
    req->apply = apply;
}

static bool hgt_arch_dirty_kept(const struct hgt_arch *a)
{
    return hgt_exists(a->dmod) && hgt_exists(a->duntr) &&
           hgt_exists(a->dnest) && hgt_exists(a->unit);
}

static bool hgt_listed(const struct host_gc_report *r, const char *path,
                       int min_count)
{
    for (size_t i = 0; i < r->nreviews; i++)
        if (!strcmp(r->reviews[i].path, path))
            return r->reviews[i].dirty_count >= min_count;
    return false;
}

static int hgt_arch_dry(const struct hgt_arch *a)
{
    struct host_gc_request req;
    struct host_gc_report report;
    const struct host_gc_class *cls;
    int failures = 0;

    TEST("host gc clean-only: a dry run lists dirty work and removes nothing") {
        hgt_arch_request(a, &req, false);
        ASSERT(host_gc_run(&req, &report));
        cls = hgt_class(&report, "z23p");
        ASSERT(cls != NULL);
        ASSERT_EQ(cls->registered, 6);
        ASSERT_EQ(cls->reapable, 2);
        ASSERT_EQ(cls->unique_archived, 1);
        ASSERT_EQ(cls->need_review, 3);
        ASSERT_EQ(cls->in_use, 1);
        ASSERT_EQ(report.nreviews, (size_t)3);
        ASSERT(hgt_listed(&report, a->dmod, 1));
        ASSERT(hgt_listed(&report, a->duntr, 1));
        ASSERT(hgt_listed(&report, a->dnest, 1));
        ASSERT(hgt_exists(a->reach) && hgt_exists(a->uniq));
        ASSERT_EQ(hgt_count_refs(a->repo, "refs/archive"), 0);
        PASS();
    }

    TEST("host gc clean-only: age_days 0 keeps a unique HEAD") {
        hgt_arch_request(a, &req, false);
        req.age_days = 0;
        ASSERT(host_gc_run(&req, &report));
        cls = hgt_class(&report, "z23p");
        ASSERT(cls != NULL);
        ASSERT_EQ(cls->reapable, 1);
        ASSERT_EQ(cls->unique_archived, 0);
        ASSERT_EQ(cls->need_review, 4);
        PASS();
    }
_test_next:;
    return failures;
}

static int hgt_arch_apply(const struct hgt_arch *a)
{
    struct host_gc_request req;
    struct host_gc_report report;
    const struct host_gc_class *cls;
    char want[HGT_OUT], got[HGT_OUT];
    const char *head[] = { "rev-parse", "HEAD", NULL };
    const char *list[] = { "for-each-ref", "--format=%(objectname)",
                           "refs/archive/wt", NULL };
    int failures = 0;

    TEST("host gc clean-only: apply removes clean trees, pins the unique HEAD, keeps dirty ones") {
        ASSERT(hgt_out(a->uniq, head, want, sizeof(want)));
        hgt_chomp(want);
        hgt_arch_request(a, &req, true);
        ASSERT(host_gc_run(&req, &report));
        cls = hgt_class(&report, "z23p");
        ASSERT(cls != NULL);
        ASSERT_EQ(cls->unique_archived, 1);
        ASSERT_EQ(cls->kept_on_failure, 0);
        ASSERT(!hgt_exists(a->reach) && !hgt_exists(a->uniq));
        ASSERT(hgt_arch_dirty_kept(a));
        ASSERT_EQ(hgt_count_refs(a->repo, "refs/archive/wt"), 1);
        ASSERT(hgt_out(a->repo, list, got, sizeof(got)));
        hgt_chomp(got);
        ASSERT_STR_EQ(got, want);
        PASS();
    }
_test_next:;
    return failures;
}

/* The pin cannot be written: the unique worktree must stand. */
static int hgt_arch_pin_failure(struct hgt_arch *a)
{
    struct host_gc_request req;
    struct host_gc_report report;
    const struct host_gc_class *cls;
    char dir[HGT_PATH + 32];
    int failures = 0;

    TEST("host gc clean-only: a failed pin keeps the unique worktree") {
        (void)snprintf(dir, sizeof(dir), "%s/.git/refs/archive/wt", a->repo);
        ASSERT(hgt_unique_gen(a, "fail", a->fail, HGT_PATH));
        ASSERT(chmod(dir, 0500) == 0);
        hgt_arch_request(a, &req, true);
        ASSERT(host_gc_run(&req, &report));
        (void)chmod(dir, 0700);
        cls = hgt_class(&report, "z23p");
        ASSERT(cls != NULL);
        ASSERT_EQ(cls->kept_on_failure, 1);
        ASSERT_EQ(cls->unique_archived, 0);
        ASSERT(hgt_exists(a->fail));
        ASSERT_EQ(hgt_count_refs(a->repo, "refs/archive/wt"), 1);
        PASS();
    }
_test_next:;
    return failures;
}

static int hgt_archive_tests(const char *tmp)
{
    struct hgt_arch a;
    int failures = 0;

    TEST("host gc clean-only: the fixture repository and its generations build") {
        memset(&a, 0, sizeof(a));
        ASSERT(hgt_arch_build(&a, tmp));
        PASS();
    }

    failures += hgt_arch_dry(&a);
    failures += hgt_arch_apply(&a);
    failures += hgt_arch_pin_failure(&a);
_test_next:;
    return failures;
}

int test_host_gc(void)
{
    int failures = 0;
    char tmp[HGT_PATH] = "", repo[HGT_PATH] = "", pool[HGT_PATH] = "";
    char fake[HGT_PATH] = "", blk[HGT_PATH] = "";
    char inuse[HGT_PATH] = "", locked[HGT_PATH] = "", orphan[HGT_PATH] = "";
    char left_pool[HGT_PATH] = "", left_gen[HGT_PATH] = "";
    char left_out[HGT_PATH] = "";
    char stuck_pool[HGT_PATH] = "", stuck_gen[HGT_PATH] = "";
    char donor_pool[HGT_PATH] = "", d_a_old[HGT_PATH] = "";
    char d_a_new[HGT_PATH] = "", d_b[HGT_PATH] = "", d_c[HGT_PATH] = "";
    pid_t occupant = -1;

    TEST("host gc: the fixture repository and its three generations build") {
        static const char *const lock[] = { "worktree", "lock", NULL, NULL };
        const char *lock_args[4];
        ASSERT(test_mkdtemp(tmp, sizeof(tmp), "host_gc") != NULL);
        (void)snprintf(repo, sizeof(repo), "%s/repo", tmp);
        (void)snprintf(pool, sizeof(pool), "%s/pool", tmp);
        ASSERT(hgt_make_repo(repo));
        ASSERT(mkdir(pool, 0700) == 0);
        ASSERT(hgt_add_gen(repo, pool, "gen-inuse", inuse, sizeof(inuse)));
        ASSERT(hgt_add_gen(repo, pool, "gen-locked", locked, sizeof(locked)));
        ASSERT(hgt_add_gen(repo, pool, "gen-orphan", orphan, sizeof(orphan)));
        lock_args[0] = lock[0];
        lock_args[1] = lock[1];
        lock_args[2] = locked;
        lock_args[3] = NULL;
        ASSERT(hgt_git(repo, lock_args));
        ASSERT(hgt_backdate(orphan, 48));
        occupant = hgt_occupy(inuse);
        ASSERT(occupant > 0);
        PASS();
    }

    failures += hgt_inventory_tests(pool, inuse, locked, orphan);
#if defined(__APPLE__)
    failures += hgt_vnode_error_tests(pool, orphan);
#endif
    failures += hgt_handler_tests(pool, inuse, locked, orphan);

    TEST("host gc: dry run labels in_use, locked and reapable, and moves nothing") {
        struct host_gc_request req;
        struct host_gc_report report;
        const struct host_gc_class *cls;
        hgt_seed_request(&req, pool);
        ASSERT(host_gc_run(&req, &report));
        cls = hgt_class(&report, "z23p");
        ASSERT(cls != NULL);
        ASSERT_EQ(cls->registered, 3);
        ASSERT_EQ(cls->in_use, 1);
        ASSERT_EQ(cls->locked, 1);
        ASSERT_EQ(cls->reapable, 1);
        ASSERT_EQ(cls->too_young, 0);
        ASSERT_EQ(cls->need_review, 0);
        ASSERT(cls->bytes_reclaimable > 0);
        ASSERT_EQ(cls->bytes_reclaimed, (uint64_t)0);
        ASSERT(hgt_exists(inuse) && hgt_exists(locked) && hgt_exists(orphan));
        PASS();
    }

    TEST("host gc: a stale pool directory does not disable the whole pool") {
        struct host_gc_request req;
        struct host_gc_report report;
        const struct host_gc_class *cls;
        char stale[HGT_PATH];
        char dotgit[HGT_PATH];
        FILE *f;
        /* Administrative gitdir already gone: git answers nothing from inside
         * it, and the outcome must not depend on readdir order. */
        (void)snprintf(stale, sizeof(stale), "%s/gen-stale", pool);
        (void)snprintf(dotgit, sizeof(dotgit), "%s/.git", stale);
        ASSERT(mkdir(stale, 0700) == 0);
        f = fopen(dotgit, "wb");
        ASSERT(f != NULL);
        ASSERT(fputs("gitdir: /nonexistent/worktrees/gen-stale\n", f) != EOF);
        ASSERT(fclose(f) == 0);
        hgt_seed_request(&req, pool);
        ASSERT(host_gc_run(&req, &report));
        cls = hgt_class(&report, "z23p");
        ASSERT(cls != NULL);
        ASSERT_STR_EQ(cls->repo, repo);
        ASSERT_EQ(cls->registered, 3);
        ASSERT_EQ(report.nrefusals, (size_t)0);
        /* Unregistered by git, so never a candidate and never removed. */
        ASSERT(hgt_exists(stale));
        PASS();
    }

    TEST("host gc: the age floor keeps everything when nothing is old enough") {
        struct host_gc_request req;
        struct host_gc_report report;
        const struct host_gc_class *cls;
        hgt_seed_request(&req, pool);
        req.floor_hours = 96;
        ASSERT(host_gc_run(&req, &report));
        cls = hgt_class(&report, "z23p");
        ASSERT(cls != NULL);
        ASSERT_EQ(cls->registered, 3);
        ASSERT_EQ(cls->reapable, 0);
        ASSERT_EQ(cls->too_young, 1);
        ASSERT_EQ(cls->in_use, 1);
        ASSERT_EQ(cls->locked, 1);
        ASSERT(hgt_exists(orphan));
        PASS();
    }

    TEST("host gc: apply reclaims the orphan and nothing else") {
        struct host_gc_request req;
        struct host_gc_report report;
        const struct host_gc_class *cls;
        hgt_seed_request(&req, pool);
        req.apply = true;
        ASSERT(host_gc_run(&req, &report));
        cls = hgt_class(&report, "z23p");
        ASSERT(cls != NULL);
        ASSERT_EQ(cls->reapable, 1);
        ASSERT(cls->bytes_reclaimed > 0);
        ASSERT(!hgt_exists(orphan));
        ASSERT(hgt_exists(inuse));
        ASSERT(hgt_exists(locked));
        PASS();
    }

    TEST("host gc: a generation git leaves behind is finished, not abandoned") {
        struct host_gc_request req;
        struct host_gc_report report;
        const struct host_gc_class *cls;
        char frozen[HGT_PATH];
        char vendor[HGT_PATH], vendor_git[HGT_PATH], vendor_head[HGT_PATH];
        /* A generation shaped like a real one. `out/` is read-only build
         * scratch: git's removal stops there and unregisters the worktree
         * anyway. `vendor/.git` is a directory (vendored submodule shape).
         * Both are .gitignore'd, so git still calls the generation clean. */
        (void)snprintf(left_pool, sizeof(left_pool), "%s/pool-left", tmp);
        ASSERT(mkdir(left_pool, 0700) == 0);
        ASSERT(hgt_add_gen(repo, left_pool, "gen-left", left_gen,
                           sizeof(left_gen)));
        (void)snprintf(vendor, sizeof(vendor), "%s/vendor", left_gen);
        (void)snprintf(vendor_git, sizeof(vendor_git), "%s/.git", vendor);
        (void)snprintf(vendor_head, sizeof(vendor_head), "%s/HEAD",
                       vendor_git);
        (void)snprintf(left_out, sizeof(left_out), "%s/out", left_gen);
        (void)snprintf(frozen, sizeof(frozen), "%s/frozen.txt", left_out);
        ASSERT(mkdir(vendor, 0700) == 0);
        ASSERT(mkdir(vendor_git, 0700) == 0);
        ASSERT(hgt_write(vendor_head, "ref: refs/heads/main\n"));
        ASSERT(mkdir(left_out, 0700) == 0);
        ASSERT(hgt_write(frozen, "build output\n"));
        ASSERT(chmod(left_out, 0500) == 0);
        ASSERT(hgt_backdate(left_gen, 48));
        hgt_seed_request(&req, left_pool);
        req.apply = true;
        ASSERT(host_gc_run(&req, &report));
        cls = hgt_class(&report, "z23p");
        ASSERT(cls != NULL);
        ASSERT_EQ(cls->registered, 1);
        ASSERT_EQ(cls->reapable, 1);
        ASSERT_EQ(cls->need_review, 0);
        ASSERT(cls->bytes_reclaimed > 0);
        ASSERT_EQ(report.nrefusals, (size_t)0);
        ASSERT(!hgt_exists(left_gen));
        PASS();
    }

    TEST("host gc: a generation nothing can remove is refused by name") {
        struct host_gc_request req;
        struct host_gc_report report;
        const struct host_gc_class *cls;
        const char *reason;
        /* The pool directory is read-only, so the generation's final rmdir is
         * impossible; it must be named in refusals[], never silent. */
        (void)snprintf(stuck_pool, sizeof(stuck_pool), "%s/pool-stuck", tmp);
        ASSERT(mkdir(stuck_pool, 0700) == 0);
        ASSERT(hgt_add_gen(repo, stuck_pool, "gen-stuck", stuck_gen,
                           sizeof(stuck_gen)));
        ASSERT(hgt_backdate(stuck_gen, 48));
        /* Establish the complete synthetic inventory before making its
         * parent read-only; otherwise this tests inventory refusal instead
         * of the intended final-rmdir failure. */
        hgt_seed_request(&req, stuck_pool);
        ASSERT(hgt_exists(req.proc_root));
        ASSERT(chmod(stuck_pool, 0500) == 0);
        req.apply = true;
        ASSERT(host_gc_run(&req, &report));
        ASSERT(chmod(stuck_pool, 0700) == 0);
        cls = hgt_class(&report, "z23p");
        ASSERT(cls != NULL);
        ASSERT_EQ(cls->registered, 1);
        ASSERT_EQ(cls->reapable, 0);
        ASSERT_EQ(cls->need_review, 1);
        ASSERT_EQ(cls->bytes_reclaimed, (uint64_t)0);
        reason = hgt_refusal(&report, stuck_gen);
        ASSERT(reason != NULL);
        ASSERT_EQ(strncmp(reason, "remove_failed:", 14), 0);
        ASSERT(hgt_exists(stuck_gen));
        PASS();
    }

    TEST("host gc: the newest complete generation per identity is kept as the warm donor") {
        struct host_gc_request req;
        struct host_gc_report report;
        const struct host_gc_class *cls;
        /* Four finished, idle, clean generations past the age floor. The
         * newest of each identity survives, at most two across the pool; the
         * superseded aa generation and the oldest cc are reaped. */
        (void)snprintf(donor_pool, sizeof(donor_pool), "%s/pool-donor", tmp);
        ASSERT(mkdir(donor_pool, 0700) == 0);
        ASSERT(hgt_add_donor(repo, donor_pool, "d-a-old", "aa", 100, d_a_old,
                             sizeof(d_a_old)));
        ASSERT(hgt_add_donor(repo, donor_pool, "d-a-new", "aa", 400, d_a_new,
                             sizeof(d_a_new)));
        ASSERT(hgt_add_donor(repo, donor_pool, "d-b", "bb", 300, d_b,
                             sizeof(d_b)));
        ASSERT(hgt_add_donor(repo, donor_pool, "d-c", "cc", 200, d_c,
                             sizeof(d_c)));
        hgt_seed_request(&req, donor_pool);
        req.apply = true;
        ASSERT(host_gc_run(&req, &report));
        cls = hgt_class(&report, "z23p");
        ASSERT(cls != NULL);
        ASSERT_EQ(cls->registered, 4);
        ASSERT_EQ(cls->reapable, 2);
        ASSERT_EQ(cls->in_use, 2);
        ASSERT_EQ(cls->need_review, 0);
        ASSERT(hgt_exists(d_a_new));
        ASSERT(hgt_exists(d_b));
        ASSERT(!hgt_exists(d_a_old));
        ASSERT(!hgt_exists(d_c));
        PASS();
    }

    TEST("host gc: every protected leaf is refused by name, never swept") {
        struct host_gc_request req;
        char reason[HOST_GC_REASON_CAP];
        char expect[HOST_GC_REASON_CAP];
        char datadir[HGT_PATH];
        char fixture_home[HGT_PATH];
        size_t nleaves = host_gc_protected_leaf_count();
        /* Walks host_gc_paths.c's protected-leaf table
         * (host_gc_protected_leaf): every protected tree, including the live
         * datadir names, is refused by name without stat(), under this test's
         * throwaway home and without spelling those names as literals. */
        (void)snprintf(fixture_home, sizeof(fixture_home),
                       "%s/fixture-home", tmp);
        hgt_seed_request(&req, pool);
        (void)snprintf(req.home, sizeof(req.home), "%s", fixture_home);
        ASSERT(nleaves > 0);
        for (size_t i = 0; i < nleaves; i++) {
            const char *leaf = host_gc_protected_leaf(i);
            ASSERT(leaf != NULL);
            (void)snprintf(datadir, sizeof(datadir), "%s/%s", fixture_home,
                           leaf);
            ASSERT(host_gc_path_protected(&req, "", datadir, reason,
                                          sizeof(reason)));
            (void)snprintf(expect, sizeof(expect), "protected_tree:%s",
                           leaf);
            ASSERT_STR_EQ(reason, expect);
        }
        PASS();
    }

    TEST("host gc: a directory holding block files is refused by contents") {
        struct host_gc_request req;
        struct host_gc_report report;
        const char *reason;
        FILE *f;
        (void)snprintf(fake, sizeof(fake), "%s/looks-like-a-pool", tmp);
        (void)snprintf(blk, sizeof(blk), "%s/blk00000.dat", fake);
        ASSERT(mkdir(fake, 0700) == 0);
        f = fopen(blk, "wb");
        ASSERT(f != NULL);
        ASSERT(fclose(f) == 0);
        hgt_seed_request(&req, fake);
        ASSERT(host_gc_run(&req, &report));
        reason = hgt_refusal(&report, fake);
        ASSERT(reason != NULL);
        ASSERT_STR_EQ(reason, "holds_chain_data");
        ASSERT(hgt_exists(blk));
        PASS();
    }

    failures += hgt_archive_tests(tmp);

_test_next:;
    /* Restore both read-only fixture directories so the recursive cleanup can run. */
    if (stuck_pool[0])
        (void)chmod(stuck_pool, 0700);
    if (left_out[0])
        (void)chmod(left_out, 0700);
    if (occupant > 0) {
        (void)kill(occupant, SIGKILL);
        (void)waitpid(occupant, NULL, 0);
    }
    if (locked[0]) {
        static const char *const unlock[] = { "worktree", "unlock", NULL,
                                              NULL };
        const char *args[4];
        args[0] = unlock[0];
        args[1] = unlock[1];
        args[2] = locked;
        args[3] = NULL;
        (void)hgt_git(repo, args);
    }
    if (tmp[0])
        (void)test_rm_rf_recursive(tmp);
    if (failures == 0)
        printf("test_host_gc: all passed\n");
    else
        printf("test_host_gc: %d FAILED\n", failures);
    return failures;
}
