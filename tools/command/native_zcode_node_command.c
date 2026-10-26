/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * `z23 join` (canonical path zcode.node.join) — the first command a stranger
 * runs after installing a node.
 *
 * It does exactly three things and says so:
 *   1. reports the join posture THIS process can actually see, through the
 *      one shared reader (zcl_zcode_join_posture_fill, native_zcode_join.c),
 *      so `join`, `zcode work toolchain` and `zcode package offered` can never
 *      disagree about package_hosting / build_worker / joined;
 *   2. detects whether a C23 compiler exists on this host, because
 *      -buildworker=1 on a box with no compiler advertises compile capacity
 *      that can never be delivered;
 *   3. persists -packagehost=1 (always) and -buildworker=1 (only when a
 *      compiler was found) into <datadir>/z23.conf, which engine/entry/main.c reads
 *      after ParseParameters so the next boot picks them up.
 *
 * ── WHAT IT DELIBERATELY DOES NOT DO ──────────────────────────────────────
 * It never starts, stops, signals or restarts anything. systemd owns the node
 * process. tools/scripts/fleet_sync.sh:18-27 records why in blood: the
 * launcher that used to live there was a way to put a SECOND z23 on
 * ONE datadir, which corrupts it. There is deliberately no fallback launcher
 * here either — the reply NAMES the restart and the operator runs it.
 *
 * ── THE TWO TIERS, REPORTED BY NAME ───────────────────────────────────────
 * SWARM needs only -packagehost=1 and rides ordinary P2P peers (gated at
 * engine/composition/src/boot_zcode_swarm.c:494 and :776). No coins, no on-chain
 * identity, no invitation. That is the tier `join` actually delivers.
 *
 * DHT additionally needs -noisetransport plus an ACTIVE on-chain ZID anchor,
 * whose registration spends a fee (chain check
 * engine/composition/src/boot_zcode_dht_chain.c:124-155). It is reported as an OPTIONAL
 * named upgrade and is never presented as a blocker for joining: a node that
 * cannot afford an anchor is still a full member of the swarm.
 */

#include "command/native_command.h"
#include "command/native_zcode_join.h"

#include "base/safe_alloc.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#if defined(_WIN32)
#include "platform/directory_transaction.h"
#endif
#include "util/file_io.h"
#include "util/spawn.h"
#include "util/util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined(_WIN32)
#include <process.h>
#endif
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

/* Bound on an existing z23.conf we are willing to rewrite. A config file this
 * large is not a config file; refusing beats silently truncating an
 * operator's settings. */
#define ZNJ_CONF_MAX_BYTES (64u * 1024u)

static void znj_fail(struct zcl_command_reply *reply, const char *code,
                     const char *message, const char *evidence)
{
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           ZCL_COMMAND_EXIT_FAILED, code, "execute",
                           false, false, message,
                           evidence ? evidence : "zcode.node.join");
}

static bool znj_write_c23_probe(const char *workdir, char *probe_path,
                                size_t probe_cap)
{
    if (!workdir || !workdir[0])
        return false;
    int pn = snprintf(probe_path, probe_cap,
                      "%s/.z23-join-c23-probe.XXXXXX", workdir);
    if (pn <= 0 || (size_t)pn >= probe_cap)
        return false;
    int probe_fd = mkstemp(probe_path);
    if (probe_fd < 0)
        return false;
    FILE *pf = fdopen(probe_fd, "w");
    if (!pf) {
        (void)close(probe_fd);
        (void)unlink(probe_path);
        return false;
    }
    bool wrote = fputs("typedef int z23_c23_probe;\n", pf) >= 0;
    if (fclose(pf) != 0)
        wrote = false;
    if (!wrote) {
        (void)unlink(probe_path);
        return false;
    }
    return true;
}

/* First line of `<compiler> --version`, or NULL, but only after that same
 * driver successfully enters strict C23 mode. A version banner proves that
 * a program exists; it does not prove the node can fulfill C23 build work.
 * The C23 probe compiles a one-declaration translation unit under `workdir`
 * rather than `/dev/null`: `-pedantic-errors` rejects an empty TU, which
 * used to report no compiler on hosts whose driver just built this tree.
 * argv[0] is resolved by execvp's PATH search; no shell is involved. */
static const char *znj_detect_compiler(const char *workdir, char *version,
                                       size_t version_cap)
{
    static const char *const drivers[] = { "cc", "gcc" };
    const char *found = NULL;
    if (version && version_cap)
        version[0] = '\0';

    char probe_path[4700];
    bool wrote_probe = znj_write_c23_probe(workdir, probe_path,
                                           sizeof(probe_path));
    if (!wrote_probe)
        return NULL;

    for (size_t i = 0; i < sizeof(drivers) / sizeof(drivers[0]); i++) {
        const char *argv[] = { drivers[i], "--version", NULL };
        const char *probe_argv[] = {
            drivers[i], "-std=c23", "-pedantic-errors", "-fsyntax-only",
            "-x", "c", probe_path, NULL,
        };
        char out[512];
        if (zcl_spawn_capture(argv, out, sizeof(out), 10000) != 0 || !out[0])
            continue;
        char probe_out[512];
        if (zcl_spawn_capture(probe_argv, probe_out, sizeof(probe_out),
                              10000) != 0)
            continue;
        out[strcspn(out, "\r\n")] = '\0';
        if (!out[0])
            continue;
        if (version && version_cap)
            snprintf(version, version_cap, "%s", out);
        found = drivers[i];
        break;
    }
    (void)unlink(probe_path);
    return found;
}

/* `line` is already trimmed of its newline. Recognises every spelling
 * ReadConfigFile accepts: `flag`, `-flag`, `flag=0`, `-noflag`.
 *
 * The effective boolean this line assigns to `flag`, or -1 when the line
 * does not mention it at all.
 *
 * It returns the VALUE, not merely "the key appeared", because the caller
 * has to decide whether a restart is needed. Presence alone cannot answer
 * that: a node joined on a box with no C23 compiler carries
 * `buildworker=0`, and when a compiler is later installed join writes
 * `buildworker=1` — a real change the operator must act on, but one whose
 * key was present both times. Reading only presence reported "nothing
 * changed" and left the operator with a node that never picks up the new
 * capability. The negated `noflag` spelling is likewise a value (0), not
 * an occurrence of the flag being on. */
static int znj_line_value(const char *line, const char *flag)
{
    const char *s = line;
    while (*s == ' ' || *s == '\t')
        s++;
    if (*s == '-')
        s++;
    bool negated = false;
    if (strncmp(s, "no", 2) == 0 && strncmp(s + 2, flag, strlen(flag)) == 0) {
        negated = true;
        s += 2;
    }
    size_t n = strlen(flag);
    if (strncmp(s, flag, n) != 0)
        return -1;
    s += n;
    while (*s == ' ' || *s == '\t')
        s++;
    int value = 1;
    if (*s == '=') {
        s++;
        while (*s == ' ' || *s == '\t')
            s++;
        value = (*s == '0') ? 0 : 1;
    } else if (*s != '\0') {
        return -1;   /* a longer flag that merely shares this prefix */
    }
    return negated ? !value : value;
}

/* "changed" is about the FLAGS' VALUES, not the bytes: re-running join
 * on an already-joined node rewrites the same two lines and must report
 * that nothing new needs a restart — but a node whose buildworker
 * answer actually flipped must report that it does. */
static void znj_set_conf_changed(bool *changed, int prev_packagehost,
                                 int prev_buildworker, bool build_worker)
{
    if (changed)
        *changed = prev_packagehost != 1 ||
                   prev_buildworker != (build_worker ? 1 : 0);
}

static bool znj_walk_conf_lines(char *existing, bool ok,
                                int *prev_packagehost, int *prev_buildworker,
                                bool (*keep_line)(void *ctx, const char *line),
                                void *ctx)
{
    for (char *line = existing; ok && line && *line;) {
        char *nl = strchr(line, '\n');
        if (nl)
            *nl = '\0';
        int v;
        if ((v = znj_line_value(line, "packagehost")) >= 0) {
            *prev_packagehost = v;
        } else if ((v = znj_line_value(line, "buildworker")) >= 0) {
            *prev_buildworker = v;
        } else if (strncmp(line, "# Written by `z23 join`", 23) != 0) {
            ok = keep_line(ctx, line);
        }
        if (!nl)
            break;
        line = nl + 1;
    }
    return ok;
}

#if defined(_WIN32)
static const char *znj_win_last_sep(const char *path)
{
    const char *slash = strrchr(path, '/');
    const char *backslash = strrchr(path, '\\');
    if (!slash || (backslash && backslash > slash))
        slash = backslash;
    return slash;
}

static bool znj_win_split_conf_path(const char *path, char *directory,
                                    size_t directory_cap, const char **leaf,
                                    char *why, size_t why_cap)
{
    const char *slash = znj_win_last_sep(path);
    size_t directory_len = slash ? (size_t)(slash - path) : 0u;
    if (slash && directory_len == 2u && path[1] == ':')
        directory_len++;
    if (!slash || slash == path || !slash[1] ||
        directory_len >= directory_cap) {
        snprintf(why, why_cap, "config file path is invalid or too long");
        return false;
    }
    memcpy(directory, path, directory_len);
    directory[directory_len] = '\0';
    *leaf = slash + 1;
    return true;
}

static bool znj_win_read_existing(struct platform_directory_transaction *dir,
                                  const char *directory, const char *leaf,
                                  char **existing_out, size_t *existing_len_out,
                                  char *why, size_t why_cap)
{
    struct platform_directory_child source;
    platform_directory_transaction_init(dir);
    platform_directory_child_init(&source);
    *existing_out = NULL;
    *existing_len_out = 0;
    bool ok = platform_directory_transaction_open(dir, directory);
    if (!ok) {
        snprintf(why, why_cap, "config directory is not private or safe");
        return false;
    }

    enum platform_directory_result opened =
        platform_directory_child_open_result(dir, leaf, false, false,
                                             &source, NULL);
    if (opened == PLATFORM_DIRECTORY_OK) {
        struct platform_directory_child_info info;
        ok = platform_directory_child_info(&source, &info) &&
             info.size <= ZNJ_CONF_MAX_BYTES;
        if (ok) {
            *existing_len_out = (size_t)info.size;
            *existing_out = zcl_malloc(*existing_len_out + 1u,
                                       "zcode.node.join.existing-config");
            ok = *existing_out != NULL &&
                 platform_directory_child_read_exact(&source, *existing_out,
                                                     *existing_len_out, 0);
            if (ok)
                (*existing_out)[*existing_len_out] = '\0';
        }
        platform_directory_child_close(&source);
        if (!ok) {
            free(*existing_out);
            platform_directory_transaction_close(dir);
            snprintf(why, why_cap,
                     "existing config file is unreadable or larger than %u bytes",
                     ZNJ_CONF_MAX_BYTES);
            return false;
        }
    } else if (opened != PLATFORM_DIRECTORY_MISSING) {
        platform_directory_transaction_close(dir);
        snprintf(why, why_cap, "existing config file is not a safe regular file");
        return false;
    }
    return true;
}

struct znj_win_conf_buf {
    char *output;
    size_t len;
};

static bool znj_win_keep_line(void *ctx, const char *line)
{
    struct znj_win_conf_buf *buf = ctx;
    size_t line_len = strlen(line);
    memcpy(buf->output + buf->len, line, line_len);
    buf->len += line_len;
    buf->output[buf->len++] = '\n';
    return true;
}

static bool znj_win_publish_conf(struct platform_directory_transaction *dir,
                                 const char *leaf, const char *output,
                                 size_t output_len, bool ok)
{
    struct platform_directory_child staged;
    platform_directory_child_init(&staged);
    char staged_leaf[64];
    int staged_n = snprintf(staged_leaf, sizeof(staged_leaf),
                            "z23.conf.join.%ld.tmp", (long)_getpid());
    bool staged_created = false;
    ok = ok && staged_n > 0 && (size_t)staged_n < sizeof(staged_leaf) &&
         platform_directory_child_create(dir, staged_leaf, &staged) &&
         (staged_created = true) &&
         platform_directory_child_write_exact(&staged, output, output_len,
                                              0) &&
         platform_directory_child_flush(&staged) &&
         platform_directory_child_replace(dir, &staged, leaf, false) &&
         platform_directory_transaction_flush(dir);
    platform_directory_child_close(&staged);
    if (!ok && staged_created)
        (void)platform_directory_child_unlink(dir, staged_leaf, true);
    return ok;
}

static char *znj_win_render_conf(char *existing, size_t existing_len,
                                 bool build_worker, size_t *output_len,
                                 int *prev_packagehost, int *prev_buildworker,
                                 bool *tail_ok)
{
    static const char header[] =
        "# Written by `z23 join`. Command-line flags still win.\n";
    size_t output_cap = existing_len + sizeof(header) + 64u;
    char *output = zcl_malloc(output_cap, "zcode.node.join.config-output");
    if (!output)
        return NULL;
    struct znj_win_conf_buf buf = { output, sizeof(header) - 1u };
    memcpy(output, header, buf.len);
    *prev_packagehost = -1;
    *prev_buildworker = -1;
    (void)znj_walk_conf_lines(existing, true, prev_packagehost,
                              prev_buildworker, znj_win_keep_line, &buf);
    int tail = snprintf(output + buf.len, output_cap - buf.len,
                        "packagehost=1\nbuildworker=%d\n",
                        build_worker ? 1 : 0);
    *tail_ok = tail > 0 && (size_t)tail < output_cap - buf.len;
    if (*tail_ok)
        buf.len += (size_t)tail;
    *output_len = buf.len;
    return output;
}

static bool znj_write_conf_windows(const char *path, bool build_worker,
                                   bool *changed, char *why, size_t why_cap)
{
    char directory[4700];
    const char *leaf = NULL;
    bool split = znj_win_split_conf_path(path, directory, sizeof(directory),
                                         &leaf, why, why_cap);
    if (!split)
        return false;

    struct platform_directory_transaction dir;
    char *existing = NULL;
    size_t existing_len = 0;
    bool read_ok = znj_win_read_existing(&dir, directory, leaf, &existing,
                                         &existing_len, why, why_cap);
    if (!read_ok)
        return false;

    int prev_packagehost = -1;
    int prev_buildworker = -1;
    size_t output_len = 0;
    bool tail_ok = false;
    char *output = znj_win_render_conf(existing, existing_len, build_worker,
                                       &output_len, &prev_packagehost,
                                       &prev_buildworker, &tail_ok);
    if (!output) {
        free(existing);
        platform_directory_transaction_close(&dir);
        snprintf(why, why_cap, "cannot allocate config output");
        return false;
    }
    bool ok = znj_win_publish_conf(&dir, leaf, output, output_len, tail_ok);
    free(output);
    free(existing);
    platform_directory_transaction_close(&dir);
    if (!ok) {
        snprintf(why, why_cap, "cannot atomically publish %s", path);
        return false;
    }
    znj_set_conf_changed(changed, prev_packagehost, prev_buildworker,
                         build_worker);
    return true;
}
#else
static bool znj_posix_keep_line(void *ctx, const char *line)
{
    FILE *f = ctx;
    return fprintf(f, "%s\n", line) >= 0;
}

static bool znj_posix_read_existing(const char *path, char **existing,
                                    size_t *existing_len, char *why,
                                    size_t why_cap)
{
    *existing = NULL;
    *existing_len = 0;
    if (access(path, F_OK) == 0 &&
        !zcl_read_whole_file_text(path, ZNJ_CONF_MAX_BYTES, existing,
                                  existing_len, "zcode.node.join")) {
        snprintf(why, why_cap,
                 "existing config file is unreadable or larger than %u bytes",
                 ZNJ_CONF_MAX_BYTES);
        return false;
    }
    return true;
}

static bool znj_posix_open_temp(const char *path, char *tmp, size_t tmp_cap,
                                FILE **out, char **existing, char *why,
                                size_t why_cap)
{
    int n = snprintf(tmp, tmp_cap, "%s.tmp", path);
    if (n <= 0 || (size_t)n >= tmp_cap) {
        free(*existing);
        *existing = NULL;
        snprintf(why, why_cap, "config file path is too long");
        return false;
    }
    *out = fopen(tmp, "we");
    if (!*out) {
        free(*existing);
        *existing = NULL;
        snprintf(why, why_cap, "cannot create %s", tmp);
        return false;
    }
    return true;
}

static bool znj_posix_write_flags(FILE *f, bool ok, bool build_worker)
{
    ok = ok && fprintf(f, "packagehost=1\n") > 0;
    ok = ok && fprintf(f, "buildworker=%d\n", build_worker ? 1 : 0) > 0;
    /* The bytes must be on the platter before the rename publishes them:
     * the whole point of the temp file is that a torn write is impossible. */
    ok = ok && fflush(f) == 0 && fsync(fileno(f)) == 0;
    if (fclose(f) != 0)
        ok = false;
    return ok;
}

static void znj_posix_fsync_parent(const char *path)
{
    /* The rename is what publishes the file, and a rename is itself only a
     * directory update: fsyncing the bytes leaves a window where the config
     * can vanish entirely on power loss even though it was never torn.
     * Best-effort — losing it costs one re-run of join, so it is not worth
     * failing an otherwise-successful write. */
    char dir[4700];
    snprintf(dir, sizeof(dir), "%s", path);
    char *slash = strrchr(dir, '/');
    if (slash) {
        *slash = '\0';
        int dfd = open(dir[0] ? dir : "/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (dfd >= 0) {
            (void)fsync(dfd);
            (void)close(dfd);
        }
    }
}

static bool znj_write_conf_posix(const char *path, bool build_worker,
                                 bool *changed, char *why, size_t why_cap)
{
    char *existing = NULL;
    size_t existing_len = 0;
    bool read_ok = znj_posix_read_existing(path, &existing, &existing_len,
                                           why, why_cap);
    if (!read_ok)
        return false;

    char tmp[4700];
    FILE *f = NULL;
    bool opened = znj_posix_open_temp(path, tmp, sizeof(tmp), &f, &existing,
                                      why, why_cap);
    if (!opened)
        return false;

    bool ok = fputs("# Written by `z23 join`. Command-line flags still win.\n",
                    f) >= 0;
    /* -1 = the flag is absent from the existing file. A later line wins, as
     * with any repeated setting. */
    int prev_packagehost = -1, prev_buildworker = -1;
    ok = znj_walk_conf_lines(existing, ok, &prev_packagehost,
                             &prev_buildworker, znj_posix_keep_line, f);
    ok = znj_posix_write_flags(f, ok, build_worker);

    if (!ok) {
        (void)unlink(tmp);
        free(existing);
        snprintf(why, why_cap, "cannot write %s", tmp);
        return false;
    }
    if (rename(tmp, path) != 0) {
        (void)unlink(tmp);
        free(existing);
        snprintf(why, why_cap, "cannot publish %s", path);
        return false;
    }
    znj_posix_fsync_parent(path);
    free(existing);
    znj_set_conf_changed(changed, prev_packagehost, prev_buildworker,
                         build_worker);
    return true;
}
#endif

/* Rewrite <datadir>/z23.conf so it carries exactly the flags we decided,
 * preserving every OTHER line the operator put there. Written to a sibling
 * temp file and renamed, so a crash mid-write can never leave a half-parsed
 * config behind. Returns false with `why` filled on any failure. */
static bool znj_write_conf(const char *path, bool build_worker,
                           bool *changed, char *why, size_t why_cap)
{
#if defined(_WIN32)
    return znj_write_conf_windows(path, build_worker, changed, why, why_cap);
#else
    return znj_write_conf_posix(path, build_worker, changed, why, why_cap);
#endif
}

static bool znj_push_tier(struct json_value *data, const char *key,
                          const char *name, const char *requires_,
                          bool optional, const char *note)
{
    struct json_value tier;
    json_init(&tier);
    json_set_object(&tier);
    bool ok = json_push_kv_str(&tier, "tier", name) &&
              json_push_kv_str(&tier, "requires", requires_) &&
              json_push_kv_bool(&tier, "optional", optional) &&
              json_push_kv_str(&tier, "note", note) &&
              json_push_kv(data, key, &tier);
    json_free(&tier);
    return ok;
}

static bool znj_join_paths(const struct zcl_command_request *request,
                           struct zcl_command_reply *reply,
                           const char **datadir_out, char *conf_path,
                           size_t conf_cap)
{
    const struct json_value *dd_in = json_get(request->input, "datadir");
    const char *datadir = dd_in ? json_get_str(dd_in) : NULL;
    if (!datadir || !datadir[0])
        datadir = zcl_native_command_datadir();
    if (!datadir || !datadir[0]) {
        znj_fail(reply, "MISSING_DATADIR",
                 "no datadir given (input datadir or -datadir=DIR)", NULL);
        return false;
    }

    /* Fail closed on a datadir that does not exist rather than minting one: a
     * typo'd path would otherwise create a directory and write a config the
     * real node never reads, and the operator would see a clean success. */
    struct stat st;
    if (stat(datadir, &st) != 0 || !S_ISDIR(st.st_mode)) {
        znj_fail(reply, "DATADIR_MISSING",
                 "that datadir does not exist; start the node once so it "
                 "creates its data directory, or pass -datadir=DIR for the "
                 "instance you meant", datadir);
        return false;
    }

    int n = snprintf(conf_path, conf_cap, "%s/%s", datadir,
                     ZCL_NODE_CONFIG_FILENAME);
    if (n <= 0 || (size_t)n >= conf_cap) {
        znj_fail(reply, "DATADIR_PATH_TOO_LONG",
                 "the datadir path is too long to hold a config file",
                 datadir);
        return false;
    }
    *datadir_out = datadir;
    return true;
}

struct znj_compiler_labels {
    const char *name;
    const char *version;
    const char *wrote_flags;
};

static void znj_compiler_labels(const char *compiler, const char *version,
                                struct znj_compiler_labels *out)
{
    out->name = compiler ? compiler : "";
    out->version = compiler ? version : "";
    out->wrote_flags = compiler ? "packagehost=1 buildworker=1"
                                : "packagehost=1 buildworker=0";
}

static bool znj_push_join_scalars(struct json_value *data, const char *datadir,
                                  const char *conf_path,
                                  const struct zcl_zcode_join_posture *posture,
                                  const char *compiler, bool changed,
                                  const struct znj_compiler_labels *labels)
{
    /* The dispatcher already ran zcl_command_reply_init with this leaf's
     * declared output_schema; re-initializing here would discard it. */
    return json_push_kv_str(data, "datadir", datadir) &&
           json_push_kv_str(data, "config_file", conf_path) &&
           zcl_zcode_join_posture_push_json(data, posture) &&
           json_push_kv_bool(data, "compiler_present", compiler != NULL) &&
           json_push_kv_str(data, "compiler", labels->name) &&
           json_push_kv_str(data, "compiler_version", labels->version) &&
           json_push_kv_str(data, "wrote_flags", labels->wrote_flags) &&
           json_push_kv_bool(data, "config_changed", changed) &&
           /* File facts, distinct from this process's flags. Swarm needs only
            * packagehost=1; `joined` stays "both flags on THIS process". */
           json_push_kv_bool(data, "config_package_hosting", true) &&
           json_push_kv_bool(data, "config_build_worker", compiler != NULL);
}

static bool znj_push_swarm_membership(struct json_value *data,
                                      const char *compiler)
{
    bool ok = json_push_kv_bool(data, "swarm_member", true) &&
              json_push_kv_str(
                  data, "swarm_member_means",
                  "swarm_member is the written file (packagehost=1); joined is "
                  "this process's flags, not the file");
    if (!compiler)
        ok = ok && json_push_kv_str(
                       data, "build_worker_note",
                       "no C23 compiler found on this host, so buildworker "
                       "stays 0: advertising compile capacity this box "
                       "cannot deliver would fail every request it wins");
    return ok;
}

static bool znj_push_join_outcome(struct json_value *data)
{
    bool ok =
        znj_push_tier(data, "swarm_tier", "swarm", "-packagehost=1", false,
                      "package hosting over ordinary P2P peers; no coins, "
                      "no on-chain identity, no invitation") &&
        znj_push_tier(data, "dht_tier", "dht",
                      "-noisetransport plus an ACTIVE on-chain ZID anchor "
                      "(its registration spends a fee)", true,
                      "an optional upgrade, never a blocker: a node "
                      "without an anchor is still a full swarm member");

    /* ── the composed verdict, from THIS vantage ───────────────────────────
     *
     * `join` is a local configuration action. It runs in a one-shot CLI that
     * started no Tor, opened no listener and built no circuit, so it can
     * observe NONE of the four reachability dimensions and none of the four
     * announcement stages. Every field below is therefore UNOBSERVABLE —
     * deliberately not UNCONFIRMED, and emphatically not defaulted to
     * "confirmed" or to "failed":
     *
     *   - claiming CONFIRMED would be an announcement this process cannot
     *     keep, and a node that announces READY early is dialled, fails, and
     *     is scored down for the honesty gap rather than for its speed;
     *   - claiming FAILED would grade a perfectly healthy node "not joined"
     *     purely because the checker was standing in the wrong place. That is
     *     the same defect as a mesh gate that required state=="active" and
     *     read 0/4 for hours while onion P2P was in fact working.
     *
     * latency stays -1: NOT MEASURED, which is neither fast nor slow. A
     * fabricated number here would eventually be read as a threshold, and a
     * threshold tuned on fast storage is how a permissionless network quietly
     * excludes the seek-bound machines it must admit. */
    struct zcl_join_verdict verdict = {
        .reachable = ZCL_JOIN_SIGNAL_UNOBSERVABLE,
        .responsive = ZCL_JOIN_SIGNAL_UNOBSERVABLE,
        .fresh = ZCL_JOIN_SIGNAL_UNOBSERVABLE,
        .serving = ZCL_JOIN_SIGNAL_UNOBSERVABLE,
        .latency_ms = -1,
        .data_age_s = -1,
        .vantage = "this one-shot CLI sees only the local filesystem; the "
                   "resident node answers these through `z23 status` and "
                   "`z23 core network onion health`",
    };
    struct zcl_join_readiness ready = {
        .descriptor_published = ZCL_JOIN_SIGNAL_UNOBSERVABLE,
        .rendezvous_established = ZCL_JOIN_SIGNAL_UNOBSERVABLE,
        .circuit_built = ZCL_JOIN_SIGNAL_UNOBSERVABLE,
        .listener_accepting = ZCL_JOIN_SIGNAL_UNOBSERVABLE,
    };
    ok = ok && zcl_join_verdict_push_json(data, &verdict, &ready) &&
         /* `joined` above is a CONFIGURATION fact (both flags set on this
          * process), not a reachability verdict. Saying so in the reply keeps
          * a convenient scalar from being read as the tuple. */
         json_push_kv_str(data, "joined_means",
                          "joined is a configuration fact, not a reachability "
                          "verdict; read the verdict tuple for that");

    /* systemd (or whatever unit manages this node) owns the process. Say
     * which restart to run; never run it. */
    ok = ok &&
         json_push_kv_bool(data, "restart_required", true) &&
         json_push_kv_str(data, "restart_command",
                          "systemctl --user restart z23-node") &&
         json_push_kv_str(data, "restart_note",
                          "the service manager owns the node process; this "
                          "command started, stopped and signalled nothing. "
                          "Substitute your own unit name if it is not "
                          "zclassic23.");
    return ok;
}

static void znj_add_offered_next(struct zcl_command_reply *reply,
                                 const char *datadir)
{
    /* ONE typed next command, hard-validated against the registry
     * (engine/modules/kernel/src/command_registry.c:1993-2034) rather than an untyped
     * next_safe_command string: after the restart, `zcode package offered`
     * reports the same posture plus the resident engine and eligible peer
     * facts needed to distinguish configured hosting from live service.
     * The next input must name THIS datadir: `{}` would inspect the
     * canonical node instead of the file join just wrote. */
    char next_in[512];
    struct json_value ni;
    json_init(&ni);
    json_set_object(&ni);
    bool nio = json_push_kv_str(&ni, "datadir", datadir);
    size_t nn = nio ? json_write(&ni, next_in, sizeof(next_in)) : 0;
    json_free(&ni);
    (void)zcl_command_reply_add_next(
        reply, "zcode.package.offered",
        (nn > 0 && nn < sizeof(next_in)) ? next_in : "{}",
        "after the restart above, verify resident Commons service");
}

static bool znj_emit_join_reply(struct zcl_command_reply *reply,
                                const char *datadir, const char *conf_path,
                                const struct zcl_zcode_join_posture *posture,
                                const char *compiler,
                                const char *compiler_version, bool changed)
{
    struct znj_compiler_labels labels;
    znj_compiler_labels(compiler, compiler_version, &labels);
    struct json_value *data = &reply->data;
    bool ok = znj_push_join_scalars(data, datadir, conf_path, posture,
                                    compiler, changed, &labels) &&
              znj_push_swarm_membership(data, compiler) &&
              znj_push_join_outcome(data);
    if (!ok) {
        znj_fail(reply, "JOIN_REPLY_REFUSED",
                 "the join reply object refused a field", conf_path);
        return false;
    }
    znj_add_offered_next(reply, datadir);
    return true;
}

void zcl_native_handle_zcode_node_join(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;

    const char *datadir = NULL;
    char conf_path[4600];
    bool paths = znj_join_paths(request, reply, &datadir, conf_path,
                                sizeof(conf_path));
    if (!paths)
        return;

    struct zcl_zcode_join_posture posture;
    if (!zcl_zcode_join_posture_fill(&posture)) {
        znj_fail(reply, "JOIN_POSTURE_UNREADABLE",
                 "this process could not read its own join posture", NULL);
        return;
    }

    char compiler_version[256];
    const char *compiler =
        znj_detect_compiler(datadir, compiler_version,
                            sizeof(compiler_version));

    char why[256] = {0};
    bool changed = false;
    if (!znj_write_conf(conf_path, compiler != NULL, &changed, why,
                        sizeof(why))) {
        znj_fail(reply, "CONFIG_WRITE_FAILED",
                 why[0] ? why : "the config file could not be written",
                 conf_path);
        return;
    }

    if (!znj_emit_join_reply(reply, datadir, conf_path, &posture, compiler,
                             compiler_version, changed))
        return;
}
