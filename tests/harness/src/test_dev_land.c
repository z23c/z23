/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ACCEPTANCE BAR for dev.land (tools/command/native_dev_land.c).
 *
 * Queue cases use isolated state and real git rigs, with the exact proof
 * replaced by ZCL_LAND_PROOF_STUB. Rebase, push, rows and locks use the
 * production paths. Watcher-admission cases separately use inert scheduler
 * fixtures to exercise structured arguments, refusal and a bounded timeout;
 * they cannot establish real watcher or proof readiness.
 *
 * The handler is called DIRECTLY, which is exactly what the CLI does after
 * input validation — and the input is additionally validated through the
 * real registry first, so a key the .def never declared is caught here
 * rather than passing in-process and failing from a shell.
 */

#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif

#include "test/test_dev_land_common.h"
#include "command/native_dev_land_selfupgrade.h"
#include "dev_proof_receipt.h"
#if !defined(_WIN32)
#include <poll.h>
#endif


#if defined(__linux__)
#include "test/app_ui_fixture.h"
#include <sys/prctl.h>

static bool dlx_su_fixture_marker(const char *state)
{
    static const char token[] = "z23-land-selfupgrade-test-v1";
    char path[1400], actual[sizeof(token)];
    struct stat st;
    if (!state || snprintf(path, sizeof(path), "%s/.land-selfupgrade-fixture", state) >= (int)sizeof(path))
        return false;
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return false;
    bool ok = fstat(fd, &st) == 0 && S_ISREG(st.st_mode) &&
        st.st_uid == getuid() && (st.st_mode & 077) == 0 &&
        read(fd, actual, sizeof(actual)) == (ssize_t)(sizeof(token) - 1) &&
        memcmp(actual, token, sizeof(token) - 1) == 0;
    if (close(fd) != 0) ok = false;
    return ok;
}
extern void zcl_native_dev_land_test_trial_entry_hook(void (*hook)(void));

static void dlx_su_crash_after_entry(void)
{
    const char *trace = getenv("ZCL_LAND_TEST_FIXTURE_TRACE");
    FILE *event = trace ? fopen(trace, "a") : NULL;
    if (!event || fprintf(event, "entered\n") < 0 || fclose(event) != 0) _exit(125);
    _exit(77);
}

static void dlx_su_pause_trial(void)
{
    const char *mode = getenv("ZCL_LAND_TEST_FIXTURE_MODE");
    const char *ready = getenv("ZCL_LAND_TEST_FIXTURE_READY");
    const char *release = getenv("ZCL_LAND_TEST_FIXTURE_RELEASE");
    int r = ready ? open(ready, O_RDWR | O_CLOEXEC) : -1;
    int g = release ? open(release, O_RDWR | O_CLOEXEC) : -1;
    if (r < 0 || g < 0) _exit(125);
    if (mode && !strcmp(mode, "pick_cancel")) {
        zcl_native_dev_land_test_pick_barrier(r, g);
        return;
    }
    char marker = 'R';
    if (write(r, &marker, 1) != 1) _exit(125);
    struct pollfd p = {.fd = g, .events = POLLIN};
    if (poll(&p, 1, 30000) != 1 || read(g, &marker, 1) != 1 || marker != 'G') _exit(125);
    close(r); close(g);
}

struct dlx_su_cli_options {
    const char *view, *cursor;
    size_t budget, items;
};

static bool dlx_su_cli_input(int argc, char **argv, bool decision,
                              struct json_value *input)
{
    if (strcmp(argv[5], "--json")) return false;
    if (!decision)
        return !strncmp(argv[4], "--input=", 8) &&
            json_read(input, argv[4] + 8, strlen(argv[4] + 8)) && input->type == JSON_OBJ;
    char *end = NULL;
    errno = 0;
    long long seq = !strncmp(argv[4], "--seq=", 6) ? strtoll(argv[4] + 6, &end, 10) : 0;
    return argc == 6 && seq > 0 && !errno && end && !*end &&
           json_push_kv_int(input, "seq", seq);
}

static bool dlx_su_cli_number(const char *arg, const char *value,
                              struct dlx_su_cli_options *opt)
{
    char *end = NULL;
    errno = 0;
    unsigned long long n = strtoull(value, &end, 10);
    if (errno || !end || *end || n > SIZE_MAX) return false;
    if (!strncmp(arg, "--budget-bytes=", 15) && !opt->budget) opt->budget = (size_t)n;
    else if (!strncmp(arg, "--max-items=", 12) && !opt->items) opt->items = (size_t)n;
    else return false;
    return true;
}

static bool dlx_su_cli_options(int argc, char **argv, struct dlx_su_cli_options *opt)
{
    for (int i = 6; i < argc; ++i) {
        const char *value = strchr(argv[i], '=');
        if (!value || !value[1]) return false;
        ++value;
        if (!strncmp(argv[i], "--view=", 7) && !opt->view) opt->view = value;
        else if (!strncmp(argv[i], "--cursor=", 9) && !opt->cursor) opt->cursor = value;
        else if (!dlx_su_cli_number(argv[i], value, opt)) return false;
    }
    return true;
}

static bool dlx_su_child_authorized(int argc, char **argv)
{
    const char *marker = getenv("ZCL_LAND_TEST_FIXTURE_STATE");
    const char *state = getenv("XDG_STATE_HOME");
    const char *enabled = getenv("ZCL_LAND_TEST_FIXTURE_CHILD");
    return marker && state && !strcmp(marker, state) && dlx_su_fixture_marker(state) &&
        enabled && !strcmp(enabled, "1") && argc >= 6 && !strcmp(argv[1], "dev") &&
        !strcmp(argv[2], "land");
}

static bool dlx_su_child_trace(const char *action)
{
    const char *trace = getenv("ZCL_LAND_TEST_FIXTURE_TRACE");
    if (!trace) return true;
    FILE *event = fopen(trace, "a");
    if (!event) return false;
    bool ok = fprintf(event, "%s\n", action) >= 0;
    if (fclose(event) != 0) ok = false;
    return ok;
}

static bool dlx_su_child_mode(bool drive)
{
    const char *mode = getenv("ZCL_LAND_TEST_FIXTURE_MODE");
    if (!drive || !mode) return true;
    if (!strcmp(mode, "crash"))
        zcl_native_dev_land_test_trial_entry_hook(dlx_su_crash_after_entry);
    if (!strcmp(mode, "entry_cancel") || !strcmp(mode, "pick_cancel"))
        zcl_native_dev_land_test_trial_entry_hook(dlx_su_pause_trial);
    return strcmp(mode, "wrongrow") || setenv("ZCL_LAND_SU_TRIAL_SEQ", "999", 1) == 0;
}

static const struct zcl_command_spec *dlx_su_child_spec(
    const struct zcl_command_registry *registry, const char *path, bool drive,
    struct zcl_command_spec *fixture)
{
    const struct zcl_command_spec *spec = zcl_command_registry_find(registry, path, NULL);
    if (!drive) return spec;
    if (!spec || spec->availability != ZCL_COMMAND_COMPAT || spec->handler) return NULL;
    *fixture = *spec;
    fixture->availability = ZCL_COMMAND_READY;
    fixture->handler = zcl_native_handle_dev_land;
    fixture->availability_reason = "";
    fixture->compat_target = "";
    return fixture;
}

static void dlx_su_child_execute(const struct zcl_command_registry *registry,
    const struct zcl_command_spec *spec, const char *path, bool ok,
    struct json_value *input, const struct dlx_su_cli_options *options)
{
    struct zcl_command_context context = {.registry = registry, .dev_build = true,
        .authority_ceiling = ZCL_COMMAND_AUTH_OPERATOR, .granted_capabilities = UINT64_MAX,
        .source_root = getenv("ZCL_DEV_SOURCE_ROOT"), .one_shot_process = true};
    char wire[65536];
    enum zcl_command_exit exit_code = ZCL_COMMAND_EXIT_INVALID;
    size_t n = ok && spec && context.source_root
        ? zcl_command_registry_execute_json(registry, spec, &context, input,
              false, path, options->view, options->budget, options->items, options->cursor,
              wire, sizeof(wire), &exit_code)
        : 0;
    json_free(input);
    if (!n || n >= sizeof(wire) || fwrite(wire, 1, n, stdout) != n ||
        fputc(10, stdout) == EOF || fflush(stdout) != 0)
        _exit(125);
    _exit((int)exit_code);
}

/* Only explicit isolated fixtures may dispatch this executable as a driver.
 * The registry validates input and serializes the real production reply. */
void dlx_selfupgrade_child_exit_if_requested(int argc, char **argv)
{
    if (!dlx_su_child_authorized(argc, argv)) return;
    bool decision = !strcmp(argv[3], "decision");
    bool drive = !strcmp(argv[3], "drive");
    if (!decision && !drive) return;
    struct json_value input = {0};
    json_set_object(&input);
    struct dlx_su_cli_options options = {0};
    bool ok = dlx_su_cli_input(argc, argv, decision, &input) &&
              dlx_su_cli_options(argc, argv, &options);
    ok = ok && dlx_su_child_trace(argv[3]);
    if (ok && !dlx_su_child_mode(drive)) _exit(125);
    const struct zcl_command_registry *registry = zcl_command_catalog();

    const char *path = decision ? "dev.land.decision" : "dev.land.drive";
    struct zcl_command_spec fixture_spec;
    const struct zcl_command_spec *spec = dlx_su_child_spec(registry, path, drive, &fixture_spec);
    dlx_su_child_execute(registry, spec, path, ok, &input, &options);

}
#else
void dlx_selfupgrade_child_exit_if_requested(int argc, char **argv)
{ (void)argc; (void)argv; }
#endif

#if !defined(_WIN32)
struct dlx_scope_case {
    struct dlx_rig rig;
    char queue[16384], origin[64], wt[1400];
    size_t queue_len;
};

static bool dlx_decision_run(struct dlx_call *c)
{
    char why[256];
    if (!c->request.spec || !c->request.spec->handler ||
        !zcl_command_registry_input_validate(c->request.spec, &c->input,
                                             why, sizeof(why))) return false;
    c->request.spec->handler(&c->request, &c->reply);
    return true;
}

static bool dlx_scope_state_matches(void)
{
    const char *xdg = getenv("XDG_STATE_HOME");
    if (!g_dlx_state[0]) return false;
    if (xdg && xdg[0]) return strcmp(xdg, g_dlx_state) == 0;
    const char *home = getenv("HOME");
    char base[4096];
    if (!home || !home[0]) return false;
    int n = snprintf(base, sizeof(base), "%s/.local/state", home);
    return n > 0 && (size_t)n < sizeof(base) && strcmp(base, g_dlx_state) == 0;
}

static bool dlx_scope_fence_prepare(struct dlx_rig *rig, const char *tag,
                                    char base[64], char wt[1400], char tip[64])
{
    return dlx_scope_state_matches() && dlx_fence_prepare(rig, tag, base, wt, tip);
}

static int dlx_scope_isolation_guard(void)
{
    int failures = 0;
    char saved[1024] = "", other[512], path[1400], base[64], wt[1400], tip[64];
    struct dlx_rig rig = {0};
    struct stat info;
    TEST("land: scope preparation refuses absent or mismatched isolated state") {
        dlx_isolate("drive_seq_scope_guard");
        (void)snprintf(saved, sizeof(saved), "%s", g_dlx_state);
        test_make_tmpdir(other, sizeof(other), "dev_land", "scope_guard_other");
        ASSERT(setenv("XDG_STATE_HOME", other, 1) == 0);
        ASSERT(!dlx_scope_fence_prepare(&rig, "scope_guard_mismatch", base, wt, tip));
        (void)snprintf(path, sizeof(path), "%s/z23/dev/land/queue.jsonl", other);
        ASSERT(lstat(path, &info) != 0 && errno == ENOENT);
        ASSERT(setenv("XDG_STATE_HOME", saved, 1) == 0);
        g_dlx_state[0] = '\0';
        ASSERT(!dlx_scope_fence_prepare(&rig, "scope_guard_absent", base, wt, tip));
        (void)snprintf(path, sizeof(path), "%s/z23/dev/land/queue.jsonl", saved);
        ASSERT(lstat(path, &info) != 0 && errno == ENOENT);
        PASS();
    }
_test_next:;
    if (saved[0]) (void)snprintf(g_dlx_state, sizeof(g_dlx_state), "%s", saved);
    dlx_restore();
    return failures;
}

static bool dlx_scope_submit(const struct dlx_rig *rig, const char *tip)
{
    if (!dlx_scope_state_matches()) return false;
    struct dlx_call c;
    dlx_submit(&c, rig, tip);
    bool ok = dlx_run(&c) && dlx_ok(&c);
    dlx_end(&c);
    return ok;
}

static bool dlx_scope_number(const char *old, const char *replacement,
                              const char *old_priority, const char *priority)
{
    return dlx_queue_field_once(old, old, replacement) &&
           dlx_queue_field_once(replacement, old_priority, priority);
}

static bool dlx_scope_terminal(struct dlx_scope_case *t, const char *state,
                                const char *base, const char *later)
{
    struct dlx_call c;
    dlx_begin(&c, "cancel");
    (void)json_push_kv_int(&c.input, "seq", 685);
    bool ok = dlx_run(&c) && dlx_ok(&c);
    dlx_end(&c);
    if (!ok || strcmp(state, "cancelled") == 0) return ok;
    char land[1200], path[1400], row[4096], wire[4200];
    dlx_landdir(land, sizeof(land));
    (void)snprintf(path, sizeof(path), "%s/outcomes.jsonl", land);
    if (!dlx_chain_row(row, sizeof(row), 685, t->rig.clone, later, base,
                        state, 0, NULL, NULL)) return false;
    int n = snprintf(wire, sizeof(wire), "%s\n", row);
    return n > 0 && (size_t)n < sizeof(wire) && dlx_write(path, wire);
}

static bool dlx_scope_prepare(struct dlx_scope_case *t, const char *tag,
                               const char *terminal)
{
    char base[64], later[64];
    dlx_isolate(tag);
    setenv("ZCL_LAND_PROOF_STUB", "running", 1);
    setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
    if (!dlx_rig_make(&t->rig, tag) || !dlx_origin_main(&t->rig, base) ||
        !dlx_scope_submit(&t->rig, t->rig.tip) ||
        !dlx_commit(t->rig.clone, "later.txt", "later\n", later) ||
        !dlx_scope_submit(&t->rig, later) ||
        !dlx_scope_number("\"seq\":1,", "\"seq\":674,",
                           "\"priority_seq\":1,", "\"priority_seq\":674,") ||
        !dlx_scope_number("\"seq\":2,", "\"seq\":685,",
                           "\"priority_seq\":2,", "\"priority_seq\":685,") ||
        (terminal && !dlx_scope_terminal(t, terminal, base, later)))
        return false;
    dlx_land_wt(t->wt, sizeof(t->wt));
    return dlx_queue_bytes(t->queue, sizeof(t->queue), &t->queue_len) &&
           dlx_origin_main(&t->rig, t->origin);
}


static bool dlx_scope_unchanged(const struct dlx_scope_case *t)
{
    char queue[16384], origin[64];
    size_t len = 0;
    struct stat info;
    return dlx_queue_bytes(queue, sizeof(queue), &len) && len == t->queue_len &&
           memcmp(queue, t->queue, len) == 0 &&
           dlx_origin_main(&t->rig, origin) && strcmp(origin, t->origin) == 0 &&
           lstat(t->wt, &info) != 0 && errno == ENOENT;
}

#if defined(__linux__)
/* The signed receipt is a trusted test-producer fixture, not build provenance. */
static bool dlx_su_binary_write(const char *path, const void *data, size_t size)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0) return false;
    const unsigned char *bytes = data;
    bool ok = true;
    while (size) {
        ssize_t n = write(fd, bytes, size);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { ok = false; break; }
        bytes += n; size -= (size_t)n;
    }
    if (fchmod(fd, 0600) != 0) ok = false;
    if (close(fd) != 0) ok = false;
    return ok;
}

static bool dlx_su_write_all(int target, const char *buffer, size_t len)
{
    size_t done = 0;
    while (done < len) {
        ssize_t n = write(target, buffer + done, len - done);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return false;
        done += (size_t)n;
    }
    return true;
}

static bool dlx_su_copy_body(int source, int target, struct sha3_256_ctx *sha)
{
    char buffer[65536];
    for (;;) {
        ssize_t n = read(source, buffer, sizeof(buffer));
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) return false;
        if (!n) return true;
        if (sha) sha3_256_write(sha, (const uint8_t *)buffer, (size_t)n);
        if (target >= 0 && !dlx_su_write_all(target, buffer, (size_t)n)) return false;
    }
}

static bool dlx_su_copy_original(const char *path, struct stat *before)
{
    int source = open("/proc/self/exe", O_RDONLY | O_CLOEXEC);
    int target = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0700);
    if (source < 0 || target < 0) {
        if (source >= 0) close(source);
        if (target >= 0) close(target);
        return false;
    }
    bool ok = fstat(source, before) == 0 && dlx_su_copy_body(source, target, NULL);
    if (close(source) != 0) ok = false;
    if (fchmod(target, 0700) != 0) ok = false;
    if (close(target) != 0) ok = false;
    return ok;
}
static bool dlx_su_tag_digest(const char *path, uint8_t digest[32], const struct stat *before)
{
    static const char domain[] = "zcl.dev_proof_executable_reuse.v1";
    static const char tag[] = "Z23-LAND-TEST-CANDIDATE";
    struct stat after; struct sha3_256_ctx sha;
    int target = open(path, O_RDWR | O_APPEND | O_CLOEXEC | O_NOFOLLOW);
    bool ok = target >= 0 && fstat(target, &after) == 0 && S_ISREG(after.st_mode) &&
        after.st_size > 0 && (uint64_t)after.st_size + sizeof(tag) - 1 <= (UINT64_C(256) << 20);
    if (ok) ok = dlx_su_write_all(target, tag, sizeof(tag) - 1);
    sha3_256_init(&sha); sha3_256_write(&sha, (const uint8_t *)domain, sizeof(domain));
    if (ok) ok = lseek(target, 0, SEEK_SET) == 0 && dlx_su_copy_body(target, -1, &sha);
    if (ok) sha3_256_finalize(&sha, digest);
    if (target >= 0 && close(target) != 0) ok = false;
    if (ok) printf("[test selfupgrade] executable bytes before=%lld after=%lld\n",
                   (long long)before->st_size, (long long)(after.st_size + sizeof(tag) - 1));
    return ok;
}
static bool dlx_su_copy_executable(const char *path, uint8_t digest[32])
{
    struct stat before;
    if (!dlx_su_copy_original(path, &before)) return false;
    const char *argv[] = {"strip", "--strip-debug", path, NULL}; char output[1024] = {0};
    if (zcl_spawn_capture(argv, output, sizeof(output), 30000) != 0) {
        fprintf(stderr, "[test selfupgrade] debug stripping failed: %s\n", output);
        return false;
    }
    return dlx_su_tag_digest(path, digest, &before);
}

static bool dlx_su_write_signed_fixture(const char *root, const char *local,
    const char *base, const uint8_t evidence[32],
    const uint8_t child[ZCL_DEV_PROOF_CHILD_WIRE_BYTES],
    const uint8_t wire[ZCL_DEV_PROOF_WIRE_BYTES])
{
    char dir[1400], path[1600], hex[65], child_path[1600];
    zcl_hex_encode(evidence, 32, hex);
    if (snprintf(dir, sizeof(dir), "%s/.cache/zcl-dev-proof/children", root) >= (int)sizeof(dir) ||
        !dlx_mkdir_p(dir) ||
        snprintf(child_path, sizeof(child_path), "%s/%s.child", dir, hex) >= (int)sizeof(child_path) ||
        !dlx_su_binary_write(child_path, child, ZCL_DEV_PROOF_CHILD_WIRE_BYTES) ||
        snprintf(dir, sizeof(dir), "%s/.cache/zcl-dev-proof/receipts", root) >= (int)sizeof(dir) ||
        !dlx_mkdir_p(dir) ||
        snprintf(path, sizeof(path), "%s/%s-%s.receipt", dir, local, base) >= (int)sizeof(path))
        return false;
    return dlx_su_binary_write(path, wire, ZCL_DEV_PROOF_WIRE_BYTES);
}

static bool dlx_su_signed_candidate(const char *root, const char *local,
                                     const char *base, char artifact[1400])
{
    uint8_t evidence[32], child[ZCL_DEV_PROOF_CHILD_WIRE_BYTES];
    uint8_t wire[ZCL_DEV_PROOF_WIRE_BYTES];
    struct zcl_dev_acceptance_receipt_v1 receipt = {0};
    if (snprintf(artifact, 1400, "%s/artifact", root) >= 1400 ||
        !dlx_su_copy_executable(artifact, evidence) ||
        !zcl_dev_proof_oid_decode(local, receipt.local_commit, &receipt.local_commit_len) ||
        !zcl_dev_proof_oid_decode(base, receipt.remote_base, &receipt.remote_base_len)) return false;
    uint8_t *roots[] = {receipt.source_root, receipt.source_cas_root, receipt.mutation_root,
        receipt.changed_set_root, receipt.impact_policy_root, receipt.compiler_root,
        receipt.flags_root, receipt.environment_root, receipt.build_graph_root};
    for (size_t n = 0; n < sizeof(roots) / sizeof(roots[0]); ++n) memset(roots[n], (int)n + 1, 32);
    struct zcl_dev_proof_dimension *compile = &receipt.dimensions[ZCL_DEV_PROOF_COMPILE];
    memcpy(compile->receipt_root, evidence, 32); compile->selected = 1; compile->reused = 1;
    struct zcl_dev_proof_dimension *lint = &receipt.dimensions[ZCL_DEV_PROOF_LINT];
    memset(lint->receipt_root, 42, 32); lint->selected = 1; lint->ran = 1;
    receipt.policy_version = ZCL_DEV_PROOF_POLICY_VERSION; receipt.complete = 1;
    if (!zcl_dev_proof_child_receipt_create(ZCL_DEV_PROOF_COMPILE, compile, child) ||
        !zcl_dev_proof_receipt_child_set_root(&receipt, receipt.child_set_root) ||
        !zcl_dev_proof_receipt_seal(&receipt) ||
        !zcl_dev_proof_receipt_serialize(&receipt, wire)) return false;
    return dlx_su_write_signed_fixture(root, local, base, compile->receipt_root, child, wire);

}

static bool dlx_su_drive(struct dlx_call *c, long long seq,
                         const struct zcl_command_context *context)
{
    dlx_begin(c, "drive");
    c->request.context = context;
    c->request.view = "normal";
    return json_push_kv_int(&c->input, "seq", seq) && dlx_run(c);
}

static unsigned dlx_su_lines(const char *text, const char *word)
{
    unsigned count = 0;
    size_t n = strlen(word);
    for (const char *p = text; (p = strstr(p, word)) != NULL; p += n) ++count;
    return count;
}

static bool dlx_su_signed_landing(const struct json_value *row, const char *expected_tip)
{
    const char *state = json_get_str(json_get(row, "state"));
    const char *tip = json_get_str(json_get(row, "remote_tip"));
    const char *source = json_get_str(json_get(row, "remote_source"));
    const char *signer = json_get_str(json_get(row, "remote_signer"));
    const char *signature = json_get_str(json_get(row, "remote_signature"));
    uint8_t signer_bytes[32], signature_bytes[64];
    return state && !strcmp(state, "landed") && tip && !strcmp(tip, expected_tip) &&
        source && source[0] && signer && strlen(signer) == 64 && signature &&
        strlen(signature) == 128 &&
        zcl_hex_decode_lower(signer, signer_bytes, sizeof(signer_bytes)) &&
        zcl_hex_decode_lower(signature, signature_bytes, sizeof(signature_bytes));
}

static bool dlx_su_one_landed_outcome(int64_t seq, const char *expected_tip)
{
    struct dlx_call c;
    dlx_begin_status(&c);
    bool ok = dlx_run(&c) && dlx_ok(&c);
    const struct json_value *rows = dlx_arr(&c, "outcomes");
    unsigned count = 0;
    if (!rows) ok = false;
    for (size_t i = 0; ok && i < rows->num_children; ++i) {
        const struct json_value *row = &rows->children[i];
        if (json_get_int(json_get(row, "seq")) != seq) continue;
        ok = dlx_su_signed_landing(row, expected_tip);
        ++count;
    }
    dlx_end(&c);
    return ok && count == 1;
}

static bool dlx_su_no_outcome(int64_t seq)
{
    struct dlx_call c;
    dlx_begin_status(&c);
    bool ok = dlx_run(&c) && dlx_ok(&c);
    const struct json_value *rows = dlx_arr(&c, "outcomes");
    if (!rows) ok = false;
    for (size_t i = 0; ok && i < rows->num_children; ++i)
        if (json_get_int(json_get(&rows->children[i], "seq")) == seq) ok = false;
    dlx_end(&c);
    return ok;
}

static bool dlx_su_no_landing(int64_t seq)
{
    struct dlx_call c;
    dlx_begin_status(&c);
    bool ok = dlx_run(&c) && dlx_ok(&c);
    const struct json_value *rows = dlx_arr(&c, "outcomes");
    if (!rows) ok = false;
    for (size_t i = 0; ok && i < rows->num_children; ++i) {
        const struct json_value *row = &rows->children[i];
        const char *state = json_get_str(json_get(row, "state"));
        if (json_get_int(json_get(row, "seq")) == seq && state && !strcmp(state, "landed")) ok = false;
    }
    dlx_end(&c);
    return ok;
}

static bool dlx_su_competing_attach(void)
{
    struct dlx_call c;
    dlx_begin(&c, "attach");
    bool ok = json_push_kv_int(&c.input, "seq", 5) && dlx_run(&c) && dlx_ok(&c) &&
        !strcmp(dlx_str(&c, "state"), "attached");
    if (!ok) fprintf(stderr, "[test competing attach] status=%d code=%.80s\n",
                     (int)c.reply.status, dlx_err_code(&c));
    dlx_end(&c);
    return ok;
}

static bool dlx_su_competing_landing(const char *tip)
{
    bool attached = false;
    for (unsigned i = 0; i < 8; ++i) {
        struct dlx_call c;
        dlx_begin(&c, "step");
        bool ok = dlx_run(&c) && dlx_ok(&c);
        bool needs_attach = !ok && !strcmp(dlx_err_code(&c), "PUBLICATION_INTENT_REQUIRED");
        const char *state = dlx_str(&c, "state");
        bool landed = state && !strcmp(state, "landed");
        if (!ok && !needs_attach) fprintf(stderr, "[test competing step] index=%u status=%d code=%.80s\n",
                                          i, (int)c.reply.status, dlx_err_code(&c));
        dlx_end(&c);
        if (needs_attach && !attached) {
            attached = dlx_su_competing_attach();
            if (attached) continue;
        }
        if (!ok) return false;
        if (landed) {
            bool signed_outcome = dlx_su_one_landed_outcome(5, tip);
            if (!signed_outcome) fprintf(stderr, "[test competing step] index=%u signed_outcome=0\n", i);
            return signed_outcome;
        }
    }
    return false;
}

struct dlx_su_race {
    char ready[1400], release[1400];
    char self[PATH_MAX], git[PATH_MAX], shell[PATH_MAX];
    int read_fd, release_fd, old_subreaper;
    bool custody;
    unsigned adopted;
    struct app_ui_child driver;
};

/* Same bounded direct-child reconciliation used by app-receive fixtures.
 * This shard is serial in its own harness worker, with no competing reaper. */
static bool dlx_su_children(pid_t pids[32], size_t *count)
{
    char path[96], text[4096];
    *count = 0;
    (void)snprintf(path, sizeof(path), "/proc/self/task/%ld/children", (long)getpid());
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return false;
    ssize_t n = read(fd, text, sizeof(text) - 1);
    bool closed = close(fd) == 0;
    if (!closed || n < 0 || (size_t)n == sizeof(text) - 1) return false;
    text[n] = 0;
    char *cursor = text;
    while (*cursor) {
        while (*cursor == ' ') ++cursor;
        if (!*cursor) break;
        char *end = NULL;
        errno = 0;
        long value = strtol(cursor, &end, 10);
        if (errno || end == cursor || value <= 1 || value > INT_MAX || *count == 32)
            return false;
        pids[(*count)++] = (pid_t)value;
        cursor = end;
    }
    return true;
}

static bool dlx_su_custody_begin(struct dlx_su_race *r)
{
    pid_t pids[32]; size_t count;
    if (!dlx_su_children(pids, &count) || count ||
        !realpath("/proc/self/exe", r->self) ||
        !realpath("/usr/bin/git", r->git) || !realpath("/bin/sh", r->shell) ||
        prctl(PR_GET_CHILD_SUBREAPER, &r->old_subreaper) != 0 ||
        prctl(PR_SET_CHILD_SUBREAPER, 1) != 0) return false;
    r->custody = true;
    return true;
}

static bool dlx_su_adopted_stop(pid_t pid, const struct dlx_su_race *r)
{
    struct app_ui_child child = {.pid = pid};
    if (!app_proc_identity(pid, child.image, &child.token))
        return app_ui_reaped_identity_failure(&child);
    /* Only images launched by this local fixture are eligible. app_proc_identity
     * normalizes the kernel's deleted suffix; app_ui_stop rechecks start+image. */
    if (!child.token || (strcmp(child.image, r->self) &&
        strcmp(child.image, "/memfd:z23-proof-executable") &&
        strcmp(child.image, r->git) && strcmp(child.image, r->shell))) return false;
    return app_ui_stop(&child);
}

static bool dlx_su_adopted_drain(struct dlx_su_race *r)
{
    for (unsigned pass = 0; pass < 8; ++pass) {
        pid_t pids[32]; size_t count;
        if (!dlx_su_children(pids, &count)) return false;
        if (!count) return true;
        for (size_t i = 0; i < count; ++i) {
            if (!dlx_su_adopted_stop(pids[i], r)) return false;
            ++r->adopted;
        }
    }
    return false;
}

static bool dlx_su_race_close(struct dlx_su_race *r)
{
    bool stopped = app_ui_stop(&r->driver);
    bool drained = r->custody && stopped && dlx_su_adopted_drain(r);
    bool restored = !r->custody ||
        (drained && prctl(PR_SET_CHILD_SUBREAPER, r->old_subreaper) == 0);
    if (r->read_fd >= 0) close(r->read_fd);
    if (r->release_fd >= 0) close(r->release_fd);
    unsetenv("ZCL_LAND_TEST_FIXTURE_READY");
    unsetenv("ZCL_LAND_TEST_FIXTURE_RELEASE");
    unsetenv("ZCL_LAND_TEST_FIXTURE_MODE");
    if (restored) {
        if (r->ready[0]) unlink(r->ready);
        if (r->release[0]) unlink(r->release);
    } else {
        fprintf(stderr, "[test selfupgrade] unresolved descendant cleanup; fixture retained\n");
    }
    return stopped && restored;
}

static bool dlx_su_race_open(struct dlx_su_race *r, bool after_check)
{
    if (!dlx_su_custody_begin(r) ||
        snprintf(r->ready, sizeof(r->ready), "%s/trial-ready", g_dlx_state) >= (int)sizeof(r->ready) ||
        snprintf(r->release, sizeof(r->release), "%s/trial-release", g_dlx_state) >= (int)sizeof(r->release) ||
        mkfifo(r->ready, 0600) != 0 || mkfifo(r->release, 0600) != 0) return false;
    r->read_fd = open(r->ready, O_RDWR | O_CLOEXEC);
    r->release_fd = open(r->release, O_RDWR | O_CLOEXEC);
    return r->read_fd >= 0 && r->release_fd >= 0 &&
        setenv("ZCL_LAND_TEST_FIXTURE_READY", r->ready, 1) == 0 &&
        setenv("ZCL_LAND_TEST_FIXTURE_RELEASE", r->release, 1) == 0 &&
        setenv("ZCL_LAND_TEST_FIXTURE_MODE", after_check ? "pick_cancel" : "entry_cancel", 1) == 0;
}

struct dlx_su_race_work {
    const struct zcl_command_context *context;
    bool after_check;
};

static int dlx_su_race_drive(void *opaque)
{
    const struct dlx_su_race_work *work = opaque;
    alarm(90);
    struct dlx_call c;
    bool ran = dlx_su_drive(&c, 5, work->context);
    bool accepted = ran && (!work->after_check || !dlx_ok(&c));
    dlx_end(&c);
    return accepted ? 0 : 1;
}

static bool dlx_su_race_start(struct dlx_su_race *r, int (*work)(void *), void *context)
{
    int gate[2];
    if (!app_ui_pipe(gate)) return false;
    r->driver.pid = fork();
    if (r->driver.pid == 0) {
        close(gate[1]);
        char go = 0;
        bool released = read(gate[0], &go, 1) == 1 && go == 'G';
        close(gate[0]);
        _exit(released ? work(context) : 126);
    }
    close(gate[0]);
    bool pinned = r->driver.pid > 1 &&
        app_proc_identity(r->driver.pid, r->driver.image, &r->driver.token) &&
        r->driver.token && !strcmp(r->driver.image, r->self);
    bool sent = pinned && write(gate[1], "G", 1) == 1;
    close(gate[1]);
    return sent;
}

static bool dlx_su_race_ready(const struct dlx_su_race *r)
{
    struct pollfd p = {.fd = r->read_fd, .events = POLLIN};
    char marker = 0;
    return poll(&p, 1, 30000) == 1 && read(r->read_fd, &marker, 1) == 1 && marker == 'R';
}

static bool dlx_su_competing_cancel(void)
{
    struct dlx_call c;
    dlx_begin(&c, "cancel");
    bool ok = json_push_kv_int(&c.input, "seq", 5) && dlx_run(&c) && dlx_ok(&c);
    dlx_end(&c);
    return ok;
}

static bool dlx_su_race_result(const struct dlx_su_race *r, const char *land,
    const char *tip, bool after_check, bool ok, bool released, bool exited,
    uint32_t code, bool clean)
{
    char pointer[ZCL_LAND_SELFUPGRADE_PATH_MAX];
    bool restored = clean && !zcl_land_selfupgrade_pointer_read(land, pointer, sizeof(pointer));
    bool outcome = clean && (after_check ? dlx_su_no_landing(5) : dlx_su_one_landed_outcome(5, tip));
    bool passed = ok && released && exited && code == 0 && clean && restored && outcome;
    if (!passed)
        fprintf(stderr, "[test competing race] after_check=%d setup_action=%d released=%d exited=%d code=%u clean=%d restored=%d outcome=%d adopted=%u\n",
                after_check, ok, released, exited, code, clean, restored, outcome, r->adopted);
    return passed;
}

static bool dlx_su_cancel_race(const struct zcl_command_context *context,
                                const char *land, const char *tip, bool after_check)
{
    struct dlx_su_race r = {.read_fd = -1, .release_fd = -1, .driver = {.pid = -1}};
    struct dlx_su_race_work work = {.context = context, .after_check = after_check};
    bool ok = dlx_su_race_open(&r, after_check) &&
        dlx_su_race_start(&r, dlx_su_race_drive, &work) && dlx_su_race_ready(&r);
    if (ok) ok = after_check ? dlx_su_competing_cancel() : dlx_su_competing_landing(tip);
    bool released = r.release_fd >= 0 && write(r.release_fd, "G", 1) == 1;
    uint32_t code = UINT32_MAX;
    bool exited = app_ui_wait(&r.driver, 95000, &code) == PLATFORM_PROCESS_WAIT_EXITED;
    bool clean = dlx_su_race_close(&r);
    return dlx_su_race_result(&r, land, tip, after_check, ok, released, exited, code, clean);

}

static int dlx_su_orphan_probe(void *opaque)
{
    const struct dlx_su_race *r = opaque;
    pid_t child = fork();
    if (child < 0) return 1;
    if (child == 0) {
        if (setsid() < 0 || write(r->read_fd, "R", 1) != 1) _exit(2);
        for (;;) pause();
    }
    for (;;) pause();
}

static int dlx_selfupgrade_cleanup_case(void)
{
    int failures = 0;
    bool closed = false;
    struct dlx_su_race r = {.read_fd = -1, .release_fd = -1, .driver = {.pid = -1}};
    TEST("land: race fixture reaps a separate-session child after its owner dies") {
        dlx_isolate("selfupgrade_cleanup");
        ASSERT(dlx_mkdir_p(g_dlx_state));
        ASSERT(dlx_su_race_open(&r, false));
        ASSERT(dlx_su_race_start(&r, dlx_su_orphan_probe, &r));
        ASSERT(dlx_su_race_ready(&r));
        ASSERT(app_ui_stop(&r.driver));
        bool clean = dlx_su_race_close(&r);
        closed = true;
        ASSERT(clean && r.adopted == 1);
        PASS();
    } _test_next:;
    if (!closed && !dlx_su_race_close(&r)) ++failures;
    dlx_restore();
    return failures;
}

static bool dlx_su_row_unchanged(const char *before, const char *after, const char *marker)
{
    const char *a = strstr(before, marker), *b = strstr(after, marker);
    if (!a || !b) return false;
    const char *ae = strchr(a, '\n'), *be = strchr(b, '\n');
    return ae && be && ae - a == be - b && memcmp(a, b, (size_t)(ae - a)) == 0;
}

static bool dlx_su_recovery_facts(const struct json_value *facts)
{
    const struct json_value *seq = json_get(facts, "seq"), *count = json_get(facts, "rows_landed");
    const struct json_value *last = json_get(facts, "last_row_landed");
    const struct json_value *recovery = json_get(facts, "recovery_required");
    return seq && seq->type == JSON_INT && seq->val.i == 5 &&
        count && count->type == JSON_INT && count->val.i == 1 &&
        last && last->type == JSON_BOOL && last->val.b &&
        recovery && recovery->type == JSON_BOOL && recovery->val.b;
}

static bool dlx_su_recovery_wire(struct dlx_call *c)
{
    char wire[3072];
    size_t n = zcl_command_registry_test_reply_wire(zcl_command_catalog(),
        c->request.spec, &c->reply, wire, sizeof(wire));
    struct json_value doc = {0};
    bool ok = n > 0 && n <= sizeof(wire) && json_read(&doc, wire, n);
    const struct json_value *error = json_get(&doc, "error");
    const struct json_value *mutated = json_get(error, "mutated");
    const char *code = json_get_str(json_get(error, "code"));
    ok = ok && code && !strcmp(code, "SELFUPGRADE_RECOVERY_REQUIRED") &&
        mutated && mutated->type == JSON_BOOL && mutated->val.b &&
        dlx_su_recovery_facts(json_get(error, "facts"));
    json_free(&doc);
    return ok;
}

static int dlx_selfupgrade_postland_case(void)
{
    int failures = 0, image = -1;
    bool opened = false;
    struct dlx_rig rig = {0};
    struct dlx_call c;
    char source[4096], tip[64], local[64], base[64], wt[1400], artifact[1400];
    char bin_dir[1600], bin[1700], why[256], land[1200];
    uint8_t digest[32];
    struct zcl_land_selfupgrade_binding pending = {0};
    const char *process = getenv("ZCL_DEVLOOP_TEST_PROCESS");
    const char *upgrade = getenv(ZCL_LAND_SELFUPGRADE_ENV);
    char *saved_process = process ? strdup(process) : NULL;
    char *saved_upgrade = upgrade ? strdup(upgrade) : NULL;
    TEST("land: verified driver landing prepares a bound admitted candidate") {
        ASSERT((!process || saved_process) && (!upgrade || saved_upgrade));
        ASSERT(getcwd(source, sizeof(source)) != NULL);
        dlx_isolate("selfupgrade_postland");
        ASSERT(setenv("ZCL_DEVLOOP_TEST_PROCESS", "1", 1) == 0);
        ASSERT(setenv("ZCL_LAND_PROOF_STUB", "running", 1) == 0);
        ASSERT(setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1) == 0);
        ASSERT(setenv(ZCL_LAND_SELFUPGRADE_ENV, "1", 1) == 0);
        ASSERT(dlx_rig_make(&rig, "selfupgrade_postland_rig"));
        ASSERT(dlx_write_dep(rig.clone, "tools/command/native_dev_land_fixture.c", "fixture\n"));
        ASSERT(dlx_commit(rig.clone, "tools/command/native_dev_land_fixture.c", "fixture\n", tip));
        ASSERT(dlx_scope_submit(&rig, tip));
        ASSERT(unsetenv("ZCL_LAND_ALLOW_UNSIGNED") == 0);
        dlx_begin(&c, "step"); opened = true;
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "started");
        dlx_end(&c); opened = false;
        dlx_begin(&c, "decision"); opened = true;
        ASSERT(dlx_decision_run(&c) && dlx_ok(&c));
        ASSERT(snprintf(local, sizeof(local), "%s", dlx_str(&c, "local")) == 40);
        ASSERT(snprintf(base, sizeof(base), "%s", dlx_str(&c, "base")) == 40);
        dlx_end(&c); opened = false;
        dlx_land_wt(wt, sizeof(wt));
        ASSERT(dlx_su_signed_candidate(wt, local, base, artifact));
        ASSERT(snprintf(bin_dir, sizeof(bin_dir), "%s/build/bin", wt) < (int)sizeof(bin_dir));
        ASSERT(dlx_mkdir_p(bin_dir));
        ASSERT(snprintf(bin, sizeof(bin), "%s/z23-dev", bin_dir) < (int)sizeof(bin));
        ASSERT(rename(artifact, bin) == 0);
        ASSERT(setenv("ZCL_LAND_PROOF_STUB", "pass", 1) == 0);
        struct zcl_command_context context = {.registry = zcl_command_catalog(),
            .source_root = source, .dev_build = true, .one_shot_process = true,
            .authority_ceiling = ZCL_COMMAND_AUTH_OPERATOR, .granted_capabilities = UINT64_MAX};
        opened = true;
        ASSERT(dlx_su_drive(&c, 1, &context) && dlx_ok(&c));
        dlx_end(&c); opened = false;
        ASSERT(dlx_su_one_landed_outcome(1, local));
        dlx_landdir(land, sizeof(land));
        ASSERT(zcl_land_selfupgrade_binding_read(land, true, &pending));
        ASSERT_STR_EQ(pending.commit, local);
        ASSERT_STR_EQ(pending.base, base);
        ASSERT_STR_EQ(pending.proof_root, wt);
        ASSERT(zcl_dev_proof_open_reused_executable(wt, local, base, bin, &image,
                                                    digest, why, sizeof(why)));
        PASS();
    } _test_next:;
    if (opened) dlx_end(&c);
    if (image >= 0) close(image);
    if (saved_process) setenv("ZCL_DEVLOOP_TEST_PROCESS", saved_process, 1);
    else unsetenv("ZCL_DEVLOOP_TEST_PROCESS");
    if (saved_upgrade) setenv(ZCL_LAND_SELFUPGRADE_ENV, saved_upgrade, 1);
    else unsetenv(ZCL_LAND_SELFUPGRADE_ENV);
    free(saved_process); free(saved_upgrade);
    dlx_restore();
    return failures;
}

static const char *dlx_su_case_name(int mode)
{
    switch (mode) {
    case 1: return "land: finish sync failure stops batch and preserves landed facts";
    case 2: return "land: a trial crash after validated entry rolls back without publication";
    case 3: return "land: wrong trial row is refused without publication";
    case 4: return "land: independently landed row before first step cannot confirm trial";
    case 5: return "land: cancel after checked trial cannot confirm transition";
    default: return "land: real admitted child shadows distinct rows and confirms a landed trial";
    }
}

static bool dlx_su_interrupted_result(int mode, const char *land, const char *trace)
{
    char events[4096], current[ZCL_LAND_SELFUPGRADE_PATH_MAX];
    size_t len = 0;
    struct zcl_land_selfupgrade_binding pending;
    if (zcl_land_selfupgrade_pointer_read(land, current, sizeof(current)) ||
        zcl_land_selfupgrade_binding_read(land, true, &pending) || !dlx_su_no_outcome(5) ||
        !dlx_slurp(trace, events, sizeof(events) - 1, &len)) return false;
    events[len] = 0;
    return dlx_su_lines(events, "decision") == 6 && dlx_su_lines(events, "drive") == 1 &&
        dlx_su_lines(events, "entered") == (mode == 2 ? 1u : 0u);
}

static bool dlx_su_interrupted_check(int mode, const struct zcl_command_context *context,
                                     const char *land, const char *trace)
{
    char before[16384], after[16384];
    size_t before_len = 0, after_len = 0;
    struct dlx_call c;
    bool ok = dlx_queue_bytes(before, sizeof(before), &before_len) &&
        setenv("ZCL_LAND_TEST_FIXTURE_MODE", mode == 2 ? "crash" : "wrongrow", 1) == 0;
    if (!ok) return false;
    bool ran = dlx_su_drive(&c, 5, context);
    ok = ran && !dlx_ok(&c);
    dlx_end(&c);
    if (unsetenv("ZCL_LAND_TEST_FIXTURE_MODE") != 0) ok = false;
    return ok && dlx_queue_bytes(after, sizeof(after), &after_len) &&
        before_len == after_len && memcmp(before, after, before_len) == 0 &&
        dlx_su_interrupted_result(mode, land, trace);
}

static bool dlx_su_finish_check(const struct zcl_command_context *context, const char *tip)
{
    char before[16384], after[16384];
    size_t before_len = 0, after_len = 0;
    if (!dlx_queue_bytes(before, sizeof(before), &before_len)) return false;
    zcl_land_selfupgrade_test_finish_sync_failure(true);
    struct dlx_call c;
    dlx_begin(&c, "drive"); c.request.context = context; c.request.view = "normal";
    c.request.budget_bytes = 3072;
    bool ok = json_push_kv_int(&c.input, "max_rows", 2) && dlx_run(&c) && !dlx_ok(&c) &&
        c.reply.status == ZCL_COMMAND_STATUS_BLOCKED && c.reply.exit_code == ZCL_COMMAND_EXIT_FAILED;
    zcl_land_selfupgrade_test_finish_sync_failure(false);
    ok = ok && dlx_su_recovery_wire(&c);
    dlx_end(&c);
    return ok && dlx_queue_bytes(after, sizeof(after), &after_len) &&
        dlx_su_row_unchanged(before, after, "{\"seq\":6,") && dlx_su_one_landed_outcome(5, tip);
}

static bool dlx_su_happy_check(const struct dlx_rig *rig,
    const struct zcl_land_selfupgrade_binding *binding, const char *land,
    const char *trace, const char *tip)
{
    char events[4096], current[ZCL_LAND_SELFUPGRADE_PATH_MAX], observed_tip[64];
    size_t len = 0;
    struct zcl_land_selfupgrade_binding confirmed;
    if (!dlx_slurp(trace, events, sizeof(events) - 1, &len)) return false;
    events[len] = 0;
    return dlx_su_lines(events, "decision") == 6 && dlx_su_lines(events, "drive") == 1 &&
        zcl_land_selfupgrade_pointer_read(land, current, sizeof(current)) &&
        zcl_land_selfupgrade_binding_read(land, false, &confirmed) &&
        !strcmp(confirmed.commit, binding->commit) && dlx_origin_main(rig, observed_tip) &&
        !strcmp(observed_tip, tip) && dlx_su_one_landed_outcome(5, tip);
}

static bool dlx_su_mode_check(int mode, const struct zcl_command_context *context,
    const struct dlx_rig *rig, const struct zcl_land_selfupgrade_binding *binding,
    const char *land, const char *trace, const char *trial_tip, const char *last_tip)
{
    switch (mode) {
    case 1: return dlx_su_finish_check(context, trial_tip);
    case 2: case 3: return dlx_su_interrupted_check(mode, context, land, trace);
    case 4: case 5: return dlx_su_cancel_race(context, land, trial_tip, mode == 5);
    default: return dlx_su_happy_check(rig, binding, land, trace, last_tip);
    }
}

struct dlx_su_fixture {
    struct dlx_rig rig;
    struct dlx_call c;
    struct zcl_land_selfupgrade_binding binding;
    struct zcl_command_context context;
    bool opened;
    int image, tamper, mode;
    char source[4096], proof[1024], artifact[1400], base[64], tip[64];
    char land[1200], trace[1400], marker_path[1400], events[4096];
    char current[ZCL_LAND_SELFUPGRADE_PATH_MAX], slot[ZCL_LAND_SELFUPGRADE_PATH_MAX];
    char last_tip[64], trial_tip[64];
    char *old_process, *old_upgrade;
};

static int dlx_su_seed_rows(struct dlx_su_fixture *f, int mode)
{
    int failures = 0;
    TEST("land: prepare private signed-fixture rows") {
        const struct zcl_command_spec *catalog_drive =
            zcl_command_registry_find(zcl_command_catalog(), "dev.land.drive", NULL);
        ASSERT(catalog_drive && catalog_drive->availability == ZCL_COMMAND_COMPAT &&
               !catalog_drive->handler);
        ASSERT(getcwd(f->source, sizeof(f->source)) != NULL);
        char state_tag[80], rig_tag[80];
        ASSERT(snprintf(state_tag, sizeof(state_tag), "real_selfupgrade_child_%d", mode) < (int)sizeof(state_tag));
        ASSERT(snprintf(rig_tag, sizeof(rig_tag), "real_selfupgrade_child_rig_%d", mode) < (int)sizeof(rig_tag));
        dlx_isolate(state_tag);
        ASSERT(setenv("ZCL_DEVLOOP_TEST_PROCESS", "1", 1) == 0);
        ASSERT(setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1) == 0);
        ASSERT(setenv("ZCL_LAND_PROOF_STUB", "pass", 1) == 0);
        ASSERT(setenv("ZCL_LAND_TEST_FIXTURE_CHILD", "1", 1) == 0);
        ASSERT(setenv("ZCL_LAND_TEST_FIXTURE_STATE", g_dlx_state, 1) == 0);
        ASSERT(dlx_rig_make(&f->rig, rig_tag));
        ASSERT(dlx_origin_main(&f->rig, f->base));
        ASSERT(dlx_scope_submit(&f->rig, f->rig.tip));
        ASSERT(snprintf(f->marker_path, sizeof(f->marker_path), "%s/.land-selfupgrade-fixture", g_dlx_state) < (int)sizeof(f->marker_path));
        ASSERT(dlx_write(f->marker_path, "z23-land-selfupgrade-test-v1") && chmod(f->marker_path, 0600) == 0);
        ASSERT(dlx_su_fixture_marker(g_dlx_state));
        memcpy(f->binding.commit, f->rig.tip, 41); memcpy(f->binding.base, f->base, 41);
        for (int n = 2; n <= (mode == 1 ? 6 : 5); ++n) {
            char name[40], content[40];
            ASSERT(snprintf(name, sizeof(name), "change-%d.txt", n) < (int)sizeof(name));
            ASSERT(snprintf(content, sizeof(content), "row-%d", n) < (int)sizeof(content));
            ASSERT(dlx_commit(f->rig.clone, name, content, f->tip));
            ASSERT(dlx_scope_submit(&f->rig, f->tip));
            if (n == 5) ASSERT(snprintf(f->trial_tip, sizeof(f->trial_tip), "%s", f->tip) < (int)sizeof(f->trial_tip));
        }
        ASSERT(snprintf(f->last_tip, sizeof(f->last_tip), "%s", f->tip) < (int)sizeof(f->last_tip));
        ASSERT(unsetenv("ZCL_LAND_ALLOW_UNSIGNED") == 0);
        PASS();
    } _test_next:;
    return failures;
}

static int dlx_su_admit_fixture(struct dlx_su_fixture *f)
{
    int failures = 0;
    uint8_t digest[32];
    TEST("land: admit exact fixture candidate and bind its trace") {
        char proof_tag[80];
        ASSERT(snprintf(proof_tag, sizeof(proof_tag), "selfupgrade-proof-%d", f->mode) < (int)sizeof(proof_tag));
        test_make_tmpdir(f->proof, sizeof(f->proof), "dev_land", proof_tag);
        ASSERT(dlx_su_signed_candidate(f->proof, f->binding.commit, f->binding.base, f->artifact));
        ASSERT(strlen(f->proof) < sizeof(f->binding.proof_root));
        memcpy(f->binding.proof_root, f->proof, strlen(f->proof) + 1);
        ASSERT(zcl_dev_proof_open_reused_executable(f->proof, f->binding.commit, f->binding.base,
            f->artifact, &f->image, digest, f->trace, sizeof(f->trace)));
        dlx_landdir(f->land, sizeof(f->land));
        ASSERT(zcl_land_selfupgrade_prepare(f->land, &f->binding, f->image));
        ASSERT(zcl_land_selfupgrade_slot_path(f->land, f->binding.commit, f->slot, sizeof(f->slot)));
        ASSERT(snprintf(f->trace, sizeof(f->trace), "%s/child-events", g_dlx_state) < (int)sizeof(f->trace));
        ASSERT(dlx_write(f->trace, ""));
        ASSERT(setenv("ZCL_LAND_TEST_FIXTURE_TRACE", f->trace, 1) == 0);
        f->context = (struct zcl_command_context){.registry = zcl_command_catalog(),
            .source_root = f->source, .dev_build = true, .one_shot_process = true,
            .authority_ceiling = ZCL_COMMAND_AUTH_OPERATOR, .granted_capabilities = UINT64_MAX};
        PASS();
    } _test_next:;
    return failures;
}

static int dlx_su_initial_checks(struct dlx_su_fixture *f)
{
    int failures = 0;
    char before[16384], after[16384];
    size_t before_len = 0, after_len = 0, events_len = 0;
    TEST("land: default-off, budget, lock and candidate refusal") {
        unsetenv(ZCL_LAND_SELFUPGRADE_ENV);
        f->opened = true;
        ASSERT(dlx_su_drive(&f->c, 1, &f->context) && dlx_ok(&f->c));
        dlx_end(&f->c); f->opened = false;
        ASSERT(dlx_slurp(f->trace, f->events, sizeof(f->events), &events_len) && events_len == 0);
        ASSERT(!zcl_land_selfupgrade_pointer_read(f->land, f->current, sizeof(f->current)));
        ASSERT(setenv(ZCL_LAND_SELFUPGRADE_ENV, "1", 1) == 0);
        ASSERT(dlx_queue_bytes(before, sizeof(before), &before_len));
        dlx_begin(&f->c, "drive"); f->c.request.context = &f->context; f->c.request.view = "normal";
        f->c.request.budget_bytes = 3071; f->opened = true;
        ASSERT(json_push_kv_int(&f->c.input, "seq", 2) && dlx_run(&f->c) && !dlx_ok(&f->c));
        ASSERT_STR_EQ(dlx_err_code(&f->c), "SELFUPGRADE_REPLY_BUDGET_REQUIRED");
        ASSERT(!f->c.reply.error.mutated);
        dlx_end(&f->c); f->opened = false;
        ASSERT(dlx_queue_bytes(after, sizeof(after), &after_len));
        ASSERT(before_len == after_len && memcmp(before, after, before_len) == 0);
        ASSERT(dlx_slurp(f->trace, f->events, sizeof(f->events), &events_len) && events_len == 0);
        ASSERT(setenv("ZCL_LAND_SU_LOCK_FD", "not-a-descriptor", 1) == 0);
        f->opened = true;
        ASSERT(dlx_su_drive(&f->c, 2, &f->context) && !dlx_ok(&f->c));
        ASSERT_STR_EQ(dlx_err_code(&f->c), "SELFUPGRADE_LOCK_REFUSED");
        dlx_end(&f->c); f->opened = false;
        unsetenv("ZCL_LAND_SU_LOCK_FD");
        ASSERT(chmod(f->slot, 0700) == 0);
        f->tamper = open(f->slot, O_WRONLY | O_APPEND | O_CLOEXEC);
        ASSERT(f->tamper >= 0 && write(f->tamper, "x", 1) == 1 && close(f->tamper) == 0); f->tamper = -1;
        f->opened = true;
        ASSERT(dlx_su_drive(&f->c, 2, &f->context) && dlx_ok(&f->c));
        dlx_end(&f->c); f->opened = false;
        ASSERT(dlx_slurp(f->trace, f->events, sizeof(f->events), &events_len) && events_len == 0);
        ASSERT(unlink(f->slot) == 0 && zcl_land_selfupgrade_prepare(f->land, &f->binding, f->image));
        ASSERT(close(f->image) == 0); f->image = -1;
        PASS();
    } _test_next:;
    return failures;
}

static int dlx_su_run_fixture(struct dlx_su_fixture *f, int mode)
{
    int failures = 0;
    TEST(dlx_su_case_name(mode)) {
        for (int seq = 3; seq <= (mode ? 4 : 5); ++seq) {
            f->opened = true;
            bool driven = dlx_su_drive(&f->c, seq, &f->context);
            if (!driven || !dlx_ok(&f->c))
                fprintf(stderr, "[test selfupgrade drive] seq=%d invoked=%d status=%d code=%.80s evidence=%.200s reason=%.200s\n",
                    seq, driven, (int)f->c.reply.status, dlx_err_code(&f->c),
                    dlx_err_evidence(&f->c), dlx_str(&f->c, "reason"));
            ASSERT(driven && dlx_ok(&f->c));
            dlx_end(&f->c); f->opened = false;
        }
        ASSERT(dlx_su_mode_check(mode, &f->context, &f->rig, &f->binding,
                                 f->land, f->trace, f->trial_tip, f->last_tip));
        PASS();
    } _test_next:;
    return failures;
}

static void dlx_su_fixture_cleanup(struct dlx_su_fixture *f, bool failed)
{
    zcl_land_selfupgrade_test_finish_sync_failure(false);
    if (f->opened) dlx_end(&f->c);
    if (f->image >= 0) close(f->image);
    if (f->tamper >= 0) close(f->tamper);
    unsetenv("ZCL_LAND_SU_LOCK_FD");
    unsetenv("ZCL_LAND_TEST_FIXTURE_MODE");
    unsetenv("ZCL_LAND_TEST_FIXTURE_CHILD");
    unsetenv("ZCL_LAND_TEST_FIXTURE_STATE");
    unsetenv("ZCL_LAND_TEST_FIXTURE_TRACE");
    if (f->old_process) setenv("ZCL_DEVLOOP_TEST_PROCESS", f->old_process, 1);
    else unsetenv("ZCL_DEVLOOP_TEST_PROCESS");
    if (f->old_upgrade) setenv(ZCL_LAND_SELFUPGRADE_ENV, f->old_upgrade, 1);
    else unsetenv(ZCL_LAND_SELFUPGRADE_ENV);
    free(f->old_process); free(f->old_upgrade);
    dlx_restore();
    if (f->proof[0] && !failed) test_rm_rf_recursive(f->proof);
    else if (f->proof[0]) fprintf(stderr, "[test selfupgrade] retained proof fixture=%s\n", f->proof);
}

static int dlx_selfupgrade_real_child_run(int mode)
{
    struct dlx_su_fixture f = {.image = -1, .tamper = -1, .mode = mode};
    const char *old = getenv("ZCL_DEVLOOP_TEST_PROCESS");
    f.old_process = old ? strdup(old) : NULL;
    old = getenv(ZCL_LAND_SELFUPGRADE_ENV);
    f.old_upgrade = old ? strdup(old) : NULL;
    int failures = dlx_su_seed_rows(&f, mode);
    if (!failures) failures += dlx_su_admit_fixture(&f);
    if (!failures) failures += dlx_su_initial_checks(&f);
    if (!failures) failures += dlx_su_run_fixture(&f, mode);
    dlx_su_fixture_cleanup(&f, failures != 0);
    return failures;
}

static int dlx_selfupgrade_real_child_case(void) { return dlx_selfupgrade_real_child_run(0); }
static int dlx_selfupgrade_finish_fault_case(void) { return dlx_selfupgrade_real_child_run(1); }
static int dlx_selfupgrade_crash_case(void) { return dlx_selfupgrade_real_child_run(2); }
static int dlx_selfupgrade_wrongrow_case(void) { return dlx_selfupgrade_real_child_run(3); }
static int dlx_selfupgrade_terminal_race_case(void) { return dlx_selfupgrade_real_child_run(4); }
static int dlx_selfupgrade_cancel_race_case(void) { return dlx_selfupgrade_real_child_run(5); }
#else
static int dlx_selfupgrade_cleanup_case(void) { return 0; }
static int dlx_selfupgrade_real_child_case(void) { return 0; }
static int dlx_selfupgrade_finish_fault_case(void) { return 0; }
static int dlx_selfupgrade_crash_case(void) { return 0; }
static int dlx_selfupgrade_postland_case(void) { return 0; }
static int dlx_selfupgrade_wrongrow_case(void) { return 0; }
static int dlx_selfupgrade_terminal_race_case(void) { return 0; }
static int dlx_selfupgrade_cancel_race_case(void) { return 0; }
#endif

static int dlx_scope_refusal_case(int seq, const char *terminal,
                                  const char *reason)
{
    int failures = 0;
    struct dlx_scope_case t = {0};
    struct dlx_call c;
    bool opened = false;
    TEST("land: named drive leaves another eligible row and its origin untouched") {
        ASSERT(dlx_scope_prepare(&t, "drive_seq_scope", terminal));
        opened = true;
        ASSERT(dlx_drive_seq(&c, seq));
        ASSERT(dlx_scope_unchanged(&t));
        ASSERT_STR_EQ(dlx_err_code(&c), "DRIVE_REFUSED");
        ASSERT(!c.reply.error.mutated);
        ASSERT(strstr(dlx_str(&c, "reason"), reason) != NULL);
        ASSERT_EQ(dlx_int(&c, "seq"), seq);
        PASS();
    }
_test_next:;
    if (opened) dlx_end(&c);
    dlx_restore();
    return failures;
}

static int dlx_scope_landed_target(void)
{
    int failures = 0;
    struct dlx_scope_case t = {0};
    struct dlx_call c;
    bool opened = false;
    TEST("land: an already landed named target does not drive the live head") {
        ASSERT(dlx_scope_prepare(&t, "drive_seq_landed_scope", "landed"));
        opened = true;
        ASSERT(dlx_drive_seq(&c, 685) && dlx_ok(&c));
        ASSERT(dlx_scope_unchanged(&t));
        ASSERT_STR_EQ(dlx_str(&c, "outcome"), "landed");
        ASSERT_EQ(dlx_int(&c, "seq"), 685);
        PASS();
    }
_test_next:;
    if (opened) dlx_end(&c);
    dlx_restore();
    return failures;
}

static bool dlx_scope_later_unchanged(const struct dlx_scope_case *t)
{
    char queue[16384];
    size_t len = 0;
    if (!dlx_queue_bytes(queue, sizeof(queue), &len)) return false;
    const char *before = strstr(t->queue, "{\"seq\":685,");
    const char *after = strstr(queue, "{\"seq\":685,");
    if (!before || !after) return false;
    const char *a = strchr(before, '\n'), *b = strchr(after, '\n');
    return a && b && a - before == b - after &&
           memcmp(before, after, (size_t)(a - before)) == 0;
}

static int dlx_scope_requested_head(void)
{
    int failures = 0;
    struct dlx_scope_case t = {0};
    struct dlx_call c;
    bool opened = false;
    TEST("land: named queue head still starts its own bounded proof") {
        ASSERT(dlx_scope_prepare(&t, "drive_seq_head_scope", NULL));
        opened = true;
        ASSERT(dlx_drive_seq(&c, 674));
        ASSERT_STR_EQ(dlx_err_code(&c), "DRIVE_STOPPED");
        ASSERT_EQ(dlx_int(&c, "seq"), 674);
        ASSERT_EQ(dlx_int(&c, "rounds"), 6);
        ASSERT(dlx_scope_later_unchanged(&t));
        dlx_end(&c); opened = false;
        dlx_begin_status(&c); opened = true;
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        const struct json_value *active = json_get(&c.reply.data, "in_flight");
        ASSERT(active && json_get_int(json_get(active, "seq")) == 674);
        const struct json_value *queued = dlx_arr(&c, "queued");
        ASSERT(queued && queued->num_children == 1);
        ASSERT_EQ(json_get_int(json_get(&queued->children[0], "seq")), 685);
        PASS();
    }
_test_next:;
    if (opened) dlx_end(&c);
    dlx_restore();
    return failures;
}

static int dlx_scope_shared_fence(void)
{
    int failures = 0;
    struct dlx_fence_case t = {0};
    char path[1400], before[32768], after[32768], old_head[64], head[64];
    size_t before_len = 0, after_len = 0;
    bool opened = false;
    TEST("land: named drive refuses a publication fence spanning another row") {
        dlx_isolate("drive_seq_fence_scope");
        ASSERT(dlx_scope_fence_prepare(&t.rig, "drive_seq_fence_scope", t.base, t.wt, t.successor));
        dlx_fence_call(&t.c, &t.rig, t.base, t.rig.tip, t.successor); opened = true;
        ASSERT(dlx_run(&t.c) && dlx_ok(&t.c));
        dlx_end(&t.c); opened = false;
        ASSERT(dlx_queue_bytes(t.before, sizeof(t.before), &t.before_len));
        dlx_landdir(t.land, sizeof(t.land));
        (void)snprintf(path, sizeof(path), "%s/fence.jsonl", t.land);
        ASSERT(dlx_slurp(path, before, sizeof(before), &before_len));
        ASSERT(dlx_origin_main(&t.rig, t.remote));
        const char *rev[] = { "rev-parse", "HEAD", NULL };
        ASSERT(dlx_git_out(t.wt, rev, old_head, sizeof(old_head)) == 0);
        dlx_begin(&t.c, "decision"); opened = true;
        ASSERT(dlx_decision_run(&t.c) && dlx_ok(&t.c));
        ASSERT_STR_EQ(dlx_str(&t.c, "dispatch"), "fence");
        ASSERT(dlx_fence_same_queue(&t));
        ASSERT(dlx_slurp(path, after, sizeof(after), &after_len));
        ASSERT(before_len == after_len && memcmp(before, after, before_len) == 0);
        dlx_end(&t.c); opened = false;
        opened = true;
        ASSERT(dlx_drive_seq(&t.c, 1));
        ASSERT_STR_EQ(dlx_err_code(&t.c), "DRIVE_REFUSED");
        ASSERT(strstr(dlx_str(&t.c, "reason"), "requested_seq=1 blocking_seq=2") != NULL);
        ASSERT(!t.c.reply.error.mutated);
        ASSERT(dlx_fence_same_queue(&t));
        ASSERT(dlx_slurp(path, after, sizeof(after), &after_len));
        ASSERT(before_len == after_len && memcmp(before, after, before_len) == 0);
        ASSERT(dlx_origin_main(&t.rig, head));
        ASSERT_STR_EQ(head, t.remote);
        ASSERT(dlx_git_out(t.wt, rev, head, sizeof(head)) == 0);
        ASSERT_STR_EQ(head, old_head);
        dlx_end(&t.c); opened = false;
        ASSERT(dlx_write(path, "malformed\n"));
        dlx_begin(&t.c, "decision"); opened = true;
        ASSERT(dlx_decision_run(&t.c));
        ASSERT_STR_EQ(dlx_err_code(&t.c), "DECISION_UNAVAILABLE");
        ASSERT(!t.c.reply.error.mutated);
        ASSERT(dlx_slurp(path, after, sizeof(after), &after_len));
        ASSERT(after_len == strlen("malformed\n") &&
               memcmp(after, "malformed\n", after_len) == 0);
        PASS();
    }
_test_next:;
    if (opened) dlx_end(&t.c);
    dlx_restore();
    return failures;
}

static bool dlx_decision_registry(struct dlx_call *c)
{
    char wire[16384];
    enum zcl_command_exit code;
    struct json_value doc;
    json_init(&doc);
    size_t len = zcl_command_registry_execute_json(zcl_command_catalog(),
        c->request.spec, NULL, &c->input, false, "dev.land.decision", NULL,
        0, 0, NULL, wire, sizeof(wire), &code);
    bool ok = len > 0 && code == ZCL_COMMAND_EXIT_OK && json_read(&doc, wire, len) &&
        json_get_bool(json_get(&doc, "ok")) &&
        dlx_eq_str(json_get_str(json_get(json_get(&doc, "data"), "dispatch")), "prepare");
    json_free(&doc);
    if (!ok || !json_push_kv_str(&c->input, "action", "step")) return false;
    json_init(&doc);
    len = zcl_command_registry_execute_json(zcl_command_catalog(),
        c->request.spec, NULL, &c->input, false, "dev.land.decision", NULL,
        0, 0, NULL, wire, sizeof(wire), &code);
    ok = len > 0 && json_read(&doc, wire, len) &&
        !json_get_bool(json_get(&doc, "ok"));
    json_free(&doc);
    return ok;
}

static bool dlx_decision_expected_hash(char out[65])
{
    static const char domain[] = "zcl.land.decision.row.v1\n";
    char queue[16384];
    size_t len = 0;
    if (!dlx_queue_bytes(queue, sizeof(queue), &len)) return false;
    const char *end = memchr(queue, '\n', len);
    if (!end || strncmp(queue, "{\"seq\":674,", strlen("{\"seq\":674,"))) return false;
    struct sha3_256_ctx hash;
    uint8_t digest[32];
    sha3_256_init(&hash);
    sha3_256_write(&hash, (const uint8_t *)domain, sizeof(domain) - 1);
    sha3_256_write(&hash, (const uint8_t *)queue, (size_t)(end - queue) + 1);
    sha3_256_finalize(&hash, digest);
    zcl_hex_encode(digest, sizeof(digest), out);
    return true;
}

static bool dlx_decision_digest(const struct dlx_call *c, char out[65])
{
    const struct json_value *schema = json_get(&c->reply.data, "row_schema");
    const struct json_value *hash = json_get(&c->reply.data, "row_sha3");
    if (!schema || schema->type != JSON_STR ||
        strcmp(json_get_str(schema), "zcl.land.decision.row.v1") ||
        !hash || hash->type != JSON_STR) return false;
    const char *hex = json_get_str(hash);
    if (!hex || strlen(hex) != 64) return false;
    for (size_t i = 0; i < 64; i++)
        if (!((hex[i] >= '0' && hex[i] <= '9') || (hex[i] >= 'a' && hex[i] <= 'f')))
            return false;
    memcpy(out, hex, 65);
    return true;
}

static int dlx_decision_row_hash_case(void)
{
    int failures = 0, lock = -1;
    struct dlx_scope_case t = {0};
    struct dlx_call c;
    bool opened = false;
    char expected[65], first[65], second[65], changed[65], land[1400];
    TEST("land: decision binds the exact selected row including hidden fields") {
        ASSERT(dlx_scope_prepare(&t, "decision_row_hash", NULL));
        dlx_landdir(land, sizeof(land));
        lock = dlx_step_lock_take(land);
        ASSERT(lock >= 0);
        dlx_step_lock_release(lock); lock = -1;
        ASSERT(dlx_decision_expected_hash(expected));
        dlx_begin(&c, "decision"); opened = true;
        ASSERT(dlx_decision_run(&c) && dlx_ok(&c));
        ASSERT_EQ(dlx_int(&c, "seq"), 674);
        ASSERT(dlx_decision_digest(&c, first));
        ASSERT_STR_EQ(first, expected);
        ASSERT(dlx_scope_unchanged(&t));
        dlx_end(&c); opened = false;
        dlx_begin(&c, "decision"); opened = true;
        ASSERT(dlx_decision_run(&c) && dlx_ok(&c) && dlx_decision_digest(&c, second));
        ASSERT_STR_EQ(second, first);
        dlx_end(&c); opened = false;
        ASSERT(dlx_queue_field_once("\"seq\":674,", "\"note\":\"\"", "\"note\":\"changed-hidden-note\""));
        ASSERT(dlx_decision_expected_hash(expected));
        dlx_begin(&c, "decision"); opened = true;
        ASSERT(dlx_decision_run(&c) && dlx_ok(&c));
        ASSERT_EQ(dlx_int(&c, "seq"), 674);
        ASSERT(dlx_decision_digest(&c, changed));
        ASSERT_STR_EQ(changed, expected);
        ASSERT(strcmp(changed, first) != 0);
        PASS();
    }
_test_next:;
    if (lock >= 0) dlx_step_lock_release(lock);
    if (opened) dlx_end(&c);
    dlx_restore();
    return failures;
}

static int dlx_decision_empty_hash_case(void)
{
    int failures = 0, fd = -1;
    struct dlx_call c;
    bool opened = false;
    char land[1400], lock[1500];
    TEST("land: empty decision omits selected row digest") {
        dlx_isolate("decision_empty_hash");
        dlx_begin(&c, "step"); opened = true;
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        dlx_end(&c); opened = false;
        /* An empty step creates step.lock but does not need queue.lock;
         * the read-only decision deliberately opens both existing files. */
        dlx_landdir(land, sizeof(land));
        ASSERT(snprintf(lock, sizeof(lock), "%s/queue.lock", land) < (int)sizeof(lock));
        fd = open(lock, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
        ASSERT(fd >= 0);
        int close_rc = close(fd); fd = -1;
        ASSERT(close_rc == 0);
        dlx_begin(&c, "decision"); opened = true;
        ASSERT(dlx_decision_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "dispatch"), "empty");
        ASSERT(!json_get(&c.reply.data, "seq"));
        ASSERT(!json_get(&c.reply.data, "row_schema"));
        ASSERT(!json_get(&c.reply.data, "row_sha3"));
        PASS();
    }
_test_next:;
    if (fd >= 0) (void)close(fd);
    if (opened) dlx_end(&c);
    dlx_restore();
    return failures;
}

static int dlx_decision_encoding_failure_case(void)
{
    int failures = 0, lock = -1;
    struct dlx_scope_case t = {0};
    struct dlx_call c;
    bool opened = false;
    char land[1400];
    TEST("land: decision encoding failure never exposes a partial snapshot") {
        ASSERT(dlx_scope_prepare(&t, "decision_encode_failure", NULL));
        dlx_landdir(land, sizeof(land));
        lock = dlx_step_lock_take(land);
        ASSERT(lock >= 0);
        dlx_step_lock_release(lock); lock = -1;
        dlx_begin(&c, "decision"); opened = true;
        ASSERT(c.request.spec && c.request.spec->handler);
        /* The first two output keys are dispatch and scope. Fail the third,
         * after both have been appended, without faulting queue JSON parsing. */
        zcl_alloc_fault_fail_nth("json_push_kv_key", 3);
        c.request.spec->handler(&c.request, &c.reply);
        bool consumed = zcl_alloc_fault_armed_label() == NULL;
        zcl_alloc_fault_clear();
        ASSERT(consumed && !dlx_ok(&c));
        ASSERT_STR_EQ(dlx_err_code(&c), "DECISION_UNAVAILABLE");
        ASSERT(!c.reply.error.mutated);
        ASSERT(!json_get(&c.reply.data, "dispatch") && !json_get(&c.reply.data, "scope"));
        ASSERT(!json_get(&c.reply.data, "row_schema") && !json_get(&c.reply.data, "row_sha3"));
        ASSERT(!json_get(&c.reply.data, "seq") && dlx_scope_unchanged(&t));
        PASS();
    }
_test_next:;
    zcl_alloc_fault_clear();
    if (lock >= 0) dlx_step_lock_release(lock);
    if (opened) dlx_end(&c);
    dlx_restore();
    return failures;
}

static bool dlx_decision_wire_script(struct dlx_call *c, const char *script)
{
    char wire[8192], body[9216];
    enum zcl_command_exit code;
    size_t n = zcl_command_registry_execute_json(zcl_command_catalog(),
        c->request.spec, NULL, &c->input, false, "dev.land.decision", NULL,
        0, 0, NULL, wire, sizeof(wire), &code);
    if (!n || n >= sizeof(wire) || code != ZCL_COMMAND_EXIT_OK) return false;
    int written = snprintf(body, sizeof(body), "#!/bin/sh\ncat <<'ZCL_DECISION_EOF'\n%.*s\nZCL_DECISION_EOF\n", (int)n, wire);
    return written > 0 && (size_t)written < sizeof(body) &&
        dlx_write(script, body) && chmod(script, 0700) == 0;
}

static int dlx_decision_selfupgrade_case(void)
{
    static const char sha[] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    static const char *const args[] = {"dev", "land", "decision", "--seq=674", NULL};
    int failures = 0, lock = -1;
    struct dlx_scope_case t = {0};
    struct dlx_call c;
    bool opened = false;
    char land[1400], root[1024], script[1200], slot[1200], ptr[1200];
    TEST("land: native decision envelope drives typed selfupgrade comparison") {
        ASSERT(dlx_scope_prepare(&t, "decision_selfupgrade", NULL));
        dlx_landdir(land, sizeof(land));
        lock = dlx_step_lock_take(land);
        ASSERT(lock >= 0);
        dlx_step_lock_release(lock); lock = -1;
        test_make_tmpdir(root, sizeof(root), "dev_land_driver", "decision_selfupgrade");
        ASSERT(snprintf(script, sizeof(script), "%s/driver", root) < (int)sizeof(script));
        dlx_begin(&c, "decision"); opened = true;
        ASSERT(json_push_kv_int(&c.input, "seq", 674));
        ASSERT(dlx_decision_wire_script(&c, script));
        dlx_end(&c); opened = false;
        ASSERT(zcl_land_selfupgrade_slot_install(root, sha, script));
        ASSERT(zcl_land_selfupgrade_slot_path(root, sha, slot, sizeof(slot)));
        ASSERT_EQ((int)zcl_land_selfupgrade_observe(root, script, sha, args, 1),
                  (int)ZCL_LAND_SU_SWITCHED);
        ASSERT(zcl_land_selfupgrade_pointer_read(root, ptr, sizeof(ptr)));
        ASSERT_STR_EQ(ptr, slot);
        ASSERT(zcl_land_selfupgrade_row_result(root, false));
        ASSERT(!zcl_land_selfupgrade_pointer_read(root, ptr, sizeof(ptr)));
        ASSERT(dlx_scope_unchanged(&t));
        PASS();
    }
_test_next:;
    if (lock >= 0) dlx_step_lock_release(lock);
    if (opened) dlx_end(&c);
    dlx_restore();
    return failures;
}

static int dlx_decision_queue_case(void)
{
    int failures = 0, lock = -1;
    struct dlx_scope_case t = {0};
    struct dlx_call c;
    bool opened = false;
    char land[1400];
    TEST("land: advisory decision selects the executor head without mutation") {
        ASSERT(dlx_scope_prepare(&t, "decision_queue", NULL));
        dlx_landdir(land, sizeof(land));
        lock = dlx_step_lock_take(land);
        ASSERT(lock >= 0);
        dlx_step_lock_release(lock); lock = -1;
        dlx_begin(&c, "decision"); opened = true;
        ASSERT(c.request.spec != NULL);
        ASSERT(dlx_decision_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "dispatch"), "prepare");
        ASSERT_EQ(dlx_int(&c, "seq"), 674);
        ASSERT(dlx_scope_unchanged(&t));
        ASSERT(dlx_decision_registry(&c));
        ASSERT(dlx_scope_unchanged(&t));
        dlx_end(&c); opened = false;
        dlx_begin(&c, "decision"); opened = true;
        ASSERT(json_push_kv_int(&c.input, "seq", 685));
        ASSERT(dlx_decision_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "dispatch"), "scope_blocked");
        ASSERT_EQ(dlx_int(&c, "seq"), 674);
        ASSERT(dlx_scope_unchanged(&t));
        dlx_end(&c); opened = false;
        lock = dlx_step_lock_take(land);
        ASSERT(lock >= 0);
        dlx_begin(&c, "decision"); opened = true;
        ASSERT(dlx_decision_run(&c));
        ASSERT_STR_EQ(dlx_err_code(&c), "DECISION_UNAVAILABLE");
        ASSERT(!c.reply.error.mutated);
        ASSERT(dlx_scope_unchanged(&t));
        PASS();
    }
_test_next:;
    if (lock >= 0) dlx_step_lock_release(lock);
    if (opened) dlx_end(&c);
    dlx_restore();
    return failures;
}

static int dlx_decision_terminal_case(void)
{
    int failures = 0, lock = -1;
    struct dlx_scope_case t = {0};
    struct dlx_call c;
    bool opened = false;
    char land[1400], path[1500], before[16384], after[16384];
    size_t before_len = 0, after_len = 0;
    TEST("land: advisory decision identifies a durable terminal replay") {
        ASSERT(dlx_scope_prepare(&t, "decision_terminal", NULL));
        dlx_landdir(land, sizeof(land));
        lock = dlx_step_lock_take(land);
        ASSERT(lock >= 0);
        dlx_step_lock_release(lock); lock = -1;
        dlx_begin(&c, "cancel"); opened = true;
        ASSERT(json_push_kv_int(&c.input, "seq", 674));
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        dlx_end(&c); opened = false;
        (void)snprintf(path, sizeof(path), "%s/queue.jsonl", land);
        ASSERT(dlx_write(path, t.queue));
        (void)snprintf(path, sizeof(path), "%s/outcomes.jsonl", land);
        ASSERT(dlx_slurp(path, before, sizeof(before), &before_len));
        dlx_begin(&c, "decision"); opened = true;
        ASSERT(dlx_decision_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "dispatch"), "terminal_replay");
        ASSERT_EQ(dlx_int(&c, "seq"), 674);
        ASSERT(dlx_scope_unchanged(&t));
        ASSERT(dlx_slurp(path, after, sizeof(after), &after_len));
        ASSERT(before_len == after_len && memcmp(before, after, before_len) == 0);
        dlx_end(&c); opened = false;
        ASSERT(dlx_write(path, "malformed\n"));
        dlx_begin(&c, "decision"); opened = true;
        ASSERT(dlx_decision_run(&c));
        ASSERT_STR_EQ(dlx_err_code(&c), "DECISION_UNAVAILABLE");
        ASSERT(!c.reply.error.mutated);
        ASSERT(dlx_slurp(path, after, sizeof(after), &after_len));
        ASSERT(after_len == strlen("malformed\n") &&
               memcmp(after, "malformed\n", after_len) == 0);
        dlx_end(&c); opened = false;
        before[before_len] = '\0';
        ASSERT(dlx_write(path, before));
        dlx_begin(&c, "step"); opened = true;
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "cancelled");
        PASS();
    }
_test_next:;
    if (lock >= 0) dlx_step_lock_release(lock);
    if (opened) dlx_end(&c);
    dlx_restore();
    return failures;
}

static int dlx_decision_unavailable_case(void)
{
    int failures = 0, lock = -1;
    struct dlx_scope_case t = {0};
    struct dlx_call c;
    bool opened = false;
    char land[1400], path[1500], after[128];
    size_t n = 0;
    struct stat st;
    TEST("land: advisory decision refuses missing state and malformed queue without writes") {
        dlx_isolate("decision_missing");
        (void)snprintf(path, sizeof(path), "%s/z23/dev/land", g_dlx_state);
        ASSERT(lstat(path, &st) != 0 && errno == ENOENT);
        dlx_begin(&c, "decision"); opened = true;
        ASSERT(dlx_decision_run(&c));
        ASSERT_STR_EQ(dlx_err_code(&c), "DECISION_UNAVAILABLE");
        ASSERT(!c.reply.error.mutated);
        ASSERT(lstat(path, &st) != 0 && errno == ENOENT);
        dlx_end(&c); opened = false;
        dlx_restore();
        ASSERT(dlx_scope_prepare(&t, "decision_malformed", NULL));
        dlx_landdir(land, sizeof(land));
        lock = dlx_step_lock_take(land);
        ASSERT(lock >= 0);
        dlx_step_lock_release(lock); lock = -1;
        (void)snprintf(path, sizeof(path), "%s/queue.jsonl", land);
        ASSERT(dlx_write(path, "malformed\n"));
        dlx_begin(&c, "decision"); opened = true;
        ASSERT(dlx_decision_run(&c));
        ASSERT_STR_EQ(dlx_err_code(&c), "DECISION_UNAVAILABLE");
        ASSERT(!c.reply.error.mutated);
        ASSERT(dlx_slurp(path, after, sizeof(after), &n));
        ASSERT(n == strlen("malformed\n") && memcmp(after, "malformed\n", n) == 0);
        PASS();
    }
_test_next:;
    if (lock >= 0) dlx_step_lock_release(lock);
    if (opened) dlx_end(&c);
    dlx_restore();
    return failures;
}

static int dlx_decision_drift_case(void)
{
    int failures = 0, lock = -1, status = 0;
    int ready[2] = {-1, -1}, release[2] = {-1, -1};
    pid_t child = -1;
    struct dlx_scope_case t = {0};
    char land[1400], path[1500], moved[1500], marker;
    TEST("land: advisory decision refuses a replaced snapshot lock") {
        ASSERT(dlx_scope_prepare(&t, "decision_drift", NULL));
        dlx_landdir(land, sizeof(land));
        lock = dlx_step_lock_take(land);
        ASSERT(lock >= 0);
        dlx_step_lock_release(lock); lock = -1;
        ASSERT(dlx_pick_barrier_open(ready, release));
        zcl_native_dev_land_test_pick_barrier(ready[1], release[0]);
        child = fork();
        ASSERT(child >= 0);
        if (child == 0) {
            (void)alarm(30);
            (void)close(ready[0]); (void)close(release[1]);
            struct dlx_call c;
            dlx_begin(&c, "decision");
            bool ok = dlx_decision_run(&c) &&
                dlx_eq_str(dlx_err_code(&c), "DECISION_UNAVAILABLE") &&
                !c.reply.error.mutated;
            dlx_end(&c);
            _exit(ok ? 0 : 1);
        }
        zcl_native_dev_land_test_pick_barrier(-1, -1);
        (void)close(ready[1]); ready[1] = -1;
        (void)close(release[0]); release[0] = -1;
        struct pollfd p = { .fd = ready[0], .events = POLLIN };
        ASSERT(poll(&p, 1, 15000) == 1 && read(ready[0], &marker, 1) == 1 && marker == 'R');
        (void)snprintf(path, sizeof(path), "%s/step.lock", land);
        (void)snprintf(moved, sizeof(moved), "%s/step-old.lock", land);
        ASSERT(rename(path, moved) == 0);
        ASSERT(dlx_write(path, ""));
        ASSERT(write(release[1], "G", 1) == 1);
        (void)close(release[1]); release[1] = -1;
        ASSERT(waitpid(child, &status, 0) == child);
        child = -1;
        ASSERT(WIFEXITED(status) && WEXITSTATUS(status) == 0);
        ASSERT(dlx_scope_unchanged(&t));
        PASS();
    }
_test_next:;
    zcl_native_dev_land_test_pick_barrier(-1, -1);
    if (lock >= 0) dlx_step_lock_release(lock);
    for (size_t i = 0; i < 2; ++i) {
        if (ready[i] >= 0) (void)close(ready[i]);
        if (release[i] >= 0) (void)close(release[i]);
    }
    if (child > 0) (void)waitpid(child, NULL, 0);
    dlx_restore();
    return failures;
}

static int dlx_status_encoding_failure_case(void)
{
    int failures = 0;
    struct dlx_scope_case t = {0};
    struct dlx_call c;
    bool opened = false;
    TEST("land: status attachment allocation failure refuses a partial snapshot") {
        ASSERT(dlx_scope_prepare(&t, "status_encode_failure", NULL));
        dlx_begin_status(&c); opened = true;
        zcl_native_handle_dev_land_status(&c.request, &c.reply);
        ASSERT(dlx_ok(&c));
        const struct json_value *queued = json_get(&c.reply.data, "queued");
        const struct json_value *outcomes = json_get(&c.reply.data, "outcomes");
        ASSERT(queued && queued->type == JSON_ARR && queued->num_children > 0);
        ASSERT(outcomes && outcomes->type == JSON_ARR);
        dlx_end(&c); opened = false;

        dlx_begin_status(&c); opened = true;
        /* Fail the top-level queued attachment after its rows were built. */
        zcl_alloc_fault_fail_nth("json_push_kv_key", 32);
        zcl_native_handle_dev_land_status(&c.request, &c.reply);
        bool consumed = zcl_alloc_fault_armed_label() == NULL;
        zcl_alloc_fault_clear();
        ASSERT(consumed && !dlx_ok(&c));
        ASSERT_STR_EQ(dlx_err_code(&c), "QUEUE_READ_FAILED");
        ASSERT(!json_get(&c.reply.data, "queued") && !json_get(&c.reply.data, "outcomes"));
        ASSERT(!json_get(&c.reply.data, "steer") && !json_get(&c.reply.data, "incident"));
        PASS();
    }
_test_next:;
    zcl_alloc_fault_clear();
    if (opened) dlx_end(&c);
    dlx_restore();
    return failures;
}

static int test_dev_land_drive_seq_scope(void)
{
    return dlx_status_encoding_failure_case() + dlx_decision_selfupgrade_case() +
           dlx_decision_row_hash_case() + dlx_decision_empty_hash_case() +
           dlx_decision_encoding_failure_case() +
           dlx_decision_queue_case() + dlx_decision_terminal_case() +
           dlx_decision_unavailable_case() + dlx_decision_drift_case() +
           dlx_scope_refusal_case(685, NULL, "requested_seq=685 blocking_seq=674") +
           dlx_scope_refusal_case(999, "cancelled", "unknown_seq_999") +
           dlx_scope_refusal_case(685, "cancelled", "row_cancelled") +
           dlx_scope_landed_target() + dlx_scope_requested_head() +
           dlx_scope_shared_fence() + dlx_scope_isolation_guard();
}
#endif

/* The historical dispatcher's ordered invocation list. Each row remains an
 * indivisible scenario; shard processes own all environment, cwd and native
 * test-hook mutation. Portable rows 2–4 keep every shard nonempty on Windows.
 * The umbrella walks this list in its original order. */
#define DLX_SHARD_COUNT 4u
#define DLX_ALL_SHARDS DLX_SHARD_COUNT
#define DLX_UMBRELLA "test_dev_land"

#if !defined(_WIN32)
static int dlx_shard_row_071(void)
{
    return test_dev_land_competing_publish("step", "step", true);
}
static int dlx_shard_row_072(void)
{
    return test_dev_land_competing_publish("step", "drive", true);
}
static int dlx_shard_row_073(void)
{
    return test_dev_land_competing_publish("drive", "step", true);
}
static int dlx_shard_row_074(void)
{
    return test_dev_land_competing_publish("step", "drive", false);
}
static int dlx_shard_row_075(void)
{
    return test_dev_land_competing_publish("drive", "step", false);
}
static int dlx_shard_row_120(void)
{
    return test_dev_land_postpush_observation_missing(false);
}
static int dlx_shard_row_121(void)
{
    return test_dev_land_postpush_observation_missing(true);
}
static int dlx_shard_row_158(void)
{
    return test_dev_land_integrated_merge(false);
}
static int dlx_shard_row_159(void)
{
    return test_dev_land_integrated_merge(true);
}

/* A retired marker file at the land path is not a missing state root.
 * Cancel reaches dl_dirs_make after only a seq check, so this drives the
 * shipped refusal from that start state. */
static int test_dev_land_land_file(void)
{
    int failures = 0;
    TEST("land: a land path that is not a directory names that path and dev land send") {
        char root[4096], land[4200];
        struct dlx_call c;
        FILE *marker;
        dlx_isolate("land_not_dir");
        ASSERT(platform_state_root(root, sizeof(root)));
        ASSERT(snprintf(land, sizeof(land), "%s/land", root) > 0);
        marker = fopen(land, "w");
        ASSERT(marker != NULL);
        ASSERT(fputs("RETIRED\n", marker) >= 0);
        ASSERT(fclose(marker) == 0);
        dlx_begin(&c, "cancel");
        (void)json_push_kv_int(&c.input, "seq", 1);
        ASSERT(dlx_run(&c));
        ASSERT(!dlx_ok(&c));
        ASSERT_STR_EQ(dlx_err_code(&c), "STATE_DIR_FAILED");
        ASSERT_STR_EQ(c.reply.error.message,
                      "this host has no land queue: the land path is not a directory");
        ASSERT_STR_EQ(dlx_err_evidence(&c), land);
        ASSERT_STR_EQ(c.reply.error.next_action,
                      "z23 dev land send --host=<queue-host> --lane=<name> --commit=<sha>");
        dlx_end(&c);
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}
#endif /* !defined(_WIN32) */

struct dlx_shard_case {
    const char *name;
    int (*run)(void);
    unsigned owner;
};

static const struct dlx_shard_case g_dlx_shard_cases[] = {
    {"dlx_selfupgrade_cleanup_case()", dlx_selfupgrade_cleanup_case, 0u},
    {"dlx_selfupgrade_real_child_case()", dlx_selfupgrade_real_child_case, 0u},
    {"dlx_selfupgrade_postland_case()", dlx_selfupgrade_postland_case, 0u},
    {"dlx_selfupgrade_finish_fault_case()", dlx_selfupgrade_finish_fault_case, 0u},
    {"dlx_selfupgrade_crash_case()", dlx_selfupgrade_crash_case, 0u},
    {"dlx_selfupgrade_wrongrow_case()", dlx_selfupgrade_wrongrow_case, 0u},
    {"dlx_selfupgrade_terminal_race_case()", dlx_selfupgrade_terminal_race_case, 0u},
    {"dlx_selfupgrade_cancel_race_case()", dlx_selfupgrade_cancel_race_case, 0u},
    {"dlx_publication_hold_cases()",
     dlx_publication_hold_cases, 0u},
    {"dlx_hold_legacy_case()",
     dlx_hold_legacy_case, 1u},
    {"dlx_guarded_priority_case()",
     dlx_guarded_priority_case, 2u},
    {"dlx_guarded_hold_mismatch_case()",
     dlx_guarded_hold_mismatch_case, 3u},
    {"dlx_hold_pushed_case()",
     dlx_hold_pushed_case, 0u},
    {"dlx_hold_malformed_case()",
     dlx_hold_malformed_case, 0u},
    {"dlx_hold_sealed_case()",
     dlx_hold_sealed_case, 0u},
    {"dlx_hold_lock_case()",
     dlx_hold_lock_case, 0u},
    {"dlx_hold_admissible_during_step()",
     dlx_hold_admissible_during_step, 0u},
    {"dlx_hold_survives_step_rewrite()",
     dlx_hold_survives_step_rewrite, 0u},
    {"dlx_launcher_join_cases()",
     dlx_launcher_join_cases, 0u},
    {"dlx_origin_config_cases()",
     dlx_origin_config_cases, 0u},
    {"dlx_attest_only_cases()",
     dlx_attest_only_cases, 0u},
    {"dlx_attest_bounded_wire_cases()",
     dlx_attest_bounded_wire_cases, 0u},
    {"dlx_attest_refusal_cases()",
     dlx_attest_refusal_cases, 0u},
    {"test_dev_land_signed_intent()",
     test_dev_land_signed_intent, 0u},
#if !defined(_WIN32)
    {"dlx_fence_cases()",
     dlx_fence_cases, 1u},
    {"dlx_fence_concurrent()",
     dlx_fence_concurrent, 0u},
    {"dlx_fence_negative_cases()",
     dlx_fence_negative_cases, 3u},
    {"test_dev_land_submit_plan_flow()",
     test_dev_land_submit_plan_flow, 0u},
    {"test_dev_land_status_registry_run()",
     test_dev_land_status_registry_run, 0u},
    {"test_dev_land_status_observation()",
     test_dev_land_status_observation, 0u},
#endif
    {"test_dev_land_signed_tamper()",
     test_dev_land_signed_tamper, 0u},
    {"test_dev_land_receipt_adversarial()",
     test_dev_land_receipt_adversarial, 0u},
    {"test_dev_land_signer_takeover()",
     test_dev_land_signer_takeover, 0u},
    {"test_dev_land_signed_stale()",
     test_dev_land_signed_stale, 0u},
    {"test_dev_land_signed_recovery()",
     test_dev_land_signed_recovery, 0u},
    {"test_dev_land_new_source_precheck()",
     test_dev_land_new_source_precheck, 0u},
    {"test_dev_land_drive_producer_reproof()",
     test_dev_land_drive_producer_reproof, 0u},
    {"test_dev_land_step_producer_recovery()",
     test_dev_land_step_producer_recovery, 0u},
#if !defined(_WIN32)
    {"test_dev_land_phase_mail_quiet()",
     test_dev_land_phase_mail_quiet, 0u},
#endif
    {"test_dev_land_phase_digest()",
     test_dev_land_phase_digest, 0u},
    {"test_dev_land_signed_lost_ack()",
     test_dev_land_signed_lost_ack, 0u},
    {"test_dev_land_signed_lost_race()",
     test_dev_land_signed_lost_race, 0u},
    {"test_dev_land_signed_lost_ack_resend()",
     test_dev_land_signed_lost_ack_resend, 0u},
    {"test_dev_land_signed_push_lost_race()",
     test_dev_land_signed_push_lost_race, 0u},
    {"test_dev_land_cancel_push_refused()",
     test_dev_land_cancel_push_refused, 0u},
    {"test_dev_land_push_declined()",
     test_dev_land_push_declined, 0u},
    {"test_dev_land_signed_publisher_death()",
     test_dev_land_signed_publisher_death, 0u},
#if !defined(_WIN32)
    {"test_dev_land_signed_crash_before_push()",
     test_dev_land_signed_crash_before_push, 0u},
    {"test_dev_land_signed_third_party_before_push()",
     test_dev_land_signed_third_party_before_push, 0u},
    {"test_dev_land_signed_unknown_not_retried_blind()",
     test_dev_land_signed_unknown_not_retried_blind, 0u},
    {"test_dev_land_two_candidates_same_base()",
     test_dev_land_two_candidates_same_base, 0u},
#endif
    {"test_dev_land_watcher_admission()",
     test_dev_land_watcher_admission, 0u},
    {"test_dev_land_main_red_advisory()",
     test_dev_land_main_red_advisory, 0u},
    {"test_dev_land_long_proof_root()",
     test_dev_land_long_proof_root, 0u},
    {"test_dev_land_malformed_queue_refusal()",
     test_dev_land_malformed_queue_refusal, 0u},
    {"test_dev_land_chain_codec()",
     test_dev_land_chain_codec, 0u},
    {"test_dev_land_chain_relation()",
     test_dev_land_chain_relation, 0u},
    {"test_dev_land_malformed_priority_refusal()",
     test_dev_land_malformed_priority_refusal, 0u},
    {"test_dev_land_malformed_outcome_refusal()",
     test_dev_land_malformed_outcome_refusal, 0u},
    {"test_dev_land_exact_tree()",
     test_dev_land_exact_tree, 0u},
    {"test_dev_land_source_binding()",
     test_dev_land_source_binding, 0u},
#if !defined(_WIN32)
    {"test_dev_land_tree_types()",
     test_dev_land_tree_types, 0u},
    {"test_dev_land_tree_malformed()",
     test_dev_land_tree_malformed, 0u},
    {"test_dev_land_tree_replacements()",
     test_dev_land_tree_replacements, 0u},
    {"test_dev_land_tree_missing()",
     test_dev_land_tree_missing, 0u},
    {"test_dev_land_proof_evidence_test()",
     test_dev_land_proof_evidence_test, 0u},
    {"test_dev_land_resubmit_failed_pair()",
     test_dev_land_resubmit_failed_pair, 0u},
    {"test_dev_land_refusal_names_next_step()",
     test_dev_land_refusal_names_next_step, 0u},
    {"test_dev_land_proof_evidence_compile()",
     test_dev_land_proof_evidence_compile, 0u},
    {"test_dev_land_gate_diagnostic_window()",
     test_dev_land_gate_diagnostic_window, 0u},
#endif
    {"dlx_case_registration()",
     dlx_case_registration, 1u},
    {"dlx_case_unknown_action()",
     dlx_case_unknown_action, 1u},
#if !defined(_WIN32)
    {"dlx_case_unsigned_tip()",
     dlx_case_unsigned_tip, 1u},
    {"dlx_case_checkout_location()",
     dlx_case_checkout_location, 1u},
    {"dlx_case_submit_status()",
     dlx_case_submit_status, 1u},
    {"dlx_case_duplicate_submit()",
     dlx_case_duplicate_submit, 1u},
    {"dlx_case_precheck()",
     dlx_case_precheck, 1u},
    {"dlx_case_empty_step()",
     dlx_case_empty_step, 1u},
    {"dlx_case_step_lock()",
     dlx_case_step_lock, 1u},
    {"dlx_case_starts_proof()",
     dlx_case_starts_proof, 1u},
    {"dlx_case_absent_watcher()",
     dlx_case_absent_watcher, 1u},
    {"dlx_case_unarmed_proof()",
     dlx_case_unarmed_proof, 1u},
    {"test_dev_land_missing_worker()",
     test_dev_land_missing_worker, 1u},
    {"test_dev_land_interrupted_proof()",
     test_dev_land_interrupted_proof, 1u},
#if !defined(_WIN32)
    {"test_dev_land_drive_base_watch()",
     test_dev_land_drive_base_watch, 1u},
#endif
    {"test_dev_land_competing_publish(\"step\", \"step\", true)",
     dlx_shard_row_071, 1u},
    {"test_dev_land_competing_publish(\"step\", \"drive\", true)",
     dlx_shard_row_072, 1u},
    {"test_dev_land_competing_publish(\"drive\", \"step\", true)",
     dlx_shard_row_073, 1u},
    {"test_dev_land_competing_publish(\"step\", \"drive\", false)",
     dlx_shard_row_074, 1u},
    {"test_dev_land_competing_publish(\"drive\", \"step\", false)",
     dlx_shard_row_075, 1u},
    {"test_dev_land_bounded_drive()",
     test_dev_land_bounded_drive, 1u},
    {"test_dev_land_drive_seq_lands()",
     test_dev_land_drive_seq_lands, 1u},
    {"test_dev_land_drive_seq_scope()",
     test_dev_land_drive_seq_scope, 1u},
    {"test_dev_land_drive_seq_refusals()",
     test_dev_land_drive_seq_refusals, 1u},
    {"test_dev_land_drive_seq_proof_failed()",
     test_dev_land_drive_seq_proof_failed, 1u},
    {"test_dev_land_drive_seq_stops()",
     test_dev_land_drive_seq_stops, 1u},
    {"test_dev_land_prove_drive1()", test_dev_land_prove_drive1, 1u},
    {"test_dev_land_prove_drive2()", test_dev_land_prove_drive2, 1u},
    {"test_dev_land_prove_drive3()", test_dev_land_prove_drive3, 1u},
    {"test_dev_land_prove_drive4()", test_dev_land_prove_drive4, 1u},
    {"test_dev_land_prove_drive5()", test_dev_land_prove_drive5, 1u},
    {"test_dev_land_prove_drive6()", test_dev_land_prove_drive6, 1u},
    {"test_dev_land_drain_cases()", test_dev_land_drain_cases, 1u},
    {"test_dev_land_qualify_make_caps()",
     test_dev_land_qualify_make_caps, 1u},
    {"test_dev_land_qualify_canonical_aliases()",
     test_dev_land_qualify_canonical_aliases, 1u},
    {"test_dev_land_qualify_unregistered_group()",
     test_dev_land_qualify_unregistered_group, 1u},
    {"test_dev_land_qualify_passes()",
     test_dev_land_qualify_passes, 1u},
    {"test_dev_land_qualify_job_caps()",
     test_dev_land_qualify_job_caps, 1u},
    {"test_dev_land_qualify_complexity()",
     test_dev_land_qualify_complexity, 1u},
    {"test_dev_land_qualify_verdict_rule()",
     test_dev_land_qualify_verdict_rule, 1u},
    {"test_dev_land_qualify_refusals()",
     test_dev_land_qualify_refusals, 1u},
    {"test_dev_land_qualify_dirty_tree()",
     test_dev_land_qualify_dirty_tree, 1u},
    {"test_dev_land_qualify_stale_doc_refused()",
     test_dev_land_qualify_stale_doc_refused, 1u},
    {"test_dev_land_qualify_group_verdicts()",
     test_dev_land_qualify_group_verdicts, 1u},
    {"test_dev_land_qualify_groups_reported()",
     test_dev_land_qualify_groups_reported, 1u},
    {"test_dev_land_qualify_wide_route()",
     test_dev_land_qualify_wide_route, 1u},
    {"test_dev_land_qualify_selection_refusals()",
     test_dev_land_qualify_selection_refusals, 1u},
    {"test_dev_land_qualify_origin_moves()",
     test_dev_land_qualify_origin_moves, 1u},
    {"test_dev_land_qualify_rebase_and_fetch_failures()",
     test_dev_land_qualify_rebase_and_fetch_failures, 1u},
    {"test_dev_land_drive_seq_landed_reply_stands_alone()",
     test_dev_land_drive_seq_landed_reply_stands_alone, 1u},
    {"test_dev_land_stubs_are_test_build_only()",
     test_dev_land_stubs_are_test_build_only, 1u},
    {"dlx_case_stub_detail()",
     dlx_case_stub_detail, 2u},
    {"dlx_case_lands_proof()",
     dlx_case_lands_proof, 2u},
    {"dlx_case_hook_refusal()",
     dlx_case_hook_refusal, 2u},
    {"dlx_case_proof_failure()",
     dlx_case_proof_failure, 2u},
    {"dlx_case_timing_detail()",
     dlx_case_timing_detail, 2u},
    {"dlx_case_moved_base()",
     dlx_case_moved_base, 2u},
    {"test_dev_land_explicit_main()",
     test_dev_land_explicit_main, 2u},
    {"test_dev_land_stale_file_retests()",
     test_dev_land_stale_file_retests, 2u},
    {"test_dev_land_missing_main()",
     test_dev_land_missing_main, 2u},
    {"test_dev_land_initial_remote_missing()",
     test_dev_land_initial_remote_missing, 2u},
    {"test_dev_land_final_observation_missing()",
     test_dev_land_final_observation_missing, 2u},
    {"dlx_case_cancel_request()",
     dlx_case_cancel_request, 2u},
    {"dlx_case_concurrent_submit()",
     dlx_case_concurrent_submit, 2u},
    {"dlx_case_dense_detail()",
     dlx_case_dense_detail, 2u},
    {"test_dev_land_publisher_death()",
     test_dev_land_publisher_death, 2u},
    {"test_dev_land_drain_adoption()",
     test_dev_land_drain_adoption, 2u},
    {"test_dev_land_postpush_observation_missing(false)",
     dlx_shard_row_120, 2u},
    {"test_dev_land_postpush_observation_missing(true)",
     dlx_shard_row_121, 2u},
    {"test_dev_land_prepush_checkpoint()",
     test_dev_land_prepush_checkpoint, 2u},
    {"test_dev_land_prepush_persist_refusal()",
     test_dev_land_prepush_persist_refusal, 2u},
    {"test_dev_land_prepush_sync_refusal()",
     test_dev_land_prepush_sync_refusal, 2u},
    {"test_dev_land_missing_publication_intent()",
     test_dev_land_missing_publication_intent, 2u},
    {"test_dev_land_attach_target_cases()",
     test_dev_land_attach_target_cases, 2u},
    {"test_dev_land_postpush_result_unconfirmed()",
     test_dev_land_postpush_result_unconfirmed, 2u},
    {"test_dev_land_expected_base_race()",
     test_dev_land_expected_base_race, 2u},
    {"test_dev_land_recovery_ignores_replace_refs()",
     test_dev_land_recovery_ignores_replace_refs, 2u},
    {"test_dev_land_nonfastforward_client_guard()",
     test_dev_land_nonfastforward_client_guard, 2u},
    {"test_dev_land_lost_persistence()",
     test_dev_land_lost_persistence, 2u},
    {"test_dev_land_after_proof_restart()",
     test_dev_land_after_proof_restart, 2u},
    {"test_dev_land_objectives_snapshot()",
     test_dev_land_objectives_snapshot, 2u},
    {"test_dev_land_objectives_append_blocked()",
     test_dev_land_objectives_append_blocked, 2u},
    {"test_dev_land_objectives_failed_outcome()",
     test_dev_land_objectives_failed_outcome, 2u},
    {"test_dev_land_terminal_replay()",
     test_dev_land_terminal_replay, 2u},
    {"test_dev_land_outcome_visible_in_mail()",
     test_dev_land_outcome_visible_in_mail, 2u},
    {"dlx_case_missing_hook()",
     dlx_case_missing_hook, 2u},
    {"dlx_case_cancel_race()",
     dlx_case_cancel_race, 2u},
    {"dlx_case_aged_successor()",
     dlx_case_aged_successor, 2u},
    {"test_dev_land_main_moves_converge()",
     test_dev_land_main_moves_converge, 2u},
    {"dlx_case_option_path()",
     dlx_case_option_path, 2u},
    {"test_dev_land_vendor_dependencies()",
     test_dev_land_vendor_dependencies, 2u},
    {"dlx_case_dependency_links()",
     dlx_case_dependency_links, 2u},
    {"dlx_case_missing_dependency()",
     dlx_case_missing_dependency, 2u},
    {"test_dev_land_missing_tor_makefile()",
     test_dev_land_missing_tor_makefile, 2u},
    {"dlx_case_tor_gitlink()",
     dlx_case_tor_gitlink, 2u},
    {"dlx_case_tor_head()",
     dlx_case_tor_head, 2u},
    {"dlx_case_hook_drift()",
     dlx_case_hook_drift, 2u},
    {"dlx_case_idle_proof()",
     dlx_case_idle_proof, 2u},
    {"dlx_case_unclaimed_proof()",
     dlx_case_unclaimed_proof, 2u},
    {"dlx_case_missing_hook_binary()",
     dlx_case_missing_hook_binary, 2u},
    {"dlx_case_quiet_hooks()",
     dlx_case_quiet_hooks, 2u},
    {"dlx_case_uninitialised_tor()",
     dlx_case_uninitialised_tor, 2u},
    {"dlx_case_current_tor()",
     dlx_case_current_tor, 2u},
    {"dlx_case_generated_conflict()",
     dlx_case_generated_conflict, 2u},
    {"dlx_case_rerere_conflict()",
     dlx_case_rerere_conflict, 2u},
    {"dlx_case_retired_generated_conflict()",
     dlx_case_retired_generated_conflict, 2u},
    {"dlx_case_mixed_conflict()",
     dlx_case_mixed_conflict, 2u},
    {"dlx_case_core_reseal()",
     dlx_case_core_reseal, 3u},
    {"test_dev_land_integrated_merge(false)",
     dlx_shard_row_158, 3u},
    {"test_dev_land_integrated_merge(true)",
     dlx_shard_row_159, 3u},
    {"test_dev_land_proof_tools_preparation()",
     test_dev_land_proof_tools_preparation, 3u},
    {"test_dev_land_final_plan_preparation()",
     test_dev_land_final_plan_preparation, 3u},
    {"test_dev_land_rebase_count_conflicts()",
     test_dev_land_rebase_count_conflicts, 3u},
    {"test_dev_land_queued_precheck_cases()",
     test_dev_land_queued_precheck_cases, 3u},
    {"test_dev_land_train_cases()",
     test_dev_land_train_cases, 2u},
    {"test_dev_land_train_culprit_cases()",
     test_dev_land_train_culprit_cases, 2u},
    {"test_dev_land_test_hatches_testing_only()",
     test_dev_land_test_hatches_testing_only, 3u},
    {"dlx_outcome_escape_cases()",
     dlx_outcome_escape_cases, 3u},
    {"dlx_optional_string_refusal_cases()",
     dlx_optional_string_refusal_cases, 3u},
    {"dlx_string_compatibility_cases()",
     dlx_string_compatibility_cases, 3u},
    {"test_dev_land_window_defer()",
     test_dev_land_window_defer, 3u},
    {"test_dev_land_window_replay()",
     test_dev_land_window_replay, 3u},
    {"test_dev_land_land_file()",
     test_dev_land_land_file, 0u},
#endif /* !defined(_WIN32) */
};
#define DLX_CASE_COUNT \
    (sizeof(g_dlx_shard_cases) / sizeof(g_dlx_shard_cases[0]))

/* Independently retained from the original dispatcher, including call
 * arguments and platform guards: dropping, duplicating or reordering a row
 * in the ownership table must fail before any scenario runs. */
static const char *const g_dlx_original_calls[] = {
    "dlx_selfupgrade_cleanup_case()",
    "dlx_selfupgrade_real_child_case()",
    "dlx_selfupgrade_postland_case()",
    "dlx_selfupgrade_finish_fault_case()",
    "dlx_selfupgrade_crash_case()",
    "dlx_selfupgrade_wrongrow_case()",
    "dlx_selfupgrade_terminal_race_case()",
    "dlx_selfupgrade_cancel_race_case()",
    "dlx_publication_hold_cases()",
    "dlx_hold_legacy_case()",
    "dlx_guarded_priority_case()",
    "dlx_guarded_hold_mismatch_case()",
    "dlx_hold_pushed_case()",
    "dlx_hold_malformed_case()",
    "dlx_hold_sealed_case()",
    "dlx_hold_lock_case()",
    "dlx_hold_admissible_during_step()",
    "dlx_hold_survives_step_rewrite()",
    "dlx_launcher_join_cases()",
    "dlx_origin_config_cases()",
    "dlx_attest_only_cases()",
    "dlx_attest_bounded_wire_cases()",
    "dlx_attest_refusal_cases()",
    "test_dev_land_signed_intent()",
#if !defined(_WIN32)
    "dlx_fence_cases()",
    "dlx_fence_concurrent()",
    "dlx_fence_negative_cases()",
    "test_dev_land_submit_plan_flow()",
    "test_dev_land_status_registry_run()",
    "test_dev_land_status_observation()",
#endif
    "test_dev_land_signed_tamper()",
    "test_dev_land_receipt_adversarial()",
    "test_dev_land_signer_takeover()",
    "test_dev_land_signed_stale()",
    "test_dev_land_signed_recovery()",
    "test_dev_land_new_source_precheck()",
    "test_dev_land_drive_producer_reproof()",
    "test_dev_land_step_producer_recovery()",
#if !defined(_WIN32)
    "test_dev_land_phase_mail_quiet()",
#endif
    "test_dev_land_phase_digest()",
    "test_dev_land_signed_lost_ack()",
    "test_dev_land_signed_lost_race()",
    "test_dev_land_signed_lost_ack_resend()",
    "test_dev_land_signed_push_lost_race()",
    "test_dev_land_cancel_push_refused()",
    "test_dev_land_push_declined()",
    "test_dev_land_signed_publisher_death()",
#if !defined(_WIN32)
    "test_dev_land_signed_crash_before_push()",
    "test_dev_land_signed_third_party_before_push()",
    "test_dev_land_signed_unknown_not_retried_blind()",
    "test_dev_land_two_candidates_same_base()",
#endif
    "test_dev_land_watcher_admission()",
    "test_dev_land_main_red_advisory()",
    "test_dev_land_long_proof_root()",
    "test_dev_land_malformed_queue_refusal()",
    "test_dev_land_chain_codec()",
    "test_dev_land_chain_relation()",
    "test_dev_land_malformed_priority_refusal()",
    "test_dev_land_malformed_outcome_refusal()",
    "test_dev_land_exact_tree()",
    "test_dev_land_source_binding()",
#if !defined(_WIN32)
    "test_dev_land_tree_types()",
    "test_dev_land_tree_malformed()",
    "test_dev_land_tree_replacements()",
    "test_dev_land_tree_missing()",
    "test_dev_land_proof_evidence_test()",
    "test_dev_land_resubmit_failed_pair()",
    "test_dev_land_refusal_names_next_step()",
    "test_dev_land_proof_evidence_compile()",
    "test_dev_land_gate_diagnostic_window()",
#endif
    "dlx_case_registration()",
    "dlx_case_unknown_action()",
#if !defined(_WIN32)
    "dlx_case_unsigned_tip()",
    "dlx_case_checkout_location()",
    "dlx_case_submit_status()",
    "dlx_case_duplicate_submit()",
    "dlx_case_precheck()",
    "dlx_case_empty_step()",
    "dlx_case_step_lock()",
    "dlx_case_starts_proof()",
    "dlx_case_absent_watcher()",
    "dlx_case_unarmed_proof()",
    "test_dev_land_missing_worker()",
    "test_dev_land_interrupted_proof()",
#if !defined(_WIN32)
    "test_dev_land_drive_base_watch()",
#endif
    "test_dev_land_competing_publish(\"step\", \"step\", true)",
    "test_dev_land_competing_publish(\"step\", \"drive\", true)",
    "test_dev_land_competing_publish(\"drive\", \"step\", true)",
    "test_dev_land_competing_publish(\"step\", \"drive\", false)",
    "test_dev_land_competing_publish(\"drive\", \"step\", false)",
    "test_dev_land_bounded_drive()",
    "test_dev_land_drive_seq_lands()",
    "test_dev_land_drive_seq_scope()",
    "test_dev_land_drive_seq_refusals()",
    "test_dev_land_drive_seq_proof_failed()",
    "test_dev_land_drive_seq_stops()",
    "test_dev_land_prove_drive1()",
    "test_dev_land_prove_drive2()",
    "test_dev_land_prove_drive3()",
    "test_dev_land_prove_drive4()",
    "test_dev_land_prove_drive5()",
    "test_dev_land_prove_drive6()",
    "test_dev_land_drain_cases()",
    "test_dev_land_qualify_make_caps()",
    "test_dev_land_qualify_canonical_aliases()",
    "test_dev_land_qualify_unregistered_group()",
    "test_dev_land_qualify_passes()",
    "test_dev_land_qualify_job_caps()",
    "test_dev_land_qualify_complexity()",
    "test_dev_land_qualify_verdict_rule()",
    "test_dev_land_qualify_refusals()",
    "test_dev_land_qualify_dirty_tree()",
    "test_dev_land_qualify_stale_doc_refused()",
    "test_dev_land_qualify_group_verdicts()",
    "test_dev_land_qualify_groups_reported()",
    "test_dev_land_qualify_wide_route()",
    "test_dev_land_qualify_selection_refusals()",
    "test_dev_land_qualify_origin_moves()",
    "test_dev_land_qualify_rebase_and_fetch_failures()",
    "test_dev_land_drive_seq_landed_reply_stands_alone()",
    "test_dev_land_stubs_are_test_build_only()",
    "dlx_case_stub_detail()",
    "dlx_case_lands_proof()",
    "dlx_case_hook_refusal()",
    "dlx_case_proof_failure()",
    "dlx_case_timing_detail()",
    "dlx_case_moved_base()",
    "test_dev_land_explicit_main()",
    "test_dev_land_stale_file_retests()",
    "test_dev_land_missing_main()",
    "test_dev_land_initial_remote_missing()",
    "test_dev_land_final_observation_missing()",
    "dlx_case_cancel_request()",
    "dlx_case_concurrent_submit()",
    "dlx_case_dense_detail()",
    "test_dev_land_publisher_death()",
    "test_dev_land_drain_adoption()",
    "test_dev_land_postpush_observation_missing(false)",
    "test_dev_land_postpush_observation_missing(true)",
    "test_dev_land_prepush_checkpoint()",
    "test_dev_land_prepush_persist_refusal()",
    "test_dev_land_prepush_sync_refusal()",
    "test_dev_land_missing_publication_intent()",
    "test_dev_land_attach_target_cases()",
    "test_dev_land_postpush_result_unconfirmed()",
    "test_dev_land_expected_base_race()",
    "test_dev_land_recovery_ignores_replace_refs()",
    "test_dev_land_nonfastforward_client_guard()",
    "test_dev_land_lost_persistence()",
    "test_dev_land_after_proof_restart()",
    "test_dev_land_objectives_snapshot()",
    "test_dev_land_objectives_append_blocked()",
    "test_dev_land_objectives_failed_outcome()",
    "test_dev_land_terminal_replay()",
    "test_dev_land_outcome_visible_in_mail()",
    "dlx_case_missing_hook()",
    "dlx_case_cancel_race()",
    "dlx_case_aged_successor()",
    "test_dev_land_main_moves_converge()",
    "dlx_case_option_path()",
    "test_dev_land_vendor_dependencies()",
    "dlx_case_dependency_links()",
    "dlx_case_missing_dependency()",
    "test_dev_land_missing_tor_makefile()",
    "dlx_case_tor_gitlink()",
    "dlx_case_tor_head()",
    "dlx_case_hook_drift()",
    "dlx_case_idle_proof()",
    "dlx_case_unclaimed_proof()",
    "dlx_case_missing_hook_binary()",
    "dlx_case_quiet_hooks()",
    "dlx_case_uninitialised_tor()",
    "dlx_case_current_tor()",
    "dlx_case_generated_conflict()",
    "dlx_case_rerere_conflict()",
    "dlx_case_retired_generated_conflict()",
    "dlx_case_mixed_conflict()",
    "dlx_case_core_reseal()",
    "test_dev_land_integrated_merge(false)",
    "test_dev_land_integrated_merge(true)",
    "test_dev_land_proof_tools_preparation()",
    "test_dev_land_final_plan_preparation()",
    "test_dev_land_rebase_count_conflicts()",
    "test_dev_land_queued_precheck_cases()",
    "test_dev_land_train_cases()",
    "test_dev_land_train_culprit_cases()",
    "test_dev_land_test_hatches_testing_only()",
    "dlx_outcome_escape_cases()",
    "dlx_optional_string_refusal_cases()",
    "dlx_string_compatibility_cases()",
    "test_dev_land_window_defer()",
    "test_dev_land_window_replay()",
    "test_dev_land_land_file()",
#endif /* !defined(_WIN32) */
};
#define DLX_ORIGINAL_COUNT \
    (sizeof(g_dlx_original_calls) / sizeof(g_dlx_original_calls[0]))

static bool dlx_shard_partition_valid(void)
{
    unsigned owned[DLX_SHARD_COUNT] = {0};
    if (DLX_CASE_COUNT != DLX_ORIGINAL_COUNT ||
        !zcl_test_group_is_umbrella(DLX_UMBRELLA) ||
        zcl_test_group_umbrella_shard_count(DLX_UMBRELLA) != DLX_SHARD_COUNT)
        return false;
    for (size_t i = 0; i < DLX_CASE_COUNT; i++) {
        const struct dlx_shard_case *row = &g_dlx_shard_cases[i];
        if (!row->run || row->owner >= DLX_SHARD_COUNT ||
            strcmp(row->name, g_dlx_original_calls[i]) != 0)
            return false;
        owned[row->owner]++;
        for (size_t j = 0; j < i; j++)
            if (strcmp(row->name, g_dlx_shard_cases[j].name) == 0)
                return false;
    }
    for (unsigned s = 0; s < DLX_SHARD_COUNT; s++) {
        char id[ZCL_TEST_GROUP_FULL_MAX];
        (void)snprintf(id, sizeof(id), DLX_UMBRELLA "_shard_%02u", s + 1u);
        if (!owned[s] || !zcl_test_group_is_umbrella_shard(DLX_UMBRELLA, id))
            return false;
    }
    return true;
}

static int dlx_run_shard(unsigned shard)
{
    /* A malformed partition never starts a scenario, even for the umbrella. */
    if (shard > DLX_ALL_SHARDS || !dlx_shard_partition_valid()) {
        printf("test_dev_land: invalid shard partition\n");
        return 1;
    }
    /* The landing snapshot reads the node rows from these instead of asking
     * a live node: no scenario here may reach one. */
    (void)setenv("ZCL_LAND_OBJECTIVES_BRIEF", "/nonexistent/z23-dl/brief.json", 1);
    (void)setenv("ZCL_LAND_OBJECTIVES_DATADIR", "/nonexistent/z23-dl/datadir", 1);
    int failures = 0;
    size_t ran = 0;
    for (size_t i = 0; i < DLX_CASE_COUNT; i++) {
        const struct dlx_shard_case *row = &g_dlx_shard_cases[i];
        if (shard != DLX_ALL_SHARDS && row->owner != shard)
            continue;
        int64_t dlx_row_started = platform_time_monotonic_us();
        int added = row->run();
        int64_t dlx_row_elapsed =
            platform_time_monotonic_us() - dlx_row_started;
        failures += added;
        ran++;
        printf("[dev-land-case] shard=%u name=%s us=%lld failures=%d\n",
               row->owner + 1u, row->name, (long long)dlx_row_elapsed, added);
    }
    dlx_restore();
    printf("test_dev_land: ran %zu of %zu scenarios (%s), %d failed\n",
           ran, DLX_CASE_COUNT,
           shard == DLX_ALL_SHARDS ? "umbrella" : "one shard", failures);
    if (failures == 0)
        printf("test_dev_land: all passed\n");
    else
        printf("test_dev_land: %d FAILED\n", failures);
    return failures;
}

int test_dev_land(void)
{
    return dlx_run_shard(DLX_ALL_SHARDS);
}

int test_dev_land_shard_01(void)
{
    return dlx_run_shard(0u);
}

int test_dev_land_shard_02(void)
{
    return dlx_run_shard(1u);
}

int test_dev_land_shard_03(void)
{
    return dlx_run_shard(2u);
}

int test_dev_land_shard_04(void)
{
    return dlx_run_shard(3u);
}
