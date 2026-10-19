/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_ops_slot_activate - `ops slot activate` and `ops slot status`
 * (tools/command/native_ops_slot_activate.c, native_ops_slot_status.c).
 *
 * The property under test: an instance moves to a slot only through a
 * drop-in, only when its MainPID really runs the slot and its health check
 * passes, and any failure leaves every instance exactly as it was.
 *
 *   a. two instances succeed: drop-ins point at the slot, exec args kept,
 *      last-good recorded, status reports it, the node unit is never touched
 *   b. the second of three fails its health check: the first AND the second
 *      are restored byte for byte, the third is never touched
 *   c. an exe mismatch is refused and rolled back (no prior drop-in: removed)
 *   d. bad slot name, missing slot and unknown class are refused, no effect
 *   e. dry_run writes nothing and runs nothing
 *   f. the listen health check: an open port passes; a closed one fails
 *      health and, as the restore cannot pass it either, is reported as
 *      SLOT_ROLLBACK_FAILED (manual attention)
 *
 *   g. the tip_parity health check: equal tips pass; a lagging node, an
 *      unreachable reference or a malformed hash fail health and roll back
 *
 * Hermetic: a fake systemctl script, a fake /proc and per-pid ./test-tmp
 * directories. Outcomes only: no timing is asserted.
 */

#include "test/test_core.h"

#include "command/native_command.h"
#include "command/native_slot_common.h"

#include "json/json.h"
#include "kernel/command_registry.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

struct osa_fx {
    char dir[PATH_MAX], slots[PATH_MAX], units[PATH_MAX], state[PATH_MAX];
    char proc[PATH_MAX], fake[PATH_MAX], calls[PATH_MAX], probe[PATH_MAX];
};

struct osa_cmd {
    struct json_value input;
    struct zcl_command_request request;
    struct zcl_command_reply reply;
};

static int osa_check(bool ok, const char *what)
{
    printf("ops_slot_activate: %s... %s\n", what, ok ? "OK" : "FAIL");
    return ok ? 0 : 1;
}

static void osa_rm_tree(const char *path)
{
    char rm[PATH_MAX + 16];
    snprintf(rm, sizeof(rm), "rm -rf '%s'", path);
    TEST_DISCARD(system(rm));
}

static bool osa_put(const char *path, const char *text, mode_t mode)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    bool ok;
    if (fd < 0)
        return false;
    ok = write(fd, text, strlen(text)) == (ssize_t)strlen(text);
    close(fd);
    return ok && chmod(path, mode) == 0;
}

static long osa_get(const char *path, char *buf, size_t cap)
{
    int fd = open(path, O_RDONLY);
    ssize_t n;
    if (fd < 0)
        return -1;
    n = read(fd, buf, cap - 1);
    close(fd);
    if (n < 0)
        return -1;
    buf[n] = '\0';
    return (long)n;
}

static bool osa_has(const char *path, const char *needle)
{
    char buf[4096];
    return osa_get(path, buf, sizeof(buf)) >= 0 && strstr(buf, needle);
}

static bool osa_exists(const char *path)
{
    struct stat sb;
    return stat(path, &sb) == 0;
}

static const char *const OSA_FAKE_SYSTEMCTL =
    "#!/bin/sh\n"
    "echo \"$*\" >> \"$FAKE_DIR/calls.log\"\n"
    "shift\n"
    "case \"$1\" in\n"
    "daemon-reload) exit 0 ;;\n"
    "restart)\n"
    "  conf=\"$FAKE_UNITS/$2.d/z23-slot.conf\"\n"
    "  bin=/fake/original/z23\n"
    "  if [ -f \"$conf\" ]; then bin=$(sed -n 's/^ExecStart=\\([^ ]*\\).*/\\1/p' \"$conf\" | tail -n 1); fi\n"
    "  if [ -f \"$FAKE_DIR/swap-once\" ]; then rm -f \"$FAKE_DIR/swap-once\"; printf evil > \"$FAKE_SWAP_FILE\"; fi\n"
    "  mkdir -p \"$FAKE_PROC/4242\"\n"
    "  ln -sfn \"${FAKE_EXE_OVERRIDE:-$bin}\" \"$FAKE_PROC/4242/exe\" ;;\n"
    "show) echo 4242 ;;\n"
    "esac\n";

static const char *const OSA_PROBE =
    "#!/bin/sh\n"
    "# fails for a unit with a fail-<unit> marker while it runs the new slot\n"
    "if [ -f \"$FAKE_DIR/fail-$1\" ] && grep -q '/new/z23' \"$FAKE_UNITS/$1.d/z23-slot.conf\"; then exit 1; fi\n"
    "exit 0\n";

static bool osa_fx_init(struct osa_fx *fx, const char *name)
{
    char cwd[PATH_MAX], path[PATH_MAX];
    memset(fx, 0, sizeof(*fx));
    if (!getcwd(cwd, sizeof(cwd)))
        return false;
    snprintf(fx->dir, sizeof(fx->dir), "%s/test-tmp/%d_osa_%s", cwd,
             (int)getpid(), name);
    osa_rm_tree(fx->dir);
    mkdir("./test-tmp", 0755);
    snprintf(fx->slots, sizeof(fx->slots), "%s/slots", fx->dir);
    snprintf(fx->units, sizeof(fx->units), "%s/units", fx->dir);
    snprintf(fx->state, sizeof(fx->state), "%s/state", fx->dir);
    snprintf(fx->proc, sizeof(fx->proc), "%s/proc", fx->dir);
    snprintf(fx->fake, sizeof(fx->fake), "%s/systemctl", fx->dir);
    snprintf(fx->calls, sizeof(fx->calls), "%s/calls.log", fx->dir);
    snprintf(fx->probe, sizeof(fx->probe), "%s/probe.sh", fx->dir);
    if (mkdir(fx->dir, 0755) != 0 || mkdir(fx->slots, 0755) != 0)
        return false;
    for (const char *slot = "old"; slot; slot = strcmp(slot, "old") ? NULL : "new") {
        snprintf(path, sizeof(path), "%s/%s", fx->slots, slot);
        mkdir(path, 0755);
        snprintf(path, sizeof(path), "%s/%s/z23", fx->slots, slot);
        if (!osa_put(path, slot, 0755))
            return false;
        {
            uint8_t sha[32];
            snprintf(path, sizeof(path), "%s/%s", fx->slots, slot);
            if (!slot_binary_digest(path, sha) || !slot_record_write(path, sha))
                return false;
        }
    }
    if (!osa_put(fx->fake, OSA_FAKE_SYSTEMCTL, 0755) ||
        !osa_put(fx->probe, OSA_PROBE, 0755))
        return false;
    setenv("ZCL_BINARY_SLOTS_DIR", fx->slots, 1);
    setenv("ZCL_SLOT_UNIT_DIR", fx->units, 1);
    setenv("ZCL_SLOT_STATE_DIR", fx->state, 1);
    setenv("ZCL_SLOT_SYSTEMCTL_BIN", fx->fake, 1);
    setenv("ZCL_SLOT_PROC_ROOT", fx->proc, 1);
    setenv("FAKE_DIR", fx->dir, 1);
    setenv("FAKE_UNITS", fx->units, 1);
    setenv("FAKE_PROC", fx->proc, 1);
    unsetenv("FAKE_EXE_OVERRIDE");
    return true;
}

static void osa_unit_path(const struct osa_fx *fx, const char *inst, char *out,
                          size_t cap)
{
    snprintf(out, cap, "%s/z23-tunnel-receiver@%s.service.d/z23-slot.conf",
             fx->units, inst);
}

/* A pre-existing drop-in running the old slot, as a prior activate left it. */
static bool osa_seed_old(const struct osa_fx *fx, const char *inst)
{
    char path[PATH_MAX], dir[PATH_MAX], text[PATH_MAX + 128];
    snprintf(dir, sizeof(dir), "%s/z23-tunnel-receiver@%s.service.d",
             fx->units, inst);
    mkdir(fx->units, 0755);
    mkdir(dir, 0755);
    osa_unit_path(fx, inst, path, sizeof(path));
    snprintf(text, sizeof(text), "[Service]\nExecStart=\nExecStart=%s/old/z23 "
             "tunnel receive --keep\n", fx->slots);
    return osa_put(path, text, 0644);
}

static void oc_run(struct osa_cmd *c, const char *json, bool status)
{
    json_init(&c->input);
    memset(&c->request, 0, sizeof(c->request));
    TEST_DISCARD(json_read(&c->input, json, strlen(json)));
    c->request.input = &c->input;
    zcl_command_reply_init(&c->reply, "zcl.ops_slot_activate_test.v1");
    if (status)
        zcl_native_handle_ops_slot_status(&c->request, &c->reply);
    else
        zcl_native_handle_ops_slot_activate(&c->request, &c->reply);
}

static void oc_free(struct osa_cmd *c)
{
    zcl_command_reply_free(&c->reply);
    json_free(&c->input);
}

static bool oc_ok(const struct osa_cmd *c)
{
    return c->reply.status == ZCL_COMMAND_STATUS_PASSED &&
           c->reply.exit_code == ZCL_COMMAND_EXIT_OK;
}

static bool oc_code(const struct osa_cmd *c, const char *code)
{
    return strcmp(c->reply.error.code, code) == 0;
}

static const char *oc_row(const struct osa_cmd *c, const char *arr, size_t i,
                          const char *key)
{
    const struct json_value *rows = json_get(&c->reply.data, arr);
    const struct json_value *row = rows ? json_at(rows, i) : NULL;
    const struct json_value *v = row ? json_get(row, key) : NULL;
    return v && v->type == JSON_STR ? json_get_str(v) : "";
}

static void osa_json(const struct osa_fx *fx, const char *cls, const char *slot,
                     const char *instances, const char *health, bool dry,
                     char *out, size_t cap)
{
    (void)fx;
    snprintf(out, cap,
             "{\"service_class\":\"%s\",\"slot\":\"%s\",\"instances\":%s,"
             "\"health\":%s,\"exec_args\":\"tunnel receive --x\",\"dry_run\":%s}",
             cls, slot, instances, health, dry ? "true" : "false");
}

static void osa_probe_json(const struct osa_fx *fx, char *out, size_t cap)
{
    snprintf(out, cap,
             "{\"kind\":\"probe\",\"timeout_ms\":200,\"argv\":[\"%s\","
             "\"{unit}\"]}", fx->probe);
}

static int test_osa_success(void)
{
    struct osa_fx fx;
    struct osa_cmd c;
    char json[1024], health[512], p1[PATH_MAX], p2[PATH_MAX], st[PATH_MAX];
    int f = 0;
    if (!osa_fx_init(&fx, "ok") || !osa_seed_old(&fx, "r1"))
        return osa_check(false, "fixture");
    osa_probe_json(&fx, health, sizeof(health));
    osa_json(&fx, "tunnel-receiver", "new", "[\"r1\",\"r2\"]", health, false,
             json, sizeof(json));
    oc_run(&c, json, false);
    osa_unit_path(&fx, "r1", p1, sizeof(p1));
    osa_unit_path(&fx, "r2", p2, sizeof(p2));
    f += osa_check(oc_ok(&c), "two instances activate");
    f += osa_check(osa_has(p1, "/new/z23 tunnel receive --x") &&
                       osa_has(p2, "/new/z23 tunnel receive --x"),
                   "both drop-ins point at the new slot with the exec args");
    snprintf(st, sizeof(st), "%s/z23-tunnel-receiver@r1.service.last-good",
             fx.state);
    f += osa_check(osa_has(st, "slot=old"), "r1 last-good is the old slot");
    f += osa_check(osa_has(fx.calls, "restart z23-tunnel-receiver@r2.service") &&
                       !osa_has(fx.calls, "zclassic23.service"),
                   "each instance restarted, the node unit never touched");
    oc_free(&c);
    snprintf(json, sizeof(json),
             "{\"service_class\":\"tunnel-receiver\",\"instances\":[\"r1\"]}");
    oc_run(&c, json, true);
    f += osa_check(oc_ok(&c) && strcmp(oc_row(&c, "instances", 0, "slot"),
                                       "new") == 0 &&
                       strcmp(oc_row(&c, "instances", 0, "last_good"),
                              "old") == 0,
                   "status reports the running slot and last-good");
    f += osa_check(strlen(oc_row(&c, "installed", 0, "sha256")) == 64,
                   "status lists installed slots with sha256");
    oc_free(&c);
    osa_rm_tree(fx.dir);
    return f;
}

static int test_osa_rollback_health(void)
{
    struct osa_fx fx;
    struct osa_cmd c;
    char json[1024], health[512], p1[PATH_MAX], p2[PATH_MAX], p3[PATH_MAX];
    char marker[PATH_MAX], b1[2048], b2[2048], a1[2048], a2[2048];
    int f = 0;
    if (!osa_fx_init(&fx, "rb") || !osa_seed_old(&fx, "r1") ||
        !osa_seed_old(&fx, "r2"))
        return osa_check(false, "fixture");
    osa_unit_path(&fx, "r1", p1, sizeof(p1));
    osa_unit_path(&fx, "r2", p2, sizeof(p2));
    osa_unit_path(&fx, "r3", p3, sizeof(p3));
    snprintf(marker, sizeof(marker), "%s/fail-z23-tunnel-receiver@r2.service",
             fx.dir);
    TEST_DISCARD(osa_put(marker, "x", 0644));
    TEST_DISCARD(osa_get(p1, b1, sizeof(b1)));
    TEST_DISCARD(osa_get(p2, b2, sizeof(b2)));
    osa_probe_json(&fx, health, sizeof(health));
    osa_json(&fx, "tunnel-receiver", "new", "[\"r1\",\"r2\",\"r3\"]", health,
             false, json, sizeof(json));
    oc_run(&c, json, false);
    f += osa_check(!oc_ok(&c) && oc_code(&c, "SLOT_ACTIVATE_ROLLED_BACK") &&
                       strcmp(c.reply.error.phase, "health") == 0 &&
                       strstr(c.reply.error.evidence, "instance=r2"),
                   "second instance health failure rolls back, naming it");
    f += osa_check(osa_get(p1, a1, sizeof(a1)) > 0 && strcmp(a1, b1) == 0 &&
                       osa_get(p2, a2, sizeof(a2)) > 0 && strcmp(a2, b2) == 0,
                   "both drop-ins restored byte for byte");
    f += osa_check(!osa_exists(p3) &&
                       !osa_has(fx.calls, "restart z23-tunnel-receiver@r3"),
                   "the third instance was never touched");
    f += osa_check(strcmp(oc_row(&c, "instances", 1, "outcome"),
                          "rolled_back") == 0,
                   "typed per-instance outcome says rolled_back");
    oc_free(&c);
    osa_rm_tree(fx.dir);
    return f;
}

static int test_osa_exe_mismatch(void)
{
    struct osa_fx fx;
    struct osa_cmd c;
    char json[1024], health[512], p1[PATH_MAX];
    int f = 0;
    if (!osa_fx_init(&fx, "exe"))
        return osa_check(false, "fixture");
    setenv("FAKE_EXE_OVERRIDE", "/elsewhere/z23", 1);
    osa_probe_json(&fx, health, sizeof(health));
    osa_json(&fx, "tunnel-receiver", "new", "[\"r1\"]", health, false, json,
             sizeof(json));
    oc_run(&c, json, false);
    osa_unit_path(&fx, "r1", p1, sizeof(p1));
    f += osa_check(!oc_ok(&c) && oc_code(&c, "SLOT_ACTIVATE_ROLLED_BACK") &&
                       strcmp(c.reply.error.phase, "exe") == 0,
                   "an exe that is not the slot is refused and rolled back");
    f += osa_check(!osa_exists(p1), "the new drop-in is gone after rollback");
    oc_free(&c);
    unsetenv("FAKE_EXE_OVERRIDE");
    osa_rm_tree(fx.dir);
    return f;
}

static int test_osa_refusals(void)
{
    struct osa_fx fx;
    struct osa_cmd c;
    char json[1024], health[512], p1[PATH_MAX];
    int f = 0;
    if (!osa_fx_init(&fx, "ref"))
        return osa_check(false, "fixture");
    osa_probe_json(&fx, health, sizeof(health));
    osa_unit_path(&fx, "r1", p1, sizeof(p1));
    osa_json(&fx, "tunnel-receiver", "../x", "[\"r1\"]", health, false, json,
             sizeof(json));
    oc_run(&c, json, false);
    f += osa_check(!oc_ok(&c) && oc_code(&c, "BAD_SLOT_NAME"),
                   "a bad slot name is refused");
    oc_free(&c);
    osa_json(&fx, "tunnel-receiver", "ghost", "[\"r1\"]", health, false, json,
             sizeof(json));
    oc_run(&c, json, false);
    f += osa_check(!oc_ok(&c) && oc_code(&c, "SLOT_NOT_INSTALLED"),
                   "a slot that is not installed is refused");
    oc_free(&c);
    osa_json(&fx, "zclassic23", "new", "[\"r1\"]", health, false, json,
             sizeof(json));
    oc_run(&c, json, false);
    f += osa_check(!oc_ok(&c) && oc_code(&c, "BAD_SERVICE_CLASS"),
                   "an unknown service class is refused");
    oc_free(&c);
    f += osa_check(!osa_exists(fx.calls) && !osa_exists(p1) &&
                       !osa_exists(fx.state),
                   "refusals ran nothing and wrote nothing");
    osa_rm_tree(fx.dir);
    return f;
}

static int test_osa_dry_run(void)
{
    struct osa_fx fx;
    struct osa_cmd c;
    char json[1024], health[512], p1[PATH_MAX];
    int f = 0;
    if (!osa_fx_init(&fx, "dry"))
        return osa_check(false, "fixture");
    osa_probe_json(&fx, health, sizeof(health));
    osa_json(&fx, "tunnel-receiver", "new", "[\"r1\",\"r2\"]", health, true,
             json, sizeof(json));
    oc_run(&c, json, false);
    osa_unit_path(&fx, "r1", p1, sizeof(p1));
    f += osa_check(oc_ok(&c) && strcmp(oc_row(&c, "instances", 1, "outcome"),
                                       "would_move") == 0,
                   "dry_run reports would_move");
    f += osa_check(!osa_exists(fx.units) && !osa_exists(fx.state) &&
                       !osa_exists(fx.calls),
                   "dry_run wrote no drop-in or state and ran no systemctl");
    oc_free(&c);
    osa_rm_tree(fx.dir);
    return f;
}

static int osa_listener(int *port)
{
    struct sockaddr_in sa;
    socklen_t len = sizeof(sa);
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (fd < 0 || bind(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0 ||
        listen(fd, 4) != 0 ||
        getsockname(fd, (struct sockaddr *)&sa, &len) != 0)
        return -1;
    *port = ntohs(sa.sin_port);
    return fd;
}

static int test_osa_listen(void)
{
    struct osa_fx fx;
    struct osa_cmd c;
    char json[1024], health[256];
    int port = 0, f = 0, fd;
    if (!osa_fx_init(&fx, "listen") || (fd = osa_listener(&port)) < 0)
        return osa_check(false, "fixture");
    snprintf(health, sizeof(health),
             "{\"kind\":\"listen\",\"port\":%d,\"timeout_ms\":300}", port);
    osa_json(&fx, "gateway", "new", "[\"g1\"]", health, false, json,
             sizeof(json));
    oc_run(&c, json, false);
    f += osa_check(oc_ok(&c), "an open listen port passes");
    oc_free(&c);
    close(fd);
    osa_json(&fx, "gateway", "old", "[\"g1\"]", health, false, json,
             sizeof(json));
    oc_run(&c, json, false);
    f += osa_check(!oc_ok(&c) && oc_code(&c, "SLOT_ROLLBACK_FAILED") &&
                       strcmp(c.reply.error.phase, "health") == 0,
                   "a closed port fails health, and the failed restore is reported");
    oc_free(&c);
    osa_rm_tree(fx.dir);
    return f;
}

static int test_osa_digest_reverify(void)
{
    struct osa_fx fx;
    struct osa_cmd c;
    char json[1024], health[512], p1[PATH_MAX], b1[2048], a1[2048];
    char bin[PATH_MAX], keep[PATH_MAX], lnk[PATH_MAX];
    int f = 0;
    if (!osa_fx_init(&fx, "dig") || !osa_seed_old(&fx, "r1"))
        return osa_check(false, "fixture");
    osa_unit_path(&fx, "r1", p1, sizeof(p1));
    TEST_DISCARD(osa_get(p1, b1, sizeof(b1)));
    snprintf(bin, sizeof(bin), "%s/new/z23", fx.slots);
    snprintf(keep, sizeof(keep), "%s/new/z23.keep", fx.slots);
    snprintf(lnk, sizeof(lnk), "%s/old/z23", fx.slots);
    osa_probe_json(&fx, health, sizeof(health));
    /* one byte of the installed binary changes after install */
    f += osa_check(osa_put(bin, "nex", 0755), "slot byte overwritten");
    osa_json(&fx, "tunnel-receiver", "new", "[\"r1\"]", health, false, json,
             sizeof(json));
    oc_run(&c, json, false);
    f += osa_check(!oc_ok(&c) && oc_code(&c, "SLOT_DIGEST_MISMATCH"),
                   "a slot whose bytes changed since install is refused");
    f += osa_check(osa_get(p1, a1, sizeof(a1)) > 0 && strcmp(a1, b1) == 0 &&
                       !osa_exists(fx.calls) && !osa_exists(fx.state),
                   "current drop-in untouched, nothing restarted, no "
                   "last-good written");
    oc_free(&c);
    /* a symlink in place of the binary is refused as well */
    TEST_DISCARD(rename(bin, keep));
    f += osa_check(symlink(lnk, bin) == 0, "symlink slot fixture");
    oc_run(&c, json, false);
    f += osa_check(!oc_ok(&c) && oc_code(&c, "SLOT_DIGEST_MISMATCH") &&
                       !osa_exists(fx.calls) &&
                       osa_get(p1, a1, sizeof(a1)) > 0 && strcmp(a1, b1) == 0,
                   "a symlinked slot binary is refused, current untouched");
    oc_free(&c);
    osa_rm_tree(fx.dir);
    return f;
}

/* The bytes of the slot change after the verify at parse time but before the
 * post-restart check: the fake service swaps the file it execs. The running
 * digest must differ from the install record, the instance must be rolled
 * back and the previous slot must be the one running again. */
static int test_osa_running_digest(void)
{
    struct osa_fx fx;
    struct osa_cmd c;
    char json[1024], health[512], p1[PATH_MAX], b1[2048], a1[2048];
    char bin[PATH_MAX], swap[PATH_MAX], exe[PATH_MAX], tgt[PATH_MAX];
    ssize_t n;
    int f = 0;
    if (!osa_fx_init(&fx, "run") || !osa_seed_old(&fx, "r1"))
        return osa_check(false, "fixture");
    osa_unit_path(&fx, "r1", p1, sizeof(p1));
    TEST_DISCARD(osa_get(p1, b1, sizeof(b1)));
    snprintf(bin, sizeof(bin), "%s/new/z23", fx.slots);
    snprintf(swap, sizeof(swap), "%s/swap-once", fx.dir);
    snprintf(exe, sizeof(exe), "%s/4242/exe", fx.proc);
    TEST_DISCARD(osa_put(swap, "x", 0644));
    setenv("FAKE_SWAP_FILE", bin, 1);
    osa_probe_json(&fx, health, sizeof(health));
    osa_json(&fx, "tunnel-receiver", "new", "[\"r1\"]", health, false, json,
             sizeof(json));
    oc_run(&c, json, false);
    f += osa_check(!oc_ok(&c) && oc_code(&c, "SLOT_RUNNING_DIGEST_MISMATCH") &&
                       strcmp(c.reply.error.phase, "running_digest") == 0,
                   "bytes swapped after install, before the post-restart "
                   "check: refused with the running-digest code");
    f += osa_check(osa_get(p1, a1, sizeof(a1)) > 0 && strcmp(a1, b1) == 0 &&
                       strcmp(oc_row(&c, "instances", 0, "outcome"),
                              "rolled_back") == 0,
                   "the prior drop-in is restored byte for byte");
    n = readlink(exe, tgt, sizeof(tgt) - 1);
    if (n > 0)
        tgt[n] = 0;
    else
        tgt[0] = 0;
    f += osa_check(n > 0 && strstr(tgt, "/old/z23") != NULL &&
                       osa_has(fx.calls, "restart z23-tunnel-receiver"),
                   "the service was restarted and the previous slot runs "
                   "again");
    oc_free(&c);
    unsetenv("FAKE_SWAP_FILE");
    osa_rm_tree(fx.dir);
    return f;
}

/* A group-writable slot dir, or a world-writable slots root, is refused. */
static int test_osa_writable_dirs(void)
{
    struct osa_fx fx;
    struct osa_cmd c;
    char json[1024], health[512], dir[PATH_MAX];
    int f = 0;
    if (!osa_fx_init(&fx, "wr"))
        return osa_check(false, "fixture");
    snprintf(dir, sizeof(dir), "%s/new", fx.slots);
    osa_probe_json(&fx, health, sizeof(health));
    osa_json(&fx, "tunnel-receiver", "new", "[\"r1\"]", health, false, json,
             sizeof(json));
    f += osa_check(chmod(dir, 0775) == 0, "slot dir made group-writable");
    oc_run(&c, json, false);
    f += osa_check(!oc_ok(&c) && oc_code(&c, "SLOT_DIR_WRITABLE") &&
                       !osa_exists(fx.calls),
                   "a group-writable slot dir is refused, nothing run");
    oc_free(&c);
    TEST_DISCARD(chmod(dir, 0755));
    f += osa_check(chmod(fx.slots, 0777) == 0, "slots root made world-writable");
    oc_run(&c, json, false);
    f += osa_check(!oc_ok(&c) && oc_code(&c, "SLOT_DIR_WRITABLE") &&
                       !osa_exists(fx.calls),
                   "a world-writable slots root is refused, nothing run");
    oc_free(&c);
    TEST_DISCARD(chmod(fx.slots, 0755));
    oc_run(&c, json, false);
    f += osa_check(oc_ok(&c), "the same slot activates once the modes are tight");
    oc_free(&c);
    osa_rm_tree(fx.dir);
    return f;
}

#define OSA_TIP_A "00000000000000000000000000000000000000000000000000000000000000aa"
#define OSA_TIP_A_UPPER "00000000000000000000000000000000000000000000000000000000000000AA"
#define OSA_TIP_B "00000000000000000000000000000000000000000000000000000000000000bb"

enum osa_tip_mode {
    TIP_EQUAL,
    TIP_NODE_BEHIND_ON_NEW,
    TIP_REF_DOWN,
    TIP_NODE_MALFORMED,
    TIP_NODE_UPPERCASE
};

static enum osa_tip_mode osa_tip_mode;
static char osa_tip_conf[PATH_MAX];

static char *osa_tip_reply(const char *hash)
{
    char buf[256];
    snprintf(buf, sizeof(buf),
             "HTTP/1.1 200 OK\r\n\r\n{\"result\":\"%s\",\"error\":null}", hash);
    return strdup(buf);
}

/* The node answers with the reference tip unless its unit runs the new slot
 * while the mode says the new slot lags. */
static char *osa_tip_rpc(const char *host, int port, const char *user,
                         const char *pass, uint32_t timeout_ms)
{
    (void)timeout_ms;
    if (strcmp(user, "u") != 0 || strcmp(pass, "p") != 0 || port != 18232)
        return NULL;
    if (strcmp(host, "ref.example") == 0)
        return osa_tip_mode == TIP_REF_DOWN ? NULL : osa_tip_reply(OSA_TIP_A);
    if (osa_tip_mode == TIP_NODE_MALFORMED)
        return osa_tip_reply("not-a-hash");
    if (osa_tip_mode == TIP_NODE_UPPERCASE)
        return osa_tip_reply(OSA_TIP_A_UPPER);
    if (osa_tip_mode == TIP_NODE_BEHIND_ON_NEW &&
        osa_has(osa_tip_conf, "/new/z23"))
        return osa_tip_reply(OSA_TIP_B);
    return osa_tip_reply(OSA_TIP_A);
}

static void osa_tip_json(const struct osa_fx *fx, char *out, size_t cap)
{
    char conf[PATH_MAX];
    snprintf(conf, sizeof(conf), "%s/rpc.conf", fx->dir);
    TEST_DISCARD(osa_put(conf, "rpcuser=u\nrpcpassword=p\nrpcport=18232\n",
                         0600));
    snprintf(out, cap,
             "{\"kind\":\"tip_parity\",\"timeout_ms\":300,\"node_conf\":\"%s\","
             "\"reference_host\":\"ref.example\",\"reference_conf\":\"%s\"}",
             conf, conf);
}

/* The canonical node unit with a prior drop-in; its path is returned. */
static bool osa_seed_node(const struct osa_fx *fx, char *conf, size_t cap)
{
    char dir[PATH_MAX], text[PATH_MAX + 128];
    snprintf(dir, sizeof(dir), "%s/z23-node.service.d", fx->units);
    mkdir(fx->units, 0755);
    mkdir(dir, 0755);
    snprintf(conf, cap, "%s/z23-slot.conf", dir);
    snprintf(text, sizeof(text),
             "[Service]\nExecStart=\nExecStart=%s/old/z23 node --keep\n",
             fx->slots);
    return osa_put(conf, text, 0644);
}

/* Activates r1 (or the node unit) under `mode`; the old drop-in is seeded so
 * a restore has bytes to put back. want_code NULL: the activation passes. */
static int osa_tip_case(const char *name, enum osa_tip_mode mode,
                        const char *want_code, bool node)
{
    struct osa_fx fx;
    struct osa_cmd c;
    char json[2048], health[1024], before[2048], after[2048];
    int f = 0;
    if (!osa_fx_init(&fx, name) ||
        !(node ? osa_seed_node(&fx, osa_tip_conf, sizeof(osa_tip_conf))
               : osa_seed_old(&fx, "r1")))
        return osa_check(false, "fixture");
    if (!node)
        osa_unit_path(&fx, "r1", osa_tip_conf, sizeof(osa_tip_conf));
    TEST_DISCARD(osa_get(osa_tip_conf, before, sizeof(before)));
    osa_tip_mode = mode;
    slot_tip_set_rpc(osa_tip_rpc);
    osa_tip_json(&fx, health, sizeof(health));
    osa_json(&fx, node ? "node" : "tunnel-receiver", "new",
             node ? "[\"node\"]" : "[\"r1\"]", health, false, json,
             sizeof(json));
    oc_run(&c, json, false);
    if (want_code) {
        f += osa_check(!oc_ok(&c) && oc_code(&c, want_code) &&
                           strcmp(c.reply.error.phase, "health") == 0,
                       "a tip_parity failure fails the health phase and rolls back");
        f += osa_check(osa_get(osa_tip_conf, after, sizeof(after)) > 0 &&
                           strcmp(after, before) == 0,
                       "the previous drop-in is restored byte for byte");
    } else {
        f += osa_check(oc_ok(&c) && osa_has(osa_tip_conf, "/new/z23"),
                       "equal tips pass and the drop-in points at the new slot");
    }
    oc_free(&c);
    slot_tip_set_rpc(NULL);
    osa_rm_tree(fx.dir);
    return f;
}

/* How the node conf is made unsafe before the activate call. */
enum osa_prep { PREP_NONE, PREP_GROUP_W, PREP_WORLD_W, PREP_SYMLINK, PREP_FIFO, PREP_FOREIGN };

struct osa_refusal {
    const char *name, *cls, *inst, *kind, *node_conf, *extra, *exec_args;
    const char *what;
    enum osa_prep prep;
};

/* A regular file owned by someone else and writable only by its owner, so
 * that ownership is the one check it fails. As root the fixture conf is
 * chowned instead. */
static bool osa_foreign_conf(const char *conf, char *alt, size_t cap,
                             bool *use_alt)
{
    struct stat st;
    if (geteuid() == 0)
        return chown(conf, 1, (gid_t)-1) == 0;
    if (lstat("/etc/passwd", &st) != 0 || !S_ISREG(st.st_mode) ||
        st.st_uid == geteuid() || (st.st_mode & (S_IWGRP | S_IWOTH)) != 0)
        return false;
    snprintf(alt, cap, "%s", "/etc/passwd");
    *use_alt = true;
    return true;
}

/* Prepares the conf named by p; false when the fixture cannot be built. */
static bool osa_prep_conf(enum osa_prep p, const char *dir, const char *conf,
                          char *alt, size_t cap, bool *use_alt)
{
    *use_alt = false;
    snprintf(alt, cap, "%s/alt.conf", dir);
    switch (p) {
    case PREP_NONE:
        return true;
    case PREP_GROUP_W:
        return chmod(conf, 0620) == 0;
    case PREP_WORLD_W:
        return chmod(conf, 0602) == 0;
    case PREP_SYMLINK:
        *use_alt = true;
        return symlink(conf, alt) == 0;
    case PREP_FIFO:
        *use_alt = true;
        return mkfifo(alt, 0600) == 0;
    case PREP_FOREIGN:
        return osa_foreign_conf(conf, alt, cap, use_alt);
    }
    return false;
}


/* Every refusal happens before any restart: no systemctl call is logged. */
static int osa_tip_refused(const struct osa_refusal *r)
{
    struct osa_fx fx;
    struct osa_cmd c;
    char json[3072], health[1536], conf[PATH_MAX];
    int f = 0;
    if (!osa_fx_init(&fx, r->name))
        return osa_check(false, "fixture");
    osa_tip_json(&fx, health, sizeof(health));
    snprintf(conf, sizeof(conf), "%s/rpc.conf", fx.dir);
    char alt[PATH_MAX];
    bool use_alt;
    if (!osa_prep_conf(r->prep, fx.dir, conf, alt, sizeof(alt), &use_alt)) {
        osa_rm_tree(fx.dir);
        return osa_check(false, r->what);
    }
    snprintf(health, sizeof(health),
             "{\"kind\":\"%s\",\"timeout_ms\":300,\"port\":1,\"node_conf\":\"%s\","
             "\"reference_host\":\"ref.example\",\"reference_conf\":\"%s\"%s%s}",
             r->kind, r->node_conf ? r->node_conf : (use_alt ? alt : conf), conf,
             r->extra[0] ? "," : "", r->extra);
    snprintf(json, sizeof(json),
             "{\"service_class\":\"%s\",\"slot\":\"new\",\"instances\":%s,"
             "\"health\":%s,\"exec_args\":\"%s\"}", r->cls, r->inst, health,
             r->exec_args);
    oc_run(&c, json, false);
    f += osa_check(!oc_ok(&c) && !osa_exists(fx.calls), r->what);
    oc_free(&c);
    osa_rm_tree(fx.dir);
    return f;
}

static int test_osa_tip_refusals(void)
{
    static const struct osa_refusal rows[] = {
        { "tr_big", "tunnel-receiver", "[\"r1\"]", "tip_parity", NULL,
          "\"node_port\":4294967297", "x",
          "a node_port that truncates to 1 is refused" },
        { "tr_str", "tunnel-receiver", "[\"r1\"]", "tip_parity", NULL,
          "\"node_port\":\"18232\"", "x",
          "a string node_port is refused, not the conf port" },
        { "tr_zero", "tunnel-receiver", "[\"r1\"]", "tip_parity", NULL,
          "\"reference_port\":0", "x", "port 0 is refused" },
        { "tr_high", "tunnel-receiver", "[\"r1\"]", "tip_parity", NULL,
          "\"reference_port\":65536", "x", "port 65536 is refused" },
        { "tr_rel", "tunnel-receiver", "[\"r1\"]", "tip_parity", "rpc.conf",
          "", "x", "a relative node_conf is refused" },
        { "nd_listen", "node", "[\"node\"]", "listen", NULL, "", "node run",
          "the node class with a listen check is refused" },
        { "nd_noargs", "node", "[\"node\"]", "tip_parity", NULL, "", "",
          "the node class without exec_args is refused" },
        { "nd_inst", "node", "[\"other\"]", "tip_parity", NULL, "", "node run",
          "the node class takes only the instance node" },
        { "cf_grp", "tunnel-receiver", "[\"r1\"]", "tip_parity", NULL, "", "x",
          "a group-writable conf is refused", PREP_GROUP_W },
        { "cf_wld", "tunnel-receiver", "[\"r1\"]", "tip_parity", NULL, "", "x",
          "a world-writable conf is refused", PREP_WORLD_W },
        { "cf_sym", "tunnel-receiver", "[\"r1\"]", "tip_parity", NULL, "", "x",
          "a symlink to a valid conf is refused", PREP_SYMLINK },
        { "cf_fifo", "tunnel-receiver", "[\"r1\"]", "tip_parity", NULL, "", "x",
          "a FIFO at the conf path is refused without blocking", PREP_FIFO },
        { "cf_own", "tunnel-receiver", "[\"r1\"]", "tip_parity", NULL, "", "x",
          "a conf owned by another user is refused", PREP_FOREIGN },
    };
    int f = 0;
    for (size_t k = 0; k < sizeof(rows) / sizeof(rows[0]); k++)
        f += osa_tip_refused(&rows[k]);
    return f;
}

static int test_osa_tip_parity(void)
{
    int f = 0;
    f += osa_tip_case("tip_eq", TIP_EQUAL, NULL, false);
    f += osa_tip_case("tip_lag", TIP_NODE_BEHIND_ON_NEW,
                      "SLOT_ACTIVATE_ROLLED_BACK", false);
    f += osa_tip_case("tip_ref", TIP_REF_DOWN, "SLOT_ROLLBACK_FAILED", false);
    f += osa_tip_case("tip_bad", TIP_NODE_MALFORMED, "SLOT_ROLLBACK_FAILED",
                      false);
    f += osa_tip_case("tip_up", TIP_NODE_UPPERCASE, "SLOT_ROLLBACK_FAILED",
                      false);
    f += osa_tip_case("node_eq", TIP_EQUAL, NULL, true);
    f += osa_tip_case("node_lag", TIP_NODE_BEHIND_ON_NEW,
                      "SLOT_ACTIVATE_ROLLED_BACK", true);
    f += test_osa_tip_refusals();
    return f;
}

int test_ops_slot_activate(void)
{
    int failures = 0;
    printf("\n=== ops slot activate tests ===\n");
    failures += test_osa_success();
    failures += test_osa_rollback_health();
    failures += test_osa_exe_mismatch();
    failures += test_osa_refusals();
    failures += test_osa_dry_run();
    failures += test_osa_listen();
    failures += test_osa_digest_reverify();
    failures += test_osa_running_digest();
    failures += test_osa_writable_dirs();
    failures += test_osa_tip_parity();
    printf("=== OPS_SLOT_ACTIVATE: %d failure(s) ===\n", failures);
    return failures;
}
