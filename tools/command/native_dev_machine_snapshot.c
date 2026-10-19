/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: dev.app.machine.snapshot and dev.app.machine.resume - save a booted
 *          RISC-V guest to a snapshot file, and continue a guest from one.
 *
 * snapshot boots exactly as dev.app.machine.boot does, runs to its goals and
 * writes the machine to snapshot_out: a file created with mode 0600 under a
 * temporary name, flushed, then renamed into place; an existing destination
 * is never replaced. resume reads a snapshot, checks the kernel and disk it
 * was taken from, builds the machine without booting and runs it on.
 *
 * Restore modes, named in the receipt: "replay" continues bit for bit and
 * hands the guest the random pool the snapshot holds, so it is NOT FOR USE
 * WITH SECRETS; "fresh" needs a snapshot taken with the host entropy device
 * and runs the guest until the device has delivered enough new bytes, or
 * refuses with FRESH_NO_HARVEST.
 * The guest resumes at the guest time of the snapshot; the machine has no
 * host clock. docs/commons/RISCV_MACHINE.md, "Snapshots". */

#include "command/native_command.h"

#include "base/cleanse.h"
#include "base/hex.h"
#include "base/safe_alloc.h"
#include "base/serialize_le.h"
#include "crypto/sha256.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "platform/positioned_file.h"
#include "platform/private_file.h"
#include "platform/rng.h"
#include "rvmachine/rvmachine.h"
#include "rvmachine/rvmachine_snapshot.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define MS_SNAPSHOT_PATH "dev.app.machine.snapshot"
#define MS_RESUME_PATH "dev.app.machine.resume"
#define MS_KERNEL_MAX (UINT64_C(1) << 30)
#define MS_RAM_MIB_DEFAULT 1024
#define MS_WORK_DEFAULT INT64_C(1000000000)
#define MS_CHUNK (1u << 20)
#define MS_TAIL 256u
#define MS_CONSOLE_MAX (UINT64_C(64) << 20)
#define MS_HEX (2u * SHA256_OUTPUT_SIZE + 1u)
#define MS_STREAM_STATE 24u /* seed, next block, bytes of it used */

static const char MS_FRESH_REASON[] =
    "fresh restore needs a snapshot taken with the host entropy device and a host entropy source; "
    "other snapshots restore only in mode replay, which is NOT FOR USE WITH SECRETS";

/* Fresh mode waits for observed harvest. The FreeBSD harvest thread feeds each
 * fast source in events of HARVESTSIZE = 2 words = 8 bytes (random_harvestq.h),
 * destination pool round-robin over RANDOM_FORTUNA_NPOOLS = 32 (fortuna.h); a
 * reseed needs 64 bytes in pool 0 (RANDOM_FORTUNA_DEFPOOLSIZE). In the worst
 * phase 8 events must reach pool 0, which takes 8 x 32 = 256 events = 2048
 * bytes from the device; the threshold is twice that. */
#define MS_HARVEST_BYTES UINT64_C(4096)
#define MS_HARVEST_CAP_MS UINT64_C(60000)
#define MS_FRESH_WARMUP_SLICE 2000000u

struct ms_file {
    const char *path;
    struct platform_positioned_file file;
    struct platform_positioned_file_snapshot before;
    bool open;
};

struct ms_run {
    struct ms_file kernel, disk, snapshot;
    const char *bootargs, *transcript, *out_path, *type_now;
    uint64_t ram_bytes, max_work;
    bool seeded, host_entropy, early, disk_full, fresh;
    uint64_t seed;
    struct rvmachine_script script;
    struct rvmachine *m;
    struct rvmachine_result res;
    int out_fd;
    bool out_failed, console_full;
    uint8_t buf[4096];
    size_t buf_len;
    struct sha256_ctx sha;
    char sha_hex[MS_HEX];
    char tail[MS_TAIL + 1u];
    size_t tail_len;
    /* the entropy streams */
    uint64_t ent_block, ent_given;
    uint8_t ent_bytes[SHA256_OUTPUT_SIZE];
    size_t ent_used;
    bool entropy_failed;
    uint64_t harvest_requests, harvest_bytes, harvest_ms;
    uint64_t early_given;
    /* snapshot facts */
    uint8_t kernel_sha[SHA256_OUTPUT_SIZE], disk_sha[SHA256_OUTPUT_SIZE];
    struct rvmachine_snapshot_info info, made; /* restored from, written */
    struct rvmachine_snapshot_inspection saved;
    bool restored;
    bool disk_checked;
};

/* ---- replies ---- */

static bool ms_fail(struct zcl_command_reply *reply, enum zcl_command_exit exit_code,
                    const char *path, const char *code, const char *phase, const char *message,
                    const char *evidence)
{
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED, exit_code, code, phase, false,
                           false, message, evidence != NULL ? evidence : path);
    return false;
}

static bool ms_bad(struct zcl_command_reply *reply, const char *path, const char *message)
{
    return ms_fail(reply, ZCL_COMMAND_EXIT_INVALID, path, "INVALID_INPUT", "input", message, NULL);
}

static bool ms_snapshot_fail(struct zcl_command_reply *reply, const char *path, const char *phase,
                             enum rvmachine_snapshot_status status)
{
    const char *code = status == RVMACHINE_SNAPSHOT_ERR_FRESH_UNAVAILABLE ? "FRESH_UNAVAILABLE"
                                                                       : "SNAPSHOT_REFUSED";
    const char *message = status == RVMACHINE_SNAPSHOT_ERR_FRESH_UNAVAILABLE
                              ? MS_FRESH_REASON : rvmachine_snapshot_status_name(status);
    return ms_fail(reply, ZCL_COMMAND_EXIT_FAILED, path, code, phase, message, NULL);
}

/* ---- input ---- */

static bool ms_opt_str(const struct json_value *v, const char **out)
{
    *out = NULL;
    if (v == NULL || v->type == JSON_NULL) return true;
    if (v->type != JSON_STR) return false;
    *out = json_get_str(v);
    return *out != NULL && (*out)[0] != '\0';
}

static bool ms_opt_int(const struct json_value *v, int64_t fallback, int64_t lo, int64_t hi,
                       int64_t *out)
{
    *out = fallback;
    if (v == NULL || v->type == JSON_NULL) return true;
    if (v->type != JSON_INT) return false;
    *out = json_get_int(v);
    return *out >= lo && *out <= hi;
}

static bool ms_parse_steps(const struct json_value *steps, struct rvmachine_script *script)
{
    if (steps == NULL || steps->type == JSON_NULL) return true;
    if (steps->type != JSON_ARR) return false;
    for (size_t i = 0; i < steps->num_children; i++) {
        const struct json_value *pair = &steps->children[i];
        if (pair->type != JSON_ARR || pair->num_children != 2u ||
            pair->children[0].type != JSON_STR || pair->children[1].type != JSON_STR)
            return false;
        const char *marker = json_get_str(&pair->children[0]);
        const char *text = json_get_str(&pair->children[1]);
        if (marker == NULL || text == NULL ||
            !rvmachine_script_add(script, marker, strlen(marker), text, strlen(text)))
            return false;
    }
    return true;
}

static bool ms_parse_script(const struct json_value *in, struct ms_run *r, const char *path,
                            struct zcl_command_reply *reply)
{
    const char *until = NULL;
    if (!ms_parse_steps(json_get(in, "type_after"), &r->script))
        return ms_bad(reply, path, "type_after must be at most 32 [marker, text] string pairs");
    if (!ms_opt_str(json_get(in, "until"), &until) ||
        (until != NULL && !rvmachine_script_until(&r->script, until, strlen(until))))
        return ms_bad(reply, path, "until must be a string of 1..255 bytes");
    if (!ms_opt_str(json_get(in, "transcript"), &r->transcript))
        return ms_bad(reply, path, "transcript must be a path");
    return true;
}

static bool ms_parse_entropy(const struct json_value *in, struct ms_run *r, const char *path,
                             struct zcl_command_reply *reply)
{
    const char *source = NULL, *early = NULL;
    int64_t seed = 0;
    const struct json_value *seed_value = json_get(in, "test_entropy_seed");
    if (!ms_opt_str(json_get(in, "entropy"), &source) ||
        (source != NULL && strcmp(source, "host") != 0))
        return ms_bad(reply, path, "entropy must be \"host\"");
    r->host_entropy = source != NULL;
    r->seeded = seed_value != NULL && seed_value->type != JSON_NULL;
    if (!ms_opt_int(seed_value, 0, 0, INT64_MAX, &seed))
        return ms_bad(reply, path, "test_entropy_seed must be a non-negative integer");
    r->seed = (uint64_t)seed;
    if (r->seeded && r->host_entropy)
        return ms_bad(reply, path, "entropy host and test_entropy_seed are mutually exclusive");
    if (!ms_opt_str(json_get(in, "early_seed"), &early) ||
        (early != NULL && strcmp(early, "host") != 0 && strcmp(early, "test") != 0) ||
        (early != NULL && (strcmp(early, "host") == 0 ? !r->host_entropy : !r->seeded)))
        return ms_bad(reply, path, "early_seed \"host\" needs entropy host; \"test\" needs test_entropy_seed");
    r->early = early != NULL;
    r->ent_used = SHA256_OUTPUT_SIZE;
    return true;
}

static bool ms_parse_common(const struct json_value *in, struct ms_run *r, const char *path,
                            struct zcl_command_reply *reply)
{
    int64_t ram_mib = 0, work = 0;
    if (in == NULL || in->type != JSON_OBJ) return ms_bad(reply, path, "input must be one JSON object");
    if (!ms_opt_str(json_get(in, "kernel"), &r->kernel.path) || r->kernel.path == NULL)
        return ms_bad(reply, path, "kernel must be the path of a kernel image");
    if (!ms_opt_str(json_get(in, "disk"), &r->disk.path))
        return ms_bad(reply, path, "disk must be the path of a disk image");
    if (!ms_opt_int(json_get(in, "ram_mib"), MS_RAM_MIB_DEFAULT, 64, 65536, &ram_mib) || ram_mib % 2)
        return ms_bad(reply, path, "ram_mib must be an even integer in 64..65536");
    if (!ms_opt_int(json_get(in, "max_instr"), MS_WORK_DEFAULT, 1, INT64_MAX, &work))
        return ms_bad(reply, path, "max_instr must be a positive integer");
    r->ram_bytes = (uint64_t)ram_mib << 20;
    r->max_work = (uint64_t)work;
    if (!ms_opt_str(json_get(in, "bootargs"), &r->bootargs) ||
        (r->bootargs != NULL && strlen(r->bootargs) >= RVMACHINE_BOOTARGS_MAX))
        return ms_bad(reply, path, "bootargs must be a string of at most 511 bytes");
    return ms_parse_script(in, r, path, reply);
}

/* ---- files ---- */

static bool ms_open(struct ms_file *f, const char *what, struct zcl_command_reply *reply)
{
    char evidence[256];
    if (f->path == NULL) return true;
    if (platform_positioned_file_open(&f->file, f->path) &&
        platform_positioned_file_snapshot(&f->file, &f->before) && f->before.size != 0) {
        f->open = true;
        return true;
    }
    snprintf(evidence, sizeof evidence, "%s: %.200s", what, f->path);
    return ms_fail(reply, ZCL_COMMAND_EXIT_FAILED, NULL, "INPUT_UNREADABLE", "open",
                   "an input is not a readable, non-empty regular file (a final symlink is "
                   "not followed)", evidence);
}

static bool ms_read_at(void *ctx, uint64_t off, void *buf, size_t n)
{
    const struct ms_file *f = ctx;
    uint8_t *out = buf;
    while (n != 0) {
        int64_t got = platform_positioned_file_read(&f->file, out, n < MS_CHUNK ? n : MS_CHUNK, off);
        if (got <= 0) return false;
        out += got;
        off += (uint64_t)got;
        n -= (size_t)got;
    }
    return true;
}

/* SHA-256 of the whole file, through its open handle. */
static bool ms_hash_file(const struct ms_file *f, uint8_t out[SHA256_OUTPUT_SIZE])
{
    struct sha256_ctx sha;
    uint8_t *buf = zcl_malloc(MS_CHUNK, "machine_snapshot_hash");
    uint64_t off = 0;
    bool ok = buf != NULL;
    sha256_init(&sha);
    while (ok && off < f->before.size) {
        size_t n = f->before.size - off < MS_CHUNK ? (size_t)(f->before.size - off) : MS_CHUNK;
        ok = ms_read_at((void *)f, off, buf, n);
        if (ok) sha256_write(&sha, buf, n);
        off += n;
    }
    free(buf);
    if (ok) sha256_finalize(&sha, out);
    return ok;
}

static void ms_close_file(struct ms_file *f)
{
    if (f->open) platform_positioned_file_close(&f->file);
    f->open = false;
}

/* ---- console ---- */

static void ms_flush(struct ms_run *r)
{
    size_t off = 0;
    while (r->out_fd >= 0 && !r->out_failed && off < r->buf_len) {
        ssize_t n = write(r->out_fd, r->buf + off, r->buf_len - off);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) r->out_failed = true;
        else off += (size_t)n;
    }
    r->buf_len = 0;
}

static void ms_console(void *ctx, uint8_t byte)
{
    struct ms_run *r = ctx;
    if (r->console_full) return;
    sha256_write(&r->sha, &byte, 1);
    r->buf[r->buf_len++] = byte;
    if (r->buf_len == sizeof r->buf) ms_flush(r);
    if (r->tail_len == MS_TAIL) {
        memmove(r->tail, r->tail + MS_TAIL / 2u, MS_TAIL / 2u);
        r->tail_len = MS_TAIL / 2u;
    }
    r->tail[r->tail_len++] = (byte >= 0x20 && byte < 0x7f) || byte == '\n' ? (char)byte : '.';
    rvmachine_script_console(&r->script, r->m, byte);
    if (r->script.console_bytes >= MS_CONSOLE_MAX) {
        r->console_full = true;
        rvmachine_request_stop(r->m);
    }
}

static bool ms_open_transcript(struct ms_run *r, struct zcl_command_reply *reply)
{
    struct platform_private_file f;
    if (r->transcript == NULL) return true;
    platform_private_file_init(&f);
    if (!platform_private_file_create(r->transcript, &f))
        return ms_fail(reply, ZCL_COMMAND_EXIT_INVALID, NULL, "TRANSCRIPT_UNAVAILABLE", "open",
                       "the transcript path exists or cannot be created; it is created "
                       "exclusively and never overwritten", r->transcript);
    r->out_fd = dup((int)f.native);
    platform_private_file_close(&f);
    return r->out_fd >= 0;
}

/* ---- entropy sources ---- */

static void ms_stream_block(const char *label, uint64_t seed, uint64_t block,
                            uint8_t out[SHA256_OUTPUT_SIZE])
{
    struct sha256_ctx sha;
    uint8_t tail[16];
    zcl_write_u64_le(tail, seed);
    zcl_write_u64_le(tail + 8, block);
    sha256_init(&sha);
    sha256_write(&sha, (const unsigned char *)label, strlen(label));
    sha256_write(&sha, tail, sizeof tail);
    sha256_finalize(&sha, out);
}

/* The public test stream of dev.app.machine.boot, continuable from a state. */
static size_t ms_test_entropy(void *ctx, uint8_t *buf, size_t n)
{
    struct ms_run *r = ctx;
    for (size_t i = 0; i < n; i++) {
        if (r->ent_used == SHA256_OUTPUT_SIZE) {
            ms_stream_block("z23 dev.app.machine.boot test entropy v1", r->seed, r->ent_block++,
                            r->ent_bytes);
            r->ent_used = 0;
        }
        buf[i] = r->ent_bytes[r->ent_used++];
    }
    r->ent_given += n;
    return n;
}

static size_t ms_host_entropy(void *ctx, uint8_t *buf, size_t n)
{
    struct ms_run *r = ctx;
    size_t done = 0;
    while (!r->entropy_failed && done < n) {
        size_t take = n - done < 4096u ? n - done : 4096u;
        if (!rng_host_fill(buf + done, take)) r->entropy_failed = true;
        else done += take;
    }
    if (!r->entropy_failed) {
        r->ent_given += n;
        return n;
    }
    memory_cleanse(buf, n);
    return 0;
}

static bool ms_test_boot_seed(void *ctx, uint8_t *buf, size_t n, size_t *got)
{
    struct ms_run *r = ctx;
    uint8_t block[SHA256_OUTPUT_SIZE];
    for (size_t done = 0; done < n; done += sizeof block) {
        size_t take = n - done < sizeof block ? n - done : sizeof block;
        ms_stream_block("z23 dev.app.machine.boot test early seed v1", r->seed,
                        done / sizeof block, block);
        memcpy(buf + done, block, take);
    }
    r->early_given = n;
    *got = n;
    return true;
}

static bool ms_host_boot_seed(void *ctx, uint8_t *buf, size_t n, size_t *got)
{
    struct ms_run *r = ctx;
    *got = 0;
    if (ms_host_entropy(r, buf, n) != n) return false;
    r->ent_given -= n;
    r->early_given = n;
    *got = n;
    return true;
}

/* The test stream's position, in the snapshot: seed, next block, bytes used. */
static void ms_stream_state(const struct ms_run *r, uint8_t out[MS_STREAM_STATE])
{
    zcl_write_u64_le(out, r->seed);
    zcl_write_u64_le(out + 8, r->ent_block);
    zcl_write_u64_le(out + 16, r->ent_used);
}

static bool ms_stream_resume(struct ms_run *r, const uint8_t *state, uint32_t len)
{
    if (len != MS_STREAM_STATE) return false;
    r->seed = zcl_read_u64_le(state);
    r->ent_block = zcl_read_u64_le(state + 8);
    r->ent_used = (size_t)zcl_read_u64_le(state + 16);
    if (r->ent_used > SHA256_OUTPUT_SIZE || (r->ent_used < SHA256_OUTPUT_SIZE && r->ent_block == 0))
        return false;
    if (r->ent_used < SHA256_OUTPUT_SIZE)
        ms_stream_block("z23 dev.app.machine.boot test entropy v1", r->seed, r->ent_block - 1u,
                        r->ent_bytes);
    return true;
}

static enum rvmachine_snapshot_entropy ms_mode(const struct ms_run *r)
{
    if (r->restored) return r->saved.entropy;
    if (r->host_entropy) return RVMACHINE_SNAPSHOT_ENTROPY_HOST;
    return r->seeded ? RVMACHINE_SNAPSHOT_ENTROPY_TEST_STREAM : RVMACHINE_SNAPSHOT_ENTROPY_NONE;
}

/* ---- the snapshot parameters ---- */

struct ms_hash {
    struct sha256_ctx sha;
};

static void ms_hash_begin(void *ctx) { sha256_init(&((struct ms_hash *)ctx)->sha); }
static void ms_hash_write(void *ctx, const uint8_t *d, size_t n)
{
    sha256_write(&((struct ms_hash *)ctx)->sha, d, n);
}
static void ms_hash_finish(void *ctx, uint8_t out[32])
{
    sha256_finalize(&((struct ms_hash *)ctx)->sha, out);
}

static struct rvmachine_snapshot_hash ms_hash_ops(struct ms_hash *h)
{
    return (struct rvmachine_snapshot_hash){h, ms_hash_begin, ms_hash_write, ms_hash_finish};
}

/* ---- machine ---- */

static struct rvmachine_config ms_config(struct ms_run *r)
{
    return (struct rvmachine_config){
        .ram_bytes = r->ram_bytes, .bootargs = r->bootargs,
        .console = ms_console, .console_ctx = r,
        .entropy = r->host_entropy ? ms_host_entropy : r->seeded ? ms_test_entropy : NULL,
        .entropy_ctx = r, .entropy_fail_closed = r->host_entropy,
        .boot_seed = r->early ? (r->host_entropy ? ms_host_boot_seed : ms_test_boot_seed) : NULL,
        .boot_seed_ctx = r};
}

static bool ms_machine_fail(struct zcl_command_reply *reply, const char *phase,
                            enum rvmachine_status status)
{
    return ms_fail(reply, ZCL_COMMAND_EXIT_FAILED, NULL, "MACHINE_REFUSED", phase,
                   rvmachine_status_name(status), NULL);
}

static uint8_t *ms_read_kernel(struct ms_file *f, size_t *len)
{
    uint8_t *image;
    if (f->before.size > MS_KERNEL_MAX) return NULL;
    image = zcl_malloc((size_t)f->before.size, "machine_snapshot_kernel");
    if (image != NULL && !ms_read_at(f, 0, image, (size_t)f->before.size)) {
        free(image);
        return NULL;
    }
    *len = (size_t)f->before.size;
    return image;
}

static bool ms_boot(struct ms_run *r, struct zcl_command_reply *reply)
{
    struct rvmachine_config config = ms_config(r);
    size_t len = 0;
    uint8_t *image = ms_read_kernel(&r->kernel, &len);
    enum rvmachine_status st = RVMACHINE_OK;
    if (image == NULL)
        return ms_fail(reply, ZCL_COMMAND_EXIT_FAILED, NULL, "INPUT_UNREADABLE", "read",
                       "the kernel image could not be read (or is above 1 GiB)", r->kernel.path);
    if (r->disk.path != NULL)
        st = rvmachine_disk_open(&config.disk, r->disk.before.size, ms_read_at, &r->disk);
    if (st == RVMACHINE_OK) {
        st = rvmachine_create(&r->m, &config);
        if (st != RVMACHINE_OK) rvmachine_disk_close(config.disk);
    }
    if (st == RVMACHINE_OK) st = rvmachine_load_kernel(r->m, image, len);
    if (st == RVMACHINE_OK) {
        struct sha256_ctx kernel_hash;
        sha256_init(&kernel_hash);
        sha256_write(&kernel_hash, image, len);
        sha256_finalize(&kernel_hash, r->kernel_sha);
    }
    free(image);
    return st == RVMACHINE_OK || ms_machine_fail(reply, "boot", st);
}

/* ---- run and verdict ---- */

static bool ms_changed(struct ms_file *f)
{
    struct platform_positioned_file_snapshot now;
    if (!f->open) return false;
    return !platform_positioned_file_snapshot(&f->file, &now) ||
           !platform_positioned_file_snapshot_equal(&now, &f->before);
}

/* Runs to the goals; finishes the transcript and the console hash. */
static enum rvmachine_status ms_run(struct ms_run *r)
{
    unsigned char hash[SHA256_OUTPUT_SIZE];
    enum rvmachine_status st = rvmachine_run(r->m, r->max_work, &r->res);
    ms_flush(r);
    if (r->out_fd >= 0 && close(r->out_fd) != 0) r->out_failed = true;
    r->out_fd = -1;
    sha256_finalize(&r->sha, hash);
    zcl_hex_encode(hash, SHA256_OUTPUT_SIZE, r->sha_hex);
    r->tail[r->tail_len] = '\0';
    return st;
}

/* Why the run did not meet its goals on unchanged inputs, or NULL. */
static const char *ms_goal_failure(struct ms_run *r, const char **code)
{
    *code = "GOAL_MISSED";
    if (r->entropy_failed) {
        *code = "ENTROPY_SOURCE_FAILED";
        return "the host OS entropy source refused a request; no fallback was used";
    }
    if (r->out_failed) {
        *code = "TRANSCRIPT_WRITE_FAILED";
        return "the transcript could not be written completely";
    }
    if (ms_changed(&r->kernel) || ms_changed(&r->disk) || ms_changed(&r->snapshot)) {
        *code = "INPUT_CHANGED";
        return "a kernel, disk or snapshot input changed during the run";
    }
    if (r->res.stop == RVMACHINE_STOP_FAULT) {
        *code = "GUEST_FAULT";
        return "the guest could not continue; pc, cause and tval are in the receipt";
    }
    if (r->console_full) {
        *code = "CONSOLE_LIMIT";
        return "the guest printed up to the console limit of 64 MiB";
    }
    if (r->script.fired < r->script.count) return "a type_after marker never appeared on the console";
    if (r->script.until_len != 0 && !r->script.until_seen)
        return "the until text never appeared on the console";
    return NULL;
}

static void ms_emit_run(const struct ms_run *r, struct json_value *data)
{
    const struct rvmachine_result *res = &r->res;
    (void)json_push_kv_str(data, "stop", rvmachine_stop_name(res->stop));
    (void)json_push_kv_bool(data, "marker_seen", r->script.until_seen);
    (void)json_push_kv_int(data, "retired", (int64_t)res->retired);
    (void)json_push_kv_int(data, "skip", (int64_t)res->skip);
    (void)json_push_kv_int(data, "fw_calls", (int64_t)res->fw_calls);
    (void)json_push_kv_int(data, "device_work", (int64_t)res->device_work);
    (void)json_push_kv_int(data, "guest_time", (int64_t)res->guest_time);
    (void)json_push_kv_int(data, "timebase_hz", RVMACHINE_TIMEBASE_HZ);
    (void)json_push_kv_int(data, "console_bytes", (int64_t)r->script.console_bytes);
    (void)json_push_kv_str(data, "transcript_sha256", r->sha_hex);
    (void)json_push_kv_int(data, "script_fired", r->script.fired);
    (void)json_push_kv_int(data, "script_total", r->script.count);
    (void)json_push_kv_str(data, "console_tail", r->tail);
    if (r->host_entropy || r->seeded) {
        struct rvvirtio_rng_counters c = rvvirtio_rng_counters_get(&r->m->rng);
        (void)json_push_kv_int(data, "entropy_requests", (int64_t)c.requests);
        (void)json_push_kv_int(data, "entropy_bytes", (int64_t)c.bytes);
    }
}

static void ms_emit_hex(struct json_value *data, const char *key, const uint8_t *digest)
{
    char hex[MS_HEX];
    zcl_hex_encode(digest, SHA256_OUTPUT_SIZE, hex);
    (void)json_push_kv_str(data, key, hex);
}

static const char *ms_entropy_name(enum rvmachine_snapshot_entropy e)
{
    switch (e) {
    case RVMACHINE_SNAPSHOT_ENTROPY_NONE: return "none";
    case RVMACHINE_SNAPSHOT_ENTROPY_TEST_STREAM: return "test_stream_not_secure";
    case RVMACHINE_SNAPSHOT_ENTROPY_HOST: return "host_os_csprng";
    default: return "undeclared";
    }
}

/* A snapshot taken at the end of a resumed run: its size and digest. */
static void ms_emit_final(const struct ms_run *r, struct json_value *data)
{
    (void)json_push_kv_str(data, "final_snapshot_path", r->out_path);
    (void)json_push_kv_int(data, "final_snapshot_bytes", (int64_t)r->made.file_size);
    ms_emit_hex(data, "final_snapshot_digest_sha256", r->made.digest);
}

static void ms_emit_snapshot(const struct ms_run *r, struct json_value *data)
{
    const struct rvmachine_snapshot_info *i = &r->made;
    (void)json_push_kv_bool(data, "restored", false);
    (void)json_push_kv_str(data, "snapshot_path", r->out_path);
    (void)json_push_kv_int(data, "snapshot_bytes", (int64_t)i->file_size);
    ms_emit_hex(data, "snapshot_digest_sha256", i->digest);
    (void)json_push_kv_int(data, "snapshot_retired", (int64_t)i->retired);
    (void)json_push_kv_int(data, "snapshot_guest_time", (int64_t)i->guest_time);
    (void)json_push_kv_int(data, "pages", (int64_t)i->pages);
    (void)json_push_kv_int(data, "overlay_blocks", (int64_t)i->overlay_blocks);
    (void)json_push_kv_str(data, "entropy_mode", ms_entropy_name(i->entropy));
    ms_emit_hex(data, "kernel_sha256", r->kernel_sha);
    if (r->disk.path != NULL) ms_emit_hex(data, "disk_sha256", r->disk_sha);
}

/* ---- snapshot ---- */

struct ms_sink {
    struct platform_private_file file;
    uint64_t off;
};

static bool ms_sink_write(void *ctx, const void *buf, size_t n)
{
    struct ms_sink *s = ctx;
    if (!platform_private_file_write_at(&s->file, buf, n, s->off)) return false;
    s->off += n;
    return true;
}

/* Removes the temporary file; when retiring it fails the descriptor is closed
 * and the name is removed by path. */
static void ms_discard(struct platform_private_file *f, const char *path)
{
    if (platform_private_file_retire(f, path)) return;
    platform_private_file_close(f);
    (void)remove(path);
}

/* Writes the snapshot under a temporary name, flushes and renames it into an
 * absent destination. */
static bool ms_write_snapshot(struct ms_run *r, struct zcl_command_reply *reply)
{
    char staging[4200];
    struct ms_sink sink;
    struct ms_hash hash;
    struct rvmachine_snapshot_params p = {.hash = ms_hash_ops(&hash), .entropy = ms_mode(r)};
    struct rvmachine_snapshot_sink out = {&sink, ms_sink_write};
    bool exists = false;
    memcpy(p.kernel_sha256, r->kernel_sha, SHA256_OUTPUT_SIZE);
    memcpy(p.disk_sha256, r->disk_sha, SHA256_OUTPUT_SIZE);
    if (r->seeded) {
        ms_stream_state(r, p.source_state);
        p.source_state_len = MS_STREAM_STATE;
    }
    snprintf(staging, sizeof staging, "%s.tmp.%ld", r->out_path, (long)getpid());
    sink.off = 0;
    platform_private_file_init(&sink.file);
    if (!platform_private_file_create(staging, &sink.file))
        return ms_fail(reply, ZCL_COMMAND_EXIT_INVALID, NULL, "SNAPSHOT_UNWRITABLE", "write",
                       "the temporary snapshot file could not be created", staging);
    enum rvmachine_snapshot_status st = rvmachine_snapshot_save(r->m, &p, &out, &r->made);
    if (st != RVMACHINE_SNAPSHOT_OK) {
        ms_discard(&sink.file, staging);
        return ms_snapshot_fail(reply, MS_SNAPSHOT_PATH, "save", st);
    }
    if (!platform_private_file_publish_no_clobber(&sink.file, staging, r->out_path, &exists) ||
        exists) {
        ms_discard(&sink.file, staging);
        return ms_fail(reply, ZCL_COMMAND_EXIT_INVALID, NULL,
                       exists ? "SNAPSHOT_EXISTS" : "SNAPSHOT_UNWRITABLE", "write",
                       exists ? "the snapshot path already exists; it is never replaced"
                              : "the snapshot could not be flushed and renamed", r->out_path);
    }
    platform_private_file_close(&sink.file);
    return true;
}

static bool ms_snapshot_parse(const struct json_value *in, struct ms_run *r,
                              struct zcl_command_reply *reply)
{
    if (!ms_parse_common(in, r, MS_SNAPSHOT_PATH, reply) ||
        !ms_parse_entropy(in, r, MS_SNAPSHOT_PATH, reply))
        return false;
    if (!ms_opt_str(json_get(in, "snapshot_out"), &r->out_path) || r->out_path == NULL)
        return ms_bad(reply, MS_SNAPSHOT_PATH, "snapshot_out must be the path of a new snapshot file");
    return true;
}

static bool ms_snapshot_prepare(struct ms_run *r, struct zcl_command_reply *reply)
{
    return ms_open(&r->kernel, "kernel", reply) && ms_open(&r->disk, "disk", reply) &&
           ms_boot(r, reply) && ms_open_transcript(r, reply);
}

static void ms_snapshot_run(struct ms_run *r, struct zcl_command_reply *reply)
{
    const char *code;
    enum rvmachine_status st = ms_run(r);
    const char *why = ms_goal_failure(r, &code);
    if (st != RVMACHINE_OK) {
        (void)ms_machine_fail(reply, "run", st);
        return;
    }
    if (why != NULL) {
        (void)ms_fail(reply, ZCL_COMMAND_EXIT_FAILED, NULL, code, "run", why, MS_SNAPSHOT_PATH);
        return;
    }
    if (r->disk.path != NULL && !ms_hash_file(&r->disk, r->disk_sha)) {
        (void)ms_fail(reply, ZCL_COMMAND_EXIT_FAILED, NULL, "INPUT_UNREADABLE", "read",
                      "the disk image could not be hashed", r->disk.path);
        return;
    }
    if (!ms_write_snapshot(r, reply)) return;
    ms_emit_run(r, &reply->data);
    ms_emit_snapshot(r, &reply->data);
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = ZCL_COMMAND_EXIT_OK;
}

static void ms_cleanup(struct ms_run *r)
{
    if (r->out_fd >= 0) close(r->out_fd);
    rvmachine_destroy(r->m);
    ms_close_file(&r->kernel);
    ms_close_file(&r->disk);
    ms_close_file(&r->snapshot);
}

static void ms_init(struct ms_run *r)
{
    memset(r, 0, sizeof *r);
    platform_positioned_file_init(&r->kernel.file);
    platform_positioned_file_init(&r->disk.file);
    platform_positioned_file_init(&r->snapshot.file);
    r->out_fd = -1;
    rvmachine_script_init(&r->script);
    sha256_init(&r->sha);
}

void zcl_native_handle_dev_machine_snapshot(const struct zcl_command_request *request,
                                            struct zcl_command_reply *reply)
{
    struct ms_run *r;
    if (reply == NULL) return;
    r = zcl_calloc(1, sizeof *r, "machine_snapshot_state");
    if (r == NULL) {
        (void)ms_fail(reply, ZCL_COMMAND_EXIT_INTERNAL, MS_SNAPSHOT_PATH, "OUT_OF_MEMORY", "setup",
                      "the run state could not be allocated", NULL);
        return;
    }
    ms_init(r);
    if (ms_snapshot_parse(request != NULL ? request->input : NULL, r, reply) &&
        ms_snapshot_prepare(r, reply))
        ms_snapshot_run(r, reply);
    ms_cleanup(r);
    free(r);
}

/* ---- resume ---- */

static bool ms_resume_files(const struct json_value *in, struct ms_run *r, struct zcl_command_reply *reply)
{
    if (!ms_opt_str(json_get(in, "snapshot"), &r->snapshot.path) || r->snapshot.path == NULL)
        return ms_bad(reply, MS_RESUME_PATH, "snapshot must be the path of a snapshot file");
    if (!ms_opt_str(json_get(in, "kernel"), &r->kernel.path) || r->kernel.path == NULL)
        return ms_bad(reply, MS_RESUME_PATH, "kernel must be the kernel image the snapshot was taken with");
    if (!ms_opt_str(json_get(in, "disk"), &r->disk.path))
        return ms_bad(reply, MS_RESUME_PATH, "disk must be the path of a disk image");
    if (!ms_opt_str(json_get(in, "snapshot_out"), &r->out_path))
        return ms_bad(reply, MS_RESUME_PATH, "snapshot_out must be the path of a new snapshot file");
    return true;
}

static bool ms_resume_modes(const struct json_value *in, struct ms_run *r, struct zcl_command_reply *reply)
{
    const char *mode = NULL, *verify = NULL;
    if (!ms_opt_str(json_get(in, "mode"), &mode) ||
        (mode != NULL && strcmp(mode, "replay") != 0 && strcmp(mode, "fresh") != 0))
        return ms_bad(reply, MS_RESUME_PATH, "mode must be \"replay\" or \"fresh\"");
    r->fresh = mode == NULL || strcmp(mode, "fresh") == 0;
    if (!ms_opt_str(json_get(in, "disk_verify"), &verify) ||
        (verify != NULL && strcmp(verify, "full") != 0 && strcmp(verify, "size") != 0))
        return ms_bad(reply, MS_RESUME_PATH, "disk_verify must be \"full\" or \"size\"");
    r->disk_full = verify == NULL || strcmp(verify, "full") == 0;
    return true;
}

static bool ms_resume_parse(const struct json_value *in, struct ms_run *r,
                            struct zcl_command_reply *reply)
{
    int64_t work = 0;
    if (in == NULL || in->type != JSON_OBJ) return ms_bad(reply, MS_RESUME_PATH, "input must be one JSON object");
    if (!ms_resume_files(in, r, reply) || !ms_resume_modes(in, r, reply)) return false;
    if (r->out_path != NULL && r->disk.path != NULL && !r->disk_full)
        return ms_fail(reply, ZCL_COMMAND_EXIT_INVALID, NULL, "SNAPSHOT_OUT_NEEDS_DISK_HASH", "input",
                       "snapshot_out records the disk hash, so it needs disk_verify full", MS_RESUME_PATH);
    if (!ms_opt_str(json_get(in, "type_now"), &r->type_now))
        return ms_bad(reply, MS_RESUME_PATH, "type_now must be a string");
    if (!ms_opt_int(json_get(in, "max_instr"), MS_WORK_DEFAULT, 1, INT64_MAX, &work))
        return ms_bad(reply, MS_RESUME_PATH, "max_instr must be a positive integer");
    r->max_work = (uint64_t)work;
    if (!ms_parse_script(in, r, MS_RESUME_PATH, reply)) return false;
    if (r->fresh && r->script.count != 0)
        return ms_bad(reply, MS_RESUME_PATH,
                      "fresh mode takes type_now only; type_after would type before the reseed interval ends");
    return true;
}

static bool ms_resume_open(struct ms_run *r, struct zcl_command_reply *reply)
{
    return ms_open(&r->snapshot, "snapshot", reply) && ms_open(&r->kernel, "kernel", reply) &&
           ms_open(&r->disk, "disk", reply);
}

/* The snapshot's own account of the machine, after its trailer verified. */
static bool ms_inspect(struct ms_run *r, struct zcl_command_reply *reply)
{
    struct ms_hash hash;
    struct rvmachine_snapshot_hash ops = ms_hash_ops(&hash);
    struct rvmachine_snapshot_source src = {&r->snapshot, r->snapshot.before.size, ms_read_at};
    enum rvmachine_snapshot_status st = rvmachine_snapshot_inspect(&src, &ops, &r->saved);
    if (st != RVMACHINE_SNAPSHOT_OK) return ms_snapshot_fail(reply, MS_RESUME_PATH, "inspect", st);
    if (r->saved.disk_present != (r->disk.path != NULL))
        return ms_bad(reply, MS_RESUME_PATH, r->saved.disk_present
                      ? "the snapshot was taken with a disk; name it in disk"
                      : "the snapshot was taken without a disk");
    r->ram_bytes = r->saved.ram_bytes;
    r->bootargs = r->saved.bootargs[0] != '\0' ? r->saved.bootargs : NULL;
    if (r->saved.entropy == RVMACHINE_SNAPSHOT_ENTROPY_HOST) r->host_entropy = r->saved.entropy_device;
    if (r->saved.entropy == RVMACHINE_SNAPSHOT_ENTROPY_TEST_STREAM) {
        r->seeded = r->saved.entropy_device;
        if (!ms_stream_resume(r, r->saved.source_state, r->saved.source_state_len))
            return ms_snapshot_fail(reply, MS_RESUME_PATH, "inspect", RVMACHINE_SNAPSHOT_ERR_FORMAT);
    }
    return true;
}

static bool ms_resume_bind(struct ms_run *r, struct rvmachine_snapshot_params *p,
                           struct zcl_command_reply *reply)
{
    if (!ms_hash_file(&r->kernel, p->kernel_sha256))
        return ms_fail(reply, ZCL_COMMAND_EXIT_FAILED, NULL, "INPUT_UNREADABLE", "read",
                       "the kernel image could not be hashed", r->kernel.path);
    memcpy(r->kernel_sha, p->kernel_sha256, SHA256_OUTPUT_SIZE);
    if (r->disk.path == NULL) return true;
    p->disk_hash_known = r->disk_full;
    /* a size-only restore inherits the disk hash its snapshot recorded */
    memcpy(p->disk_sha256, r->saved.disk_sha256, SHA256_OUTPUT_SIZE);
    if (r->disk_full && !ms_hash_file(&r->disk, p->disk_sha256))
        return ms_fail(reply, ZCL_COMMAND_EXIT_FAILED, NULL, "INPUT_UNREADABLE", "read",
                       "the disk image could not be hashed", r->disk.path);
    memcpy(r->disk_sha, p->disk_sha256, SHA256_OUTPUT_SIZE);
    return true;
}

static bool ms_restore(struct ms_run *r, struct zcl_command_reply *reply)
{
    struct ms_hash hash;
    struct rvmachine_snapshot_params p = {.hash = ms_hash_ops(&hash)};
    struct rvmachine_config config = ms_config(r);
    struct rvmachine_snapshot_source src = {&r->snapshot, r->snapshot.before.size, ms_read_at};
    enum rvmachine_snapshot_status st;
    if (!ms_resume_bind(r, &p, reply)) return false;
    config.wait_stops = r->saved.wait_stops;
    config.boot_seed = NULL;
    config.entropy = r->saved.entropy_device ? config.entropy : NULL;
    if (r->disk.path != NULL &&
        rvmachine_disk_open(&config.disk, r->disk.before.size, ms_read_at, &r->disk) != RVMACHINE_OK)
        return ms_machine_fail(reply, "disk", RVMACHINE_ERR_DISK);
    st = rvmachine_snapshot_restore(&r->m, &config, &p, r->fresh ? RVMACHINE_SNAPSHOT_FRESH :
                                    RVMACHINE_SNAPSHOT_REPLAY, &src, &r->info);
    if (st != RVMACHINE_SNAPSHOT_OK) {
        rvmachine_disk_close(config.disk);
        return ms_snapshot_fail(reply, MS_RESUME_PATH, "restore", st);
    }
    r->restored = true;
    r->disk_checked = r->info.disk_hash_checked;
    return true;
}

/* The mode label; fresh states what was observed and what it does not cover. */
static void ms_emit_mode(const struct ms_run *r, struct json_value *data)
{
    char label[640];
    (void)json_push_kv_str(data, "mode", r->fresh ? "fresh" : "replay");
    if (!r->fresh) {
        (void)json_push_kv_str(data, "mode_label",
                               "replay: continues bit for bit; NOT FOR USE WITH SECRETS");
        return;
    }
    snprintf(label, sizeof label,
             "fresh; reseed: guest harvest from host entropy device, observed %llu bytes in "
             "%llu requests over %llu ms of guest time; the kernel pool reseeds at the guest's "
             "next read; processes running at save time keep their own generator state and "
             "kernel arc4random users may repeat for up to 300 s; the snapshot must predate "
             "every long-lived key",
             (unsigned long long)r->harvest_bytes, (unsigned long long)r->harvest_requests,
             (unsigned long long)r->harvest_ms);
    (void)json_push_kv_str(data, "mode_label", label);
    (void)json_push_kv_int(data, "harvest_requests", (int64_t)r->harvest_requests);
    (void)json_push_kv_int(data, "harvest_bytes", (int64_t)r->harvest_bytes);
    (void)json_push_kv_int(data, "harvest_guest_ms", (int64_t)r->harvest_ms);
}

static void ms_emit_resume(const struct ms_run *r, struct json_value *data)
{
    const struct rvmachine_snapshot_info *i = &r->info;
    (void)json_push_kv_bool(data, "restored", true);
    ms_emit_mode(r, data);
    (void)json_push_kv_int(data, "snapshot_bytes", (int64_t)i->file_size);
    ms_emit_hex(data, "snapshot_digest_sha256", i->digest);
    (void)json_push_kv_int(data, "snapshot_retired", (int64_t)i->retired);
    (void)json_push_kv_int(data, "snapshot_guest_time", (int64_t)i->guest_time);
    (void)json_push_kv_int(data, "instructions_since_restore",
                           (int64_t)(r->res.retired - i->retired));
    (void)json_push_kv_int(data, "pages", (int64_t)i->pages);
    (void)json_push_kv_int(data, "overlay_blocks", (int64_t)i->overlay_blocks);
    (void)json_push_kv_str(data, "entropy_mode", ms_entropy_name(i->entropy));
    (void)json_push_kv_str(data, "disk_binding", r->disk.path == NULL ? "none" :
                           r->disk_checked ? "sha256" : "size_only");
}

static void ms_harvest_note(struct ms_run *r, const struct rvvirtio_rng_counters *base)
{
    struct rvvirtio_rng_counters now = rvvirtio_rng_counters_get(&r->m->rng);
    r->harvest_requests = now.requests - base->requests;
    r->harvest_bytes = now.bytes - base->bytes;
    r->harvest_ms = (r->res.guest_time - r->info.guest_time) / (RVMACHINE_TIMEBASE_HZ / 1000u);
}

/* Runs the guest until the entropy device has delivered MS_HARVEST_BYTES new
 * bytes, before any typed input. Reaching MS_HARVEST_CAP_MS of guest time
 * first is a refusal: the guest did not take the bytes. */
static bool ms_warmup(struct ms_run *r, struct zcl_command_reply *reply)
{
    const struct rvvirtio_rng_counters base = rvvirtio_rng_counters_get(&r->m->rng);
    const uint64_t cap = r->info.guest_time + MS_HARVEST_CAP_MS * (RVMACHINE_TIMEBASE_HZ / 1000u);
    const uint64_t slices = r->max_work / MS_FRESH_WARMUP_SLICE + 1u;
    char why[200];
    for (uint64_t i = 0;; i++) {
        enum rvmachine_status st = rvmachine_run(r->m, MS_FRESH_WARMUP_SLICE, &r->res);
        if (st != RVMACHINE_OK) return ms_machine_fail(reply, "warmup", st);
        ms_harvest_note(r, &base);
        if (r->harvest_bytes >= MS_HARVEST_BYTES) return true;
        if (r->res.stop != RVMACHINE_STOP_BUDGET)
            return ms_fail(reply, ZCL_COMMAND_EXIT_FAILED, NULL, "WARMUP_INCOMPLETE", "run",
                           "the guest stopped before it took the new entropy", MS_RESUME_PATH);
        if (r->res.guest_time >= cap) break;
        if (i >= slices)
            return ms_fail(reply, ZCL_COMMAND_EXIT_FAILED, NULL, "WARMUP_INCOMPLETE", "run",
                           "max_instr ended before the new entropy was taken", MS_RESUME_PATH);
    }
    snprintf(why, sizeof why,
             "the guest took %llu of %llu new entropy bytes in %llu ms of guest time; the "
             "entropy driver may not have been attached when the snapshot was taken",
             (unsigned long long)r->harvest_bytes, (unsigned long long)MS_HARVEST_BYTES,
             (unsigned long long)r->harvest_ms);
    return ms_fail(reply, ZCL_COMMAND_EXIT_FAILED, NULL, "FRESH_NO_HARVEST", "run", why,
                   MS_RESUME_PATH);
}

static void ms_resume_run(struct ms_run *r, struct zcl_command_reply *reply)
{
    const char *code;
    if (r->fresh && !ms_warmup(r, reply)) return;
    if (r->type_now != NULL)
        (void)rvmachine_console_input(r->m, (const uint8_t *)r->type_now, strlen(r->type_now));
    enum rvmachine_status st = ms_run(r);
    const char *why = ms_goal_failure(r, &code);
    if (st != RVMACHINE_OK) {
        (void)ms_machine_fail(reply, "run", st);
        return;
    }
    if (why != NULL) {
        (void)ms_fail(reply, ZCL_COMMAND_EXIT_FAILED, NULL, code, "run", why, MS_RESUME_PATH);
        return;
    }
    if (r->out_path != NULL && !ms_write_snapshot(r, reply)) return;
    ms_emit_run(r, &reply->data);
    ms_emit_resume(r, &reply->data);
    if (r->out_path != NULL) ms_emit_final(r, &reply->data);
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = ZCL_COMMAND_EXIT_OK;
}

void zcl_native_handle_dev_machine_resume(const struct zcl_command_request *request,
                                          struct zcl_command_reply *reply)
{
    struct ms_run *r;
    if (reply == NULL) return;
    r = zcl_calloc(1, sizeof *r, "machine_resume_state");
    if (r == NULL) {
        (void)ms_fail(reply, ZCL_COMMAND_EXIT_INTERNAL, MS_RESUME_PATH, "OUT_OF_MEMORY", "setup",
                      "the run state could not be allocated", NULL);
        return;
    }
    ms_init(r);
    if (ms_resume_parse(request != NULL ? request->input : NULL, r, reply) &&
        ms_resume_open(r, reply) && ms_inspect(r, reply) && ms_restore(r, reply) &&
        ms_open_transcript(r, reply))
        ms_resume_run(r, reply);
    ms_cleanup(r);
    free(r);
}
