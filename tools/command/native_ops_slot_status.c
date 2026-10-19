/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: ops.slot.status - read-only report of which slot each service
 *          instance runs (from its z23-slot.conf drop-in), its recorded
 *          last-good slot, and every installed slot with its sha256. It
 *          starts no process and writes nothing.
 */

#include "command/native_command.h"
#include "command/native_slot_common.h"

#include "base/hex.h"
#include "crypto/sha256.h"
#include "json/json.h"
#include "kernel/command_registry.h"

#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#if defined(_WIN32)
static void oss_execute(const struct zcl_command_request *request,
                        struct zcl_command_reply *reply)
{
    (void)request;
    if (reply)
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_FAILED, "UNSUPPORTED_PLATFORM",
                               "normalize", false, false,
                               "slot status needs POSIX file semantics",
                               "ops.slot.status");
}
#else

#define OSS_CMD "ops.slot.status"
#define OSS_TEXT_MAX 4096u

/* sha256 and size of a regular file; false when unreadable. */
static bool oss_hash(const char *path, char hex[65], int64_t *size)
{
    struct sha256_ctx ctx;
    unsigned char buf[8192], digest[SHA256_OUTPUT_SIZE];
    int64_t total = 0;
    ssize_t n;
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return false;
    sha256_init(&ctx);
    while ((n = read(fd, buf, sizeof(buf))) > 0) {
        sha256_write(&ctx, buf, (size_t)n);
        total += n;
    }
    close(fd);
    if (n < 0)
        return false;
    sha256_finalize(&ctx, digest);
    zcl_hex_encode(digest, sizeof(digest), hex);
    *size = total;
    return true;
}

static void oss_push_installed(const char *slots, struct json_value *out)
{
    struct json_value arr;
    DIR *d = opendir(slots);
    json_init(&arr);
    json_set_array(&arr);
    for (struct dirent *e = d ? readdir(d) : NULL; e; e = readdir(d)) {
        char path[SLOT_PATH_MAX], hex[65];
        struct stat sb;
        int64_t size;
        struct json_value row;
        if (!slot_name_ok(e->d_name) ||
            snprintf(path, sizeof(path), "%s/%s/%s", slots, e->d_name,
                     SLOT_FILE) >= (int)sizeof(path) ||
            lstat(path, &sb) != 0 || !S_ISREG(sb.st_mode) ||
            !oss_hash(path, hex, &size))
            continue;
        json_init(&row);
        json_set_object(&row);
        json_push_kv_str(&row, "name", e->d_name);
        json_push_kv_str(&row, "sha256", hex);
        json_push_kv_int(&row, "size", size);
        json_push_back(&arr, &row);
        json_free(&row);
    }
    if (d)
        closedir(d);
    json_push_kv(out, "installed", &arr);
    json_free(&arr);
}

/* "slot=<name>\n" -> name, or "" when absent. */
static void oss_last_good(const char *state_dir, const char *unit, char *out,
                          size_t cap)
{
    char path[SLOT_PATH_MAX], text[128];
    out[0] = '\0';
    if (snprintf(path, sizeof(path), "%s/%s.last-good", state_dir, unit) >=
            (int)sizeof(path) ||
        slot_read_file(path, text, sizeof(text)) < 0 ||
        strncmp(text, "slot=", 5) != 0)
        return;
    text[strcspn(text, "\n")] = '\0';
    snprintf(out, cap, "%s", text + 5);
}

static void oss_push_instance(const char *unit_dir, const char *state_dir,
                              const char *name, const char *unit,
                              struct json_value *arr)
{
    char path[SLOT_PATH_MAX], text[OSS_TEXT_MAX], bin[SLOT_PATH_MAX];
    char args[OSS_TEXT_MAX], slot[SLOT_NAME_MAX + 2], lg[SLOT_NAME_MAX + 2];
    struct json_value row;
    bool has = false;
    slot[0] = '\0';
    if (snprintf(path, sizeof(path), "%s/%s.d/z23-slot.conf", unit_dir,
                 unit) < (int)sizeof(path) &&
        slot_read_file(path, text, sizeof(text)) >= 0 &&
        slot_dropin_exec(text, bin, sizeof(bin), args, sizeof(args))) {
        has = true;
        if (!slot_name_from_binary(bin, slot, sizeof(slot)))
            slot[0] = '\0';
    }
    oss_last_good(state_dir, unit, lg, sizeof(lg));
    json_init(&row);
    json_set_object(&row);
    json_push_kv_str(&row, "instance", name);
    json_push_kv_str(&row, "unit", unit);
    json_push_kv_bool(&row, "dropin", has);
    json_push_kv_str(&row, "slot", slot);
    json_push_kv_str(&row, "last_good", lg);
    json_push_back(arr, &row);
    json_free(&row);
}

static bool oss_instances(const struct json_value *in, const char *cls,
                          struct json_value *out,
                          struct zcl_command_reply *reply)
{
    const struct json_value *arr = json_get(in, "instances");
    size_t count = arr && arr->type == JSON_ARR ? json_size(arr) : 0;
    char unit_dir[SLOT_PATH_MAX], state_dir[SLOT_PATH_MAX];
    struct json_value rows;
    if (count == 0 || count > 64 || !slot_unit_dir(unit_dir, sizeof(unit_dir)) ||
        !slot_state_dir(state_dir, sizeof(state_dir))) {
        slot_refuse(reply, "MISSING_INPUT",
                    "instances must be a non-empty array of instance names "
                    "and the unit/state directories must be resolvable",
                    OSS_CMD);
        return false;
    }
    json_init(&rows);
    json_set_array(&rows);
    for (size_t i = 0; i < count; i++) {
        const struct json_value *item = json_at(arr, i);
        const char *name = item ? json_get_str(item) : NULL;
        char unit[160];
        if (!name || !slot_unit_name(cls, name, unit, sizeof(unit))) {
            json_free(&rows);
            slot_refuse(reply, "BAD_INSTANCE",
                        "an instance is a name of 1-64 characters of a-z 0-9 "
                        ". _ -", name ? name : "");
            return false;
        }
        oss_push_instance(unit_dir, state_dir, name, unit, &rows);
    }
    json_push_kv(out, "instances", &rows);
    json_free(&rows);
    return true;
}

static void oss_execute(const struct zcl_command_request *request,
                        struct zcl_command_reply *reply)
{
    const struct json_value *cls = json_get(request->input, "service_class");
    const char *c = cls ? json_get_str(cls) : NULL;
    char slots[SLOT_PATH_MAX];
    if (!c || !slot_class_ok(c)) {
        slot_refuse(reply, "BAD_SERVICE_CLASS",
                    "service_class must be tunnel-receiver or gateway",
                    c ? c : OSS_CMD);
        return;
    }
    if (!slot_root(slots, sizeof(slots))) {
        slot_refuse(reply, "NO_SLOTS_DIR",
                    "cannot locate the slots directory: set "
                    "ZCL_BINARY_SLOTS_DIR to an absolute path or ensure HOME "
                    "is set", OSS_CMD);
        return;
    }
    if (!oss_instances(request->input, c, &reply->data, reply))
        return;
    oss_push_installed(slots, &reply->data);
    json_push_kv_str(&reply->data, "service_class", c);
    json_push_kv_int(&reply->data, "zcl_spent", 0);
}

#endif /* _WIN32 */

void zcl_native_handle_ops_slot_status(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    oss_execute(request, reply);
}
