/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: the slot naming and path rules shared by ops.slot.install,
 *          ops.slot.activate and ops.slot.status, so every leaf agrees on
 *          what a slot name is and where <slots>/<name>/z23 lives.
 */
#ifndef ZCL_NATIVE_SLOT_COMMON_H
#define ZCL_NATIVE_SLOT_COMMON_H

#include <stdbool.h>
#include <stddef.h>

#define SLOT_FILE "z23"
#define SLOT_NAME_MAX 64u
#define SLOT_PATH_MAX 1536u

struct slot_paths {
    char slots[SLOT_PATH_MAX];
    char name_dir[SLOT_PATH_MAX];
    char final_path[SLOT_PATH_MAX];
    char tmp_path[SLOT_PATH_MAX];
};

enum slot_path_status { SLOT_PATH_OK, SLOT_PATH_NO_ROOT, SLOT_PATH_TOO_LONG };

/* One path component of [a-z0-9._-], 1..64 bytes, not starting with '-' or
 * '.', and never the ".tmp." staging name of another install. */
bool slot_name_ok(const char *name);

/* <slots> root: ZCL_BINARY_SLOTS_DIR, else the launcher's per-user
 * directory under HOME. Must be absolute. */
bool slot_root(char *out, size_t cap);

/* Fill every path for slot `name` (already slot_name_ok). */
enum slot_path_status slot_paths_resolve(struct slot_paths *out,
                                         const char *name);


/* ---- service-instance side (activate and status) ------------------------ */

/* The only service classes a slot may be activated for. The canonical node
 * unit is deliberately not among them. */
bool slot_class_ok(const char *service_class);

/* <unit-prefix><instance>.service for an allow-listed class. */
bool slot_unit_name(const char *service_class, const char *instance,
                    char *out, size_t cap);

/* systemd --user unit directory: ZCL_SLOT_UNIT_DIR, else under HOME. */
bool slot_unit_dir(char *out, size_t cap);

/* Small state directory for last-good records: ZCL_SLOT_STATE_DIR, else
 * under HOME. */
bool slot_state_dir(char *out, size_t cap);

/* Read a small text file whole into buf (NUL-terminated). Returns its length,
 * or -1 when it cannot be read. */
long slot_read_file(const char *path, char *buf, size_t cap);

/* From a drop-in's text: the binary and the argument string of its last
 * non-empty ExecStart= line. False when there is none. */
bool slot_dropin_exec(const char *text, char *bin, size_t bin_cap, char *args,
                      size_t args_cap);

/* "<slots>/<name>/z23" -> "<name>". */
bool slot_name_from_binary(const char *binary, char *out, size_t cap);

#endif
