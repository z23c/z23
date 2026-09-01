/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * postmortem — crash capsule writer/reader.
 *
 * Signal-path capture writes an unpacked `.cap` directory. Boot maintenance
 * can later package prior capsules as `.cap.gz` outside the crash path. */

#ifndef ZCL_SIM_POSTMORTEM_H
#define ZCL_SIM_POSTMORTEM_H

#include "sim/seed_tape.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct postmortem_capture_opts {
    const char *dir;          /* Parent directory for capsules. */
    const seed_tape_t *tape;  /* Non-owning; serialized to tape.bin. */
    int crash_signal;
    int64_t crash_unix;
    const char *reason;       /* Optional manifest field. */
    const char *log_path;     /* Optional source for log.txt tail. */
};

struct postmortem_capsule_entry {
    char name[128];
    char path[512];
    int64_t crash_unix;
    int crash_signal;
    size_t tape_size_bytes;
};

struct postmortem_summary {
    char path[512];
    int64_t crash_unix;
    int crash_signal;
    size_t capsule_bytes;
    size_t tape_size_bytes;
};

int postmortem_capture_write(const struct postmortem_capture_opts *opts,
                             char *capsule_path_out,
                             size_t capsule_path_cap);

int postmortem_install(seed_tape_t *tape, const char *dir);
void postmortem_uninstall(void);

int postmortem_list(const char *dir,
                    struct postmortem_summary *out,
                    size_t out_cap,
                    size_t *count_out);
seed_tape_t *postmortem_load(const char *path);

bool postmortem_capsule_validate(const char *capsule_path);
seed_tape_t *postmortem_capsule_load_tape(const char *capsule_path);

int postmortem_capsule_compress(const char *capsule_path,
                                char *compressed_path_out,
                                size_t compressed_path_cap);
int postmortem_capsule_compress_unpacked(const char *dir,
                                         size_t *compressed_out);

int postmortem_capsule_list(const char *dir,
                            struct postmortem_capsule_entry *entries,
                            size_t entry_cap,
                            size_t *count_out);

int postmortem_capsule_prune(const char *dir,
                             int64_t now_unix,
                             int64_t max_age_seconds,
                             size_t keep_latest,
                             size_t *pruned_out);

#ifdef __cplusplus
}
#endif

#endif /* ZCL_SIM_POSTMORTEM_H */
