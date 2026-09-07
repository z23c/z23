/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: private declarations shared between the native `zcode work run`
 * command siblings (native_zcode_work_run_command.c,
 * native_zcode_work_run_deps.c and native_zcode_work_run_packet.c). Nothing
 * here is a public API: every symbol is a static-linkage-turned-internal-
 * linkage helper reused across exactly these sibling translation units,
 * never included elsewhere. */
#ifndef ZCL_NATIVE_ZCODE_WORK_RUN_PRIV_H
#define ZCL_NATIVE_ZCODE_WORK_RUN_PRIV_H

#include "json/json.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define ZWORK_RUN_PATH_MAX 4400
#define ZWORK_ADAPTER_OUTPUT_MAX (32u * 1024u)
#define ZWORK_ADAPTER_PACKET_MAX (512u * 1024u)
#define ZWORK_DEPENDENCY_HEADER_MAX (64u * 1024u)
#define ZWORK_DEPENDENCY_CONTEXT_MAX (192u * 1024u)
#define ZWORK_DEPENDENCY_API_MAX 256u
#define ZWORK_RUN_LOG "zcode.work.run"
#define ZWORK_PREFLIGHT_OUTPUT_MAX 2048u

/* Shared JSON accessors (native_zcode_work_run_command.c). */
const char *run_str(const struct json_value *input, const char *key);
bool run_bool(const struct json_value *input, const char *key);

#if defined(_WIN32)
/* Shared stable-read primitive (native_zcode_work_run_packet.c), Windows
 * only: POSIX siblings use plain open/read/fstat instead. */
bool run_stable_read(const char *path, void *bytes, size_t cap,
                     size_t *len_out, bool current_user_only);
#endif

/* Dependency-context and candidate-metadata entry points
 * (native_zcode_work_run_deps.c), called from run_admit_input(). */
struct vcs_zcode_task_v1;
struct vcs_zcode_agent_context_v1;
bool run_dependency_context_json(
    struct json_value *locked_out, struct json_value *selected_out,
    const char *workspace, const char *datadir,
    const struct vcs_zcode_task_v1 *task, const char *goal,
    char detail[256]);
bool run_excerpts_json(
    struct json_value *out, const struct vcs_zcode_agent_context_v1 *context);
bool run_candidate_metadata_read(
    const char *candidate_workspace, struct json_value *document);
bool run_candidate_metadata_write(
    const char *candidate_workspace, const struct json_value *document);
bool run_compose_candidate_metadata(
    const char *candidate_workspace, const struct vcs_zcode_task_v1 *task,
    const char *workspace, bool *changed_out);

/* Ephemeral adapter packet (native_zcode_work_run_packet.c): composition of
 * the bounded model context, private staging, repair-packet readback and
 * removal of the ephemeral adapter files. */
struct vcs_zcode_write_scope_v1;
bool run_packet_path(const char *candidate_workspace,
                     char path[ZWORK_RUN_PATH_MAX]);
bool run_write_packet(const char *candidate_workspace,
                      const struct json_value *packet,
                      char path[ZWORK_RUN_PATH_MAX]);
int run_read_packet(const char *candidate_workspace,
                    char **wire_out, size_t *len_out);
bool run_repair_packet_valid(const struct json_value *packet,
                             const char *goal, uint64_t candidate_sequence);
void run_adapter_cleanup(const char *candidate_workspace,
                         const char *packet_path);
bool run_packet(struct json_value *packet, const char *goal,
                const char *workspace, const char *datadir,
                const struct vcs_zcode_task_v1 *task,
                const struct vcs_zcode_agent_context_v1 *context,
                const struct vcs_zcode_write_scope_v1 *scope,
                char detail[256]);

#endif
