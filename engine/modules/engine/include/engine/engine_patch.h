/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * engine_patch — turn assistant text into a bounded set of file writes.
 *
 * ── WHY NOT A UNIFIED DIFF ───────────────────────────────────────────────
 * Because models cannot count. A unified diff has to carry correct line
 * numbers and correct context for a file the model is recalling rather than
 * reading, and when it is wrong `git apply` refuses the whole thing. The
 * result is a harness whose dominant failure mode is "the model did fine work
 * and the patch would not apply", which teaches everyone to loosen the apply
 * step. Whole-file bodies have no line numbers to get wrong.
 *
 * ── THE ENVELOPE ─────────────────────────────────────────────────────────
 * Three markers, each alone on its own line, matched exactly:
 *
 *     Z23-BEGIN-FILE <path>
 *     ...verbatim file content...
 *     Z23-END-FILE
 *
 *     Z23-DELETE-FILE <path>
 *
 * Everything outside an envelope is prose and is ignored, so a model may
 * think out loud before and after without breaking the protocol.
 *
 * ── WHAT IS REFUSED ──────────────────────────────────────────────────────
 * The whole patch, never part of it. A partial apply leaves a tree that is
 * neither the old one nor the proposed one, and the gate result from such a
 * tree means nothing.
 *
 *   - a BEGIN with no matching END (a truncated reply, which is exactly what
 *     an output-token limit produces);
 *   - a BEGIN inside an open envelope;
 *   - an END with no open envelope;
 *   - more than ENGINE_PATCH_MAX_FILES entries, or one over
 *     ENGINE_PATCH_MAX_FILE_BYTES;
 *   - any path that is absolute, contains a `..` segment, starts with `.git/`,
 *     or contains a byte outside [A-Za-z0-9._/+-]. This is the containment
 *     boundary: the applier writes relative to an isolated worktree root, and
 *     a path that cannot escape that root is the only kind it will accept.
 *
 * A patch with zero entries is NOT an error here — it is a well-formed reply
 * that proposed nothing. That distinction matters, because "the model said it
 * was done and changed nothing" is a verdict this harness must be able to
 * reach honestly rather than by crashing.
 *
 * ── A PATH NAMED TWICE ─────────────────────────────────────────────────
 * Last envelope wins, not "refuse the whole reply". A model that revises
 * itself mid-reply — emits a file, keeps thinking, then emits a corrected
 * whole-file body for the same path — is not malformed; refusing the entire
 * patch over it throws away a working (later) file alongside everything
 * else the reply proposed. The final entries[] holds only the LAST envelope
 * seen for each path (a later Z23-DELETE-FILE for a path with an earlier
 * write applies as a delete, and vice versa), and each supersession is
 * logged at LOG_WARN so a reviewer can see it happened.
 */

#ifndef ZCL_ENGINE_PATCH_H
#define ZCL_ENGINE_PATCH_H

#include <stdbool.h>
#include <stddef.h>

#define ENGINE_PATCH_MAX_FILES       64u
#define ENGINE_PATCH_MAX_FILE_BYTES  (512u * 1024u)
#define ENGINE_PATCH_MAX_PATH        200u

#define ENGINE_PATCH_BEGIN   "Z23-BEGIN-FILE "
#define ENGINE_PATCH_END     "Z23-END-FILE"
#define ENGINE_PATCH_DELETE  "Z23-DELETE-FILE "

struct engine_patch_entry {
    char   path[ENGINE_PATCH_MAX_PATH];
    char  *content;      /* NULL for a deletion */
    size_t content_len;
    bool   remove;
};

struct engine_patch {
    struct engine_patch_entry entries[ENGINE_PATCH_MAX_FILES];
    size_t count;
};

void engine_patch_free(struct engine_patch *p);

/* Parse the envelope out of `text`. Returns false on any violation above,
 * leaving `p` empty and freed. Returns true with p->count == 0 when the text
 * is well formed and simply proposes no change. */
bool engine_patch_parse(const char *text, size_t len, struct engine_patch *p);

/* The containment rule, exported because it is the security-relevant half and
 * deserves to be tested on its own rather than only through the parser. */
bool engine_patch_path_ok(const char *path);

/* Count lines the way a human reading a diff would: the number of '\n' bytes,
 * plus one more if the buffer is non-empty and does not end in one (a final
 * unterminated line is still a line). An empty buffer is 0 lines. */
size_t engine_patch_count_lines(const char *text, size_t len);

/* Is replacing a file of `old_lines` with one of `new_lines` a drastic
 * shrink — the shape of a model whole-file reply that lost most of a file it
 * meant to edit a few lines of? True only when the file existed before
 * (old_lines > 0) and the new body is under half its old line count. A brand
 * new file (old_lines == 0) is never a shrink, whatever its size. */
bool engine_patch_is_drastic_shrink(size_t old_lines, size_t new_lines);

/* The exact protocol text handed to a model. One definition, so the prompt
 * and the parser can never drift into describing different envelopes. */
const char *engine_patch_protocol_text(void);

/* Render one line per entry ("path: N bytes" or "path: DELETE") describing
 * what a successfully parsed patch would apply. Used to archive what the
 * envelope parser extracted from a reply, separately from whether the
 * apply step itself later succeeds. Writes at most buf_len - 1 bytes plus a
 * NUL into buf (truncating the last line safely if it would overflow) and
 * returns the number of bytes written excluding the NUL. p->count == 0
 * writes nothing and returns 0. */
size_t engine_patch_describe(const struct engine_patch *p, char *buf,
                              size_t buf_len);

#endif /* ZCL_ENGINE_PATCH_H */
