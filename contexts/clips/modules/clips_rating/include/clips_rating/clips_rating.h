/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: the Clips content levels and the pure viewer and serve decisions
 * of spec 6.6. No I/O, no clock, no codec dependency: callers pass plain
 * evidence and settings structs. */

#ifndef ZCL_CLIPS_RATING_H
#define ZCL_CLIPS_RATING_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum clips_level {
    CLIPS_LEVEL_GENERAL = 1,
    CLIPS_LEVEL_MILD = 2,
    CLIPS_LEVEL_SENSITIVE = 3,
    CLIPS_LEVEL_MATURE = 4,
    CLIPS_LEVEL_EXPLICIT = 5,
};
#define CLIPS_LEVEL_MAX 5

enum clips_descriptor {
    CLIPS_DESC_NUDITY = 1u << 0,
    CLIPS_DESC_SEXUAL = 1u << 1,
    CLIPS_DESC_VIOLENCE = 1u << 2,
    CLIPS_DESC_LANGUAGE = 1u << 3,
    CLIPS_DESC_DRUGS = 1u << 4,
    CLIPS_DESC_SELF_HARM = 1u << 5,
    CLIPS_DESC_HATE = 1u << 6,
};
#define CLIPS_DESC_MASK 0x7fu

enum clips_evidence {
    CLIPS_EVIDENCE_NONE = 0,
    CLIPS_EVIDENCE_AUTHOR,
    CLIPS_EVIDENCE_RATER,
    CLIPS_EVIDENCE_TEXT,
};

#define CLIPS_RATER_MAX 32

/* Every field is a value the caller already holds. Levels are 1..5 except
 * where noted. A rater_levels entry of 0 is a retraction or no rating and is
 * not evidence. text_level is the text check result: 1..5 when it returned a
 * level, 0 when it is unverified (no evidence and no level). is_reshare or
 * is_comment with target_shown false (hidden or not held) is hidden by row 0.
 * report_held is set only for a held report of reason abuse, illegal, sexual or
 * misrated from an accepted rater or a followed author. rater_levels holds one
 * newest level per rater; the caller takes the strictest of two records with the
 * same (rater, 2, seq). */
struct clips_rating_input {
    uint8_t declared_level;
    uint8_t rater_levels[CLIPS_RATER_MAX];
    size_t rater_count;
    uint8_t text_level;
    bool is_comment;
    bool is_reshare;
    bool target_shown;
    bool illegal_match;
    bool owner_blocked;
    bool own_key;
    bool owner_allowed;
    bool on_block_list;
    bool report_held;
    bool accepted_author;
    uint8_t viewer_level;
    bool show_unrated;
};

struct clips_rating_decision {
    bool shown;
    bool own;
    bool owner_allowed;
    bool blocked_by_list;
    bool reported;
    bool target_hidden;
    bool rating_above_level;
    bool rating_unverified;
    uint8_t effective_level;
    enum clips_evidence evidence;
};

/* The viewer decision: rows 0 to 9. Returns false, with *out hidden, for
 * NULL arguments, a declared_level outside 1..5, or more raters than
 * CLIPS_RATER_MAX. The serve decision refuses the same inputs. An out-of-range
 * viewer_level decides as General with show_unrated false. */
bool clips_rating_decide(const struct clips_rating_input *in,
                         struct clips_rating_decision *out);

/* The serve decision for a request from another owner: rows 1, 2, 5 and 7
 * only, against serve_level. An owner's own key gets no exemption, and missing
 * evidence does not refuse serving. An out-of-range serve_level decides as
 * General. */
bool clips_rating_decide_serve(const struct clips_rating_input *in, uint8_t serve_level,
                               struct clips_rating_decision *out);

#endif /* ZCL_CLIPS_RATING_H */
