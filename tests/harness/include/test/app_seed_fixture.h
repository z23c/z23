/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: shared runner for the app.seed and app journey groups (app_seed,
 * app_seed_skycombat, app_front_door, app_journey, app_journey_skycombat).
 * A leaf runs as the CLI and MCP run it: the registry input contract, the
 * handler, the reply budget. Plan/confirm leaves are driven through the
 * returned plan_id; a front-door verb runs as a person types it. */
#ifndef ZCL_TEST_APP_SEED_FIXTURE_H
#define ZCL_TEST_APP_SEED_FIXTURE_H

#include "command/cli_confirm.h"
#include "command/native_command.h"
#include "json/json.h"
#include "kernel/command_registry.h"

#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>

struct asf_leaf {
    struct json_value in;
    struct zcl_command_request req;
    struct zcl_command_reply out;
};

void asf_open(struct asf_leaf *l);
void asf_close(struct asf_leaf *l);
const struct zcl_command_spec *asf_spec(const char *path);

/* Input contract, then handler; false when the leaf is missing, the input
 * is refused by its contract or the reply is over budget. */
bool asf_exec(const char *path, struct asf_leaf *l);
/* asf_exec and the reply passed. */
bool asf_pass(const char *path, struct asf_leaf *l);
/* The reply refused with exactly this code. */
bool asf_refusal(const struct asf_leaf *l, const char *code);
/* A string field of the reply data ("" when absent). */
const char *asf_get(const struct asf_leaf *l, const char *key);
bool asf_flag(const struct asf_leaf *l, const char *key);
/* Plan, then repeat with the plan_id and confirm:true; both must pass. */
bool asf_plan_confirm(const char *path, struct asf_leaf *l);

/* Write text to dir/rel (parents must exist). */
bool asf_put(const char *dir, const char *rel, const char *text);

/* app.seed {app, source, datadir} planned and confirmed; the confirm reply
 * stays in l. */
bool asf_seed(struct asf_leaf *l, const char *app, const char *source,
              const char *datadir);
/* zcode.package.adopt of release into datadir; copy receives its absolute
 * directory. */
bool asf_adopt(const char *release, const char *datadir, char *copy,
               size_t cap);
/* app.build {copy, datadir} planned and confirmed; the reply stays in l. */
bool asf_build(struct asf_leaf *l, const char *copy, const char *datadir);

/* Replace the one occurrence of `from` in dir/rel with `to`; false when it
 * is absent or occurs more than once. */
bool asf_replace(const char *dir, const char *rel, const char *from,
                 const char *to);

/* text holds a short publisher fingerprint: xxxx-xxxx-xxxx-xxxx, four
 * groups of four lowercase hex. */
bool asf_short_fingerprint(const char *text);

/* MCP refuses this owner-authority leaf, plan and confirm, by owner
 * authority (MUTATION_REFUSED_OWNER_AUTHORITY); key=value is its target. */
bool asf_mcp_refuses_owner(const char *path, const char *key,
                           const char *value);

#if !defined(_WIN32)
#define ASF_DOOR_OUT (16u * 1024u)

/* One `z23 app VERB TARGET` as a person types it: HOME and the working
 * directory set, the front door's human lines captured, and for ASK the
 * injected answer is yes with the question kept. */
struct asf_door {
    int rc;
    bool asked;
    char question[512];
    char text[ASF_DOOR_OUT];
};
void asf_door_run(const char *home, const char *cwd, const char *datadir,
                  const char *verb, const char *target,
                  enum zcl_cli_confirm_mode mode, struct asf_door *run);
/* The value of a "  key: value" line the front door printed ("" if none). */
const char *asf_door_line(const struct asf_door *run, const char *key,
                          char *out, size_t cap);
/* "pid N" in the front door's output (0 when absent). */
long asf_door_pid(const char *text);
/* The pid was alive, and is now killed and reaped. */
bool asf_alive_then_stop(long pid);

/* The whole journey with ONE owner key, two HOMEs and two datadirs, every
 * step a front-door verb as typed. A, in the checkout `source`: copy APP
 * (no release yet, so app.seed publishes one with A's key), edit, save,
 * build, open, share. B, in B's HOME: open A's NAME.z23share (receive,
 * build, open). Each step returns false with its reason printed. */
struct asf_journey {
    const char *app;
    char source[1200];
    char root[600];
    char a_home[700], a_datadir[700], b_home[700], b_datadir[700];
    char copy[96];
    char a_copy[1300];
    char share[1300];
    char b_copy[1300];
    char image_built[65];  /* A's build before share */
    char image_shared[65]; /* A's build of the shared version */
    char image_b[65];      /* B's build of the received file */
    char path_shared[1300], path_b[1300];
    int commands_a, commands_b;
    int shares; /* shares A has made so far */
};
/* root is an existing scratch directory; source the checkout A copies in. */
bool asf_journey_init(struct asf_journey *j, const char *app,
                      const char *source, const char *root);
/* A: z23 app copy APP, which seeds through app.seed and adopts. */
bool asf_journey_copy(struct asf_journey *j);
/* A (after the caller's edit): save, build, open; the open's pid stops. */
bool asf_journey_save_build_open(struct asf_journey *j);
/* A: share, then the shared version's image; A's key published twice in
 * this ISO week (seed and share), both recorded. */
bool asf_journey_share(struct asf_journey *j);
/* B: open the share file (asked once, with the short fingerprint), which
 * receives, builds and opens; B's image equals A's shared image. */
bool asf_journey_receive(struct asf_journey *j);
#endif

#if defined(__linux__)
/* Xvfb on this host, or NULL. */
const char *asf_xvfb_path(void);
/* Start Xvfb on a free display it picks itself (-displayfd), logging to
 * logdir/xvfb.log, and point DISPLAY at it. */
bool asf_xvfb_start(const char *xvfb, const char *logdir, pid_t *pid);
void asf_xvfb_stop(pid_t *pid);
/* The first window-system header the game's raylib build reads on Linux
 * that this host lacks, or NULL. */
const char *asf_missing_game_header(void);
/* Run `image --qa-frames=120`; its exit status (-1 when it did not run). */
int asf_qa_frames(const char *image);
#endif

#endif /* ZCL_TEST_APP_SEED_FIXTURE_H */
