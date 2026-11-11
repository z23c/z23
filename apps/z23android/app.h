/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef Z23_ANDROID_APP_H
#define Z23_ANDROID_APP_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "scan.h"
#include "thermal.h"

#define ZAPP_TEXT_CAP 65536
#define ZAPP_NOTICE_CAP 1024u
#define ZAPP_ERROR_CAP 256
#define ZAPP_PENDING_CAP 1024u

enum zapp_reply_state { ZAPP_REPLY_READY, ZAPP_REPLY_WAITING, ZAPP_REPLY_CANCELLING };
enum zapp_voice_state { ZAPP_VOICE_READY, ZAPP_VOICE_RECORDING, ZAPP_VOICE_TRANSCRIBING,
    ZAPP_VOICE_OBSERVING, ZAPP_VOICE_SYNTHESIZING, ZAPP_VOICE_PLAYING, ZAPP_VOICE_CANCELLING };

/* The shell's verdict on the chain a node reports (zapp_chain_check). */
enum zapp_chain { ZAPP_CHAIN_NONE, ZAPP_CHAIN_WAITING, ZAPP_CHAIN_BEHIND, ZAPP_CHAIN_UNCONFIRMED, ZAPP_CHAIN_CURRENT };
struct zapp_view {
    char notice[ZAPP_NOTICE_CAP];
    char result[ZAPP_NOTICE_CAP];
    /* The latest Start node or Stop node for screens with no notice line of their own: what it does while queued, then why it
     * did not take effect; empty once the node line shows the outcome. */
    char node_action_notice[256];
    char transcript[ZAPP_TEXT_CAP];
    char connection[256];
    char sync_status[1024];
    char fleet_token[8192];
    bool fleet_machine;
    bool fleet_review_typed;
    char fleet_review_input[8192];
    char fleet_onion[128];
    char fleet_preview[2048];
    char fleet_receipt[8192];
    bool fleet_receipt_saved;
    char fleet_status[8192];
    bool fleet_stale;
    bool fleet_paired;
    bool busy;
    bool node_running;
    bool node_process_running;
    bool node_starting; /* Start has been reserved but has not completed. */
    bool node_installing; /* A one-time state install is running. */
    bool node_wallet_replaying;
    char node_wallet_replay[96];
    bool node_wanted;
    bool node_stopping; /* A stop was sent to the node process that is still running. */
    bool node_serving;  /* The node's boot status says it serves (zapp_node_serving), read while it answers. */
    bool scanning;
    bool scan_paste; /* The current scan reads submitted text, not the camera. */
    bool scan_permission_denied; /* The live camera request was refused. */
    bool scan_checking; /* A decoded fleet code is being verified. */
    unsigned scans_done;           /* Scan actions that have finished, with or without a code. */
    enum zapp_scan_kind scan_kind; /* Kind of the last code scanned by the scan action. */
    char scan_text[256];           /* That code's text when it is shown, else empty. */
    enum zapp_reply_state reply_state;
    enum zapp_voice_state voice_state;
    char voice_status[256];
    char voice_proposal[32];
    char pair_offer[256]; /* Descriptor offered over USB, awaiting the owner's decision. */
    char pair_code[8];
    char node_line[96]; /* One-line phone node summary for the main screen. */
    int64_t node_height;        /* Height the node reports, -1 when it does not answer or reports none. */
    enum zapp_chain chain_state;  /* The verdict on the node's chain (zapp_chain_check). */
    int64_t node_reference;       /* Height the verdict judges the node against, -1 when none. */
    char chain_doubt[48];         /* Reason for a WAITING or UNCONFIRMED verdict, else empty. */
    bool node_seen_height;        /* A height was seen since the node process started. */
    enum zapp_pace pace; /* Pace the node reports in its status, normal when it reports none. */
    char suggestion[96]; /* One question for the current state, or empty. */
    char pending_question[ZAPP_PENDING_CAP]; /* Question being answered, shown until its answer or cancel. */
    char ops_host[16];   /* Fleet host the host controls act on. */
    char ops_text[1536]; /* Errors, plugin inventory, restart plan or outcome last shown for that host. */
    char ops_plan[33];   /* Plan id awaiting Confirm restart, or empty. */
};
#endif
