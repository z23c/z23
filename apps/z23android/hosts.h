/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZAPP_HOSTS_H
#define ZAPP_HOSTS_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "thermal.h"
/* Formats the laptop host's fleet snapshot as a headline and one block per host.
 * Unknown or missing values are shown as unknown, never as zero. */
bool zapp_hosts_format(const char *json, char *out, size_t cap);
/* The same snapshot as one verdict per host for the voice model: "in sync", "not in sync: N blocks
 * behind", "not counted in sync: <reason>". The headline count uses the same rule; heights are left out. */
bool zapp_hosts_verdicts(const char *json, char *out, size_t cap);
/* The main screen's fleet line from a zapp_hosts_format report: its headline, "no current report"
 * once a request has failed, or "checking" while a paired laptop host has not answered, so the
 * line holds its place from the first frame. Empty when no host is paired and none answered. */
const char *zapp_fleet_line(const char *report, bool stale, bool paired, char *out, size_t cap);
/* Writes value with comma thousands separators, which models copy more reliably than long digit
 * runs; negative values are written plainly. Returns out. */
const char *zapp_grouped(int64_t value, char out[32]);
/* Evidence about the chain beyond the node's own height. fleet_height is the highest height a
 * reachable fleet host reports, or -1; quiet_secs is how long the node's tip has not moved, or -1; onion_only is
 * set when the node dials only onion peers, so a shortage of peers reads as a shortage of onion peers. */
struct zapp_chain_evidence { int64_t fleet_height, quiet_secs; bool onion_only; };
/* A node is called in sync only within ZAPP_CHAIN_SKEW blocks of the highest height it has heard of,
 * and only with proof the chain is live: at least ZAPP_CHAIN_MIN_PEERS peers, or a fleet height that
 * agrees. With fewer peers, or a tip silent for more than ZAPP_CHAIN_QUIET_SECS (about six block
 * times), it says what it knows and that it cannot confirm. */
enum { ZAPP_CHAIN_SKEW = 2, ZAPP_CHAIN_MIN_PEERS = 2, ZAPP_CHAIN_QUIET_SECS = 900 };
/* A fleet snapshot is evidence for this long after the host observed it, and for this long ahead of the phone clock. */
enum { ZAPP_FLEET_MAX_AGE_SECS = 180, ZAPP_FLEET_FUTURE_SECS = 60 };
/* The highest height any reachable host of a current fleet snapshot (the laptop host's JSON) reports; -1 for none
 * or when the snapshot is missing its observed_at, old, or dated ahead. now_unix is the phone clock in seconds. */
int64_t zapp_fleet_height(const char *json, int64_t now_unix);
/* One line for the phone node on the main screen. stopping wins until the node exits; height,
 * target and peers are negative when unknown; target is the highest height reported by peers.
 * onion_ready adds the onion service state, shown only while the node responds. evidence may be NULL.
 * Returns out. */
const char *zapp_node_line(bool responding, bool process_running, bool stopping, bool onion_ready,
                           int64_t height, int64_t target, int64_t peers,
                           const struct zapp_chain_evidence *evidence, char *out, size_t cap);
/* The sentence under More that adds what the node line does not say: how many blocks are left,
 * or that none are. Arguments as for zapp_node_line. Returns out. */
/* The pace the node reports in a status reply (data.pace), normal when the reply lacks it, the word is
 * unknown or the reply is NULL or unreadable. A node that does not apply the pace file reports none. */
enum zapp_pace zapp_status_pace(const char *status);
/* The main-screen node line for the pace in effect: while the phone is warm the node says so instead
 * of its sync progress. node_line is used for a normal pace or when the node process is not running.
 * Returns out. */
const char *zapp_paced_line(enum zapp_pace pace, bool process_running, const char *node_line,
                            char *out, size_t cap);
const char *zapp_sync_line(bool responding, bool process_running, int64_t height, int64_t target, int64_t peers,
                           const struct zapp_chain_evidence *evidence, char *out, size_t cap);
/* Hosts not in sync in a zapp_hosts_format report, read from its headline; 0 for an empty or
 * unreadable report. */
int zapp_fleet_attention(const char *report);
/* The one question offered under Talk, or "" when none is worth asking. Not paired: "". In order:
 * node trouble (waiting for peers, then catching up), which hosts need attention, what is wrong with
 * the first host the report shows out of sync, then a general fleet question. asked is the question
 * last answered, or NULL: the offer is the first question after it in that order, never asked itself,
 * so an answered question gives way to its follow-up. report is a zapp_hosts_format report, or NULL
 * when none is current. Height, target and peers are negative when unknown. Questions only, never a
 * control such as start, stop or join. Returns out. */
const char *zapp_suggestion(bool paired, bool responding, int64_t height, int64_t target, int64_t peers,
                            const char *report, const char *asked, char *out, size_t cap);
/* The label of the index-th host row of a zapp_hosts_format report, or false past the last row. */
bool zapp_hosts_label(const char *report, size_t index, char label[16]);
/* Formats a host's reply to zapp_speech_client_ops as the text under the host controls. A plan
 * reply also copies its 32-character plan id to plan; otherwise plan is empty. False for a refusal,
 * a failure or a reply that is not understood, with the reason in text. */
bool zapp_ops_view(const char *json, char *text, size_t cap, char plan[33]);
#endif
