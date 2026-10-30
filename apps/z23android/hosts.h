/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZAPP_HOSTS_H
#define ZAPP_HOSTS_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
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
/* One line for the phone node on the main screen. stopping wins until the node exits; height,
 * target and peers are negative when unknown; target is the highest height reported by peers.
 * Returns out. */
const char *zapp_node_line(bool responding, bool process_running, bool stopping, int64_t height,
                           int64_t target, int64_t peers, char *out, size_t cap);
/* The sentence under More that adds what the node line does not say: how many blocks are left,
 * or that none are. Arguments as for zapp_node_line. Returns out. */
const char *zapp_sync_line(bool responding, bool process_running, int64_t height, int64_t target,
                           char *out, size_t cap);
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
#endif
