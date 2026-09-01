/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Bounded top-N incident scoring and selection for the peer lifecycle
 * incidents report: given host groups and entries the caller already
 * gathered under g_pl.lock, score them, classify the dominant issue, and
 * keep the highest-scoring PEER_LIFECYCLE_INCIDENT_LIMIT/
 * PEER_LIFECYCLE_HOST_INCIDENT_LIMIT picks in ranked order. Nothing here
 * reads or writes g_pl directly, which is what lets this scoring/ranking
 * job live apart from the state-mutating note_*() path in
 * peer_lifecycle.c. */

#include "peer_lifecycle_internal.h"

#include <stdio.h>
#include <string.h>

int64_t duplicate_entries_for_host(
    const struct peer_lifecycle_host_group *groups, const char *host)
{
    for (size_t i = 0; i < PEER_LIFECYCLE_GROUP_LIMIT; i++) {
        if (groups[i].used && strcmp(groups[i].host, host) == 0)
            return groups[i].entries;
    }
    return 1;
}

static bool incident_pick_better(const struct peer_lifecycle_incident_pick *a,
                                 const struct peer_lifecycle_incident_pick *b)
{
    if (a->score != b->score)
        return a->score > b->score;
    int64_t a_seen = a->entry ? a->entry->last_seen : 0;
    int64_t b_seen = b->entry ? b->entry->last_seen : 0;
    return a_seen > b_seen;
}

int64_t host_group_incident_score(
    const struct peer_lifecycle_host_group *g)
{
    if (!g)
        return 0;
    int64_t score = 0;
    if (g->entries > 1)
        score += (g->entries - 1) * 2;
    if (g->open_connections > 1)
        score += (g->open_connections - 1) * 4;
    if (g->handshaked_open_connections > 1)
        score += (g->handshaked_open_connections - 1) * 6;
    score += g->reconnects * 3;
    score += g->timeout * 3;
    score += g->rejected * 3;
    score += g->pre_handshake_disconnects * 2;
    score += g->disconnected;
    return score;
}

const char *host_group_issue_class(
    const struct peer_lifecycle_host_group *g)
{
    if (!g)
        return "none";
    if (g->handshaked_open_connections > 1)
        return "duplicate_handshaked_connections";
    if (g->open_connections > 1)
        return "duplicate_current_connections";
    if (g->timeout > 0 && g->entries > 1)
        return "reconnect_timeout_pressure";
    if (g->entries > 1)
        return "duplicate_host_history";
    if (g->timeout > 0)
        return "timeout_pressure";
    if (g->rejected > 0)
        return "reject_pressure";
    if (g->pre_handshake_disconnects > 0)
        return "pre_handshake_disconnect_pressure";
    if (g->reconnects > 0)
        return "reconnect_pressure";
    return "none";
}

const char *host_group_next_action(
    const struct peer_lifecycle_host_group *g)
{
    if (!g)
        return "monitor_peer_lifecycle";
    if (g->handshaked_open_connections > 1 || g->open_connections > 1)
        return "inspect_duplicate_current_connections_for_host";
    if (g->timeout > 0 && g->entries > 1)
        return "inspect_peer_timeline_for_reconnect_timeouts";
    if (g->entries > 1)
        return "monitor_duplicate_host_history";
    if (g->timeout > 0)
        return "inspect_peer_timeout_reason";
    if (g->rejected > 0)
        return "inspect_peer_reject_reason";
    if (g->pre_handshake_disconnects > 0)
        return "inspect_pre_handshake_disconnects";
    if (g->reconnects > 0)
        return "monitor_reconnect_pressure";
    return "monitor_peer_lifecycle";
}

static bool host_pick_better(const struct peer_lifecycle_host_pick *a,
                             const struct peer_lifecycle_host_pick *b)
{
    if (a->score != b->score)
        return a->score > b->score;
    int64_t a_seen = a->group ? a->group->last_seen : 0;
    int64_t b_seen = b->group ? b->group->last_seen : 0;
    return a_seen > b_seen;
}

static void host_pick_sort(struct peer_lifecycle_host_pick *picks,
                           size_t count)
{
    for (size_t i = 0; i < count; i++) {
        for (size_t j = i + 1; j < count; j++) {
            if (host_pick_better(&picks[j], &picks[i])) {
                struct peer_lifecycle_host_pick tmp = picks[i];
                picks[i] = picks[j];
                picks[j] = tmp;
            }
        }
    }
}

void host_pick_consider(struct peer_lifecycle_host_pick *picks,
                               size_t *count,
                               const struct peer_lifecycle_host_group *g)
{
    if (!picks || !count || !g)
        return;
    int64_t score = host_group_incident_score(g);
    if (score <= 0)
        return;
    struct peer_lifecycle_host_pick candidate = {
        .group = g,
        .score = score,
    };
    if (*count < PEER_LIFECYCLE_HOST_INCIDENT_LIMIT) {
        picks[*count] = candidate;
        (*count)++;
        host_pick_sort(picks, *count);
        return;
    }
    if (host_pick_better(&candidate,
                         &picks[PEER_LIFECYCLE_HOST_INCIDENT_LIMIT - 1])) {
        picks[PEER_LIFECYCLE_HOST_INCIDENT_LIMIT - 1] = candidate;
        host_pick_sort(picks, *count);
    }
}

static void incident_pick_sort(struct peer_lifecycle_incident_pick *picks,
                               size_t count)
{
    for (size_t i = 0; i < count; i++) {
        for (size_t j = i + 1; j < count; j++) {
            if (incident_pick_better(&picks[j], &picks[i])) {
                struct peer_lifecycle_incident_pick tmp = picks[i];
                picks[i] = picks[j];
                picks[j] = tmp;
            }
        }
    }
}

void incident_pick_consider(
    struct peer_lifecycle_incident_pick *picks, size_t *count,
    const struct peer_lifecycle_entry *e, int64_t score,
    int64_t duplicate_host_entries, const char *host)
{
    if (!picks || !count || !e || score <= 0)
        return;
    struct peer_lifecycle_incident_pick candidate = {
        .entry = e,
        .score = score,
        .duplicate_host_entries = duplicate_host_entries,
    };
    snprintf(candidate.host, sizeof(candidate.host), "%s", host);
    if (*count < PEER_LIFECYCLE_INCIDENT_LIMIT) {
        picks[*count] = candidate;
        (*count)++;
        incident_pick_sort(picks, *count);
        return;
    }
    if (incident_pick_better(&candidate,
                             &picks[PEER_LIFECYCLE_INCIDENT_LIMIT - 1])) {
        picks[PEER_LIFECYCLE_INCIDENT_LIMIT - 1] = candidate;
        incident_pick_sort(picks, *count);
    }
}
