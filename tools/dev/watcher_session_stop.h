/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Prove dev begin/status/stop against recorded watcher stand-ins. */

#ifndef ZCL_WATCHER_SESSION_STOP_H
#define ZCL_WATCHER_SESSION_STOP_H

/* repo supplies the default dev binary and holder fixture when bin or
 * fixture is NULL. bin is the dev binary under test. fixture is the
 * watcher stand-in source. Returns 0 after the pass line. */
int zcl_watcher_session_stop(const char *repo, const char *bin,
                             const char *fixture);

#endif
