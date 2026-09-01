/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Who is on the other end: the broker's peer-identity surface.
 *
 * The peer is identified once per connection, before any verb is dispatched,
 * from the kernel's own attribution — so a client that asserts an identity in
 * its own bytes is not merely disbelieved, it is never asked.
 *
 * WHICH kernel attribution is not a detail. SO_PEERCRED names the process that
 * CREATED the socket: for an accept()ed connection that is the peer, but for a
 * socketpair(2) it is the BROKER, on both ends, so it cannot tell the broker
 * apart from the child it handed the other end to. The socketpair posture
 * therefore identifies the peer from SCM_CREDENTIALS on the message it sent,
 * which the kernel stamps per message and the sender cannot forge. See
 * agent_broker_identify_peer().
 *
 * The expectation check (agent_broker_peer_authorized) fails closed: a null
 * credential, a credential the kernel never supplied, and an expectation that
 * constrains nothing are all refusals, each with a reason the caller can show.
 */
#if !defined(_WIN32)
#define _GNU_SOURCE  /* struct ucred, SO_PASSCRED — must precede every include */
#endif
#include "session/agent_broker.h"
#include "base/log_macros.h"
#include <errno.h>
#include <stdio.h>
#include <string.h>
#if !defined(_WIN32)
#include <sys/socket.h>
#if defined(__APPLE__)
#include <sys/un.h>
#endif
#include <unistd.h>
#endif

#define BROKER_TAG "agent.broker"

/* ── SO_PEERCRED ────────────────────────────────────────────────────────── */

bool agent_broker_peercred(int fd, struct agent_peer_cred *out)
{
#if defined(_WIN32)
    (void)fd;
    if (out) memset(out, 0, sizeof(*out));
    return false;
#else
    if (!out)
        LOG_FAIL(BROKER_TAG, "null out for fd=%d", fd);
    memset(out, 0, sizeof(*out));
    if (fd < 0)
        LOG_FAIL(BROKER_TAG, "bad fd=%d", fd);
#if defined(__APPLE__)
    uid_t uid = 0;
    gid_t gid = 0;
    if (getpeereid(fd, &uid, &gid) != 0)
        LOG_FAIL(BROKER_TAG, "getpeereid on fd=%d failed: %s", fd,
                 strerror(errno));
    pid_t pid = -1;
    socklen_t pid_len = sizeof(pid);
    if (getsockopt(fd, SOL_LOCAL, LOCAL_PEERPID, &pid, &pid_len) != 0)
        LOG_FAIL(BROKER_TAG, "LOCAL_PEERPID on fd=%d failed: %s", fd,
                 strerror(errno));
    if (pid_len != sizeof(pid) || pid <= 0)
        LOG_FAIL(BROKER_TAG,
                 "LOCAL_PEERPID on fd=%d returned invalid pid=%d len=%u",
                 fd, (int)pid, (unsigned)pid_len);
    out->pid = pid;
    out->uid = uid;
    out->gid = gid;
#else
    struct ucred uc;
    socklen_t len = sizeof(uc);
    if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &uc, &len) != 0 ||
        len != sizeof(uc))
        LOG_FAIL(BROKER_TAG, "SO_PEERCRED on fd=%d failed: %s", fd,
                 strerror(errno));
    out->pid   = uc.pid;
    out->uid   = uc.uid;
    out->gid   = uc.gid;
#endif
    out->valid = true;
    return true;
#endif
}
bool agent_broker_sender_cred(int fd, struct agent_peer_cred *out)
{
#if defined(_WIN32)
    (void)fd;
    if (out) memset(out, 0, sizeof(*out));
    return false;
#elif defined(__APPLE__)
    return agent_broker_peercred(fd, out);
#else
    if (!out)
        LOG_FAIL(BROKER_TAG, "null out for fd=%d", fd);
    memset(out, 0, sizeof(*out));
    if (fd < 0)
        LOG_FAIL(BROKER_TAG, "bad fd=%d", fd);
    /* Enabling this on the RECEIVING socket is what makes the kernel attach
     * credentials to messages; a sender cannot opt out of being named. */
    int on = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_PASSCRED, &on, sizeof(on)) != 0)
        LOG_FAIL(BROKER_TAG, "SO_PASSCRED on fd=%d failed: %s", fd,
                 strerror(errno));
    uint8_t peek;
    struct iovec iov = { .iov_base = &peek, .iov_len = 1 };
    union {
        struct cmsghdr align;
        char           bytes[CMSG_SPACE(sizeof(struct ucred))];
    } control;
    memset(&control, 0, sizeof(control));
    struct msghdr msg;
    memset(&msg, 0, sizeof(msg));
    msg.msg_iov        = &iov;
    msg.msg_iovlen     = 1;
    msg.msg_control    = control.bytes;
    msg.msg_controllen = sizeof(control.bytes);
    ssize_t r;
    do {
        r = recvmsg(fd, &msg, MSG_PEEK);
    } while (r < 0 && errno == EINTR);
    if (r <= 0)
        LOG_FAIL(BROKER_TAG, "nothing to attribute on fd=%d: %s", fd,
                 r == 0 ? "peer closed without sending" : strerror(errno));
    for (struct cmsghdr *c = CMSG_FIRSTHDR(&msg); c; c = CMSG_NXTHDR(&msg, c)) {
        if (c->cmsg_level != SOL_SOCKET || c->cmsg_type != SCM_CREDENTIALS ||
            c->cmsg_len != CMSG_LEN(sizeof(struct ucred)))
            continue;
        struct ucred uc;
        memcpy(&uc, CMSG_DATA(c), sizeof(uc));
        out->pid   = uc.pid;
        out->uid   = uc.uid;
        out->gid   = uc.gid;
        out->valid = true;
        return true;
    }
    LOG_FAIL(BROKER_TAG,
             "the kernel attached no credentials to the message on fd=%d "
             "(SO_PASSCRED must be set before the peer sends)", fd);
#endif
}
bool agent_broker_identify_peer(int fd, struct agent_peer_cred *out)
{
#if defined(_WIN32)
    (void)fd;
    if (out) memset(out, 0, sizeof(*out));
    return false;
#else
    if (!out)
        LOG_FAIL(BROKER_TAG, "null out for fd=%d", fd);
    if (!agent_broker_peercred(fd, out))
        LOG_FAIL(BROKER_TAG, "no socket credentials on fd=%d", fd);
    /* SO_PEERCRED just named the socket's CREATOR. When that is us, this is a
     * socketpair we made and both ends carry our pid — an answer about the
     * broker, not about the peer. Ask who actually sent instead. */
    if (out->pid == getpid()) {
        struct agent_peer_cred sender;
        if (agent_broker_sender_cred(fd, &sender) && sender.valid)
            *out = sender;
    }
    return true;
#endif
}
bool agent_broker_peer_authorized(const struct agent_peer_cred *c,
                                  const struct agent_peer_expectation *e,
                                  char *why, size_t why_cap)
{
    if (why && why_cap)
        why[0] = '\0';
    if (!c || !e) {
        if (why && why_cap)
            snprintf(why, why_cap, "internal: null credential or expectation");
        return false;
    }
    if (!c->valid) {
        if (why && why_cap)
            snprintf(why, why_cap,
                     "kernel did not supply peer credentials for this socket");
        return false;
    }
    /* An expectation that checks nothing would accept every local process.
     * That is a misconfiguration, and it fails closed. */
    if (!e->require_uid && !e->require_gid && !e->require_pid) {
        if (why && why_cap)
            snprintf(why, why_cap,
                     "expectation constrains nothing (no uid/gid/pid required)");
        return false;
    }
    if (e->require_uid && c->uid != e->uid) {
        if (why && why_cap)
            snprintf(why, why_cap, "uid mismatch: peer=%u expected=%u",
                     (unsigned)c->uid, (unsigned)e->uid);
        return false;
    }
    if (e->require_gid && c->gid != e->gid) {
        if (why && why_cap)
            snprintf(why, why_cap, "gid mismatch: peer=%u expected=%u",
                     (unsigned)c->gid, (unsigned)e->gid);
        return false;
    }
    if (e->require_pid && c->pid != e->pid) {
        if (why && why_cap)
            snprintf(why, why_cap, "pid mismatch: peer=%d expected=%d",
                     (int)c->pid, (int)e->pid);
        return false;
    }
    return true;
}
