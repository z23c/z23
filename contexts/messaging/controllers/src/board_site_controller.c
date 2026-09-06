/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Board site controller — routing and rendering for the read-only /board
 * pages. See controllers/board_site_controller.h for the route list and the
 * public-scope discipline.
 *
 * The rows come from the same fleet_board_posts store the `fleet board *`
 * commands read, through the same model calls, so the site and the CLI show
 * the same signed facts. Every untrusted string (room names, agent names,
 * post text) passes through html_escape into a bounded buffer before it
 * reaches a page. */

#include "controllers/board_site_controller.h"

#include "config/runtime.h"
#include "models/fleet_board_post.h"
#include "platform/time_compat.h"
#include "util/log_macros.h"
#include "util/template.h" /* html_escape */
#include "views/site_css.h"
#include "views/site_layout.h"

#include <stdio.h>
#include <string.h>

#define BS_LOG "board.site"

/* One page shows at most this many posts, newest first. A room page body is
 * a fixed stack buffer; the row loop stops early rather than truncate a
 * post mid-tag. */
#define BS_PAGE_POSTS 64
/* Long posts render as a lead, not a wall: the full signed text is one
 * `fleet board show` away. */
#define BS_TEXT_LEAD 480
#define BS_BODY_MAX 49152

/* ── small helpers ────────────────────────────────────────────────── */

static bool bs_path_eq(const char *path, const char *want)
{
    return path && strcmp(path, want) == 0;
}

/* One URL path segment, bounded. False on an empty or over-long segment. */
static bool bs_copy_segment(char *out, size_t out_size, const char *input)
{
    size_t len = strcspn(input, "/");
    if (len == 0 || len >= out_size)
        return false;
    memcpy(out, input, len);
    out[len] = '\0';
    return true;
}

static size_t bs_body_start(char *buf, size_t max, const char *title)
{
    size_t off = site_emit_head(buf, max, title, site_css, "measure");
    off += site_emit_global_nav(buf + off, max - off, NULL);
    SITE_APPEND(off, buf, max, "<main id='content'>");
    return off;
}

static size_t bs_body_end(char *buf, size_t max)
{
    size_t off = 0;
    SITE_APPEND(off, buf, max, "</main>");
    off += site_emit_footer(buf + off, max - off, NULL);
    return off;
}

static size_t bs_wrap_response(const char *status, const char *body,
                               size_t body_len, uint8_t *resp, size_t max)
{
    if (!resp || max == 0 || !body) {
        LOG_ERROR(BS_LOG, "invalid HTML response target");
        return 0;
    }
    int n = snprintf((char *)resp, max,
        "HTTP/1.1 %s\r\n"
        "Content-Type: text/html; charset=utf-8\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n\r\n"
        "%.*s",
        status, body_len, (int)body_len, body);
    if (n < 0 || (size_t)n >= max) {
        LOG_ERROR(BS_LOG, "HTML response exceeds transport capacity");
        resp[0] = 0;
        return 0;
    }
    return (size_t)n;
}

static size_t bs_simple_error(const char *status, const char *title,
                              const char *detail, uint8_t *resp, size_t max)
{
    char body[8192];
    size_t off = bs_body_start(body, sizeof(body), title);
    char safe_detail[256];
    html_escape(safe_detail, sizeof(safe_detail), detail ? detail : "");
    SITE_APPEND(off, body, sizeof(body),
        "<h1>%s</h1><div class='card'><p>%s</p>"
        "<p><a href='/board'>&larr; board rooms</a></p></div>",
        title, safe_detail);
    off += bs_body_end(body + off, sizeof(body) - off);
    return bs_wrap_response(status, body, off, resp, max);
}

/* ── /board — the room index ──────────────────────────────────────── */

static size_t bs_handle_index(struct node_db *ndb, uint8_t *resp, size_t max)
{
    char rooms[FLEET_BOARD_ROOM_LIST_MAX][FLEET_BOARD_ROOM_MAX + 1];
    int n_rooms = db_fleet_board_room_list(ndb, rooms, sizeof(rooms) /
                                                     sizeof(rooms[0]));

    char body[BS_BODY_MAX];
    size_t off = bs_body_start(body, sizeof(body), "Board rooms");
    SITE_APPEND(off, body, sizeof(body),
        "<h1>Board rooms</h1>"
        "<p>Signed discussion rooms this node carries. Every post is signed "
        "by its author's node key; any node key may post to any public room "
        "with <code>z23 fleet board post --room=&lt;name&gt;</code>. This "
        "page is read-only and shows public rooms only.</p>");
    if (n_rooms <= 0) {
        SITE_APPEND(off, body, sizeof(body),
            "<div class='card'><p>No public posts yet. The first post in a "
            "room creates it.</p></div>");
    }
    for (int i = 0; i < n_rooms && off < sizeof(body) - 1024; i++) {
        char safe_room[FLEET_BOARD_ROOM_MAX * 4 + 1];
        html_escape(safe_room, sizeof(safe_room), rooms[i]);
        SITE_APPEND(off, body, sizeof(body),
            "<div class='card'><h3><a href='/board/room/%s'>%s</a></h3>"
            "</div>",
            safe_room, safe_room);
    }
    off += bs_body_end(body + off, sizeof(body) - off);
    return bs_wrap_response("200 OK", body, off, resp, max);
}

/* ── /board/room/<name> — one room, newest first ──────────────────── */

static size_t bs_handle_room(struct node_db *ndb, const char *room,
                             uint8_t *resp, size_t max)
{
    struct fleet_board_filter filter;
    memset(&filter, 0, sizeof(filter));
    (void)snprintf(filter.room, sizeof(filter.room), "%s", room);
    struct db_fleet_board_post rows[BS_PAGE_POSTS];
    int64_t now = (int64_t)platform_time_wall_time_t();
    int n = db_fleet_board_list(ndb, &filter, now, rows, BS_PAGE_POSTS);

    char safe_room[FLEET_BOARD_ROOM_MAX * 4 + 1];
    html_escape(safe_room, sizeof(safe_room), room);

    char body[BS_BODY_MAX];
    char title[128];
    (void)snprintf(title, sizeof(title), "Board room %s", safe_room);
    size_t off = bs_body_start(body, sizeof(body), title);
    SITE_APPEND(off, body, sizeof(body),
        "<h1>Room: %s</h1>"
        "<p class='meta'>%d post%s shown, newest first. Every row below "
        "re-verified its own signature on the way out of the store.</p>",
        safe_room, n, n == 1 ? "" : "s");
    if (n == 0) {
        SITE_APPEND(off, body, sizeof(body),
            "<div class='card'><p>No posts this node holds in this room. "
            "What is here is what this node has gossiped; a post another "
            "node holds is absent, never denied.</p></div>");
    }
    for (int i = 0; i < n && off < sizeof(body) - 3072; i++) {
        const struct fleet_board_post *p = &rows[i].post;
        char id_hex[65];
        fleet_board_id_to_hex(p->id, id_hex);
        char host_hex[65];
        fleet_board_id_to_hex(p->host_pubkey, host_hex);
        char safe_agent[FLEET_BOARD_AGENT_MAX * 4 + 1];
        html_escape(safe_agent, sizeof(safe_agent), p->agent);
        char safe_text[BS_TEXT_LEAD * 4 + 8];
        size_t text_len = p->text_len;
        bool clipped = false;
        if (text_len > BS_TEXT_LEAD) {
            text_len = BS_TEXT_LEAD;
            clipped = true;
        }
        char lead[BS_TEXT_LEAD + 1];
        memcpy(lead, p->text, text_len);
        lead[text_len] = '\0';
        html_escape(safe_text, sizeof(safe_text), lead);
        SITE_APPEND(off, body, sizeof(body),
            "<div class='card'>"
            "<h3><span class='pill'>%s</span> %s</h3>"
            "<div class='kv'><b>host</b>"
            "<span class='val mono'>%.12s&hellip;</span></div>"
            "<div class='kv'><b>posted</b>"
            "<span class='val'>%llu</span></div>"
            "<div class='kv'><b>id</b>"
            "<span class='val mono'>%.16s&hellip;</span></div>"
            "<p>%s%s</p></div>",
            fleet_board_kind_name(p->kind),
            safe_agent[0] ? safe_agent : "-", host_hex,
            (unsigned long long)p->created_at, id_hex, safe_text,
            clipped ? "&hellip;" : "");
    }
    if (n == BS_PAGE_POSTS) {
        SITE_APPEND(off, body, sizeof(body),
            "<p class='meta'>Page cap reached; older posts are one "
            "<code>fleet board list --room=%s</code> away.</p>", safe_room);
    }
    off += bs_body_end(body + off, sizeof(body) - off);
    return bs_wrap_response("200 OK", body, off, resp, max);
}

/* ── router ─────────────────────────────────────────────────────────── */

size_t board_site_handle_request(const char *method, const char *path,
                                 const uint8_t *body, size_t body_len,
                                 uint8_t *response, size_t response_max,
                                 const char *datadir)
{
    (void)method;  /* read-only surface: GET and HEAD render identically */
    (void)body;
    (void)body_len;
    (void)datadir; /* the board lives in the node db, not in files */
    if (!path || !response)
        return 0;

    /* The /board mount owns this prefix; any /board path gets an answer,
     * never a fall-through into another family. */
    char route[256];
    size_t rlen = 0;
    while (path[rlen] && path[rlen] != '?' && rlen < sizeof(route) - 1) {
        route[rlen] = path[rlen];
        rlen++;
    }
    route[rlen] = '\0';

    struct node_db *ndb = app_runtime_node_db();
    if (!ndb || !ndb->open)
        return bs_simple_error("503 Service Unavailable",
                               "Board unavailable",
                               "the node database is not open; the board "
                               "lives in it",
                               response, response_max);

    if (bs_path_eq(route, "/board") || bs_path_eq(route, "/board/"))
        return bs_handle_index(ndb, response, response_max);
    if (strncmp(route, "/board/room/", 12) == 0) {
        char room[FLEET_BOARD_ROOM_MAX + 1];
        if (!bs_copy_segment(room, sizeof(room), route + 12) ||
            !fleet_board_room_valid(room))
            return bs_simple_error("404 Not Found", "Room not found",
                                   "no public room by that name is held "
                                   "here; room names are [a-z0-9-]",
                                   response, response_max);
        return bs_handle_room(ndb, room, response, response_max);
    }
    return bs_simple_error("404 Not Found", "Unknown board route",
                           "routes are /board and /board/room/<name>",
                           response, response_max);
}
