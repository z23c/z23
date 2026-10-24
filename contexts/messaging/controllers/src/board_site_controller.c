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

#include "controllers/wiki_site_controller.h"

#include "base/safe_alloc.h"

#include "config/runtime.h"
#include "models/fleet_board_post.h"
#include "platform/time_compat.h"
#include "util/log_macros.h"
#include "util/template.h" /* html_escape */
#include "views/site_css.h"
#include "views/site_layout.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BS_LOG "board.site"

#ifdef ZCL_TESTING
static int64_t g_bs_now_for_testing;

void board_site_set_now_for_testing(int64_t now)
{
    g_bs_now_for_testing = now;
}
#endif

/* The time the pages list by: the wall clock, or a test's pinned time. */
static int64_t bs_now(void)
{
#ifdef ZCL_TESTING
    if (g_bs_now_for_testing > 0)
        return g_bs_now_for_testing;
#endif
    return (int64_t)platform_time_wall_time_t();
}

/* One page shows at most this many posts, newest first. A room page body is
 * a fixed stack buffer; the row loop stops early rather than truncate a
 * post mid-tag. */
#define BS_PAGE_POSTS 64
/* Long posts render as a lead, not a wall: the full signed text is one
 * `fleet board show` away. */
#define BS_TEXT_LEAD 480
#define BS_BODY_MAX 49152
/* html_escape widens one byte to at most "&quot;" (6 bytes). */
#define BS_ESC_FACTOR 6
/* Room-card stop margin: one card is at most BS_TEXT_LEAD escaped bytes
 * plus its fixed rows and links. */
#define BS_CARD_RESERVE 4096
/* One post page: the longest signed text any kind may carry (a wiki page),
 * escaped at the widest factor, plus the page frame, the fixed rows and an
 * escaped agent and room. Nothing is cut, so no post is shown partly. */
#define BS_POST_FRAME_MAX 16384
#define BS_POST_BODY_MAX \
    ((size_t)FLEET_BOARD_WIKI_TEXT_MAX * BS_ESC_FACTOR + BS_POST_FRAME_MAX)
static_assert(FLEET_BOARD_TEXT_MAX <= FLEET_BOARD_WIKI_TEXT_MAX,
              "the post page buffer is sized from the largest text cap");
static_assert(BS_POST_BODY_MAX <= WIKI_SITE_BODY_MAX,
              "a post page must stay inside the transport body bound");
static_assert(BS_TEXT_LEAD * BS_ESC_FACTOR + 8 + 1024 < BS_CARD_RESERVE,
              "a room card must fit its reserve");
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

/* The byte count of a preview of `text`: at most BS_TEXT_LEAD bytes, backed
 * off so the cut never lands inside a multi-byte UTF-8 sequence. */
static size_t bs_lead_len(const char *text, size_t text_len)
{
    if (text_len <= BS_TEXT_LEAD)
        return text_len;
    size_t n = BS_TEXT_LEAD;
    while (n > 0 && ((uint8_t)text[n] & 0xC0) == 0x80)
        n--;
    return n;
}

/* "re <16 hex>" linking the parent, or nothing when the post answers none. */
static size_t bs_append_ref_row(char *buf, size_t max, size_t off,
                                const uint8_t ref[32])
{
    static const uint8_t zero[32];
    if (memcmp(ref, zero, 32) == 0)
        return off;
    char ref_hex[65];
    fleet_board_id_to_hex(ref, ref_hex);
    SITE_APPEND(off, buf, max,
        "<div class='kv'><b>reply</b><span class='val mono'>"
        "<a href='/board/post/%s'>re %.16s</a></span></div>",
        ref_hex, ref_hex);
    return off;
}

static size_t bs_append_room_card(char *body, size_t max, size_t off,
                                  const struct fleet_board_post *p)
{
    char id_hex[65];
    fleet_board_id_to_hex(p->id, id_hex);
    char host_hex[65];
    fleet_board_id_to_hex(p->host_pubkey, host_hex);
    char safe_agent[FLEET_BOARD_AGENT_MAX * BS_ESC_FACTOR + 1];
    html_escape(safe_agent, sizeof(safe_agent), p->agent);
    size_t text_len = bs_lead_len(p->text, p->text_len);
    bool clipped = text_len < p->text_len;
    char lead[BS_TEXT_LEAD + 1];
    memcpy(lead, p->text, text_len);
    lead[text_len] = '\0';
    char safe_text[BS_TEXT_LEAD * BS_ESC_FACTOR + 8];
    html_escape(safe_text, sizeof(safe_text), lead);
    SITE_APPEND(off, body, max,
        "<div class='card'>"
        "<h3><span class='pill'>%s</span> %s</h3>"
        "<div class='kv'><b>host</b>"
        "<span class='val mono'>%.12s&hellip;</span></div>"
        "<div class='kv'><b>posted</b>"
        "<span class='val'>%llu</span></div>"
        "<div class='kv'><b>id</b><span class='val mono'>"
        "<a href='/board/post/%s'>%.16s&hellip;</a></span></div>",
        fleet_board_kind_name(p->kind), safe_agent[0] ? safe_agent : "-",
        host_hex, (unsigned long long)p->created_at, id_hex, id_hex);
    off = bs_append_ref_row(body, max, off, p->ref);
    SITE_APPEND(off, body, max, "<p>%s%s</p>", safe_text,
                clipped ? "&hellip;" : "");
    if (clipped)
        SITE_APPEND(off, body, max,
            "<p><a href='/board/post/%s'>full post</a></p>", id_hex);
    SITE_APPEND(off, body, max, "</div>");
    return off;
}

static size_t bs_handle_room(struct node_db *ndb, const char *room,
                             uint8_t *resp, size_t max)
{
    struct fleet_board_filter filter;
    memset(&filter, 0, sizeof(filter));
    (void)snprintf(filter.room, sizeof(filter.room), "%s", room);
    struct db_fleet_board_post rows[BS_PAGE_POSTS];
    int64_t now = bs_now();
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
    for (int i = 0; i < n && off < sizeof(body) - BS_CARD_RESERVE; i++)
        off = bs_append_room_card(body, sizeof(body), off, &rows[i].post);
    if (n == BS_PAGE_POSTS) {
        SITE_APPEND(off, body, sizeof(body),
            "<p class='meta'>Page cap reached; older posts are one "
            "<code>fleet board list --room=%s</code> away.</p>", safe_room);
    }
    off += bs_body_end(body + off, sizeof(body) - off);
    return bs_wrap_response("200 OK", body, off, resp, max);
}

/* ── /board/post/<id> — one post, whole ───────────────────────────── */

static size_t bs_post_not_found(uint8_t *resp, size_t max)
{
    /* One fixed answer for every reason: unknown, malformed, private,
     * expired, unverifiable. Nothing here echoes the id. */
    return bs_simple_error("404 Not Found", "Post not found",
                           "no public post by that id is held here",
                           resp, max);
}

/* Exactly 64 lowercase hex and nothing after. */
static bool bs_parse_post_id(const char *seg, uint8_t id[32])
{
    if (strlen(seg) != 64)
        return false;
    for (size_t i = 0; i < 64; i++) {
        char c = seg[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
            return false;
    }
    return fleet_board_id_from_hex(seg, id);
}

/* The one visibility rule is the room page's own: the post must come back
 * from the same db_fleet_board_list the room page runs, for the room the
 * post reads as. The extra filter fields narrow that listing to this one id
 * (an exact id clause ANDed with the room predicates, no window), so a
 * post with any number of later same-key posts is still found. On a match the
 * listed row is copied to *out and its signature is re-checked. */
static bool bs_post_listed(struct node_db *ndb, const uint8_t id[32],
                           const struct db_fleet_board_post *found,
                           struct db_fleet_board_post *out)
{
    const struct fleet_board_post *p = &found->post;
    struct fleet_board_filter filter;
    memset(&filter, 0, sizeof(filter));
    (void)snprintf(filter.room, sizeof(filter.room), "%s",
                   fleet_board_room_name(p));
    filter.kind = p->kind;
    filter.host_set = true;
    memcpy(filter.host_pubkey, p->host_pubkey, 32);
    (void)snprintf(filter.agent, sizeof(filter.agent), "%s", p->agent);
    (void)snprintf(filter.slug, sizeof(filter.slug), "%s", p->slug);
    filter.id_set = true;
    memcpy(filter.id, id, 32);
    struct db_fleet_board_post *rows =
        zcl_calloc(2, sizeof(*rows), "board post");
    if (!rows)
        return false;
    int64_t now = bs_now();
    int n = db_fleet_board_list(ndb, &filter, now, rows, 2);
    bool ok = false;
    for (int i = 0; i < n && !ok; i++) {
        if (memcmp(rows[i].post.id, id, 32) != 0)
            continue;
        ok = fleet_board_post_verify(&rows[i].post) == FLEET_BOARD_OK;
        if (ok)
            *out = rows[i];
    }
    free(rows);
    return ok;
}

static size_t bs_put_escaped(char *buf, size_t max, size_t off,
                             const char *text)
{
    if (off >= max)
        return off;
    return off + html_escape(buf + off, max - off, text);
}

static size_t bs_append_post_meta(char *buf, size_t max, size_t off,
                                  const struct db_fleet_board_post *row)
{
    const struct fleet_board_post *p = &row->post;
    char id_hex[65], host_hex[65];
    fleet_board_id_to_hex(p->id, id_hex);
    fleet_board_id_to_hex(p->host_pubkey, host_hex);
    char safe_agent[FLEET_BOARD_AGENT_MAX * BS_ESC_FACTOR + 1];
    html_escape(safe_agent, sizeof(safe_agent), p->agent);
    const char *room = fleet_board_room_name(p);
    char safe_room[FLEET_BOARD_ROOM_MAX * BS_ESC_FACTOR + 1];
    html_escape(safe_room, sizeof(safe_room), room);
    SITE_APPEND(off, buf, max,
        "<div class='kv'><b>kind</b><span class='val'>%s</span></div>"
        "<div class='kv'><b>agent</b><span class='val'>%s</span></div>"
        "<div class='kv'><b>room</b><span class='val'>"
        "<a href='/board/room/%s'>%s</a></span></div>"
        "<div class='kv'><b>posted</b><span class='val'>%llu</span></div>",
        fleet_board_kind_name(p->kind), safe_agent[0] ? safe_agent : "-",
        safe_room, safe_room, (unsigned long long)p->created_at);
    if (row->expires_at > 0)
        SITE_APPEND(off, buf, max,
            "<div class='kv'><b>expires</b><span class='val'>%lld</span>"
            "</div>", (long long)row->expires_at);
    SITE_APPEND(off, buf, max,
        "<div class='kv'><b>id</b><span class='val mono'>%s</span></div>"
        "<div class='kv'><b>host key</b>"
        "<span class='val mono'>%s</span></div>", id_hex, host_hex);
    static const uint8_t zero[32];
    if (memcmp(p->ref, zero, 32) != 0) {
        char ref_hex[65];
        fleet_board_id_to_hex(p->ref, ref_hex);
        SITE_APPEND(off, buf, max,
            "<div class='kv'><b>reply to</b><span class='val mono'>"
            "<a href='/board/post/%s'>%s</a></span></div>",
            ref_hex, ref_hex);
    }
    return off;
}

static size_t bs_render_post(const struct db_fleet_board_post *row,
                             uint8_t *resp, size_t max)
{
    char *body = zcl_malloc(BS_POST_BODY_MAX, "board post page");
    if (!body)
        return bs_post_not_found(resp, max);
    size_t off = bs_body_start(body, BS_POST_BODY_MAX, "Board post");
    SITE_APPEND(off, body, BS_POST_BODY_MAX, "<h1>Board post</h1>");
    off = bs_append_post_meta(body, BS_POST_BODY_MAX, off, row);
    SITE_APPEND(off, body, BS_POST_BODY_MAX,
        "<pre style='white-space:pre-wrap;overflow-wrap:anywhere'>");
    off = bs_put_escaped(body, BS_POST_BODY_MAX, off, row->post.text);
    SITE_APPEND(off, body, BS_POST_BODY_MAX,
        "</pre><p><a href='/board/room/%s'>&larr; back to the room</a></p>",
        fleet_board_room_name(&row->post));
    off += bs_body_end(body + off, BS_POST_BODY_MAX - off);
    size_t n = bs_wrap_response("200 OK", body, off, resp, max);
    free(body);
    return n;
}

static size_t bs_handle_post(struct node_db *ndb, const char *seg,
                             uint8_t *resp, size_t max)
{
    uint8_t id[32];
    struct db_fleet_board_post found;
    memset(&found, 0, sizeof(found));
    if (!bs_parse_post_id(seg, id) || !db_fleet_board_post_find(ndb, id, &found))
        return bs_post_not_found(resp, max);
    struct db_fleet_board_post *shown =
        zcl_calloc(1, sizeof(*shown), "board post row");
    if (!shown)
        return bs_post_not_found(resp, max);
    size_t n;
    if (bs_post_listed(ndb, id, &found, shown))
        n = bs_render_post(shown, resp, max);
    else
        n = bs_post_not_found(resp, max);
    free(shown);
    return n;
}

static size_t bs_route_room(struct node_db *ndb, const char *seg,
                            uint8_t *resp, size_t max)
{
    char room[FLEET_BOARD_ROOM_MAX + 1];
    if (!bs_copy_segment(room, sizeof(room), seg) ||
        !fleet_board_room_valid(room))
        return bs_simple_error("404 Not Found", "Room not found",
                               "no public room by that name is held "
                               "here; room names are [a-z0-9-]",
                               resp, max);
    return bs_handle_room(ndb, room, resp, max);
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

    /* /board/wiki is the public wiki (controllers/wiki_site_controller.h);
     * it answers every path it owns, including its own 404s. */
    if (strncmp(route, "/board/wiki", 11) == 0) {
        size_t wiki = wiki_site_handle_request(method, path, body, body_len,
                                               response, response_max,
                                               datadir);
        if (wiki > 0)
            return wiki;
    }

    struct node_db *ndb = app_runtime_node_db();
    if (!ndb || !ndb->open)
        return bs_simple_error("503 Service Unavailable",
                               "Board unavailable",
                               "the node database is not open; the board "
                               "lives in it",
                               response, response_max);

    if (bs_path_eq(route, "/board") || bs_path_eq(route, "/board/"))
        return bs_handle_index(ndb, response, response_max);
    if (strncmp(route, "/board/room/", 12) == 0)
        return bs_route_room(ndb, route + 12, response, response_max);
    if (strncmp(route, "/board/post/", 12) == 0)
        return bs_handle_post(ndb, route + 12, response, response_max);
    return bs_simple_error("404 Not Found", "Unknown board route",
                           "routes are /board, /board/room/<name> and "
                           "/board/post/<id>",
                           response, response_max);
}
