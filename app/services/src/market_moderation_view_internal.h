/* Private, same-island presentation vocabulary. Public contracts stay in the
 * service header; changing these bytes recompiles and publishes one island. */
#ifndef ZCL_MARKET_MODERATION_VIEW_INTERNAL_H
#define ZCL_MARKET_MODERATION_VIEW_INTERNAL_H

#define MMV_REASON_INVALID "unknown profile or local review state"
#define MMV_REASON_OPEN "open-view shows every locally ingested offer"
#define MMV_REASON_GENERAL \
    "general-audience.v1 shows locally reviewed_ok offers"
#define MMV_REASON_HIDDEN \
    "this node's own profile neither lists nor hosts this offer"
#define MMV_GENERAL_SHOWS "offers the node itself marked reviewed_ok"
#define MMV_GENERAL_HIDES \
    "unreviewed and sensitive offers (kept and never deleted; not listed, not served, not relayed)"
#define MMV_OPEN_SHOWS \
    "every offer the node ingested, annotated with local review_state"
#define MMV_LIVE_SURFACE \
    "profile resolution, visibility decisions, bounded local-view rendering"

#endif /* ZCL_MARKET_MODERATION_VIEW_INTERNAL_H */
