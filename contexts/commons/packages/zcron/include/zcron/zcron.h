/*
 * zcron — standard 5-field cron schedule parsing and next-fire
 * computation, with no dependency on the C time library (no mktime,
 * no localtime, no timezones): everything is computed in UTC from a
 * Unix epoch using civil-calendar arithmetic.
 *
 * Supported syntax per field:
 *   *            any value
 *   n            single value
 *   a-b          inclusive range
 *   a-b/s, star/s step within a range (default range is the field's)
 *   x,y,z        comma list of any of the above
 * Month names (jan..dec) and weekday names (sun..sat) are accepted
 * case-insensitively.  Weekday accepts both 0 and 7 for Sunday.
 *
 * Day-of-month / day-of-week semantics follow Vixie cron: if both are
 * restricted (not '*'), a time matches when EITHER field matches;
 * otherwise both must match.
 *
 * Ranges must be ascending (a <= b); steps must be >= 1; values must
 * be within the field's range.  Anything else is rejected with an
 * explanatory message.
 */
#ifndef ZCRON_H
#define ZCRON_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
  uint64_t minute; /* bits 0..59  */
  uint32_t hour;   /* bits 0..23  */
  uint32_t dom;    /* bits 1..31  */
  uint16_t month;  /* bits 1..12  */
  uint16_t dow;    /* bits 0..6 (0 = Sunday); 7 is folded to 0 */
  int dom_star;    /* nonzero if dom field was '*' */
  int dow_star;    /* nonzero if dow field was '*' */
} zcron;

/*
 * Parse a 5-field cron expression.  Returns 1 on success, 0 on error.
 * On error and when err/errcap are usable, a short message is written.
 */
int zcron_parse(const char *s, size_t len, zcron *out, char *err,
                size_t err_cap);

/*
 * Compute the next fire time strictly after `after` (Unix epoch,
 * seconds), in UTC.  Returns the epoch of the next matching minute
 * (always a multiple of 60), or -1 if no fire time exists within the
 * next 8 years (e.g. Feb 31) or `after` is negative.
 */
long long zcron_next(const zcron *c, long long after);

/*
 * Validate then render the schedule back to a canonical string form
 * ("a-b/s" runs, comma lists).  snprintf-style: returns the length
 * that would have been written, always NUL-terminates if cap > 0.
 * Useful for tests and normalisation.
 */
size_t zcron_format(const zcron *c, char *out, size_t cap);

#ifdef __cplusplus
}
#endif

#endif /* ZCRON_H */
