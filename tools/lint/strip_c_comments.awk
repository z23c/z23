# Shared scanner helper — remove C comments from a translation unit so a
# text gate matches CODE and not PROSE.
#
# WHY THIS EXISTS. check_model_sql_literals.sh reported
# app/models/include/models/model_fields.h for "carrying a hand-written SQL
# statement". The file carries no SQL at all: its header comment documents
# how to USE the column macros, with example lines like
#     "SELECT " BLOG_POST_COLUMNS " FROM blog_posts WHERE event_id=?"
# A gate that reads documentation as evidence punishes writing it, and the
# only ways to "fix" the file are to delete the explanation or to add a row
# to a shrink-only baseline that explicitly says a row is not a fix.
#
# MODES.
#   strings=0 (default) — remove comments, keep string literals VERBATIM.
#     For gates whose whole subject is what is inside a string literal.
#   strings=1 — also replace each string/char literal with a single space.
#     For gates looking for identifiers in code, where a name appearing
#     inside a literal is not a call.
# Either way literals are TRACKED, so a /* inside a string does not open a
# comment and a quote inside a comment does not open a string.
#
# LIMITS, stated rather than discovered. Line-continued (\ at end of line)
# tokens are not rejoined; raw newlines inside a literal are not handled
# because C has no multi-line literals; digraphs and trigraphs are not
# translated. Output is line-for-line aligned with the input, so a line
# number from a scan of the output is still the right line in the source.
BEGIN { inblk = 0 }
{
    line = $0; out = ""; i = 1; n = length(line)
    while (i <= n) {
        c = substr(line, i, 1)
        d = substr(line, i, 2)
        if (inblk) {
            if (d == "*/") { inblk = 0; i += 2 } else { i++ }
            continue
        }
        # C translation phase 3 replaces each comment with one space.  The
        # space is load-bearing: deleting a comment would merge the tokens
        # around `static/**/inline`, while turning `F/**/(x)` into the
        # different function-like macro token sequence `F(x)`.
        if (d == "/*") { out = out " "; inblk = 1; i += 2; continue }
        if (d == "//") { out = out " "; break }
        if (c == "\"" || c == "'") {
            q = c
            lit = c
            i++
            while (i <= n) {
                e = substr(line, i, 1)
                if (e == "\\") { lit = lit substr(line, i, 2); i += 2; continue }
                lit = lit e
                i++
                if (e == q) break
            }
            if (strings == 1) out = out " "
            else out = out lit
            continue
        }
        out = out c
        i++
    }
    print out
}
