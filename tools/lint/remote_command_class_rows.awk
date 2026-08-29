# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# remote_command_class_rows.awk — parse config/remote_command_classes.def into
# one tab-separated row per classified leaf:
#
#   <leaf>\t<class>\t<reason>
#
# A row is REMOTE_COMMAND_CLASS(leaf, class, reason) and may wrap across lines,
# so the whole invocation is accumulated by parenthesis depth before its three
# arguments are read. A malformed row (missing class token) is emitted with the
# class field set to "?" so the caller can fail LOUD rather than skip it — a
# parser that silently drops rows it does not understand is how an
# unclassified leaf gets reported as classified.
#
# Kept as a standalone .awk file (never inlined into a shell gate) because an
# apostrophe inside a single-quoted inline awk program swallows the rest of the
# script — see docs/AGENT_TRAPS.md.

function quote_count(s,   i, n) {
    n = 0
    for (i = 1; i <= length(s); i++)
        if (substr(s, i, 1) == "\"")
            n++
    return n
}

function emit(  leaf, cls, reason, rest, form) {
    if (buf == "")
        return
    leaf = "?"
    cls = "?"
    reason = ""
    if (match(buf, /"[^"]*"/)) {
        leaf = substr(buf, RSTART + 1, RLENGTH - 2)
        rest = substr(buf, RSTART + RLENGTH)
        if (match(rest, /REMOTE_CLASS_[A-Z_]+/)) {
            cls = substr(rest, RSTART, RLENGTH)
            rest = substr(rest, RSTART + RLENGTH)
            if (match(rest, /"[^"]*"/))
                reason = substr(rest, RSTART + 1, RLENGTH - 2)
        }
    }
    # A well-formed row carries exactly two string literals — the leaf and the
    # reason — hence exactly four quote characters. A bare `"` typed inside the
    # reason prose is invisible to every check above (the reason still parses,
    # just truncated at the stray quote) and yet would not compile the day a
    # consumer #includes this table as C. Report the count and let the gate
    # decide, so the row is caught while it is being written rather than by the
    # first build that tries to use it.
    form = (quote_count(buf) == 4) ? "WELLFORMED" : "MALFORMED"
    gsub(/\t/, " ", reason)
    printf "%s\t%s\t%s\t%s\n", leaf, cls, reason, form
    buf = ""
}

/^REMOTE_COMMAND_CLASS\(/ {
    emit()
    collecting = 1
    depth = 0
    buf = ""
    sub(/^REMOTE_COMMAND_CLASS/, "", $0)
}

collecting {
    buf = buf " " $0
    parens = $0
    gsub(/[^()]/, "", parens)
    for (i = 1; i <= length(parens); i++) {
        if (substr(parens, i, 1) == "(")
            depth++
        else
            depth--
    }
    if (depth <= 0) {
        collecting = 0
        emit()
    }
}

END { emit() }
