# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# ship_progress_lib.sh — observed-progress verdicts for tools/ship.sh.
# Sourced, never executed. No `set` here: it must not change the caller's
# shell options.
#
# ── WHY THIS FILE EXISTS ────────────────────────────────────────────────────
# tools/ship.sh put a stopwatch in front of a REMOTE, DESTRUCTIVE rollback
# across every host in one command. Four loops each asked "did this box get
# healthy inside N seconds?" and, on no, restored the previous binary:
#
#   ZCL_SHIP_REMOTE_HEALTH_SECONDS:-300   candidate qualification (remote leg)
#   a hard-coded 300, no override at all   candidate re-check (local leg)
#   ZCL_SHIP_ROLLBACK_HEALTH_SECONDS:-60   restore qualification, both legs
#
# All four required `timeout 20 "/proc/$pid/exe" status` to answer. A remote
# box booting a ~22 GB datadir on a 7200rpm disk exceeds 300s routinely — a
# cold block-file scan plus index reconcile is measured in tens of minutes at
# under 2 MB/s. Under the old code that box got its correctly-shipped binary
# rolled back, and because ship touches the fleet in one command, so did every
# other slow box. That is how a network quietly becomes SSD-only.
#
# The property those deadlines were standing in for is "is this process
# making progress?", and that is directly observable for nothing:
#
#   /proc/<pid>/io    rchar/wchar/read_bytes/write_bytes — bytes moved
#   /proc/<pid>/stat  utime+stime — CPU burned
#   /proc/<pid>/stat  delayacct_blkio_ticks — the decisive one: it climbs
#                     precisely while the process is BLOCKED on the disk. A
#                     box grinding through a cold index on a spinning platter
#                     burns almost no CPU and moves this counter constantly.
#                     It needs CONFIG_TASK_DELAY_ACCT; where the kernel lacks
#                     it the field simply reads 0 and CPU + I/O carry the
#                     signal, which is why all three are summed into one token
#                     rather than any single one being trusted.
#
# A WEDGE IS SILENCE, NOT SLOWNESS. So the only clock allowed to authorise a
# rollback measures time spent with NOTHING moving. An absolute ceiling still
# exists, but its role changed completely: it is a REPORTING window. When it
# expires while the process is demonstrably still advancing, that is its own
# outcome with its own exit code and NO destructive action follows.
#
# ── THE VERDICTS ────────────────────────────────────────────────────────────
# Five different machine states, five different words, and no two of them
# share an exit code:
#
#   QUALIFIED   exact candidate bytes + deploy identity + the process answered
#               `status`.                                              exit 0
#   CRASHED     the process is not staying up — absent, or its pid/start-time
#               changed across CRASH_SAMPLES consecutive observations. This is
#               a restart loop, not a slow machine.                     exit 1
#   WEDGED      the process exists and NOTHING about it moved for the whole
#               silence limit: no bytes, no CPU, no blocked-on-disk ticks.
#               Proven silence.                                         exit 1
#   SLOW        the reporting window expired while progress was still being
#               observed. NOT a failure. The candidate stays installed.  exit 3
#   UNVERIFIED  the window expired with no observed progress either way, and
#               silence has not been established for long enough to convict.
#               Refusing to guess.                                      exit 3
#   UNKNOWN     evidence is UNAVAILABLE — the host could not be reached, or
#               /proc could not be read — for UNKNOWN_SAMPLES in a row. An
#               unreachable host is not a failed deploy; it is a host nobody
#               has looked at. A human decides.                         exit 4
#
# Fail-safe direction here is the OPPOSITE of a lint gate. A lint gate that
# cannot see must fail closed. A rollback that cannot see must NOT fire: the
# damage from rolling a good binary off a reachable-but-quiet fleet is real
# and immediate, while the damage from waiting is a human reading a report.
#
# ── WHY IT IS ONE FILE ──────────────────────────────────────────────────────
# The same verdict has to be reached on TWO machines: inside the ssh heredoc
# that runs on the target box, and in the local loop that re-checks it from
# here. The target box has no checkout of this repo, so the remote leg cannot
# source anything — this file is concatenated ahead of the remote script and
# travels over the wire with it. That transport constraint, not convenience,
# is why the /proc parsers live here in full rather than being imported.
#
# The parser bodies and the compose-don't-collapse shape are deliberately the
# same as the ones proven in deploy/zclassic23-host-watchdog.sh and
# tools/deploy_verify.sh, so all four sites answer a slow box identically.
#
# STRICTLY POSIX sh: no arrays, no `local`, no process substitution. It is
# interpreted by whatever /bin/sh the remote operator happens to have.

# ── /proc parsers (pure text in, one number out, so a fixture can pin them) ──
# Field numbering is post-strip of the "pid (comm) " prefix, so proc(5) fields
# shift down by two: utime(14)/stime(15) -> $12/$13, starttime(22) -> $20,
# delayacct_blkio_ticks(42) -> $40. The comm field can contain spaces and
# parentheses, which is exactly why it is stripped by pattern and not counted.
#
# The `.*` is GREEDY on purpose — the one place in this tree where that is the
# correct choice. comm is the last parenthesised group on the line (every
# field after it is numeric), so the last `)` is the right anchor, while the
# non-greedy `([^)]*)` stops at the FIRST `)` and silently shifts every field
# by however many words the comm contained. A daemon named `z23 (node)` then
# reports someone else's number as its blocked-on-disk ticks — which is the
# reading that decides whether a slow box gets rolled back.
ship_cpu_ticks_from_text() {
    printf '%s\n' "${1:-}" |
        sed 's/^[0-9][0-9]* (.*) //' |
        awk 'NF >= 13 && !seen { printf "%.0f\n", $12 + $13; seen = 1 }
             END { if (!seen) print 0 }'
}

# The counter that makes a slow disk legible. It climbs while the task is in
# uninterruptible block I/O wait — i.e. exactly when a spinning platter is the
# bottleneck and CPU is flat. 0 on kernels without CONFIG_TASK_DELAY_ACCT.
ship_blkio_ticks_from_text() {
    printf '%s\n' "${1:-}" |
        sed 's/^[0-9][0-9]* (.*) //' |
        awk 'NF >= 40 && !seen { printf "%.0f\n", $40; seen = 1 }
             END { if (!seen) print 0 }'
}

# Start time in clock ticks since boot. Paired with the pid it identifies ONE
# process incarnation: a pid alone is reused, so a restart loop that lands on
# the same pid would otherwise read as a stable process.
ship_start_ticks_from_text() {
    printf '%s\n' "${1:-}" |
        sed 's/^[0-9][0-9]* (.*) //' |
        awk 'NF >= 20 && !seen { printf "%.0f\n", $20; seen = 1 }
             END { if (!seen) print 0 }'
}

ship_io_bytes_from_text() {
    printf '%s\n' "${1:-}" |
        awk '/^(rchar|wchar|read_bytes|write_bytes):[ \t]*[0-9]+$/ { total += $2 }
             END { printf "%.0f\n", total + 0 }'
}

# ── observation line ────────────────────────────────────────────────────────
# One line, space separated key=value, values never contain a space:
#
#   observed=<0|1> exists=<0|1> pid=<n> start=<n> sha=<hex|-> \
#   ident=<yes|no> rpc=<ok|no> cpu=<n> blkio=<n> io=<n>
#
# observed=0 is the ONLY thing that means "no evidence" and it is never
# confused with exists=0, which is a positive statement that the box looked
# and found no process. Collapsing those two was the fifth defect: an ssh
# timeout used to read as a dead daemon.
ship_no_evidence_line() {
    printf 'observed=0 exists=0 pid=0 start=0 sha=- ident=no rpc=no cpu=0 blkio=0 io=0\n'
}

# ship_field <line> <key> — pipeline-free extraction. The leading space in the
# match is load-bearing: without it, asking for `io` would match inside
# `blkio=`, and the whole slow-disk signal would be read as I/O bytes.
ship_field() {
    _ship_hay=" $1 "
    _ship_key=" $2="
    case "$_ship_hay" in
        *"$_ship_key"*)
            _ship_t="${_ship_hay#*"$_ship_key"}"
            printf '%s\n' "${_ship_t%% *}"
            ;;
        *) printf '\n' ;;
    esac
}

# ship_field_num <line> <key> — same, defaulting to 0 so arithmetic is safe on
# a truncated or garbled transcript rather than aborting the loop.
ship_field_num() {
    _ship_v="$(ship_field "$1" "$2")"
    case "$_ship_v" in
        ''|*[!0-9]*) printf '0\n' ;;
        *) printf '%s\n' "$_ship_v" ;;
    esac
}

# ── the observer: runs ON the box being judged ──────────────────────────────
# ship_observe <unit> <want_sha> <want_src> <want_commit> <rpc_budget>
#
# want_src empty means "this leg has no deploy identity to check" — the
# restore path puts back a binary that predates the identity drop-in, and
# demanding one there would call every successful rollback a failure.
#
# It ALWAYS exits 0. Its caller distinguishes "the box answered and said X"
# from "the box did not answer" by transport status, and an observer that
# could exit non-zero would blur exactly that line.
ship_observe() {
    _ship_unit="$1"; _ship_want_sha="$2"; _ship_want_src="$3"
    _ship_want_commit="$4"; _ship_budget="$5"

    _ship_pid="$(systemctl --user show "$_ship_unit" -p MainPID --value 2>/dev/null)" || {
        ship_no_evidence_line
        return 0
    }
    case "$_ship_pid" in
        ''|*[!0-9]*|0)
            printf 'observed=1 exists=0 pid=0 start=0 sha=- ident=no rpc=no cpu=0 blkio=0 io=0\n'
            return 0
            ;;
    esac
    _ship_stat="$(cat "/proc/$_ship_pid/stat" 2>/dev/null || true)"
    if [ -z "$_ship_stat" ]; then
        # The unit named a pid and the pid is gone: the box looked, and there
        # is no process. That is existence, not missing evidence.
        printf 'observed=1 exists=0 pid=%s start=0 sha=- ident=no rpc=no cpu=0 blkio=0 io=0\n' \
            "$_ship_pid"
        return 0
    fi
    _ship_io="$(cat "/proc/$_ship_pid/io" 2>/dev/null || true)"
    _ship_sha="$(sha256sum < "/proc/$_ship_pid/exe" 2>/dev/null | awk '{print $1}' || true)"
    [ -n "$_ship_sha" ] || _ship_sha=-

    _ship_ident=yes
    if [ -n "$_ship_want_src" ]; then
        _ship_ident="$(tr '\000' '\n' < "/proc/$_ship_pid/environ" 2>/dev/null |
            awk -v src="ZCL_AGENT_EXPECT_SOURCE_ID=$_ship_want_src" \
                -v commit="ZCL_AGENT_EXPECT_BUILD_COMMIT=$_ship_want_commit" \
                -v origin="ZCL_AGENT_EXPECT_BUILD_SOURCE=ship" '
                    $0 == src { have_src = 1 }
                    $0 == commit { have_commit = 1 }
                    $0 == origin { have_origin = 1 }
                    END { if (have_src && have_commit && have_origin) print "yes"; else print "no" }
                ' || true)"
        [ -n "$_ship_ident" ] || _ship_ident=no
    fi

    # A non-answer here is NEVER a fault on its own. Patience is expressed by
    # asking again on the next poll with a bigger budget (ship_rpc_budget),
    # not by one large timeout: a node replaying a cold index answers no RPC
    # at all for as long as that takes, and it is working the whole time.
    _ship_rpc=no
    if timeout "$_ship_budget" "/proc/$_ship_pid/exe" status >/dev/null 2>&1; then
        _ship_rpc=ok
    fi

    printf 'observed=1 exists=1 pid=%s start=%s sha=%s ident=%s rpc=%s cpu=%s blkio=%s io=%s\n' \
        "$_ship_pid" \
        "$(ship_start_ticks_from_text "$_ship_stat")" \
        "$_ship_sha" "$_ship_ident" "$_ship_rpc" \
        "$(ship_cpu_ticks_from_text "$_ship_stat")" \
        "$(ship_blkio_ticks_from_text "$_ship_stat")" \
        "$(ship_io_bytes_from_text "$_ship_io")"
}

# ship_rpc_budget <attempt> <budget-list> — escalating patience. A late answer
# is an ANSWER; the list sticks at its last entry rather than growing forever,
# because an unbounded probe would just move the wedge into the probe itself.
ship_rpc_budget() {
    _ship_want="$1"
    _ship_i=0
    _ship_pick=
    for _ship_b in $2; do
        _ship_i=$((_ship_i + 1))
        _ship_pick="$_ship_b"
        if [ "$_ship_i" -ge "$_ship_want" ]; then break; fi
    done
    [ -n "$_ship_pick" ] || _ship_pick=20
    printf '%s\n' "$_ship_pick"
}

# ── the classifier ──────────────────────────────────────────────────────────
# ship_verdict <qualified> <observed> <exists> <silent_for> <silence_limit> \
#              <unstable_streak> <crash_samples> <unknown_streak> \
#              <unknown_samples> <window_expired> <advances>
#
# Nothing in here is a duration except silent_for, and silent_for measures the
# SUBJECT (how long it has been still) rather than the observer's patience.
# Order matters and is the fail-safe direction:
#   - a positive crash observation outranks missing evidence;
#   - missing evidence outranks a silence claim, because a box we cannot see
#     has not been proven still;
#   - silence outranks the window, so a real wedge is still named on time;
#   - the window is last and can only ever produce a non-destructive word.
ship_verdict() {
    _ship_q="$1"; _ship_obs="$2"; _ship_ex="$3"
    _ship_sil="$4"; _ship_sill="$5"
    _ship_ust="$6"; _ship_ustl="$7"
    _ship_unk="$8"; _ship_unkl="$9"
    shift 9
    _ship_we="$1"; _ship_adv="$2"

    if [ "$_ship_q" -eq 1 ]; then printf 'QUALIFIED\n'; return 0; fi
    if [ "$_ship_ust" -ge "$_ship_ustl" ]; then printf 'CRASHED\n'; return 0; fi
    if [ "$_ship_unk" -ge "$_ship_unkl" ]; then printf 'UNKNOWN\n'; return 0; fi
    if [ "$_ship_obs" -eq 1 ] && [ "$_ship_ex" -eq 1 ] &&
       [ "$_ship_sil" -ge "$_ship_sill" ]; then
        printf 'WEDGED\n'; return 0
    fi
    if [ "$_ship_we" -eq 1 ]; then
        if [ "$_ship_adv" -gt 0 ]; then printf 'SLOW\n'; else printf 'UNVERIFIED\n'; fi
        return 0
    fi
    printf 'WATCHING\n'
}

# ship_verdict_code <verdict> — the exit-code contract. Five answers, and the
# only ones that authorise a destructive rollback are the two that PROVE a
# fault. 3 and 4 are both "no rollback", kept apart because they need
# different follow-up: 3 says keep watching, 4 says go look at the host.
ship_verdict_code() {
    case "$1" in
        QUALIFIED) printf '0\n' ;;
        CRASHED|WEDGED) printf '1\n' ;;
        SLOW|UNVERIFIED) printf '3\n' ;;
        UNKNOWN) printf '4\n' ;;
        *) printf '5\n' ;;
    esac
}

# ship_verdict_is_destructive <verdict> — the single place that decides whether
# a verdict may trigger a rollback. Callers ask this rather than testing an
# exit code inline, so a sixth verdict added later has to come through here to
# become destructive.
ship_verdict_is_destructive() {
    case "$1" in
        CRASHED|WEDGED) return 0 ;;
        *) return 1 ;;
    esac
}

# ── the loop ────────────────────────────────────────────────────────────────
# ship_await <label> <observer-command> <want_sha>
#
# <observer-command> is invoked as `<cmd> <rpc_budget>` and must print exactly
# one observation line. It is the seam: on the target box it is a wrapper
# around ship_observe, and from here it is a wrapper around ssh, so the same
# loop and the same verdicts span both machines. A fixture substitutes for it
# with no host at all.
#
# Knobs (all read from the environment so both legs configure identically):
#   SHIP_AWAIT_WINDOW          reporting window, seconds. NOT a failure clock.
#   SHIP_AWAIT_SILENCE         observed stillness that convicts, seconds.
#   SHIP_AWAIT_POLL            seconds between observations.
#   SHIP_AWAIT_CRASH_SAMPLES   consecutive absent/unstable observations.
#   SHIP_AWAIT_UNKNOWN_SAMPLES consecutive no-evidence observations.
#   SHIP_AWAIT_RPC_BUDGETS     escalating `status` timeouts.
#
# Prints evidence, returns ship_verdict_code, and leaves SHIP_AWAIT_LAST_* set.
ship_await() {
    _ship_label="$1"; _ship_obs_cmd="$2"; _ship_want_sha="$3"

    _ship_window="${SHIP_AWAIT_WINDOW:-900}"
    _ship_silence="${SHIP_AWAIT_SILENCE:-300}"
    _ship_poll="${SHIP_AWAIT_POLL:-2}"
    _ship_crash_n="${SHIP_AWAIT_CRASH_SAMPLES:-3}"
    _ship_unknown_n="${SHIP_AWAIT_UNKNOWN_SAMPLES:-5}"
    _ship_budgets="${SHIP_AWAIT_RPC_BUDGETS:-5 20 60}"

    _ship_t0="$(date +%s)"
    _ship_window_end=$((_ship_t0 + _ship_window))
    _ship_last_change="$_ship_t0"
    _ship_now="$_ship_t0"
    _ship_silent=0
    _ship_prev_token=
    _ship_prev_pid=
    _ship_prev_start=
    _ship_advances=0
    _ship_unstable=0
    _ship_unknown=0
    _ship_attempt=0
    _ship_line=
    _ship_verdict=WATCHING

    while : ; do
        _ship_attempt=$((_ship_attempt + 1))
        _ship_budget="$(ship_rpc_budget "$_ship_attempt" "$_ship_budgets")"
        # NEVER judge through a pipe: the observer's own text is captured, and
        # its transport status is captured on its own line.
        _ship_line="$("$_ship_obs_cmd" "$_ship_budget" 2>/dev/null)" || _ship_line=
        [ -n "$_ship_line" ] || _ship_line="$(ship_no_evidence_line)"

        _ship_now="$(date +%s)"
        _ship_observed="$(ship_field_num "$_ship_line" observed)"
        _ship_exists="$(ship_field_num "$_ship_line" exists)"
        _ship_qualified=0

        if [ "$_ship_observed" -eq 1 ]; then
            _ship_unknown=0
            if [ "$_ship_exists" -eq 1 ]; then
                _ship_pid="$(ship_field "$_ship_line" pid)"
                _ship_start="$(ship_field "$_ship_line" start)"
                if [ -n "$_ship_prev_pid" ] &&
                   { [ "$_ship_pid" != "$_ship_prev_pid" ] ||
                     [ "$_ship_start" != "$_ship_prev_start" ]; }; then
                    # A different incarnation than the one we were watching.
                    # One of these is the restart we asked for; a stream of
                    # them is a crash loop, which CRASH_SAMPLES separates.
                    _ship_unstable=$((_ship_unstable + 1))
                else
                    _ship_unstable=0
                fi
                _ship_prev_pid="$_ship_pid"
                _ship_prev_start="$_ship_start"

                _ship_token="$(ship_field "$_ship_line" cpu)/$(ship_field "$_ship_line" blkio)/$(ship_field "$_ship_line" io)"
                if [ -z "$_ship_prev_token" ]; then
                    _ship_last_change="$_ship_now"
                elif [ "$_ship_token" != "$_ship_prev_token" ]; then
                    _ship_advances=$((_ship_advances + 1))
                    _ship_last_change="$_ship_now"
                fi
                _ship_prev_token="$_ship_token"

                if [ "$(ship_field "$_ship_line" sha)" = "$_ship_want_sha" ] &&
                   [ "$(ship_field "$_ship_line" ident)" = yes ] &&
                   [ "$(ship_field "$_ship_line" rpc)" = ok ]; then
                    _ship_qualified=1
                fi
            else
                _ship_unstable=$((_ship_unstable + 1))
            fi
        else
            _ship_unknown=$((_ship_unknown + 1))
        fi

        _ship_silent=$((_ship_now - _ship_last_change))
        _ship_expired=0
        if [ "$_ship_now" -ge "$_ship_window_end" ]; then _ship_expired=1; fi

        _ship_verdict="$(ship_verdict "$_ship_qualified" "$_ship_observed" \
            "$_ship_exists" "$_ship_silent" "$_ship_silence" \
            "$_ship_unstable" "$_ship_crash_n" \
            "$_ship_unknown" "$_ship_unknown_n" \
            "$_ship_expired" "$_ship_advances")"
        if [ "$_ship_verdict" != WATCHING ]; then break; fi
        sleep "$_ship_poll"
    done

    SHIP_AWAIT_LAST_VERDICT="$_ship_verdict"
    SHIP_AWAIT_LAST_LINE="$_ship_line"
    SHIP_AWAIT_LAST_ELAPSED=$((_ship_now - _ship_t0))
    SHIP_AWAIT_LAST_SILENT="$_ship_silent"
    SHIP_AWAIT_LAST_ADVANCES="$_ship_advances"
    SHIP_AWAIT_LAST_ATTEMPTS="$_ship_attempt"

    # Evidence is printed for EVERY verdict, not only the destructive ones: a
    # rollback that cannot show what justified it is indistinguishable from a
    # rollback that fired on a clock, which is the defect being removed.
    printf '%s: %s after %ss (%s observations, %s observed advances, still for %ss; window %ss, silence limit %ss)\n' \
        "$_ship_label" "$_ship_verdict" "$SHIP_AWAIT_LAST_ELAPSED" \
        "$_ship_attempt" "$_ship_advances" "$_ship_silent" \
        "$_ship_window" "$_ship_silence"
    printf '%s: last observation: %s\n' "$_ship_label" "$_ship_line"

    return "$(ship_verdict_code "$_ship_verdict")"
}

# ── remote transport seam ───────────────────────────────────────────────────
# ship_remote_sh <program-text> — run one shell program on the target box.
# ZCL_SHIP_REMOTE_EXEC replaces ssh entirely so the whole two-machine loop can
# be exercised with no host: the hook receives the same program text and can
# script any answer, including no answer at all.
#
# SHIP_SSH_OPTS is deliberately word-split; every option is a single word.
ship_remote_sh() {
    if [ -n "${ZCL_SHIP_REMOTE_EXEC:-}" ]; then
        "$ZCL_SHIP_REMOTE_EXEC" sh "$1"
        return $?
    fi
    # shellcheck disable=SC2086
    ssh $SHIP_SSH_OPTS "$SHIP_REMOTE_HOST" "$1"
}

# ship_remote_script <arg>... — run the script on stdin on the target box.
ship_remote_script() {
    if [ -n "${ZCL_SHIP_REMOTE_EXEC:-}" ]; then
        "$ZCL_SHIP_REMOTE_EXEC" script "$@"
        return $?
    fi
    # shellcheck disable=SC2086
    ssh $SHIP_SSH_OPTS "$SHIP_REMOTE_HOST" bash -s -- "$@"
}

# ship_observer_program <lib-text> <unit> <want_sha> <want_src> <want_commit>
#                       <rpc_budget>
# The exact text executed on the target box for one observation: this whole
# library, then one call. The box has no checkout, so the library travels with
# the question. Always exits 0 — see ship_observe.
#
# It goes over as ONE ssh argv word, which Linux caps at 128 KB per argument.
# This file is a small fraction of that and a poll is once every few seconds,
# so the cost is noise — but if it ever approaches that ceiling the fix is to
# send it on stdin to `sh -s`, NOT to trim the observer. Note that a naive
# `printf ... | ssh` would report printf's SIGPIPE (141) instead of ssh's
# status under pipefail, which is precisely the inversion that must not decide
# whether a host gets rolled back; write it to a temp file and redirect.
ship_observer_program() {
    printf '%s\n' "$1"
    printf "ship_observe '%s' '%s' '%s' '%s' '%s'\nexit 0\n" \
        "$2" "$3" "$4" "$5" "$6"
}

# ship_remote_observe <budget> — the local leg's observer command. Reads its
# subject from SHIP_OBS_* so it matches ship_await's one-argument seam.
#
# Transport failure prints the no-evidence line and returns 0: an ssh that did
# not connect is an UNKNOWN host, never a dead daemon. Conflating those two is
# what let one flaky network path roll a good binary off a working box.
ship_remote_observe() {
    _ship_prog="$(ship_observer_program "$SHIP_LIB_TEXT" "$SHIP_OBS_UNIT" \
        "$SHIP_OBS_SHA" "$SHIP_OBS_SRC" "$SHIP_OBS_COMMIT" "$1")"
    _ship_out="$(ship_remote_sh "$_ship_prog" 2>/dev/null)" || _ship_out=
    case "$_ship_out" in
        *observed=*) printf '%s\n' "$_ship_out" ;;
        *) ship_no_evidence_line ;;
    esac
    return 0
}
