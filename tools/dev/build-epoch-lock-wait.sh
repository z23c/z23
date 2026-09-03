# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# Bounded exclusive-lock acquisition for the compile-epoch authority tools.
# Every flock(2) wait in the epoch pipeline (alias publication, admission,
# GC, object publication, coverage objects) goes through
# z23_build_epoch_flock_bounded so a stuck holder turns the caller red with
# the lock path and the holder pid instead of hanging the lint gate forever.
#
# Tuning: ZCL_BUILD_EPOCH_LOCK_TIMEOUT (positive integer seconds, default
# 120). Ordinary holds are milliseconds (copy + verify); the bound only
# fires when the holder is stuck or dead without releasing. A hung gate
# must turn red, never wait.
#
# Bash only. No new processes on the success path; stat/readlink under
# /proc on the failure path only.

# Print nothing; set the timeout via the caller's environment. Validation
# lives in z23_build_epoch_flock_bounded so every caller shares one funnel.
z23_build_epoch_lock_holders()
{
    local lock_file="$1"
    local want="" key="" candidate="" target="" holders=""
    if [ -n "$lock_file" ] && [ -e "$lock_file" ]; then
        want="$(stat -Lc '%d:%i' "$lock_file" 2>/dev/null)" || want=""
    fi
    if [ -n "$want" ]; then
        for pid_fd in /proc/[0-9]*/fd/[0-9]*; do
            target="$(readlink "$pid_fd" 2>/dev/null)" || continue
            case "$target" in
                "$lock_file"|"$lock_file (deleted)") ;;
                *) continue ;;
            esac
            candidate="${pid_fd#/proc/}"
            candidate="${candidate%%/*}"
            [ "$candidate" != "$$" ] || continue
            key="$(stat -Lc '%d:%i' "$pid_fd" 2>/dev/null)" || continue
            [ "$key" = "$want" ] || continue
            case " $holders " in
                *" $candidate "*) ;;
                *) holders="${holders:+$holders }$candidate" ;;
            esac
        done 2>/dev/null
    fi
    [ -n "$holders" ] ||
        holders='unknown (no matching open file descriptor found)'
    printf '%s\n' "$holders"
}

# usage: z23_build_epoch_flock_bounded <tag> <fd> <lock-file> <lock-kind>
# Acquires an exclusive flock on the already-open fd with a wall-clock
# bound. Returns 0 with the lock held. On timeout (or an invalid timeout)
# prints "<tag>: ..." diagnostics naming the lock and the holder pid(s)
# and returns 1; the caller fails closed through its own fail().
z23_build_epoch_flock_bounded()
{
    local tag="$1" fd="$2" lock_file="$3" kind="$4"
    local timeout holders
    timeout="${ZCL_BUILD_EPOCH_LOCK_TIMEOUT:-120}"
    [[ "$timeout" =~ ^[1-9][0-9]*$ ]] || {
        printf '%s: invalid ZCL_BUILD_EPOCH_LOCK_TIMEOUT=%s (must be a positive integer number of seconds)\n' \
            "$tag" "$timeout" >&2
        return 1
    }
    if flock -w "$timeout" "$fd"; then
        return 0
    fi
    holders="$(z23_build_epoch_lock_holders "$lock_file")"
    printf '%s: timed out after %ss waiting for exclusive %s lock %s (held by pid(s): %s)\n' \
        "$tag" "$timeout" "$kind" "$lock_file" "$holders" >&2
    return 1
}
