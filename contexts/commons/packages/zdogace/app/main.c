/* zdogace pilot process: bounded obs->ctl pipe loop.
 *
 * Protocol (set by the arena runner): the process reads one
 * ZDOG_OBS_WIRE_LEN-byte observation frame per living plane of its
 * team per tick and answers each with one ZDOG_CTL_WIRE_LEN-byte
 * control frame, until stdin reaches EOF (match over). No other I/O,
 * no allocation, no clock: the process is meant to run under the
 * full-isolation sandbox profile with zero filesystem grants.
 *
 * Any malformed frame is a hard exit(2); the runner treats a dead
 * pilot as deterministic neutral controls, so a crash can never alter
 * a match silently — it is visible in the replay as neutral frames.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "zdogace/zdogace.h"

static int read_exact(int fd, uint8_t *buf, size_t len)
{
    size_t got = 0;
    while (got < len) {
        ssize_t n = read(fd, buf + got, len - got);
        if (n == 0)
            return 0; /* clean EOF: match over */
        if (n < 0)
            return -1;
        got += (size_t)n;
    }
    return 1;
}

static int write_exact(int fd, const uint8_t *buf, size_t len)
{
    size_t put = 0;
    while (put < len) {
        ssize_t n = write(fd, buf + put, len - put);
        if (n <= 0)
            return -1;
        put += (size_t)n;
    }
    return 0;
}

int main(void)
{
    uint8_t obs_wire[ZDOG_OBS_WIRE_LEN];
    uint8_t ctl_wire[ZDOG_CTL_WIRE_LEN];
    zdog_obs obs;
    zdog_ctl ctl;

    for (;;) {
        int r = read_exact(STDIN_FILENO, obs_wire, sizeof(obs_wire));
        if (r == 0)
            return 0;
        if (r < 0 || !zdog_obs_decode(obs_wire, sizeof(obs_wire), &obs))
            return 2;
        zdogace_step(&obs, &ctl);
        if (zdog_ctl_encode(&ctl, ctl_wire, sizeof(ctl_wire)) != sizeof(ctl_wire))
            return 2;
        if (write_exact(STDOUT_FILENO, ctl_wire, sizeof(ctl_wire)) != 0)
            return 2;
    }
}
