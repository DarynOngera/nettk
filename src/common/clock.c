#include "clock.h"

#include <errno.h>
#include <poll.h>
#include <time.h>

uint64_t nt_now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

uint64_t nt_now_us(void)
{
    return nt_now_ns() / 1000ULL;
}

uint64_t nt_ms_to_ns(uint64_t ms)
{
    return ms * 1000000ULL;
}

int nt_poll_until(int fd, short events, uint64_t deadline_ns)
{
    for (;;) {
        uint64_t now = nt_now_ns();
        if (now >= deadline_ns)
            return 0;
        uint64_t rem = deadline_ns - now;
        int ms = (int)((rem + 999999ULL) / 1000000ULL);

        struct pollfd pfd = { .fd = fd, .events = events, .revents = 0 };
        int r = poll(&pfd, 1, ms);
        if (r > 0)
            return 1;
        if (r == 0)
            return 0;
        if (errno != EINTR)
            return -1;
    }
}
