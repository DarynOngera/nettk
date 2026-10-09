/* M0: monotonic clock and deadline polling. */
#include "nt_test.h"
#include "clock.h"

#include <poll.h>
#include <time.h>
#include <unistd.h>

static void test_now(void)
{
    uint64_t a = nt_now_ns();
    uint64_t b = nt_now_ns();
    NT_CHECK(b >= a);
    NT_CHECK(nt_now_us() > 0);
    NT_EQ_INT(nt_ms_to_ns(5), 5000000ull);
    NT_EQ_INT(nt_ms_to_ns(0), 0ull);
}

static void test_poll(void)
{
    int fd[2];
    NT_CHECK(pipe(fd) == 0);

    /* empty pipe, short deadline -> timeout */
    NT_EQ_INT(nt_poll_until(fd[0], POLLIN, nt_now_ns() + nt_ms_to_ns(20)), 0);

    /* deadline already passed -> immediate timeout */
    NT_EQ_INT(nt_poll_until(fd[0], POLLIN, nt_now_ns()), 0);

    /* data present -> ready */
    NT_CHECK(write(fd[1], "x", 1) == 1);
    NT_EQ_INT(nt_poll_until(fd[0], POLLIN, nt_now_ns() + nt_ms_to_ns(100)), 1);

    close(fd[0]);
    close(fd[1]);
}

int main(void)
{
    test_now();
    test_poll();
    NT_DONE();
}
