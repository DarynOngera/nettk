/* Monotonic clock and deadline helpers shared by the tracer/ping loops. */
#ifndef NT_CLOCK_H
#define NT_CLOCK_H

#include <stdint.h>

uint64_t nt_now_ns(void);                 /* CLOCK_MONOTONIC, nanoseconds */
uint64_t nt_now_us(void);                 /* CLOCK_MONOTONIC, microseconds */
uint64_t nt_ms_to_ns(uint64_t ms);

/* Wait until fd is ready for events or deadline_ns (nt_now_ns scale) passes.
 * Returns 1 ready, 0 timeout, -1 error (errno set). EINTR is retried. */
int nt_poll_until(int fd, short events, uint64_t deadline_ns);

#endif /* NT_CLOCK_H */
